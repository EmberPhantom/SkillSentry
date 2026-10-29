"""Map-reduce semantic analyzer using grounded Gemma evaluation and coverage tracking."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
)
from skillsentry.core.models.base import ModelClient
from skillsentry.core.models.errors import (
    ModelBadResponse,
    ModelTimeout,
    ModelUnavailable,
    PromptTruncated,
)
from skillsentry.core.parser import SkillPackage
from skillsentry.core.semantic.chunker import (
    Chunk,
    FileChunker,
    compute_chunk_budget,
)
from skillsentry.core.semantic.coverage import CoverageLedger
from skillsentry.core.semantic.grounding import ground_quote
from skillsentry.core.semantic.prompts import (
    MAP_SYSTEM_PROMPT,
    PROMPT_VERSION,
    REDUCE_SYSTEM_PROMPT,
    build_map_user_prompt,
    build_reduce_user_prompt,
)
from skillsentry.core.semantic.schemas import MAP_SCHEMA, REDUCE_SCHEMA, SCHEMA_VERSION

_INSTRUCTION_TYPES = frozenset(
    {"instruction-injection", "hidden-instruction", "prompt-injection", "auditor-injection"}
)

_CAPABILITY_SEVERITY = {
    "prompt_injection_to_auditor": Severity.HIGH,
    "credential_access": Severity.HIGH,
    "env_secrets": Severity.HIGH,
    "data_upload": Severity.HIGH,
    "contradicts_declared_intent": Severity.HIGH,
    "fs_write_outside_package": Severity.HIGH,
    "persistence": Severity.HIGH,
    "obfuscation": Severity.MEDIUM,
    "process_exec": Severity.MEDIUM,
    "network_request": Severity.MEDIUM,
    "dns_activity": Severity.MEDIUM,
    "hidden_behavior": Severity.MEDIUM,
}

_SEVERITY_SCORE = {
    Severity.CRITICAL: 95.0,
    Severity.HIGH: 72.0,
    Severity.MEDIUM: 42.0,
    Severity.LOW: 18.0,
    Severity.NOTE: 0.0,
}


class GemmaAnalyzer:
    """Orchestrates chunked map-reduce semantic analysis with strict grounding."""

    def __init__(
        self,
        model: Optional[ModelClient],
        max_chunks: int = 64,
        max_total_model_seconds: float = 300.0,
        min_confidence: float = 0.5,
    ) -> None:
        self.model = model
        self.max_chunks = max_chunks
        self.max_total_model_seconds = max_total_model_seconds
        self.min_confidence = min_confidence

    def analyze(
        self,
        package: SkillPackage,
        anchors: StageResult,
        timeout_s: Optional[float] = None,
    ) -> StageResult:
        """Runs the map-reduce semantic analysis pipeline over the skill package."""
        start_time = time.monotonic()
        time_limit = min(self.max_total_model_seconds, timeout_s or self.max_total_model_seconds)

        # 1. Compute deterministic instruction floor from anchor findings
        instruction_floor = 0.0
        for f in anchors.findings:
            if f.finding_type in _INSTRUCTION_TYPES:
                instruction_floor = max(instruction_floor, _SEVERITY_SCORE.get(f.severity, 42.0))

        # Check model availability
        if self.model is None:
            return StageResult(
                stage=Stage.SEMANTIC,
                degraded=True,
                error="semantic model not configured or unavailable",
                signals={"semantic": instruction_floor} if instruction_floor else {},
                findings=[
                    Finding(
                        stage=Stage.SEMANTIC,
                        severity=Severity.NOTE,
                        message="Semantic model not configured or disabled; relying on deterministic floors.",
                        type="semantic-model-unavailable",
                        evidence=FindingEvidence(file="SKILL.md", line=1),
                    )
                ],
            )

        # 2. Extract anchor lines per file
        anchor_lines_per_file: Dict[str, Set[int]] = {}
        for f in anchors.findings:
            if f.evidence and f.evidence.file and f.evidence.line:
                norm_f = f.evidence.file.replace("\\", "/").lstrip("./")
                anchor_lines_per_file.setdefault(norm_f, set()).add(f.evidence.line)

        # 3. Chunk all analyzable text files
        effective_ctx = getattr(self.model, "effective_ctx", 16384)
        chunk_budget = compute_chunk_budget(effective_ctx)
        chunker = FileChunker(chunk_budget_tokens=chunk_budget)
        ledger = CoverageLedger()

        all_chunks: List[Chunk] = []
        for tf in package.text_files:
            rel = tf.relative.replace("\\", "/").lstrip("./")
            ledger.record_file_lines(rel, tf.line_count)
            f_anchor_lines = anchor_lines_per_file.get(rel, set())
            is_entry = rel.lower() in {"skill.md", "main.py", "run.py", "index.js"}
            chunks = chunker.chunk_file(
                rel,
                tf.text,
                anchor_lines=f_anchor_lines,
                is_entrypoint=is_entry,
            )
            all_chunks.extend(chunks)

        # Sort all chunks by priority (0=highest), then file, then line
        all_chunks.sort(key=lambda c: (c.priority, c.file, c.start_line))

        # 4. Map phase
        grounded_claims: List[Dict[str, Any]] = []
        total_claims = 0
        ungrounded_claims = 0
        prompt_eval_count_sum = 0
        eval_count_sum = 0
        degraded = False
        degraded_error: Optional[str] = None
        reduce_res: Dict[str, Any] = {
            "intent": "other",
            "consistency": "consistent",
            "consistency_reason": "No discrepancies noted",
            "needs_human_review": False,
        }

        chunks_analyzed = 0
        for idx, chunk in enumerate(all_chunks):
            # Check budgets
            elapsed = time.monotonic() - start_time
            if idx >= self.max_chunks or elapsed >= time_limit:
                ledger.record_unanalyzed(chunk.file, chunk.start_line, chunk.end_line, "budget-exhausted")
                continue

            user_prompt = build_map_user_prompt(
                declared_name=package.name,
                declared_desc=package.description or "",
                file_rel_path=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                chunk_text=chunk.text,
            )

            try:
                # Call model
                res = self.model.generate_json(MAP_SYSTEM_PROMPT, user_prompt, MAP_SCHEMA)
                if hasattr(self.model, "last_call"):
                    call_info = getattr(self.model, "last_call")
                    prompt_eval_count_sum += getattr(call_info, "prompt_eval_count", 0)
                    eval_count_sum += getattr(call_info, "eval_count", 0)
            except PromptTruncated:
                ledger.record_unanalyzed(chunk.file, chunk.start_line, chunk.end_line, "prompt-truncated")
                degraded = True
                continue
            except (ModelUnavailable, ModelTimeout, ModelBadResponse, Exception) as exc:
                degraded = True
                degraded_error = f"Model map call failed: {exc}"
                ledger.record_unanalyzed(chunk.file, chunk.start_line, chunk.end_line, "model-error")
                break

            # Process claims or legacy suspicious patterns
            claims = res.get("claims", [])
            for claim in claims:
                total_claims += 1
                quote = claim.get("quote", "")
                loc = ground_quote(quote, chunk)
                if loc is not None:
                    s_line, e_line = loc
                    grounded_claims.append({
                        "capability": claim.get("capability"),
                        "quote": quote,
                        "why": claim.get("why"),
                        "confidence": float(claim.get("confidence", 0.0)),
                        "file": chunk.file,
                        "line": s_line,
                        "end_line": e_line,
                    })
                else:
                    ungrounded_claims += 1

            for pattern in res.get("suspicious_patterns", []):
                total_claims += 1
                ev = pattern.get("evidence", "")
                loc = ground_quote(ev, chunk) or (chunk.start_line, chunk.end_line)
                sev_str = str(pattern.get("severity", "high")).lower()
                sev = (
                    Severity.CRITICAL
                    if sev_str == "critical"
                    else (Severity.HIGH if sev_str == "high" else Severity.MEDIUM)
                )
                grounded_claims.append({
                    "capability": pattern.get("type", "suspicious_pattern"),
                    "quote": ev,
                    "why": f"Model-reported {pattern.get('type')}: {ev[:100]}",
                    "confidence": float(res.get("confidence", 0.9)),
                    "file": pattern.get("file") or chunk.file,
                    "line": loc[0],
                    "end_line": loc[1],
                    "severity": sev,
                })
            if res.get("is_deceptive"):
                reduce_res["consistency"] = "deceptive"
                reduce_res["consistency_reason"] = "Model flagged deceptive intent"

            ledger.record_analyzed(chunk.file, chunk.start_line, chunk.end_line)
            chunks_analyzed += 1

        # 5. Reduce phase
        coverage_complete = ledger.is_complete()

        if not degraded and grounded_claims:
            anchor_dicts = [
                {
                    "type": f.finding_type,
                    "severity": f.severity.value,
                    "file": f.evidence.file if f.evidence else None,
                    "line": f.evidence.line if f.evidence else None,
                }
                for f in anchors.findings
            ]
            reduce_prompt = build_reduce_user_prompt(
                declared_name=package.name,
                declared_desc=package.description or "",
                grounded_claims=grounded_claims,
                anchor_findings=anchor_dicts,
                coverage_complete=coverage_complete,
            )
            try:
                reduce_res = self.model.generate_json(REDUCE_SYSTEM_PROMPT, reduce_prompt, REDUCE_SCHEMA)
                if hasattr(self.model, "last_call"):
                    call_info = getattr(self.model, "last_call")
                    prompt_eval_count_sum += getattr(call_info, "prompt_eval_count", 0)
                    eval_count_sum += getattr(call_info, "eval_count", 0)
            except Exception as exc:
                degraded = True
                degraded_error = f"Model reduce call failed: {exc}"

        # 6. Formulate Findings
        findings: List[Finding] = []

        # Convert grounded claims to findings
        for gc in grounded_claims:
            conf = gc.get("confidence", 0.0)
            cap = gc.get("capability", "unknown")
            sev = gc.get("severity") or _CAPABILITY_SEVERITY.get(cap, Severity.MEDIUM)

            if conf >= self.min_confidence:
                findings.append(
                    Finding(
                        stage=Stage.SEMANTIC,
                        severity=sev,
                        message=f"Model-grounded {cap}: {gc.get('why')} (quote: {gc.get('quote')[:200]})",
                        type=f"semantic-{cap.replace('_', '-')}",
                        evidence=FindingEvidence(
                            file=gc.get("file"),
                            line=gc.get("line"),
                            code=gc.get("quote"),
                        ),
                    )
                )

        # Deception or consistency finding
        consistency = reduce_res.get("consistency", "consistent")
        if consistency == "deceptive":
            findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.HIGH,
                    message=f"Declared intent contradicts actual behaviour: {reduce_res.get('consistency_reason')}",
                    type="deception",
                    evidence=FindingEvidence(file="SKILL.md", line=1),
                )
            )

        # Unanalyzed coverage finding
        if not coverage_complete:
            degraded = True
            findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.MEDIUM,
                    message=f"Incomplete semantic coverage: {len(ledger.unanalyzed)} file(s) have unanalyzed chunks.",
                    type="semantic-partial-coverage",
                    evidence=FindingEvidence(file="SKILL.md", line=1),
                )
            )

        # Low grounding ratio notice
        if total_claims > 0 and (ungrounded_claims / total_claims) > 0.5:
            findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.NOTE,
                    message=f"High proportion of ungrounded claims ({ungrounded_claims}/{total_claims}); human review suggested.",
                    type="semantic-low-grounding",
                    evidence=FindingEvidence(file="SKILL.md", line=1),
                )
            )

        if not findings:
            findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.NOTE,
                    message="Semantic analysis completed: no anomalous or deceptive patterns identified.",
                    type="semantic-clean",
                    evidence=FindingEvidence(file="SKILL.md", line=1),
                )
            )

        # 7. Compute Score (Rule: Model escalation is capped at SUSPICIOUS = 60.0 max unless critical)
        model_score = 0.0
        if any(f.severity == Severity.CRITICAL for f in findings):
            model_score = 95.0
        elif any(f.severity == Severity.HIGH for f in findings):
            model_score = 60.0  # Max advisory ceiling for 4B model
        elif any(f.severity == Severity.MEDIUM for f in findings):
            model_score = 42.0
        elif any(f.severity == Severity.LOW for f in findings):
            model_score = 18.0

        if consistency == "deceptive":
            model_score = max(model_score, 60.0)

        # Cap non-critical model escalation at SUSPICIOUS (60.0)
        if not any(f.severity == Severity.CRITICAL for f in findings):
            model_score = min(60.0, model_score)

        # Anchor floor can never be lowered by model
        final_score = max(instruction_floor, model_score)

        telemetry = {
            "backend": getattr(self.model, "backend", "unknown"),
            "model_name": getattr(self.model, "model_name", "unknown"),
            "model_digest": getattr(self.model, "digest", ""),
            "effective_ctx": effective_ctx,
            "chunks_total": len(all_chunks),
            "chunks_analyzed": chunks_analyzed,
            "coverage_complete": coverage_complete,
            "total_claims": total_claims,
            "ungrounded_claims": ungrounded_claims,
            "prompt_version": PROMPT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "sum_prompt_eval_count": prompt_eval_count_sum,
            "sum_eval_count": eval_count_sum,
            "instruction_floor": instruction_floor,
            "coverage_ledger": ledger.to_dict(),
        }

        return StageResult(
            stage=Stage.SEMANTIC,
            findings=findings,
            signals={"semantic": final_score},
            telemetry=telemetry,
            degraded=degraded,
            error=degraded_error,
        )
