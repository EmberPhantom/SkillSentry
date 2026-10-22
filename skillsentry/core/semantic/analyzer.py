"""Semantic analyzer: declared intent vs. actual behaviour.

The model is advisory.  Deterministic anchors are injected as ground truth and
the analyzer keeps an independent prompt-injection floor, so a compromised or
hallucinating model cannot talk a scanner out of an instruction it can read.
Model failures always produce a degraded stage, never a clean result.
"""

from __future__ import annotations

from typing import Any

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
)
from skillsentry.core.models._json import validate_json
from skillsentry.core.models.base import ModelClient
from skillsentry.core.parser import SkillPackage, TextFile
from skillsentry.core.semantic.prompts import SEMANTIC_SCHEMA, SYSTEM_PROMPT

MAX_PROMPT_CHARS = 32_000
MAX_FILES_IN_PROMPT = 30
_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SEVERITY_SCORE = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 72,
    Severity.MEDIUM: 42,
    Severity.LOW: 18,
    Severity.NOTE: 0,
}
_INSTRUCTION_TYPES = frozenset({"instruction-injection", "hidden-instruction"})


def _file_lookup(package: SkillPackage) -> dict[str, TextFile]:
    return {text_file.relative.replace("\\", "/"): text_file for text_file in package.text_files}


def _find_location(
    evidence: str,
    *,
    supplied_file: str | None,
    supplied_line: int | None,
    files: dict[str, TextFile],
) -> tuple[str, int, str]:
    fallback = ("SKILL.md", 1, evidence[:500])
    needle = evidence.strip().splitlines()[0][:200] if evidence.strip() else ""
    if supplied_file:
        relative = supplied_file.replace("\\", "/").lstrip("./")
        text_file = files.get(relative)
        if text_file is not None:
            if supplied_line and 1 <= supplied_line <= text_file.line_count:
                line = text_file.line(supplied_line) or ""
                return relative, supplied_line, line.strip()[:500]
            if needle:
                for number, line in enumerate(text_file.text.splitlines(), start=1):
                    if needle.lower() in line.lower():
                        return relative, number, line.strip()[:500]
            return relative, 1, needle[:500]
    if needle:
        for relative, text_file in files.items():
            for number, line in enumerate(text_file.text.splitlines(), start=1):
                if needle.lower() in line.lower():
                    return relative, number, line.strip()[:500]
    return fallback


def _build_prompt(package: SkillPackage, anchors: StageResult) -> str:
    anchor_lines = []
    for finding in anchors.findings[:40]:
        location = finding.evidence.file or "?"
        if finding.evidence.line:
            location += f":{finding.evidence.line}"
        anchor_lines.append(
            f"- [{finding.severity.value}] {finding.finding_type or 'anchor'} at {location}: "
            f"{finding.message}: {finding.evidence.code or ''}"
        )
    if not anchor_lines:
        anchor_lines.append("- none")

    chunks = [
        "DECLARED INTENT (from frontmatter, untrusted):",
        package.description or "(missing)",
        "",
        "DETERMINISTIC ANCHOR FINDINGS (ground truth - do not contradict):",
        *anchor_lines,
        "",
        "UNTRUSTED SKILL CONTENT BEGINS",
    ]
    used = sum(len(chunk) for chunk in chunks)
    ordered = sorted(
        package.text_files,
        key=lambda item: (item.relative != "SKILL.md", item.relative),
    )[:MAX_FILES_IN_PROMPT]
    for text_file in ordered:
        if used >= MAX_PROMPT_CHARS:
            break
        remaining = MAX_PROMPT_CHARS - used
        body = text_file.text[:remaining]
        chunks.append(f"\n===== FILE: {text_file.relative} =====\n{body}")
        used += len(body) + len(text_file.relative) + 20
    chunks.append("\nUNTRUSTED SKILL CONTENT ENDS")
    return "\n".join(chunks)


def _model_score(response: dict[str, Any], patterns: list[Finding]) -> float:
    score = 5.0
    if patterns:
        score = max(_SEVERITY_SCORE[item.severity] for item in patterns)
        score = min(100.0, score + min(8, (len(patterns) - 1) * 2))
    if response.get("is_deceptive"):
        score = max(score, 88.0)
    confidence = float(response.get("confidence") or 0)
    if confidence >= 0.9 and score >= 80:
        score = min(100.0, score + 2)
    return score


def analyze_semantics(
    package: SkillPackage,
    anchors: StageResult,
    model: ModelClient | None,
    *,
    timeout_s: float | None = None,
) -> StageResult:
    """Run semantic analysis; never raises for a model/reporting failure."""

    del timeout_s
    try:
        prompt = _build_prompt(package, anchors)
    except Exception as exc:  # pragma: no cover - defensive only
        return StageResult(
            stage=Stage.SEMANTIC,
            degraded=True,
            error=f"could not build semantic prompt: {exc}",
        )

    instruction_floor = 0.0
    for finding in anchors.findings:
        if finding.finding_type in _INSTRUCTION_TYPES:
            instruction_floor = max(instruction_floor, _SEVERITY_SCORE.get(finding.severity, 42))

    if model is None:
        result = StageResult(
            stage=Stage.SEMANTIC,
            degraded=True,
            error="semantic model unavailable",
            signals={"semantic": instruction_floor} if instruction_floor else {},
        )
        return result

    try:
        response = model.generate_json(SYSTEM_PROMPT, prompt, SEMANTIC_SCHEMA, retries=1)
        validate_json(response, SEMANTIC_SCHEMA)
    except Exception as exc:
        return StageResult(
            stage=Stage.SEMANTIC,
            degraded=True,
            error=f"semantic model unavailable: {exc}",
            signals={"semantic": instruction_floor} if instruction_floor else {},
        )

    files = _file_lookup(package)
    findings: list[Finding] = []
    patterns_raw = response.get("suspicious_patterns")
    if isinstance(patterns_raw, list):
        for item in patterns_raw[:50]:
            if not isinstance(item, dict):
                continue
            evidence = str(item.get("evidence") or "").strip()
            if not evidence:
                continue
            relative, line, code = _find_location(
                evidence,
                supplied_file=item.get("file") if isinstance(item.get("file"), str) else None,
                supplied_line=(
                    int(item["line"])
                    if isinstance(item.get("line"), int) and not isinstance(item.get("line"), bool)
                    else None
                ),
                files=files,
            )
            severity = _SEVERITY.get(str(item.get("severity", "medium")).lower(), Severity.MEDIUM)
            findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=severity,
                    message=f"Model-reported {item.get('type', 'suspicious pattern')}: {evidence[:300]}",
                    type=str(item.get("type") or "semantic-suspicious")[:80],
                    evidence=FindingEvidence(file=relative, line=line, code=code or None),
                )
            )

    if response.get("is_deceptive") and not any(
        item.severity.rank >= Severity.HIGH.rank for item in findings
    ):
        findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.HIGH,
                message=(
                    "Declared intent does not match actual behaviour: "
                    f"{package.description or package.name}"
                ),
                type="deception",
                evidence=FindingEvidence(file="SKILL.md", line=1),
            )
        )
    if not findings:
        findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message="No instruction/behaviour contradiction found",
                type="semantic-clean",
                evidence=FindingEvidence(file="SKILL.md", line=1),
            )
        )

    score = max(instruction_floor, _model_score(response, findings))
    capabilities = response.get("actual_capabilities")
    return StageResult(
        stage=Stage.SEMANTIC,
        findings=findings,
        signals={"semantic": score},
        telemetry={
            "declared_intent": response.get("declared_intent"),
            "actual_capabilities": capabilities if isinstance(capabilities, list) else [],
            "is_deceptive": bool(response.get("is_deceptive")),
            "confidence": float(response.get("confidence") or 0),
            "model_backend": getattr(model, "backend", "unknown"),
            "model_version": getattr(model, "model_version", "unknown"),
            "instruction_floor": instruction_floor,
            "prompt_chars": len(prompt),
        },
    )


__all__ = ["analyze_semantics"]
