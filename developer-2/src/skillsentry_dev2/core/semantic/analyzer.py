"""
LLM Semantic Analysis Orchestrator (Stage 2).

Coordinates Gemma 4 E4B text analysis via the Model Client interface (I2).
Detects deceptive intent, hidden instructions, and capability contradictions
by evaluating what a skill claims to do versus what the code actually does.

CL-D2-3 · REQ-SEM-01/02 · Source: docs/02-architecture.md §2.3,
developer-2/03-functional-specifications.md Cap D.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from skillsentry_dev2.contracts import (
    LEGAL_INTENT_KEYWORDS,
    Finding,
    ModelClient,
    ModelUnavailableError,
    PackageManifest,
    StageResult,
)
from skillsentry_dev2.core.semantic.ast_anchor import AnchorFinding
from skillsentry_dev2.core.semantic.prompts import (
    PROMPT_VERSION,
    SEMANTIC_RESPONSE_SCHEMA,
    build_system_prompt,
    build_user_prompt,
)

logger = logging.getLogger(__name__)

# ── Intent Keyword Extraction ───────────────────────────────────────────

# Mapping from common terms to canonical intent keywords
INTENT_KEYWORD_MAP: dict[str, str] = {
    # AWS
    "aws": "aws", "s3": "aws", "ec2": "aws", "lambda": "aws",
    "credentials": "aws", "iam": "aws", "boto": "aws", "dynamodb": "aws",
    # Cloud (generic)
    "cloud": "cloud", "azure": "cloud", "gcp": "cloud",
    "storage": "cloud", "bucket": "cloud",
    # GitHub
    "github": "github", "git": "github", "repo": "github",
    "pull request": "github", "pr": "github", "commit": "github",
    # Slack
    "slack": "slack", "webhook": "slack", "channel": "slack",
    "slack_bot": "slack", "xoxb": "slack",
    # SSH
    "ssh": "ssh", "id_rsa": "ssh", "scp": "ssh", "sftp": "ssh",
    "authorized_keys": "ssh", "private key": "ssh",
    # DevOps
    "docker": "devops", "kubernetes": "devops", "k8s": "devops",
    "helm": "devops", "ansible": "devops", "terraform": "devops",
    "ci/cd": "devops", "pipeline": "devops", "deploy": "devops",
}


def _extract_intent_keywords(
    declared_intent: str,
    description: str,
    actual_capabilities: list[str],
) -> list[str]:
    """Extract normalized intent keywords from analysis results.

    Maps free-text declared intent and capabilities to the canonical
    keyword set consumed by Dev 1's context-aware honeypots (INT-1).
    """
    keywords: set[str] = set()
    search_text = f"{declared_intent} {description} {' '.join(str(c) for c in actual_capabilities)}".lower()

    for term, keyword in INTENT_KEYWORD_MAP.items():
        if term in search_text:
            keywords.add(keyword)

    # If nothing matched, use generic
    if not keywords:
        keywords.add("generic")

    # Validate against legal set
    return sorted(keywords & LEGAL_INTENT_KEYWORDS)


# ── Response Validation ─────────────────────────────────────────────────

def _validate_semantic_response(response: dict[str, Any]) -> list[str]:
    """Validate a semantic analysis response against the expected schema.

    Returns a list of validation error messages (empty if valid).
    """
    errors: list[str] = []

    required = ["declared_intent", "actual_capabilities", "is_deceptive",
                "suspicious_patterns", "confidence"]
    for field in required:
        if field not in response:
            errors.append(f"Missing required field: {field}")

    if "declared_intent" in response and not isinstance(response["declared_intent"], str):
        errors.append("'declared_intent' must be a string")

    if "actual_capabilities" in response:
        if not isinstance(response["actual_capabilities"], list):
            errors.append("'actual_capabilities' must be a list")

    if "is_deceptive" in response and not isinstance(response["is_deceptive"], bool):
        errors.append("'is_deceptive' must be a boolean")

    if "suspicious_patterns" in response:
        if not isinstance(response["suspicious_patterns"], list):
            errors.append("'suspicious_patterns' must be a list")
        else:
            valid_sevs = {"critical", "high", "medium", "low", "note"}
            for idx, pat in enumerate(response["suspicious_patterns"]):
                if not isinstance(pat, dict):
                    errors.append(f"suspicious_patterns[{idx}] must be a dict")
                else:
                    sev = str(pat.get("severity", "")).lower()
                    if sev and sev not in valid_sevs:
                        errors.append(f"suspicious_patterns[{idx}].severity '{sev}' is invalid")

    if "confidence" in response:
        conf = response["confidence"]
        if not isinstance(conf, (int, float)) or conf < 0 or conf > 1:
            errors.append("'confidence' must be a number between 0.0 and 1.0")

    return errors


# ── Anchor Contradiction Guard ──────────────────────────────────────────

def _check_anchor_contradictions(
    response: dict[str, Any],
    anchor_findings: list[AnchorFinding],
) -> list[Finding]:
    """Check if the LLM response contradicts confirmed anchor findings.

    Per docs/04-security.md §4.8: if the model claims no dangerous
    activity but anchors confirm otherwise, the anchor wins.
    """
    contradiction_findings: list[Finding] = []

    if not anchor_findings:
        return contradiction_findings

    # Check if model says "not deceptive" but anchors found critical/high patterns
    has_critical_anchors = any(
        f.severity in ("critical", "high") for f in anchor_findings
    )

    if has_critical_anchors and not response.get("is_deceptive", True):
        # Build list of contradicted anchors
        critical_anchors = [
            f"{f.file}:{f.line} ({f.description})"
            for f in anchor_findings
            if f.severity in ("critical", "high")
        ]
        contradiction_findings.append(Finding(
            stage="semantic",
            severity="note",
            message=(
                "Anchor contradiction: LLM claims skill is not deceptive, "
                f"but deterministic anchors confirm dangerous patterns: "
                f"{'; '.join(critical_anchors[:3])}"
            ),
        ))

    return contradiction_findings


# ── Public API ──────────────────────────────────────────────────────────

def analyze_semantics(
    manifest: PackageManifest,
    anchor_block: str,
    anchor_findings: list[AnchorFinding],
    model_client: ModelClient,
) -> StageResult:
    """Run semantic analysis on a skill package via the model client.

    Args:
        manifest: Parsed PackageManifest from Stage 1.
        anchor_block: Serialized anchor findings text for prompt injection.
        anchor_findings: Raw anchor findings for contradiction checking.
        model_client: I2 model client (real or MockGemma).

    Returns:
        StageResult with stage='semantic' and findings.
    """
    system_prompt = build_system_prompt()
    user_prompt, was_truncated = build_user_prompt(manifest, anchor_block=anchor_block, return_truncated=True)

    findings: list[Finding] = []
    signals: dict[str, float] = {"semantic_risk": 0.0}
    stage_degraded = bool(was_truncated)

    if was_truncated:
        findings.append(Finding(
            stage="semantic",
            severity="medium",
            message="Skill content was truncated to fit character budget; semantic analysis may be degraded",
            evidence_json={"pattern": "prompt_budget_truncated"},
        ))

    # Call the model with one retry on failure
    response: Optional[dict[str, Any]] = None
    try:
        response = model_client.generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            schema=SEMANTIC_RESPONSE_SCHEMA,
            retries=1,
        )
    except ModelUnavailableError:
        logger.warning("Model client unavailable for semantic analysis")
    except Exception as e:
        logger.error(f"Semantic analysis error: {e}")

    if response is None:
        # Model unavailable — emit degraded finding (NEVER clean)
        findings.append(Finding(
            stage="semantic",
            severity="note",
            message="Semantic analysis unavailable: model client unreachable or failed",
        ))
        return StageResult(
            stage="semantic",
            findings=findings,
            signals=signals,
            degraded=True,
            telemetry={"prompt_version": PROMPT_VERSION, "intent_keywords": ["generic"]},
        )

    # Validate response schema
    validation_errors = _validate_semantic_response(response)
    if validation_errors:
        findings.append(Finding(
            stage="semantic",
            severity="note",
            message=f"Semantic response validation errors: {'; '.join(validation_errors)}",
        ))
        return StageResult(
            stage="semantic",
            findings=findings,
            signals=signals,
            degraded=True,
            telemetry={"prompt_version": PROMPT_VERSION, "intent_keywords": ["generic"]},
        )

    # Extract results
    declared_intent = response.get("declared_intent", "")
    actual_capabilities = response.get("actual_capabilities", [])
    is_deceptive = response.get("is_deceptive", False)
    suspicious_patterns = response.get("suspicious_patterns", [])
    confidence = response.get("confidence", 0.5)

    # Convert suspicious patterns to findings (DEF-08: defensive validation)
    valid_sevs = {"critical", "high", "medium", "low", "note"}
    for pattern in suspicious_patterns:
        if isinstance(pattern, dict):
            raw_sev = str(pattern.get("severity", "medium")).lower()
            sev = raw_sev if raw_sev in valid_sevs else "medium"
            raw_line = pattern.get("line")
            try:
                line_no = int(raw_line) if raw_line is not None else None
            except (ValueError, TypeError):
                line_no = None
            findings.append(Finding(
                stage="semantic",
                severity=sev,
                message=f"Semantic: {pattern.get('type', 'unknown')} — {pattern.get('evidence', '')}",
                file=str(pattern.get("file")) if pattern.get("file") is not None else None,
                line=line_no,
                evidence_json={
                    "type": pattern.get("type"),
                    "evidence": pattern.get("evidence"),
                },
            ))

    # Add deception finding
    if is_deceptive:
        findings.append(Finding(
            stage="semantic",
            severity="high",
            message=(
                f"Deceptive skill detected: declares '{declared_intent}' "
                f"but actually performs: {', '.join(str(c) for c in actual_capabilities[:3])}"
            ),
        ))

    # Check anchor contradictions
    contradiction_findings = _check_anchor_contradictions(response, anchor_findings)
    findings.extend(contradiction_findings)

    # Compute semantic risk signal
    if is_deceptive:
        # Per developer-2/09-integration-risks-and-decisions.md §2.3
        semantic_risk = max(75.0, confidence * 100.0)
    else:
        semantic_risk = min(20.0, (1.0 - confidence) * 100.0)

    # Override if anchor contradictions found
    if contradiction_findings and anchor_findings:
        # Anchor wins: ensure risk reflects anchor severity
        max_anchor_weight = max(f.weight for f in anchor_findings)
        semantic_risk = max(semantic_risk, float(max_anchor_weight))

    signals["semantic_risk"] = semantic_risk
    signals["semantic"] = semantic_risk

    # Extract intent keywords (INT-1)
    intent_keywords = _extract_intent_keywords(
        declared_intent, manifest.description, actual_capabilities,
    )

    return StageResult(
        stage="semantic",
        findings=findings,
        signals=signals,
        degraded=stage_degraded,
        telemetry={
            "prompt_version": PROMPT_VERSION,
            "intent_keywords": intent_keywords,
            "declared_intent": declared_intent,
            "is_deceptive": is_deceptive,
            "confidence": confidence,
        },
    )

