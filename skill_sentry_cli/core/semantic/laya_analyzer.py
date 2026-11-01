"""Laya-backed semantic analysis.

Replaces the Gemma prompt path when a typed decision backend is selected.  The
deterministic anchors are sent as ground truth, the skill text is sent as
delimited untrusted data, and the answers are mapped back to findings that cite
only code-owned locations.  Any backend failure yields a degraded stage with the
instruction floor preserved, never a clean result.
"""

from __future__ import annotations

from typing import Any

from skill_sentry_cli.core.contracts import Finding, FindingEvidence, Severity, Stage, StageResult
from skill_sentry_cli.core.decisions.base import DecisionClient, DecisionError, EvidenceCandidate
from skill_sentry_cli.core.decisions.mapping import CAPABILITY_THRESHOLD, map_decisions
from skill_sentry_cli.core.decisions.questions import adjudication_questions, semantic_questions
from skill_sentry_cli.core.parser import SkillPackage
from skill_sentry_cli.core.semantic.analyzer import _INSTRUCTION_TYPES, _SEVERITY_SCORE
from skill_sentry_cli.core.semantic.candidates import build_candidates, candidate_state

ADJUDICATE_TOP_N = 5
MAX_STATE_CHARS = 24_000
MAX_STATE_FILES = 30
MAX_SNIPPET_CHARS = 2_000


def instruction_floor(anchors: StageResult) -> float:
    """Score floor from anchor instruction findings; decisions can never lower it."""

    floor = 0.0
    for finding in anchors.findings:
        if finding.finding_type in _INSTRUCTION_TYPES:
            floor = max(floor, _SEVERITY_SCORE.get(finding.severity, 42))
    return floor


def degraded_semantic_stage(anchors: StageResult, reason: str) -> StageResult:
    """Degraded semantic stage that keeps the anchor floor and never reads as clean."""

    floor = instruction_floor(anchors)
    return StageResult(
        stage=Stage.SEMANTIC,
        degraded=True,
        error=reason,
        signals={"semantic": floor} if floor else {},
    )


def deterministic_only_stage(anchors: StageResult) -> StageResult:
    """Semantic stage when the operator turned typed semantics off (not degraded)."""

    floor = instruction_floor(anchors)
    return StageResult(
        stage=Stage.SEMANTIC,
        findings=[
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message="Semantic decision backend disabled; deterministic evidence only",
                type="semantic-disabled",
                evidence=FindingEvidence(file="SKILL.md", line=1),
            )
        ],
        signals={"semantic": floor} if floor else {},
    )


def _build_snippets(package: SkillPackage) -> tuple[list[dict[str, Any]], int]:
    """Return ``(snippets, omitted)``; ``omitted`` counts files not sent."""

    ordered = sorted(
        package.text_files,
        key=lambda item: (item.relative != "SKILL.md", item.relative),
    )
    omitted = max(0, len(ordered) - MAX_STATE_FILES)
    snippets: list[dict[str, Any]] = []
    used = 0
    for text_file in ordered[:MAX_STATE_FILES]:
        body = text_file.text[:MAX_SNIPPET_CHARS]
        if used + len(body) > MAX_STATE_CHARS:
            omitted += 1
            continue
        snippets.append({"file": text_file.relative.replace("\\", "/"), "text": body})
        used += len(body)
    return snippets, omitted


def _adjudicate(
    client: DecisionClient,
    state: dict[str, Any],
    candidates: list[EvidenceCandidate],
    timeout_s: float | None,
) -> tuple[dict[str, float] | None, str | None]:
    """Ask one yes/no question per top candidate; return ``(probabilities, error)``.

    Probabilities are keyed by candidate ID.  Failure is reported, never raised,
    because the main answers remain valid without adjudication.
    """

    top = candidates[:ADJUDICATE_TOP_N]
    if not top:
        return None, None
    try:
        answered = client.decide(state, adjudication_questions(top), timeout_s=timeout_s)
    except Exception as exc:
        return None, str(exc) or type(exc).__name__

    probabilities: dict[str, float] = {}
    for candidate in top:
        answer = answered.answers.get(f"adj_{candidate.candidate_id}")
        if answer is not None and not answer.abstention and answer.noul is not None:
            probabilities[candidate.candidate_id] = float(answer.noul)
    if not probabilities:
        return None, "adjudication returned no usable answers"
    return probabilities, None


def build_decision_state(
    package: SkillPackage,
    anchors: StageResult,
) -> tuple[dict[str, Any], list[EvidenceCandidate], int, int]:
    """Build the delimited JSON state sent to a decision backend.

    Returns ``(state, candidates, candidates_omitted, snippets_omitted)``.  The
    state carries anchors as ground truth and skill files as untrusted snippets.
    """

    candidates, candidates_omitted = build_candidates(anchors)
    snippets, snippets_omitted = _build_snippets(package)
    state: dict[str, Any] = {
        "declared_intent": package.description or "",
        "package_name": package.name,
        "anchors": candidate_state(candidates),
        "snippets": snippets,
    }
    return state, candidates, candidates_omitted, snippets_omitted


def analyze_semantics_laya(
    package: SkillPackage,
    anchors: StageResult,
    client: DecisionClient,
    *,
    timeout_s: float | None = None,
    threshold: float = CAPABILITY_THRESHOLD,
    temperature: float = 1.0,
) -> StageResult:
    """Run the V1 question set through ``client``; never raises for backend failure."""

    state, candidates, candidates_omitted, snippets_omitted = build_decision_state(package, anchors)

    try:
        result = client.decide(state, semantic_questions(), timeout_s=timeout_s)
    except DecisionError as exc:
        return degraded_semantic_stage(anchors, f"laya decision unavailable: {exc}")
    except Exception as exc:
        return degraded_semantic_stage(anchors, f"laya decision failed: {exc}")

    if all(answer.abstention for answer in result.answers.values()):
        # No usable answer is evidence of nothing; it must not read as clean.
        return degraded_semantic_stage(anchors, "laya abstained on every semantic question")

    adjudication, adjudication_error = _adjudicate(client, state, candidates, timeout_s)
    mapped = map_decisions(
        result,
        candidates=candidates,
        adjudication=adjudication,
        threshold=threshold,
        temperature=temperature,
    )
    findings = list(mapped.findings)
    if adjudication_error:
        # Non-fatal: the main answers stand, and the citation fallback is disclosed.
        findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message=(
                    "Per-candidate adjudication was unavailable; capability findings cite the "
                    f"first anchor candidate: {adjudication_error[:200]}"
                ),
                type="semantic-adjudication-unavailable",
                evidence=FindingEvidence(file="SKILL.md", line=1),
            )
        )
    if candidates_omitted or snippets_omitted:
        findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message=(
                    f"Semantic context was limited: {candidates_omitted} anchor candidate(s) "
                    f"and {snippets_omitted} file snippet(s) were not sent to the decision backend"
                ),
                type="semantic-context-truncated",
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

    score = max(instruction_floor(anchors), mapped.capability_risk, mapped.deception_risk)
    return StageResult(
        stage=Stage.SEMANTIC,
        findings=findings,
        signals={"semantic": score},
        telemetry={
            "decision_backend": "laya",
            "model_backend": result.backend,
            "checkpoint": result.checkpoint,
            "model_version": result.model_version,
            "routing": result.routing,
            "declared_intent": package.description,
            "actual_capabilities": mapped.telemetry["actual_capabilities"],
            "is_deceptive": mapped.telemetry["deception"] == "deceptive",
            "decisions": mapped.telemetry,
            "candidates": len(candidates),
            "candidates_omitted": candidates_omitted,
            "snippets_omitted": snippets_omitted,
            "instruction_floor": instruction_floor(anchors),
            "state_chars": len(str(state)),
        },
    )


__all__ = [
    "analyze_semantics_laya",
    "build_decision_state",
    "degraded_semantic_stage",
    "deterministic_only_stage",
    "instruction_floor",
]
