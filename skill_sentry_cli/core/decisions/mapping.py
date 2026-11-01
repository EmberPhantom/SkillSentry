"""Map typed decision answers onto deterministic findings and a semantic score.

Laya is advisory.  A capability is reported only when its calibrated probability
clears ``CAPABILITY_THRESHOLD`` *and* deterministic code can cite a location for
it.  The semantic score is a maximum over the instruction floor, so a ``benign``
answer can never lower an anchor-derived floor.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from skill_sentry_cli.core.contracts import Finding, FindingEvidence, Severity, Stage
from skill_sentry_cli.core.decisions.base import DecisionResult, EvidenceCandidate
from skill_sentry_cli.core.decisions.calibration import calibrate_probability
from skill_sentry_cli.core.decisions.questions import CAPABILITY_QUESTIONS
from skill_sentry_cli.core.semantic.analyzer import _SEVERITY_SCORE

# Placeholder until calibration (L5) sets the real value.  Do not tune by hand.
CAPABILITY_THRESHOLD = 0.7
LOW_CONFIDENCE = 0.5
DECEPTION_SCORE = _SEVERITY_SCORE[Severity.HIGH]

# Capabilities whose presence is high risk on its own.  Everything else is medium.
_HIGH_RISK_CAPABILITIES = frozenset(
    {
        "cap_credentials",
        "cap_env_secrets",
        "cap_upload",
        "cap_dns",
        "cap_persistence",
        "cap_obfuscation",
        "cap_hidden_behavior",
    }
)
_CODE_OWNED_LOCATION = ("SKILL.md", 1)


@dataclass
class MappedDecisions:
    """Findings and score inputs derived from one :class:`DecisionResult`."""

    findings: list[Finding] = field(default_factory=list)
    capability_risk: float = 0.0
    deception_risk: float = 0.0
    telemetry: dict[str, Any] = field(default_factory=dict)


def select_evidence(
    candidates: list[EvidenceCandidate],
    adjudication: Mapping[str, float] | None,
) -> tuple[EvidenceCandidate | None, float | None]:
    """Pick the candidate a capability finding cites, and its adjudicated probability.

    With adjudication, the candidate with the highest harm probability wins.
    Without it, the first anchor candidate is used and the caller records that
    adjudication was unavailable.  The returned location is always code-owned.
    """

    if not candidates:
        return None, None
    if not adjudication:
        return candidates[0], None
    best_id = max(adjudication, key=lambda candidate_id: adjudication[candidate_id])
    chosen = next((c for c in candidates if c.candidate_id == best_id), candidates[0])
    return chosen, float(adjudication[best_id])


def map_decisions(
    result: DecisionResult,
    *,
    candidates: list[EvidenceCandidate],
    adjudication: Mapping[str, float] | None = None,
    threshold: float = CAPABILITY_THRESHOLD,
    temperature: float = 1.0,
) -> MappedDecisions:
    """Turn typed answers into findings that cite only code-owned evidence.

    ``adjudication`` maps candidate IDs to per-candidate harm probabilities.  If
    the best adjudicated probability is below ``threshold``, the capability
    finding is downgraded to a note and contributes no risk.
    """

    mapped = MappedDecisions()
    low_confidence_seen = False
    capabilities: dict[str, float] = {}
    unanchored: list[str] = []
    evidence_candidate, adjudicated_probability = select_evidence(candidates, adjudication)
    if adjudicated_probability is not None:
        adjudicated_probability = calibrate_probability(adjudicated_probability, temperature)

    for question_id in CAPABILITY_QUESTIONS:
        answer = result.answers.get(question_id)
        if answer is None or answer.abstention or answer.noul is None:
            continue
        probability = float(answer.noul)
        calibrated = calibrate_probability(probability, temperature)
        capabilities[question_id] = round(probability, 4)
        if calibrated < threshold:
            continue
        low_confidence = answer.confidence is not None and answer.confidence < LOW_CONFIDENCE
        low_confidence_seen = low_confidence_seen or low_confidence
        if evidence_candidate is None:
            unanchored.append(question_id)
            continue
        severity = Severity.HIGH if question_id in _HIGH_RISK_CAPABILITIES else Severity.MEDIUM
        if low_confidence and severity.rank > Severity.MEDIUM.rank:
            # Low-confidence answers never create a high-severity finding.
            severity = Severity.MEDIUM
        if adjudicated_probability is not None and adjudicated_probability < threshold:
            # The cited code was adjudicated as not harmful: report, do not score.
            severity = Severity.NOTE
        mapped.capability_risk = max(mapped.capability_risk, _SEVERITY_SCORE[severity])
        mapped.findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=severity,
                message=(
                    f"Laya reports capability {question_id} (p={probability:.2f}): "
                    f"{CAPABILITY_QUESTIONS[question_id]}"
                ),
                type=question_id,
                evidence=FindingEvidence(
                    file=evidence_candidate.file,
                    line=evidence_candidate.line,
                    code=evidence_candidate.code,
                ),
            )
        )

    deception_choice: str | None = None
    deception = result.answers.get("deception")
    if deception is not None and not deception.abstention and deception.choice:
        deception_choice = deception.choice
        if deception.confidence is not None and deception.confidence < LOW_CONFIDENCE:
            low_confidence_seen = True
        elif deception_choice == "deceptive":
            mapped.deception_risk = DECEPTION_SCORE
            mapped.findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.HIGH,
                    message="Laya reports declared intent contradicted by the implementation",
                    type="deception",
                    evidence=FindingEvidence(
                        file=_CODE_OWNED_LOCATION[0], line=_CODE_OWNED_LOCATION[1]
                    ),
                )
            )
        elif deception_choice == "unclear":
            mapped.findings.append(
                Finding(
                    stage=Stage.SEMANTIC,
                    severity=Severity.NOTE,
                    message="Laya could not decide whether the implementation matches its intent",
                    type="semantic-unclear-deception",
                    evidence=FindingEvidence(
                        file=_CODE_OWNED_LOCATION[0], line=_CODE_OWNED_LOCATION[1]
                    ),
                )
            )

    if unanchored:
        mapped.findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message=(
                    "Laya reported capabilities with no deterministic location to cite: "
                    + ", ".join(sorted(unanchored))
                ),
                type="semantic-unanchored-capability",
                evidence=FindingEvidence(
                    file=_CODE_OWNED_LOCATION[0], line=_CODE_OWNED_LOCATION[1]
                ),
            )
        )
    if low_confidence_seen:
        mapped.findings.append(
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.NOTE,
                message="Laya answered with low confidence; treat semantic results as review hints",
                type="semantic-low-confidence",
                evidence=FindingEvidence(
                    file=_CODE_OWNED_LOCATION[0], line=_CODE_OWNED_LOCATION[1]
                ),
            )
        )

    intent = result.answers.get("intent")
    mapped.telemetry = {
        "intent": intent.choice if intent is not None else None,
        "deception": deception_choice,
        "capabilities": capabilities,
        "threshold": threshold,
        "temperature": temperature,
        "unanchored_capabilities": sorted(unanchored),
        "adjudicated": adjudication is not None and bool(adjudication),
        "adjudication": {
            str(candidate_id): round(float(probability), 4)
            for candidate_id, probability in (adjudication or {}).items()
        },
        "low_confidence": low_confidence_seen,
        "actual_capabilities": sorted(
            qid for qid, value in capabilities.items() if value >= threshold
        ),
    }
    return mapped


__all__ = [
    "CAPABILITY_THRESHOLD",
    "MappedDecisions",
    "map_decisions",
]
