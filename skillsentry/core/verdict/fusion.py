"""Weighted signal fusion and hard-evidence overrides (docs/02 §2.4).

The rules are intentionally small and explicit:

* missing signal sources are renormalised over the sources that did run;
* a typosquat finding adds its configured bonus after the weighted average;
* findings impose severity floors: CRITICAL >= 95 (MALICIOUS), HIGH >= 70
  (SUSPICIOUS boundary), MEDIUM >= 30 (SUSPICIOUS boundary).  A single strong
  deterministic/vision finding must never be diluted below SAFE by a large
  number of clean-looking signals;
* Poisoned Well / evasion overrides force ``MALICIOUS`` with confidence 1.0;
  evasion reports 100 because it is a direct observation of hostile intent;
* a degraded stage can never leave a scan looking ``SAFE``;
* if no stage produced a signal at all, :class:`FusionError` is raised rather
  than fabricating a clean verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from skillsentry.core.contracts import (
    Finding,
    OverrideSignal,
    Severity,
    Stage,
    StageResult,
    VerdictTier,
)
from skillsentry.core.version import DEFAULT_WEIGHTS

_TIER_RANK = {
    VerdictTier.SAFE: 0,
    VerdictTier.SUSPICIOUS: 1,
    VerdictTier.MALICIOUS: 2,
}
# Evidence floors, not weights.  The score remains the primary explanation;
# these ensure that explicit hostile evidence cannot be averaged away.
SEVERITY_FLOORS: dict[Severity, int] = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 70,
    Severity.MEDIUM: 30,
    Severity.LOW: 0,
    Severity.NOTE: 0,
}


class FusionError(RuntimeError):
    """The stage results cannot produce a trustworthy verdict."""


@dataclass(frozen=True)
class FusionResult:
    """Outcome of one fusion pass.

    ``findings`` includes the stage findings plus an explicit note for every
    degraded stage.  ``missing_signals`` is retained for the caller to surface
    in logs/telemetry; fusion itself renormalises over present signals.
    """

    risk_score: int
    verdict: VerdictTier
    confidence: float
    signals: dict[str, float] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    override: OverrideSignal | None = None
    degraded_stages: tuple[Stage, ...] = ()
    missing_signals: tuple[str, ...] = ()
    typosquat_bonus: int = 0
    coverage: float = 0.0
    evidence_floor: int = 0


def fuse(
    stage_results: Iterable[StageResult],
    *,
    weights: Mapping[str, float] | None = None,
    typosquat_bonus: int = 15,
    safe_max: int = 30,
    malicious_min: int = 70,
    typosquat_detected: bool | None = None,
    typosquat_floor: int = 30,
) -> FusionResult:
    """Fuse stage results into a risk score and tier.

    ``weights`` uses the four canonical keys (``anchors``, ``semantic``,
    ``vision``, ``sandbox``).  Any source absent from the results is omitted
    from the denominator, so partial scans remain useful without manufacturing
    a zero contribution.
    """

    results = tuple(stage_results)
    if not results:
        raise FusionError("cannot fuse an empty stage-result list")
    if typosquat_bonus < 0:
        raise ValueError("typosquat_bonus must be non-negative")
    if not 0 <= safe_max <= 100:
        raise ValueError("safe_max must be between 0 and 100")
    if not 0 <= malicious_min <= 100:
        raise ValueError("malicious_min must be between 0 and 100")
    if safe_max >= malicious_min:
        raise ValueError("safe_max must be lower than malicious_min")
    if not 0 <= typosquat_floor <= 100:
        raise ValueError("typosquat_floor must be between 0 and 100")

    normalised_weights = _normalise_weights(weights)
    signals, typo_signal = _collect_signals(results, normalised_weights)
    # Typosquat is a bonus, not a weighted signal, even if a caller leaves it
    # in a custom weight map.
    present = tuple(key for key in normalised_weights if key != "typosquat" and key in signals)
    detected = (
        typosquat_detected
        if typosquat_detected is not None
        else _typosquat_detected(results, typo_signal)
    )
    override = _select_override(results)
    degraded = tuple(result.stage for result in results if result.degraded or result.error)
    if not present and not detected and override is None and not degraded:
        raise FusionError("no usable stage signals were produced; refusing to emit a SAFE verdict")

    denominator = sum(normalised_weights[key] for key in present)
    if present and denominator <= 0:
        raise FusionError("fusion weights sum to zero")

    weighted = (
        sum(normalised_weights[key] * signals[key] for key in present) / denominator
        if present
        else 0.0
    )
    bonus = int(typosquat_bonus) if detected else 0
    score = _clamp_score(round(weighted) + bonus)
    findings = _collect_findings(results)
    evidence_floor = _evidence_floor(findings, detected=detected, typosquat_floor=typosquat_floor)
    score = max(score, evidence_floor)
    coverage = (
        sum(normalised_weights[key] for key in present) / sum(normalised_weights.values())
        if present
        else 0.0
    )

    tier = score_to_verdict(score, safe_max=safe_max, malicious_min=malicious_min)
    if override is not None:
        if override.verdict == VerdictTier.MALICIOUS:
            # Evasion is direct proof of adversarial behaviour; Poisoned Well is
            # proof of exfiltration.  Both are malicious, but the documented
            # slack fixture requires the evasion score to reach 100.
            override_floor = 100 if override.source == Stage.EVASION else 95
            score = max(score, override_floor)
            tier = VerdictTier.MALICIOUS
        else:
            tier = _max_tier(tier, override.verdict)
            if tier == VerdictTier.SUSPICIOUS:
                score = max(score, safe_max)

    # A scan with a failed stage is not clean, even when the usable signals are
    # all zero.  The note finding makes the reason visible instead of silently
    # lowering the score.
    if degraded and tier == VerdictTier.SAFE:
        score = max(score, safe_max)
        tier = VerdictTier.SUSPICIOUS

    malicious_override = override is not None and override.verdict == VerdictTier.MALICIOUS
    if malicious_override:
        confidence = 1.0
    elif override is not None:
        confidence = max(float(override.confidence), coverage)
    else:
        confidence = round(min(1.0, max(0.0, coverage)), 3)
    if degraded and not malicious_override:
        confidence = min(confidence, 0.5)

    return FusionResult(
        risk_score=score,
        verdict=tier,
        confidence=confidence,
        signals=signals,
        findings=findings,
        override=override,
        degraded_stages=degraded,
        missing_signals=tuple(key for key in normalised_weights if key not in signals),
        typosquat_bonus=bonus,
        coverage=round(coverage, 3),
        evidence_floor=evidence_floor,
    )


def score_to_verdict(
    score: int | float,
    *,
    safe_max: int = 30,
    malicious_min: int = 70,
) -> VerdictTier:
    """Map a 0-100 score to the frozen tier boundaries."""

    if not 0 <= safe_max <= 100:
        raise ValueError("safe_max must be between 0 and 100")
    if not 0 <= malicious_min <= 100:
        raise ValueError("malicious_min must be between 0 and 100")
    if safe_max >= malicious_min:
        raise ValueError("safe_max must be lower than malicious_min")
    value = _clamp_score(round(score))
    if value < safe_max:
        return VerdictTier.SAFE
    if value > malicious_min:
        return VerdictTier.MALICIOUS
    return VerdictTier.SUSPICIOUS


def degradation_findings(stage_results: Iterable[StageResult]) -> list[Finding]:
    """Return explicit note findings for stages that failed or degraded."""

    findings: list[Finding] = []
    for result in stage_results:
        if not (result.degraded or result.error):
            continue
        detail = result.error or "stage marked degraded"
        findings.append(
            Finding(
                stage=result.stage,
                severity=Severity.NOTE,
                message=f"{result.stage.value} degraded: {detail}",
                finding_type="stage-degraded",
            )
        )
    return findings


def _evidence_floor(findings: Iterable[Finding], *, detected: bool, typosquat_floor: int) -> int:
    floor = int(typosquat_floor) if detected else 0
    for finding in findings:
        floor = max(floor, SEVERITY_FLOORS.get(finding.severity, 0))
    return floor


def _normalise_weights(weights: Mapping[str, float] | None) -> dict[str, float]:
    source = dict(weights or DEFAULT_WEIGHTS)
    normalised: dict[str, float] = {}
    for key, raw in source.items():
        if key == "typosquat":
            continue
        value = float(raw)
        if value < 0:
            raise ValueError(f"weight for {key!r} must be non-negative")
        if value == 0:
            continue
        normalised[str(key)] = value
    if not normalised:
        raise ValueError("at least one fusion weight must be positive")
    return normalised


def _collect_signals(
    results: tuple[StageResult, ...], weights: Mapping[str, float]
) -> tuple[dict[str, float], float]:
    signals: dict[str, float] = {}
    typo_signal = 0.0
    for result in results:
        # A stage may emit more than one weighted key (e.g. a combined
        # deterministic stage); take the maximum rather than double-counting.
        for key, raw in result.signals.items():
            if key not in weights and key != "typosquat":
                continue
            value = max(0.0, min(100.0, float(raw)))
            signals[key] = max(signals.get(key, 0.0), value)
            if key == "typosquat":
                typo_signal = max(typo_signal, value)
    return signals, typo_signal


def _typosquat_detected(results: tuple[StageResult, ...], typo_signal: float) -> bool:
    if typo_signal > 0:
        return True
    for result in results:
        if result.stage != Stage.TYPOSQUAT:
            continue
        if result.findings or result.signals.get("typosquat", 0) > 0:
            return True
    return False


def _select_override(results: tuple[StageResult, ...]) -> OverrideSignal | None:
    overrides = [result.override for result in results if result.override is not None]
    if not overrides:
        return None
    malicious = [item for item in overrides if item.verdict == VerdictTier.MALICIOUS]
    if malicious:
        return max(malicious, key=lambda item: item.confidence)
    return max(overrides, key=lambda item: item.confidence)


def _max_tier(left: VerdictTier, right: VerdictTier) -> VerdictTier:
    return left if _TIER_RANK[left] >= _TIER_RANK[right] else right


def _collect_findings(results: tuple[StageResult, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for result in results:
        findings.extend(result.findings)
    findings.extend(degradation_findings(results))
    return tuple(findings)


def _clamp_score(value: int) -> int:
    return max(0, min(100, value))


__all__ = [
    "SEVERITY_FLOORS",
    "FusionError",
    "FusionResult",
    "degradation_findings",
    "fuse",
    "score_to_verdict",
]
