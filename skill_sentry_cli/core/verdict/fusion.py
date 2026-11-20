"""Weighted signal fusion and hard-evidence overrides (docs/02 §2.4).

The rules are intentionally small and explicit:

* missing signal sources are renormalised over the sources that did run;
* a typosquat finding adds its configured bonus after the weighted average;
* findings impose severity floors: CRITICAL >= 95 (MALICIOUS), HIGH >= 70
  (SUSPICIOUS boundary), MEDIUM >= 30 (SUSPICIOUS boundary).  A single strong
  deterministic/vision finding must never be diluted below SAFE by a large
  number of clean-looking signals;
* a lone typosquat hit scores ``typosquat_floor``, by default a quarter of the way up the
  SUSPICIOUS band, so one point of rounding cannot move it across the SAFE boundary;
* ``confidence`` is certainty in the verdict, not the share of stages that ran (see
  :func:`_confidence`); ``completeness`` is that share, over the analyses that apply;
* Poisoned Well / evasion overrides force ``MALICIOUS`` with confidence 1.0;
  evasion reports 100 because it is a direct observation of hostile intent;
* a degraded stage can never leave a scan looking ``SAFE``;
* if no stage produced a signal at all, :class:`FusionError` is raised rather
  than fabricating a clean verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from skill_sentry_cli.core.contracts import (
    COVERAGE_GAP,
    Finding,
    FindingEvidence,
    OverrideSignal,
    Severity,
    Stage,
    StageResult,
    VerdictTier,
)
from skill_sentry_cli.core.version import DEFAULT_WEIGHTS

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
    # Share of the applicable analyses that ran: what the verdict JSON calls ``coverage``.
    completeness: float = 0.0


def fuse(
    stage_results: Iterable[StageResult],
    *,
    weights: Mapping[str, float] | None = None,
    typosquat_bonus: int = 15,
    safe_max: int = 30,
    malicious_min: int = 70,
    typosquat_detected: bool | None = None,
    typosquat_floor: int | None = None,
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
    if typosquat_floor is None:
        typosquat_floor = default_typosquat_floor(safe_max, malicious_min)
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
    # A coverage gap (a file the scan could not read) is why a result is UNSCANNED. It says
    # nothing about what the file holds, so it is never threat evidence: it sets no floor and
    # supports no model claim.
    threats = tuple(f for f in findings if f.finding_type != COVERAGE_GAP)
    evidence_floor = _evidence_floor(
        [finding for finding in threats if finding.stage != Stage.SEMANTIC],
        detected=detected,
        typosquat_floor=typosquat_floor,
    )
    # A model-reported finding raises a verdict to SUSPICIOUS only when something
    # independent supports it: a deterministic, sandbox, or vision finding, a typosquat
    # hit, or a non-zero non-model signal.  Alone, it stays on the weighted score, and a
    # note says so.  It never reaches MALICIOUS by itself.
    model_findings = [finding for finding in findings if finding.stage == Stage.SEMANTIC]
    corroborated = _model_is_corroborated(threats, signals, detected=detected)
    model_floor = (
        min(
            _evidence_floor(model_findings, detected=False, typosquat_floor=0),
            malicious_min,
        )
        if corroborated
        else 0
    )
    uncorroborated_model = not corroborated and _evidence_floor(
        model_findings, detected=False, typosquat_floor=0
    )
    if uncorroborated_model:
        findings = (*findings, _uncorroborated_model_note())
    evidence_floor = max(evidence_floor, model_floor)
    score = max(score, evidence_floor)
    if uncorroborated_model:
        # The model's signal alone must not lift the score into the SUSPICIOUS band.
        score = min(score, safe_max - 1)
    coverage = (
        sum(normalised_weights[key] for key in present) / sum(normalised_weights.values())
        if present
        else 0.0
    )

    tier = score_to_verdict(score, safe_max=safe_max, malicious_min=malicious_min)
    if override is not None:
        if override.verdict == VerdictTier.MALICIOUS:
            # Every malicious override applies its own floor, so a Poisoned Well
            # hit cannot hide an evasion probe that reports a higher floor.
            malicious_floor = max(_override_floor(item) for item in _malicious_overrides(results))
            score = max(score, malicious_floor)
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

    # A MALICIOUS tier needs evidence that is not model output alone: a malicious
    # override, or a non-semantic finding of HIGH or above.  Otherwise the model's
    # verdict is capped at the SUSPICIOUS boundary and the cap is stated.
    if (
        tier == VerdictTier.MALICIOUS
        and override is None
        and not _has_strong_non_semantic_evidence(threats, signals, detected=detected)
    ):
        tier = VerdictTier.SUSPICIOUS
        score = min(score, malicious_min)
        findings = (*findings, _semantic_cap_note())

    completeness = _completeness(results, normalised_weights)
    confidence = _confidence(
        tier=tier,
        override=override,
        completeness=completeness,
        strong_evidence=_has_strong_non_semantic_evidence(threats, signals, detected=detected),
        independent_evidence=_has_independent_evidence(threats, signals, detected=detected),
        model_flags=any(
            finding.stage == Stage.SEMANTIC and finding.severity.rank >= Severity.MEDIUM.rank
            for finding in findings
        ),
        uncorroborated_model=bool(uncorroborated_model),
        degraded=bool(degraded),
    )

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
        completeness=completeness,
    )


def default_typosquat_floor(safe_max: int = 30, malicious_min: int = 70) -> int:
    """Score of a lone typosquat hit: a quarter of the way up the SUSPICIOUS band.

    With the default tiers that is 40. The SAFE boundary is 30 (a score below ``safe_max`` is
    SAFE), so a lone typosquat used to sit exactly on it and a one-point change flipped the
    verdict. Ten points of headroom keep it SUSPICIOUS and well short of MALICIOUS.
    """

    return min(malicious_min, safe_max + max(5, (malicious_min - safe_max) // 4))


# What each fusion signal's stage is, for judging how much of the analysis ran.
_SIGNAL_STAGES = {
    "anchors": Stage.DETERMINISTIC_ANCHOR,
    "semantic": Stage.SEMANTIC,
    "vision": Stage.VISION,
    "sandbox": Stage.SANDBOX,
}
# A stage that skipped for one of these reasons had nothing to analyse; it did not fail.
_NOT_APPLICABLE_REASONS = frozenset({"no executable content in the package"})


def _completeness(results: tuple[StageResult, ...], weights: Mapping[str, float]) -> float:
    """Share of the applicable analyses that ran, weighted like the score.

    A stage that does not apply (vision with no images, the sandbox for a skill with nothing
    to run) is left out of both sides. A stage that failed, was switched off, or never ran
    counts as not run. So a fully analysed text-only skill scores 1.0, and a scan with the
    sandbox off scores lower. A semantic stage that read only part of the text (the rest was
    read by the static checks only) counts for the share it read.
    """

    ran = 0.0
    applicable = 0.0
    for key, stage in _SIGNAL_STAGES.items():
        weight = weights.get(key, 0.0)
        if weight <= 0:
            continue
        found = [result for result in results if result.stage == stage]
        result = found[-1] if found else None
        telemetry = (result.telemetry or {}) if result else {}
        if telemetry.get("vision_status") == "not_applicable":
            continue
        if telemetry.get("skipped") and telemetry.get("reason") in _NOT_APPLICABLE_REASONS:
            continue
        applicable += weight
        if (
            result is not None
            and not (result.degraded or result.error)
            and not telemetry.get("skipped")
        ):
            # Text that only the static checks read counts for the static share of the weight,
            # not the model's: coverage falls by the share the model did not read.
            share = telemetry.get("model_read_share") if stage == Stage.SEMANTIC else None
            ran += weight * (float(share) if isinstance(share, int | float) else 1.0)
    return round(ran / applicable, 3) if applicable else 0.0


def _has_independent_evidence(
    findings: Iterable[Finding], signals: Mapping[str, float], *, detected: bool
) -> bool:
    """Evidence that does not come from the model: a MEDIUM or worse finding from another
    stage, a typosquat hit, or a clearly raised non-model signal."""

    if detected:
        return True
    medium = SEVERITY_FLOORS[Severity.MEDIUM]
    return any(
        finding.stage not in {Stage.SEMANTIC, Stage.VERDICT, Stage.SPEC}
        and finding.severity.rank >= Severity.MEDIUM.rank
        for finding in findings
    ) or any(key != "semantic" and value >= medium for key, value in signals.items())


def _confidence(
    *,
    tier: VerdictTier,
    override: OverrideSignal | None,
    completeness: float,
    strong_evidence: bool,
    independent_evidence: bool,
    model_flags: bool,
    uncorroborated_model: bool,
    degraded: bool,
) -> float:
    """How certain the verdict is, from 0 to 1.

    * A malicious override (a canary left the sandbox, an evasion probe ran) is a direct
      observation: 1.0.
    * MALICIOUS from deterministic evidence: 0.85, and 0.95 when the model also flags it.
    * SUSPICIOUS: with independent evidence 0.65, and 0.75 when the model agrees; only the
      model speaking, 0.40; nothing but a failed stage, 0.30.
    * SAFE: 0.50 plus 0.45 times how much of the applicable analysis ran, so a full scan of a
      skill reaches 0.95 and a scan with the sandbox off less. If the model flagged something
      that nothing else supported, the result is multiplied by 0.6, because the model and
      the evidence disagree.
    * A failed stage caps anything below MALICIOUS at 0.5 and costs a MALICIOUS 0.05.
    """

    if override is not None and override.verdict == VerdictTier.MALICIOUS:
        return 1.0
    if tier == VerdictTier.MALICIOUS:
        value = 0.85 + (0.10 if model_flags else 0.0)
        if not strong_evidence:
            value = 0.6
        if degraded:
            value -= 0.05
    elif tier == VerdictTier.SUSPICIOUS:
        if independent_evidence:
            value = 0.65 + (0.10 if model_flags else 0.0)
        elif model_flags:
            value = 0.40
        else:
            value = 0.30
    else:
        value = 0.50 + 0.45 * completeness
        if uncorroborated_model:
            value *= 0.6
    if override is not None:
        value = max(value, float(override.confidence))
    if degraded and tier != VerdictTier.MALICIOUS:
        value = min(value, 0.5)
    return round(min(1.0, max(0.0, value)), 3)


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


def _has_strong_non_semantic_evidence(
    findings: Iterable[Finding],
    signals: Mapping[str, float],
    *,
    detected: bool,
) -> bool:
    if detected:
        return True
    strong_signal = any(
        key != "semantic" and value >= SEVERITY_FLOORS[Severity.HIGH]
        for key, value in signals.items()
    )
    strong_finding = any(
        finding.stage != Stage.SEMANTIC and finding.severity.rank >= Severity.HIGH.rank
        for finding in findings
    )
    return strong_signal or strong_finding


def _model_is_corroborated(
    findings: Iterable[Finding],
    signals: Mapping[str, float],
    *,
    detected: bool,
) -> bool:
    if detected:
        return True
    independent_finding = any(
        finding.stage != Stage.SEMANTIC and finding.severity.rank > 0 for finding in findings
    )
    independent_signal = any(key != "semantic" and value > 0 for key, value in signals.items())
    return independent_finding or independent_signal


def _uncorroborated_model_note() -> Finding:
    return Finding(
        stage=Stage.VERDICT,
        severity=Severity.NOTE,
        message=(
            "A model-reported finding was not corroborated by any deterministic, sandbox, "
            "vision, or typosquat evidence, so it did not raise the verdict."
        ),
        finding_type="semantic-uncorroborated",
        evidence=FindingEvidence(file="SKILL.md", line=1),
    )


def _semantic_cap_note() -> Finding:
    return Finding(
        stage=Stage.VERDICT,
        severity=Severity.NOTE,
        message=(
            "Verdict capped at SUSPICIOUS: the only malicious evidence is model-reported. "
            "A MALICIOUS verdict needs a deterministic, sandbox, or vision finding."
        ),
        finding_type="semantic-only-capped",
        evidence=FindingEvidence(file="SKILL.md", line=1),
    )


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


def _override_floor(item: OverrideSignal) -> int:
    """Score floor for a malicious override.

    Evasion is direct proof of adversarial behaviour; Poisoned Well is proof of
    exfiltration.  Both are malicious, but the documented slack fixture requires
    the evasion score to reach 100.
    """
    return 100 if item.source == Stage.EVASION else 95


def _malicious_overrides(results: tuple[StageResult, ...]) -> list[OverrideSignal]:
    return [
        result.override
        for result in results
        if result.override is not None and result.override.verdict == VerdictTier.MALICIOUS
    ]


def _select_override(results: tuple[StageResult, ...]) -> OverrideSignal | None:
    overrides = [result.override for result in results if result.override is not None]
    if not overrides:
        return None
    malicious = [item for item in overrides if item.verdict == VerdictTier.MALICIOUS]
    if malicious:
        # Confidence first; on a tie, the stronger floor (evasion) is reported.
        return max(malicious, key=lambda item: (item.confidence, _override_floor(item)))
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
