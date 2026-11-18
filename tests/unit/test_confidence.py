"""`confidence` is certainty in the verdict; `coverage` is how much of the analysis ran;
the tier boundaries behave as documented."""

from __future__ import annotations

import pytest
from skill_sentry_cli.core.contracts import (
    Finding,
    FindingEvidence,
    OverrideSignal,
    Severity,
    Stage,
    StageResult,
    VerdictTier,
)
from skill_sentry_cli.core.verdict.fusion import (
    default_typosquat_floor,
    fuse,
    score_to_verdict,
)


def _finding(stage: Stage, severity: Severity, kind: str = "x") -> Finding:
    return Finding(
        stage=stage,
        severity=severity,
        message=f"{kind} finding",
        finding_type=kind,
        evidence=FindingEvidence(file="SKILL.md", line=1),
    )


def _clean_run(*, sandbox: str = "ran", vision: str = "na") -> list[StageResult]:
    """Every stage ran and found nothing."""

    results = [
        StageResult(stage=Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 0}),
        StageResult(stage=Stage.SEMANTIC, signals={"semantic": 0}),
    ]
    if vision == "na":
        results.append(
            StageResult(stage=Stage.VISION, telemetry={"vision_status": "not_applicable"})
        )
    else:
        results.append(StageResult(stage=Stage.VISION, signals={"vision": 0}))
    if sandbox == "ran":
        results.append(StageResult(stage=Stage.SANDBOX, signals={"sandbox": 0}))
    elif sandbox == "off":
        results.append(
            StageResult(
                stage=Stage.SANDBOX,
                telemetry={"skipped": True, "reason": "disabled by request or config"},
            )
        )
    elif sandbox == "nothing-to-run":
        results.append(
            StageResult(
                stage=Stage.SANDBOX,
                telemetry={"skipped": True, "reason": "no executable content in the package"},
            )
        )
    return results


def test_a_fully_analysed_clean_skill_is_safe_with_high_confidence_and_full_coverage():
    fused = fuse(_clean_run())

    assert fused.verdict == VerdictTier.SAFE
    assert fused.confidence == pytest.approx(0.95)
    assert fused.completeness == pytest.approx(1.0)


def test_a_text_only_skill_with_nothing_to_run_is_still_fully_analysed():
    fused = fuse(_clean_run(sandbox="nothing-to-run"))

    assert fused.completeness == pytest.approx(1.0)
    assert fused.confidence == pytest.approx(0.95)


def test_turning_the_sandbox_off_lowers_coverage_and_confidence():
    full = fuse(_clean_run())
    static_only = fuse(_clean_run(sandbox="off"))

    assert static_only.verdict == VerdictTier.SAFE
    assert static_only.completeness < full.completeness
    assert static_only.confidence < full.confidence


def test_a_fully_analysed_safe_scores_higher_than_a_degraded_scan():
    safe = fuse(_clean_run())
    degraded_results = _clean_run()
    degraded_results[1] = StageResult(
        stage=Stage.SEMANTIC, degraded=True, error="semantic model unavailable"
    )
    degraded = fuse(degraded_results)

    assert degraded.verdict == VerdictTier.SUSPICIOUS
    assert degraded.confidence <= 0.5
    assert safe.confidence > degraded.confidence


def test_only_the_model_speaking_is_less_certain_than_a_clean_scan():
    results = _clean_run()
    results[1] = StageResult(
        stage=Stage.SEMANTIC,
        signals={"semantic": 60},
        findings=[_finding(Stage.SEMANTIC, Severity.HIGH, "deception")],
    )
    fused = fuse(results)

    assert fused.verdict == VerdictTier.SAFE
    assert any(f.finding_type == "semantic-uncorroborated" for f in fused.findings)
    assert fused.confidence == pytest.approx(0.57)
    assert fused.confidence < fuse(_clean_run()).confidence


def test_an_anchor_backed_malicious_skill_is_more_certain_with_the_model_in_agreement():
    anchor = _finding(Stage.DETERMINISTIC_ANCHOR, Severity.CRITICAL, "shell-exec")
    alone = _clean_run()
    alone[0] = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 95}, findings=[anchor]
    )
    agreeing = list(alone)
    agreeing[1] = StageResult(
        stage=Stage.SEMANTIC,
        signals={"semantic": 80},
        findings=[_finding(Stage.SEMANTIC, Severity.HIGH, "deception")],
    )

    anchor_only = fuse(alone)
    both = fuse(agreeing)

    assert anchor_only.verdict == both.verdict == VerdictTier.MALICIOUS
    assert anchor_only.confidence == pytest.approx(0.85)
    assert both.confidence == pytest.approx(0.95)


def test_a_malicious_override_is_certain():
    override = OverrideSignal(reason="canary left the sandbox", source=Stage.SANDBOX)
    results = [*_clean_run(), StageResult(stage=Stage.POISONED_WELL, override=override)]

    assert fuse(results).confidence == 1.0


def test_an_anchor_backed_suspicion_sits_between_the_extremes():
    results = _clean_run()
    results[0] = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        signals={"anchors": 40},
        findings=[_finding(Stage.DETERMINISTIC_ANCHOR, Severity.MEDIUM, "network")],
    )
    fused = fuse(results)

    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.confidence == pytest.approx(0.65)


def test_the_four_situations_give_four_different_confidences():
    safe = fuse(_clean_run()).confidence
    degraded_results = _clean_run()
    degraded_results[3] = StageResult(stage=Stage.SANDBOX, degraded=True, error="docker down")
    degraded = fuse(degraded_results).confidence
    model_only_results = _clean_run()
    model_only_results[1] = StageResult(
        stage=Stage.SEMANTIC,
        signals={"semantic": 60},
        findings=[_finding(Stage.SEMANTIC, Severity.HIGH)],
    )
    model_only = fuse(model_only_results).confidence
    malicious_results = _clean_run()
    malicious_results[0] = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        signals={"anchors": 95},
        findings=[_finding(Stage.DETERMINISTIC_ANCHOR, Severity.CRITICAL)],
    )
    malicious = fuse(malicious_results).confidence

    assert len({safe, degraded, model_only, malicious}) == 4
    assert degraded < model_only < safe
    assert malicious > degraded


def test_confidence_stays_in_range():
    for results in (_clean_run(), _clean_run(sandbox="off")):
        assert 0.0 <= fuse(results).confidence <= 1.0


# -- tiers -------------------------------------------------------------------
def test_tier_boundaries_are_as_documented():
    # SAFE is below safe_max; SUSPICIOUS runs from safe_max up to and including malicious_min;
    # MALICIOUS is above malicious_min.
    assert score_to_verdict(29, safe_max=30, malicious_min=70) == VerdictTier.SAFE
    assert score_to_verdict(30, safe_max=30, malicious_min=70) == VerdictTier.SUSPICIOUS
    assert score_to_verdict(70, safe_max=30, malicious_min=70) == VerdictTier.SUSPICIOUS
    assert score_to_verdict(71, safe_max=30, malicious_min=70) == VerdictTier.MALICIOUS


def test_the_boundaries_move_with_the_configured_tiers():
    assert score_to_verdict(44, safe_max=45, malicious_min=80) == VerdictTier.SAFE
    assert score_to_verdict(45, safe_max=45, malicious_min=80) == VerdictTier.SUSPICIOUS
    assert score_to_verdict(81, safe_max=45, malicious_min=80) == VerdictTier.MALICIOUS


def _typosquat() -> StageResult:
    return StageResult(
        stage=Stage.TYPOSQUAT,
        findings=[_finding(Stage.TYPOSQUAT, Severity.MEDIUM, "typosquat")],
    )


def test_a_lone_typosquat_has_headroom_above_the_safe_boundary():
    fused = fuse([*_clean_run(), _typosquat()])

    assert default_typosquat_floor() == 40
    assert fused.risk_score == 40
    assert fused.verdict == VerdictTier.SUSPICIOUS
    # Ten points above the boundary: a one-point change cannot flip it.
    assert fused.risk_score - 30 >= 5
    assert fused.verdict == score_to_verdict(fused.risk_score - 5, safe_max=30, malicious_min=70)


def test_the_typosquat_headroom_follows_custom_tiers():
    fused = fuse([*_clean_run(), _typosquat()], safe_max=45, malicious_min=80)

    assert fused.risk_score == default_typosquat_floor(45, 80) == 53
    assert fused.verdict == VerdictTier.SUSPICIOUS


def test_a_lone_typosquat_never_reaches_malicious():
    for safe_max, malicious_min in [(30, 70), (10, 20), (50, 55), (0, 100)]:
        floor = default_typosquat_floor(safe_max, malicious_min)
        assert safe_max <= floor <= malicious_min
        assert (
            score_to_verdict(floor, safe_max=safe_max, malicious_min=malicious_min)
            != VerdictTier.MALICIOUS
        )
