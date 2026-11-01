"""Weighted fusion, renormalisation, typosquat bonus, and hard overrides."""

from __future__ import annotations

import pytest
from skill_sentry_cli.core.contracts import (
    Finding,
    OverrideSignal,
    Severity,
    Stage,
    StageResult,
    VerdictTier,
)
from skill_sentry_cli.core.verdict.fusion import FusionError, fuse, score_to_verdict

DEFAULT_SIGNALS = {"anchors": 20.0, "semantic": 20.0, "vision": 20.0, "sandbox": 20.0}


def _result(
    stage: Stage,
    *,
    signals: dict[str, float] | None = None,
    findings: list[Finding] | None = None,
    override: OverrideSignal | None = None,
    degraded: bool = False,
    error: str | None = None,
) -> StageResult:
    return StageResult(
        stage=stage,
        signals=signals or {},
        findings=findings or [],
        override=override,
        degraded=degraded,
        error=error,
    )


def test_weighted_average_uses_all_present_signals():
    results = [
        _result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 40}),
        _result(Stage.SEMANTIC, signals={"semantic": 80}),
    ]
    fused = fuse(results)
    # (0.15*40 + 0.20*80) / (0.15+0.20) = 62.857 -> 63
    assert fused.risk_score == 63
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.signals["anchors"] == 40
    assert fused.missing_signals == ("vision", "sandbox")


def test_missing_stage_is_renormalised():
    only_anchors = fuse([_result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 20})])
    assert only_anchors.risk_score == 20
    assert only_anchors.verdict == VerdictTier.SAFE
    assert only_anchors.coverage == pytest.approx(0.187)


def test_typosquat_bonus_and_signal_detection():
    results = [
        _result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 10}),
        _result(
            Stage.TYPOSQUAT,
            findings=[
                Finding(
                    stage=Stage.TYPOSQUAT,
                    severity=Severity.MEDIUM,
                    message="name is close to a known skill",
                )
            ],
        ),
    ]
    fused = fuse(results)
    assert fused.typosquat_bonus == 15
    assert fused.risk_score == 30
    assert fused.verdict == VerdictTier.SUSPICIOUS


def test_typosquat_alone_can_produce_a_score():
    fused = fuse(
        [
            _result(
                Stage.TYPOSQUAT,
                findings=[
                    Finding(
                        stage=Stage.TYPOSQUAT,
                        severity=Severity.MEDIUM,
                        message="typosquat",
                    )
                ],
            )
        ]
    )
    assert fused.risk_score == 30
    assert fused.typosquat_bonus == 15
    assert fused.verdict == VerdictTier.SUSPICIOUS


def test_override_forces_malicious_95_and_confidence_one():
    results = [
        _result(
            Stage.POISONED_WELL,
            signals={"sandbox": 10},
            override=OverrideSignal(
                verdict=VerdictTier.MALICIOUS,
                confidence=1.0,
                reason="canary marker in outbound DNS",
                source=Stage.POISONED_WELL,
            ),
        )
    ]
    fused = fuse(results)
    assert fused.risk_score >= 95
    assert fused.verdict == VerdictTier.MALICIOUS
    assert fused.confidence == 1.0
    assert fused.override is not None


def test_override_works_without_weighted_signals():
    fused = fuse(
        [
            _result(
                Stage.EVASION,
                override=OverrideSignal(
                    verdict=VerdictTier.MALICIOUS,
                    confidence=1.0,
                    reason="dockerenv probe",
                    source=Stage.EVASION,
                ),
            )
        ]
    )
    assert fused.risk_score == 100
    assert fused.verdict == VerdictTier.MALICIOUS
    assert fused.confidence == 1.0


def test_degraded_without_signals_still_floors_at_suspicious():
    fused = fuse([_result(Stage.SANDBOX, degraded=True, error="docker down")])
    assert fused.risk_score == 30
    assert fused.verdict == VerdictTier.SUSPICIOUS


def test_degraded_stage_never_yields_safe():
    results = [_result(Stage.SEMANTIC, signals={"semantic": 0}, degraded=True, error="model down")]
    fused = fuse(results)
    assert fused.risk_score == 30
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.degraded_stages == (Stage.SEMANTIC,)
    assert any(finding.finding_type == "stage-degraded" for finding in fused.findings)
    assert fused.confidence <= 0.5


def test_empty_results_are_an_error_not_safe():
    with pytest.raises(FusionError):
        fuse([])


def test_no_signals_are_an_error_not_safe():
    with pytest.raises(FusionError, match="no usable"):
        fuse([_result(Stage.SEMANTIC, signals={})])


def test_tier_boundaries_are_exact():
    assert score_to_verdict(0) == VerdictTier.SAFE
    assert score_to_verdict(29) == VerdictTier.SAFE
    assert score_to_verdict(30) == VerdictTier.SUSPICIOUS
    assert score_to_verdict(70) == VerdictTier.SUSPICIOUS
    assert score_to_verdict(71) == VerdictTier.MALICIOUS
    assert score_to_verdict(100) == VerdictTier.MALICIOUS


def test_custom_weights_and_bonus_are_respected():
    fused = fuse(
        [_result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 100})],
        weights={"anchors": 1.0},
        typosquat_bonus=0,
    )
    assert fused.risk_score == 100
    assert fused.verdict == VerdictTier.MALICIOUS


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError):
        fuse([_result(Stage.SEMANTIC, signals={"semantic": 1})], safe_max=70, malicious_min=30)
    with pytest.raises(ValueError):
        fuse([_result(Stage.SEMANTIC, signals={"semantic": 1})], typosquat_bonus=-1)
    with pytest.raises(ValueError):
        score_to_verdict(10, safe_max=-1)
    with pytest.raises(ValueError):
        score_to_verdict(10, malicious_min=101)


def _finding(stage: Stage, severity: Severity) -> Finding:
    return Finding(stage=stage, severity=severity, message=f"{severity.value} evidence")


def test_high_finding_floor_prevents_safe_verdict():
    fused = fuse(
        [
            _result(
                Stage.SEMANTIC,
                signals={"semantic": 5},
                findings=[_finding(Stage.SEMANTIC, Severity.HIGH)],
            ),
            _result(Stage.VISION, signals={"vision": 0}),
            _result(Stage.SANDBOX, signals={"sandbox": 0}),
        ]
    )
    assert fused.risk_score >= 70
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.evidence_floor == 70


def test_critical_finding_floor_is_malicious_95():
    fused = fuse(
        [
            _result(
                Stage.VISION,
                signals={"vision": 5},
                findings=[_finding(Stage.VISION, Severity.CRITICAL)],
            ),
            _result(Stage.SEMANTIC, signals={"semantic": 0}),
        ]
    )
    assert fused.risk_score >= 95
    assert fused.verdict == VerdictTier.MALICIOUS
    assert fused.evidence_floor == 95


def test_medium_finding_floor_is_suspicious_30():
    fused = fuse(
        [
            _result(
                Stage.DETERMINISTIC_ANCHOR,
                signals={"anchors": 0},
                findings=[_finding(Stage.DETERMINISTIC_ANCHOR, Severity.MEDIUM)],
            )
        ]
    )
    assert fused.risk_score == 30
    assert fused.verdict == VerdictTier.SUSPICIOUS


def test_svg_active_content_is_at_least_suspicious():
    fused = fuse(
        [
            _result(
                Stage.DETERMINISTIC_ANCHOR,
                signals={"anchors": 0},
            ),
            _result(
                Stage.SEMANTIC,
                signals={"semantic": 5},
            ),
            _result(
                Stage.VISION,
                signals={"vision": 0},
                findings=[
                    Finding(
                        stage=Stage.VISION,
                        severity=Severity.HIGH,
                        message="Active content detected in SVG asset",
                        finding_type="svg-active-content",
                    )
                ],
            ),
        ]
    )
    assert fused.verdict != VerdictTier.SAFE
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.risk_score >= 70


def test_benign_signals_without_high_findings_remain_safe():
    fused = fuse(
        [
            _result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 0}),
            _result(Stage.SEMANTIC, signals={"semantic": 5}),
            _result(Stage.VISION, signals={"vision": 0}),
            _result(Stage.SANDBOX, signals={"sandbox": 0}),
        ]
    )
    assert fused.verdict == VerdictTier.SAFE
    assert fused.risk_score < 30
    assert fused.evidence_floor == 0


def test_evasion_floor_wins_when_poisoned_well_is_listed_first():
    # Both overrides carry confidence 1.0. The stronger evasion floor must not be
    # hidden by stage order: the documented slack-notif-mal fixture needs 100.
    results = [
        _result(
            Stage.POISONED_WELL,
            override=OverrideSignal(
                verdict=VerdictTier.MALICIOUS,
                confidence=1.0,
                reason="canary marker in outbound DNS",
                source=Stage.POISONED_WELL,
            ),
        ),
        _result(
            Stage.EVASION,
            override=OverrideSignal(
                verdict=VerdictTier.MALICIOUS,
                confidence=1.0,
                reason="dockerenv probe",
                source=Stage.EVASION,
            ),
        ),
    ]
    fused = fuse(results)
    assert fused.risk_score == 100
    assert fused.override is not None
    assert fused.override.source == Stage.EVASION


def test_evasion_floor_wins_when_listed_second_regardless_of_order():
    results = [
        _result(
            Stage.EVASION,
            override=OverrideSignal(
                verdict=VerdictTier.MALICIOUS,
                confidence=1.0,
                reason="dockerenv probe",
                source=Stage.EVASION,
            ),
        ),
        _result(
            Stage.POISONED_WELL,
            override=OverrideSignal(
                verdict=VerdictTier.MALICIOUS,
                confidence=1.0,
                reason="canary marker in outbound DNS",
                source=Stage.POISONED_WELL,
            ),
        ),
    ]
    fused = fuse(results)
    assert fused.risk_score == 100
    assert fused.override.source == Stage.EVASION


# ---------------------------------------------------------------------------
# Model-reported evidence can raise a verdict to SUSPICIOUS, never to MALICIOUS
# on its own.
# ---------------------------------------------------------------------------


def test_lone_model_critical_is_capped_at_suspicious():
    fused = fuse(
        [
            _result(
                Stage.SEMANTIC,
                signals={"semantic": 95.0},
                findings=[_finding(Stage.SEMANTIC, Severity.CRITICAL)],
            ),
            _result(Stage.SPEC, signals={}),
        ],
        weights={"semantic": 1.0},
        typosquat_bonus=0,
    )
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.risk_score <= 70
    assert any(f.finding_type == "semantic-only-capped" for f in fused.findings)


def test_model_high_finding_still_raises_to_suspicious():
    fused = fuse(
        [
            _result(
                Stage.SEMANTIC,
                signals={"semantic": 5.0},
                findings=[_finding(Stage.SEMANTIC, Severity.HIGH)],
            )
        ],
        weights={"semantic": 1.0},
        typosquat_bonus=0,
    )
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.risk_score >= 30


def test_model_critical_with_an_anchor_finding_can_be_malicious():
    fused = fuse(
        [
            _result(
                Stage.SEMANTIC,
                signals={"semantic": 95.0},
                findings=[_finding(Stage.SEMANTIC, Severity.CRITICAL)],
            ),
            _result(
                Stage.DETERMINISTIC_ANCHOR,
                signals={"anchors": 10.0},
                findings=[_finding(Stage.DETERMINISTIC_ANCHOR, Severity.CRITICAL)],
            ),
        ],
        typosquat_bonus=0,
    )
    assert fused.verdict == VerdictTier.MALICIOUS
    assert not any(f.finding_type == "semantic-only-capped" for f in fused.findings)


def test_model_critical_with_a_strong_anchor_signal_can_be_malicious():
    fused = fuse(
        [
            _result(Stage.SEMANTIC, signals={"semantic": 95.0}),
            _result(Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 100.0}),
        ],
        typosquat_bonus=0,
    )
    assert fused.verdict == VerdictTier.MALICIOUS


def test_vision_finding_keeps_its_floor():
    fused = fuse(
        [
            _result(
                Stage.VISION,
                signals={"vision": 5.0},
                findings=[_finding(Stage.VISION, Severity.CRITICAL)],
            ),
        ],
        weights={"vision": 1.0},
        typosquat_bonus=0,
    )
    assert fused.verdict == VerdictTier.MALICIOUS
