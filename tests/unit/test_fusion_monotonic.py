"""Unit tests for fusion monotonicity and floor enforcement."""

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    OverrideSignal,
    Severity,
    Stage,
    StageResult,
    VerdictTier,
)
from skillsentry.core.verdict.fusion import fuse


def test_anchor_malicious_overrides_benign_model():
    """Anchor-detected malicious behavior cannot be downgraded by a benign semantic model."""
    anchor_finding = Finding(
        stage=Stage.DETERMINISTIC_ANCHOR,
        severity=Severity.CRITICAL,
        message="Critical credential leak",
        evidence=FindingEvidence(file="scripts/exfil.py", line=10),
    )
    anchor_res = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        findings=[anchor_finding],
        signals={"anchors": 75.0},
    )
    # Model claims clean/benign with 0 risk
    semantic_res = StageResult(
        stage=Stage.SEMANTIC,
        signals={"semantic": 0.0},
    )

    fused = fuse([anchor_res, semantic_res])
    assert fused.verdict == VerdictTier.MALICIOUS
    assert fused.risk_score >= 70


def test_degraded_stage_prevents_safe_verdict():
    """Any degraded stage prevents a clean SAFE verdict, flooring at SUSPICIOUS."""
    degraded_semantic = StageResult(
        stage=Stage.SEMANTIC,
        degraded=True,
        error="Model connection timeout",
        signals={"semantic": 0.0},
    )
    fused = fuse([degraded_semantic])
    assert fused.verdict == VerdictTier.SUSPICIOUS
    assert fused.risk_score >= 30


def test_hard_override_wins_over_everything():
    """Evasion override forces MALICIOUS 100 regardless of other clean stages."""
    clean_anchors = StageResult(stage=Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 0.0})
    clean_semantic = StageResult(stage=Stage.SEMANTIC, signals={"semantic": 0.0})
    evasion_override = StageResult(
        stage=Stage.EVASION,
        override=OverrideSignal(
            verdict=VerdictTier.MALICIOUS,
            confidence=1.0,
            reason="Sandbox evasion probe detected",
            source=Stage.EVASION,
        ),
    )

    fused = fuse([clean_anchors, clean_semantic, evasion_override])
    assert fused.verdict == VerdictTier.MALICIOUS
    assert fused.risk_score == 100


def test_fusion_idempotency_and_determinism():
    """Identical inputs produce identical fused risk scores and findings."""
    r1 = StageResult(stage=Stage.DETERMINISTIC_ANCHOR, signals={"anchors": 45.0})
    r2 = StageResult(stage=Stage.SEMANTIC, signals={"semantic": 20.0})

    out1 = fuse([r1, r2])
    out2 = fuse([r1, r2])

    assert out1.risk_score == out2.risk_score
    assert out1.verdict == out2.verdict
    assert out1.confidence == out2.confidence
