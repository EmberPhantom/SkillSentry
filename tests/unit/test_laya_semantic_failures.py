"""Laya semantic failure paths: a failed backend is degraded, never clean."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skill_sentry.core.contracts import Finding, FindingEvidence, Severity, Stage, StageResult
from skill_sentry.core.decisions import DecisionAnswer, DecisionQuestion, DecisionResult
from skill_sentry.core.decisions.base import DecisionUnavailable
from skill_sentry.core.parser import parse_skill
from skill_sentry.core.semantic.laya_analyzer import (
    analyze_semantics_laya,
    degraded_semantic_stage,
    deterministic_only_stage,
)


class _RaisingClient:
    backend = "raising"
    model_version = "test"

    def __init__(self, error: Exception) -> None:
        self._error = error

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        raise self._error

    def health(self) -> bool:
        return True


class _AbstainingClient:
    backend = "abstain"
    model_version = "test"

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        return DecisionResult(
            answers={qid: DecisionAnswer(abstention=True) for qid in questions},
            backend="abstain",
        )

    def health(self) -> bool:
        return True


def _package(tmp_path: Path):  # type: ignore[no-untyped-def]
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Summarise documents\n---\nBody\n",
        encoding="utf-8",
    )
    return parse_skill(root)


def _injection_anchors() -> StageResult:
    return StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        findings=[
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=Severity.CRITICAL,
                message="hidden instruction",
                type="instruction-injection",
                evidence=FindingEvidence(file="SKILL.md", line=5, code="ignore previous"),
            )
        ],
    )


def test_unavailable_backend_is_degraded_and_keeps_instruction_floor(tmp_path: Path) -> None:
    stage = analyze_semantics_laya(
        _package(tmp_path),
        _injection_anchors(),
        _RaisingClient(DecisionUnavailable("checkpoint missing")),
    )

    assert stage.degraded is True
    assert "checkpoint missing" in (stage.error or "")
    assert stage.findings == []
    assert stage.signals["semantic"] == 95


def test_unexpected_backend_exception_is_degraded_not_raised(tmp_path: Path) -> None:
    stage = analyze_semantics_laya(
        _package(tmp_path),
        _injection_anchors(),
        _RaisingClient(RuntimeError("cuda out of memory")),
    )

    assert stage.degraded is True
    assert "cuda out of memory" in (stage.error or "")
    assert stage.signals["semantic"] == 95


def test_full_abstention_is_degraded_not_clean(tmp_path: Path) -> None:
    stage = analyze_semantics_laya(_package(tmp_path), _injection_anchors(), _AbstainingClient())

    assert stage.degraded is True
    assert "abstained" in (stage.error or "")
    assert not [f for f in stage.findings if f.finding_type == "semantic-clean"]
    assert stage.signals["semantic"] == 95


def test_degraded_stage_without_anchors_carries_no_score() -> None:
    stage = degraded_semantic_stage(StageResult(stage=Stage.DETERMINISTIC_ANCHOR), "down")

    assert stage.degraded is True
    assert stage.error == "down"
    assert stage.signals == {}


def test_deterministic_only_stage_is_not_degraded() -> None:
    stage = deterministic_only_stage(_injection_anchors())

    assert stage.degraded is False
    assert stage.signals["semantic"] == 95
    assert [f.finding_type for f in stage.findings] == ["semantic-disabled"]
