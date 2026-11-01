"""Report metadata for the Laya decision layer and explicit vision status."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from skill_sentry_cli.core.contracts import (
    ExportFormat,
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
    Verdict,
    VerdictTier,
)
from skill_sentry_cli.core.decisions.report import decision_summary
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.reports import render_report
from skill_sentry_cli.core.vision.vision_scanner import scan_vision

LEAK_MARKER = "SECRET-PROMPT-MARKER-7f3a"


def _verdict() -> Verdict:
    return Verdict(
        skill="demo-skill",
        skill_id=uuid4(),
        scan_id=uuid4(),
        verdict=VerdictTier.SUSPICIOUS,
        risk_score=60,
        confidence=0.8,
        cached=False,
        scan_duration_ms=5,
        findings=[
            Finding(
                stage=Stage.SEMANTIC,
                severity=Severity.HIGH,
                message="Laya reports capability cap_credentials",
                type="cap_credentials",
                evidence=FindingEvidence(file="scripts/sync.py", line=2, code="os.environ"),
            )
        ],
    )


def _stages(*, vision_status: str = "not_applicable") -> list[StageResult]:
    return [
        StageResult(
            stage=Stage.SEMANTIC,
            signals={"semantic": 72},
            telemetry={
                "decision_backend": "laya",
                "model_backend": "laya",
                "checkpoint": "english",
                "model_version": "laya-0.4.17",
                "calibration_version": "cal-7",
                "instruction_floor": 0,
                "decisions": {
                    "threshold": 0.7,
                    "capabilities": {"cap_credentials": 0.93},
                },
                # Keys below must never reach a report.
                "prompt": LEAK_MARKER,
                "routing": {"raw": LEAK_MARKER},
            },
        ),
        StageResult(
            stage=Stage.VISION,
            telemetry={"vision_status": vision_status},
        ),
    ]


def test_markdown_shows_decision_layer_metadata() -> None:
    rendered = render_report(
        _verdict(), ExportFormat.MARKDOWN, stage_results=_stages()
    ).content.decode("utf-8")

    assert "## Decision layer" in rendered
    assert "`laya`" in rendered
    assert "`english`" in rendered
    assert "`cal-7`" in rendered
    assert "`cap_credentials`: 0.93" in rendered
    assert "semantic (laya)" in rendered


def test_reports_never_contain_raw_prompt_or_routing() -> None:
    stages = _stages()
    markdown = render_report(_verdict(), ExportFormat.MARKDOWN, stage_results=stages).content
    sarif = render_report(_verdict(), ExportFormat.SARIF, stage_results=stages).content

    assert LEAK_MARKER.encode() not in markdown
    assert LEAK_MARKER.encode() not in sarif


def test_missing_stage_results_say_not_recorded_not_clean() -> None:
    rendered = render_report(_verdict(), ExportFormat.MARKDOWN).content.decode("utf-8")

    assert "Not recorded for this export." in rendered
    assert "complete" not in rendered


def test_sarif_carries_decision_layer_properties() -> None:
    sarif = json.loads(
        render_report(_verdict(), ExportFormat.SARIF, stage_results=_stages()).content
    )
    properties = sarif["runs"][0]["properties"]["decisionLayer"]

    assert properties["decision_backend"] == "laya"
    assert properties["checkpoint"] == "english"
    assert properties["calibration_version"] == "cal-7"
    assert "prompt" not in properties


def test_degraded_semantic_stage_is_reported_as_degraded() -> None:
    stages = [
        StageResult(
            stage=Stage.SEMANTIC,
            degraded=True,
            error="laya decision unavailable: checkpoint missing",
            signals={},
        )
    ]
    summary = decision_summary(stages)

    assert summary["semantic_degraded"] is True
    assert "checkpoint missing" in (summary["semantic_error"] or "")


def test_vision_status_defaults_to_not_evaluated_when_absent() -> None:
    summary = decision_summary([])

    assert summary["vision_status"] == "not_evaluated"


def test_vision_status_passes_through_known_values_only() -> None:
    assert decision_summary(_stages(vision_status="evaluated"))["vision_status"] == "evaluated"
    assert decision_summary(_stages(vision_status="bogus"))["vision_status"] == "not_evaluated"


def test_scan_without_images_reports_vision_not_applicable(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: plain\ndescription: Plain skill\n---\nBody\n",
        encoding="utf-8",
    )
    stage = scan_vision(parse_skill(root), model=None)

    assert stage.telemetry["vision_status"] == "not_applicable"
    assert stage.degraded is False
