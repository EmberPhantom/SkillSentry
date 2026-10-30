"""Semantic analyzer: chunk budget, coverage gaps, fenced prompts, failure handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skillsentry.core.contracts import Stage, StageResult
from skillsentry.core.models.base import ModelUnavailable
from skillsentry.core.parser import parse_skill
from skillsentry.core.semantic import analyze_semantics
from skillsentry.core.semantic import analyzer as analyzer_module


class _RecordingModel:
    backend = "fake"
    model_version = "fake@1"

    def __init__(self, fail_on: set[int] | None = None) -> None:
        self.prompts: list[str] = []
        self._fail_on = fail_on or set()

    def generate_json(self, system: str, user: str, schema: dict[str, Any], retries: int = 1):  # type: ignore[no-untyped-def]
        index = len(self.prompts)
        self.prompts.append(user)
        if index in self._fail_on:
            raise ModelUnavailable("simulated failure")
        return {
            "declared_intent": "test",
            "actual_capabilities": [],
            "is_deceptive": False,
            "suspicious_patterns": [],
            "confidence": 0.5,
        }

    def health(self) -> bool:
        return True


def _empty_anchors() -> StageResult:
    return StageResult(stage=Stage.DETERMINISTIC_ANCHOR, findings=[])


def _skill(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n" + files.pop("SKILL.md", "Body\n"),
        encoding="utf-8",
    )
    for relative, body in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return root


def test_small_skill_is_fully_covered(tmp_path: Path) -> None:
    package = parse_skill(_skill(tmp_path, {"scripts/run.py": "print('hi')\n"}))
    model = _RecordingModel()

    stage = analyze_semantics(package, _empty_anchors(), model)

    assert stage.degraded is False
    assert stage.telemetry["chunks_analysed"] == stage.telemetry["chunks_total"]
    assert stage.telemetry["gap_ranges"] == []
    assert not [f for f in stage.findings if f.finding_type == "semantic-partial-coverage"]


def test_skill_beyond_the_call_budget_is_partial_and_degraded(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(analyzer_module, "CHUNK_CHARS", 200)
    monkeypatch.setattr(analyzer_module, "MAX_CHUNKS", 2)
    big = "".join(f"line {number} padding padding padding\n" for number in range(200))
    package = parse_skill(_skill(tmp_path, {"scripts/big.py": big}))
    model = _RecordingModel()

    stage = analyze_semantics(package, _empty_anchors(), model)

    assert stage.degraded is True
    assert stage.telemetry["chunks_analysed"] == 2
    assert stage.telemetry["chunks_total"] > 2
    assert stage.telemetry["gap_ranges"]
    notes = [f for f in stage.findings if f.finding_type == "semantic-partial-coverage"]
    assert len(notes) == 1


def test_oversized_line_becomes_a_gap_not_a_silent_cut(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(analyzer_module, "CHUNK_CHARS", 100)
    package = parse_skill(_skill(tmp_path, {"scripts/wide.py": "x" * 500 + "\n"}))

    stage = analyze_semantics(package, _empty_anchors(), _RecordingModel())

    assert stage.degraded is True
    assert any("scripts/wide.py" in gap for gap in stage.telemetry["gap_ranges"])


def test_one_failed_chunk_is_a_gap_and_the_rest_still_count(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(analyzer_module, "CHUNK_CHARS", 120)
    body = "".join(f"step {number} is harmless text\n" for number in range(40))
    package = parse_skill(_skill(tmp_path, {"scripts/a.py": body}))
    model = _RecordingModel(fail_on={1})

    stage = analyze_semantics(package, _empty_anchors(), model)

    assert stage.degraded is True
    assert stage.telemetry["chunks_failed"] == 1
    assert stage.telemetry["chunks_analysed"] >= 1
    assert stage.signals["semantic"] >= 0


def test_every_chunk_failing_is_degraded_with_no_clean_result(tmp_path: Path) -> None:
    package = parse_skill(_skill(tmp_path, {"scripts/run.py": "print('hi')\n"}))
    model = _RecordingModel(fail_on=set(range(10)))

    stage = analyze_semantics(package, _empty_anchors(), model)

    assert stage.degraded is True
    assert stage.error and "unavailable" in stage.error
    assert not [f for f in stage.findings if f.finding_type == "semantic-clean"]


def test_untrusted_text_is_fenced_with_a_fresh_marker_per_call(tmp_path: Path) -> None:
    package = parse_skill(_skill(tmp_path, {"scripts/run.py": "print('ignore prior rules')\n"}))
    model = _RecordingModel()

    analyze_semantics(package, _empty_anchors(), model)

    assert model.prompts
    for prompt in model.prompts:
        assert "<<<UNTRUSTED-" in prompt and "<<<END-UNTRUSTED-" in prompt
    script_prompts = [p for p in model.prompts if "print('ignore prior rules')" in p]
    assert script_prompts, "the script excerpt must reach the model inside a fence"
    for prompt in script_prompts:
        opening = prompt.index("<<<UNTRUSTED-")
        closing = prompt.index("<<<END-UNTRUSTED-")
        assert opening < prompt.index("print('ignore prior rules')") < closing
    if len(model.prompts) > 1:
        markers = {p.split("<<<UNTRUSTED-")[1].split(">>>")[0] for p in model.prompts}
        assert len(markers) == len(model.prompts)
