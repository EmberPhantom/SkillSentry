"""Temperature scaling, held-out fitting, and corpus manifest validity.

These tests check the fitting procedure on synthetic records and the corpus
manifest on disk.  They do not produce calibration evidence: that needs a real
Laya run through ``scripts/calibrate_laya.py``.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from skillsentry.core.decisions import MockDecisionClient
from skillsentry.core.decisions.calibration import (
    CalibrationError,
    CorpusRecord,
    calibrate_probability,
    expected_calibration_error,
    fit_calibration,
    fit_temperature,
    split_held_out,
)
from skillsentry.core.decisions.questions import CAPABILITY_QUESTIONS

REPO = Path(__file__).resolve().parents[2]
LABELS = REPO / "tests" / "fixtures" / "decisions" / "labels.json"


def _load_script():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "calibrate_laya", REPO / "scripts" / "calibrate_laya.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_identity_temperature_leaves_probability_unchanged() -> None:
    assert calibrate_probability(0.73, 1.0) == pytest.approx(0.73, abs=1e-5)


def test_higher_temperature_pulls_probability_toward_one_half() -> None:
    assert calibrate_probability(0.95, 3.0) < 0.95
    assert calibrate_probability(0.05, 3.0) > 0.05


def test_non_positive_temperature_is_rejected() -> None:
    with pytest.raises(CalibrationError):
        calibrate_probability(0.5, 0.0)


def test_overconfident_scores_fit_a_temperature_above_one() -> None:
    # Raw 0.95 scores, but only 60% of them are true: the backend is overconfident.
    samples = [(0.95, index % 5 != 0) for index in range(50)]

    temperature = fit_temperature(samples)

    assert temperature > 1.0


def test_fit_temperature_with_no_samples_is_identity() -> None:
    assert fit_temperature([]) == 1.0


def test_perfectly_calibrated_bin_has_zero_error() -> None:
    samples = [(0.9, index < 9) for index in range(10)]

    assert expected_calibration_error(samples) == 0.0


def test_held_out_split_is_deterministic() -> None:
    fit, held = split_held_out(list(range(8)), every=4)

    assert held == [0, 4]
    assert fit == [1, 2, 3, 5, 6, 7]


def _record(case_id: str, label: str, truths: list[str] | None, high: str | None) -> CorpusRecord:
    raw = {qid: 0.05 for qid in CAPABILITY_QUESTIONS}
    if high is not None:
        raw[high] = 0.95
    return CorpusRecord(
        case_id=case_id,
        label=label,
        capabilities=frozenset(truths) if truths is not None else None,
        raw=raw,
    )


def _synthetic_records() -> list[CorpusRecord]:
    records: list[CorpusRecord] = []
    for index in range(8):
        records.append(_record(f"benign-{index}", "benign", [], None))
    for index in range(8):
        records.append(_record(f"mal-{index}", "malicious", ["cap_upload"], "cap_upload"))
    records.append(_record("unsure", "review", ["cap_network"], "cap_network"))
    return records


def test_fit_calibration_separates_synthetic_classes() -> None:
    calibration, report = fit_calibration(
        _synthetic_records(), version="synthetic-1", checkpoint="test"
    )

    assert calibration.false_negatives == 0
    assert calibration.benign_flagged == 0
    assert calibration.evaluated_cases == 16
    assert calibration.temperature > 0
    assert report["review_cases_excluded"] == ["unsure"]
    assert report["held_out"] is not None
    assert report["final"]["false_negatives"] == 0


def test_fit_calibration_refuses_without_malicious_cases() -> None:
    records = [_record("b", "benign", [], None)]

    with pytest.raises(CalibrationError):
        fit_calibration(records, version="x", checkpoint="y")


def test_corpus_manifest_is_consistent_on_disk() -> None:
    manifest = json.loads(LABELS.read_text(encoding="utf-8"))
    cases = manifest["cases"]

    assert len(cases) >= 39
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        assert (REPO / case["path"] / "SKILL.md").exists(), case["id"]
        assert case["label"] in {"benign", "malicious", "review"}
        truths = case.get("capabilities")
        if truths is not None:
            assert set(truths) <= set(CAPABILITY_QUESTIONS), case["id"]
        if case["label"] == "malicious" and truths is not None:
            assert truths, f"malicious case {case['id']} records no capability truth"


def test_pipeline_runs_over_the_corpus_with_mock_client(tmp_path: Path) -> None:
    script = _load_script()
    manifest = json.loads(LABELS.read_text(encoding="utf-8"))

    records, checkpoint = script.run_corpus(
        MockDecisionClient("auto"),  # type: ignore[arg-type]
        manifest,
        root=REPO,
        timeout_s=30.0,
    )
    calibration, report = fit_calibration(records, version="pipeline-check", checkpoint=checkpoint)

    assert len(records) == len(manifest["cases"])
    assert checkpoint == "mock"
    assert report["review_cases_excluded"] == [
        case["id"] for case in manifest["cases"] if case["label"] == "review"
    ]
    assert calibration.version == "pipeline-check"
