"""Calibration: threshold fitting, file validation, and fail-closed wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.contracts import ScanOptions
from skill_sentry_cli.core.decisions import DecisionAnswer, MockDecisionClient
from skill_sentry_cli.core.decisions.calibration import (
    SCHEMA,
    Calibration,
    CalibrationError,
    fit_capability_threshold,
    load_calibration,
    write_calibration,
)
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.poisoned_well.canary_gen import generate_canary_set
from skill_sentry_cli.core.sandbox.runner import SandboxRequest, SandboxResult
from tests.unit.test_engine_live import _write_skill


def test_fit_threshold_keeps_every_malicious_case() -> None:
    cases = [(0.2, False), (0.4, False), (0.91, True), (0.78, True), (0.66, False)]

    threshold, false_negatives, benign_flagged = fit_capability_threshold(cases)

    assert threshold == 0.78
    assert false_negatives == 0
    assert benign_flagged == 0


def test_fit_threshold_counts_benign_cases_above_threshold() -> None:
    cases = [(0.8, False), (0.9, True), (0.85, True), (0.92, False)]

    threshold, false_negatives, benign_flagged = fit_capability_threshold(cases)

    assert threshold == 0.85
    assert false_negatives == 0
    assert benign_flagged == 1


def test_fit_threshold_requires_a_malicious_case() -> None:
    with pytest.raises(CalibrationError):
        fit_capability_threshold([(0.1, False), (0.2, False)])


def test_calibration_round_trips_through_file(tmp_path: Path) -> None:
    calibration = Calibration(
        version="cal-1",
        checkpoint="english",
        capability_threshold=0.73,
        evaluated_cases=10,
        malicious_cases=4,
        false_negatives=0,
        benign_flagged=1,
    )
    target = tmp_path / "nested" / "calibration.json"

    write_calibration(target, calibration)
    loaded = load_calibration(target)

    assert loaded == calibration
    assert json.loads(target.read_text(encoding="utf-8"))["schema"] == SCHEMA


def test_missing_path_means_no_calibration() -> None:
    assert load_calibration(None) is None
    assert load_calibration("   ") is None


def test_wrong_schema_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "calibration.json"
    target.write_text(json.dumps({"schema": "other", "capability_threshold": 0.5}))

    with pytest.raises(CalibrationError):
        load_calibration(target)


def test_out_of_range_threshold_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "calibration.json"
    target.write_text(json.dumps({"schema": SCHEMA, "capability_threshold": 0}))

    with pytest.raises(CalibrationError):
        load_calibration(target)


class _EmptyRunner:
    def run(self, request: SandboxRequest) -> SandboxResult:
        canaries = generate_canary_set(request.scan_id, request.declared_intent)
        return SandboxResult(
            scan_id=request.scan_id,
            container_id="fake-container",
            canaries=canaries,
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout="",
            stderr="",
        )


def _laya_config(calibration_path: str) -> SkillsEntryConfig:
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    config.decision.backend = "laya"
    config.decision.calibration_path = calibration_path
    return config


def test_unreadable_calibration_fails_closed_not_to_default(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    config = _laya_config(str(bad))
    store = SQLiteStore(tmp_path / "cal.sqlite")
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=MockDecisionClient("benign"),
    )
    try:
        outcome = engine.scan(
            _write_skill(tmp_path),
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        semantic = next(r for r in outcome.stage_results if r.stage.value == "semantic")
        assert semantic.degraded is True
        assert "calibration unavailable" in (semantic.error or "")
        assert outcome.cached is False
    finally:
        engine.close()
        store.close()


def test_fitted_threshold_is_applied_to_capability_findings(tmp_path: Path) -> None:
    calibration_path = tmp_path / "calibration.json"
    write_calibration(
        calibration_path,
        Calibration(
            version="cal-high",
            checkpoint="english",
            capability_threshold=0.99,
            evaluated_cases=2,
            malicious_cases=1,
            false_negatives=0,
            benign_flagged=0,
        ),
    )
    config = _laya_config(str(calibration_path))
    store = SQLiteStore(tmp_path / "cal.sqlite")
    client = MockDecisionClient(
        "benign",
        answers={"cap_network": DecisionAnswer(noul=0.95, confidence=0.9)},
    )
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=client,
    )
    try:
        outcome = engine.scan(
            _write_skill(tmp_path),
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        semantic = next(r for r in outcome.stage_results if r.stage.value == "semantic")
        assert semantic.telemetry["calibration_version"] == "cal-high"
        assert semantic.telemetry["capability_threshold"] == 0.99
        assert not [f for f in semantic.findings if f.finding_type == "cap_network"]
    finally:
        engine.close()
        store.close()
