"""Cache identity for the Laya decision layer: invalidation, degradation, lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import SkillsEntryConfig
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.decisions import DecisionQuestion, DecisionResult, MockDecisionClient
from skillsentry.core.decisions.base import DecisionUnavailable
from skillsentry.core.engine import ScanEngine
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.poisoned_well.canary_gen import generate_canary_set
from skillsentry.core.sandbox.runner import SandboxRequest, SandboxResult
from tests.unit.test_engine_live import _write_skill


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


class _CountingClient(MockDecisionClient):
    """Mock client that counts health probes and closes, for lifecycle checks."""

    def __init__(self) -> None:
        super().__init__("benign")
        self.health_calls = 0
        self.closed = 0

    def health(self) -> bool:
        self.health_calls += 1
        return True

    def close(self) -> None:
        self.closed += 1


class _DownClient:
    backend = "laya"
    model_version = "down-test"

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        raise DecisionUnavailable("checkpoint failed to load")

    def health(self) -> bool:
        return True


def _config(**decision: Any) -> SkillsEntryConfig:
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    config.sandbox.enabled = True
    config.decision.backend = "laya"
    for key, value in decision.items():
        setattr(config.decision, key, value)
    return config


def _scan(engine: ScanEngine, skill: Path, config: SkillsEntryConfig):  # type: ignore[no-untyped-def]
    return engine.scan(
        skill,
        options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
    )


def test_laya_scan_is_cached_then_invalidated_by_checkpoint_change(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    skill = _write_skill(tmp_path)
    config = _config()
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=MockDecisionClient("benign"),
    )
    try:
        first = _scan(engine, skill, config)
        assert first.cached is False
        assert _scan(engine, skill, config).cached is True
    finally:
        engine.close()
        store.close()

    store = SQLiteStore(tmp_path / "cache.sqlite")
    changed = _config(checkpoint="multilingual")
    engine = ScanEngine(
        changed,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=MockDecisionClient("benign"),
    )
    try:
        assert _scan(engine, skill, changed).cached is False
    finally:
        engine.close()
        store.close()


def test_calibration_version_change_invalidates_cache(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    skill = _write_skill(tmp_path)
    first_config = _config(calibration_version="cal-1")
    engine = ScanEngine(
        first_config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=MockDecisionClient("benign"),
    )
    try:
        _scan(engine, skill, first_config)
    finally:
        engine.close()
    assert store.cache_stats()[0] == 1

    second_config = _config(calibration_version="cal-2")
    engine = ScanEngine(
        second_config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=MockDecisionClient("benign"),
    )
    try:
        assert _scan(engine, skill, second_config).cached is False
    finally:
        engine.close()
        store.close()


def test_degraded_laya_scan_is_never_cached(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    skill = _write_skill(tmp_path)
    config = _config()
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=_DownClient(),  # type: ignore[arg-type]
    )
    try:
        first = _scan(engine, skill, config)
        second = _scan(engine, skill, config)
        assert first.cached is False
        assert second.cached is False
        assert store.cache_stats()[0] == 0
        semantic = next(r for r in first.stage_results if r.stage.value == "semantic")
        assert semantic.degraded is True
    finally:
        engine.close()
        store.close()


def test_decision_client_is_selected_once_and_closed_with_engine(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    skill = _write_skill(tmp_path)
    config = _config()
    client = _CountingClient()
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
        decision_client=client,  # type: ignore[arg-type]
    )
    try:
        _scan(engine, skill, config)
        _scan(engine, skill, config)
        assert client.health_calls == 1
    finally:
        engine.close()
        store.close()

    assert client.closed == 1


def test_model_identity_reports_laya_when_active(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    config = _config()
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        decision_client=MockDecisionClient("benign"),
    )
    try:
        _, version = engine.model_identity()
        assert "laya:" in version
        assert config.decision.cache_identity in version
    finally:
        engine.close()
        store.close()


def test_legacy_identity_is_unchanged_without_laya(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cache.sqlite")
    config = _config(backend="legacy")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    try:
        _, version = engine.model_identity()
        assert "laya" not in version
    finally:
        engine.close()
        store.close()
