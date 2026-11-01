"""Failure injection: each outage must fail closed, and must stay contained to its scan.

Scans run in sequence on one engine, as a batch does.  An outage in one scan may
degrade that scan, but a later healthy scan must still come back clean, and a
degraded scan must never reach the reusable cache.  Assertions use typed fields
(stage, degraded, verdict, code), never message text.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skill_sentry import cli
from skill_sentry.core.cache import SQLiteStore
from skill_sentry.core.cache.sqlite_store import StoreError
from skill_sentry.core.config import SkillsEntryConfig
from skill_sentry.core.contracts import ScanOptions
from skill_sentry.core.engine import ScanEngine, ScanError, ScanOutcome
from skill_sentry.core.models.mock import MockGemma
from skill_sentry.core.poisoned_well.canary_gen import generate_canary_set
from skill_sentry.core.sandbox.runner import (
    SandboxError,
    SandboxRequest,
    SandboxResult,
    SandboxUnavailable,
)
from typer.testing import CliRunner

runner = CliRunner()


def _write_skill(root: Path, name: str) -> Path:
    skill = root / name
    (skill / "scripts").mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f"""---
name: {name}
description: A local test skill that reads text files.
entrypoint: python scripts/run.py
---

# {name}

Reads a local text file and prints its length.  No network access.
""",
        encoding="utf-8",
    )
    (skill / "scripts" / "run.py").write_text(
        """from pathlib import Path
print(len(Path("SKILL.md").read_text(encoding="utf-8")))
""",
        encoding="utf-8",
    )
    return skill


def _config() -> SkillsEntryConfig:
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    config.sandbox.enabled = True
    return config


def _clean_result(request: SandboxRequest, *, timed_out: bool = False) -> SandboxResult:
    return SandboxResult(
        scan_id=request.scan_id,
        container_id="fake-container",
        canaries=generate_canary_set(request.scan_id, request.declared_intent),
        exit_code=None if timed_out else 0,
        timed_out=timed_out,
        duration_ms=1,
        stdout="",
        stderr="",
    )


class _FlakyRunner:
    """Healthy for the first ``healthy_calls`` requests, then every call raises."""

    def __init__(self, healthy_calls: int, error: Exception) -> None:
        self.healthy_calls = healthy_calls
        self.error = error
        self.calls = 0

    def run(self, request: SandboxRequest) -> SandboxResult:
        self.calls += 1
        if self.calls > self.healthy_calls:
            raise self.error
        return _clean_result(request)


class _TimedOutRunner:
    def run(self, request: SandboxRequest) -> SandboxResult:
        return _clean_result(request, timed_out=True)


def _sandbox(outcome: ScanOutcome):  # type: ignore[no-untyped-def]
    return next(result for result in outcome.stage_results if result.stage.value == "sandbox")


def _semantic(outcome: ScanOutcome):  # type: ignore[no-untyped-def]
    return next(result for result in outcome.stage_results if result.stage.value == "semantic")


@pytest.mark.parametrize(
    "error",
    [
        SandboxUnavailable("daemon gone"),
        SandboxError("container create failed"),
        RuntimeError("unexpected failure inside the runner"),
    ],
    ids=["docker-unavailable", "sandbox-error", "unexpected-exception"],
)
def test_docker_outage_mid_batch_degrades_only_the_affected_scans(
    tmp_path: Path, error: Exception
) -> None:
    config = _config()
    store = SQLiteStore(tmp_path / "docker-batch.sqlite")
    flaky = _FlakyRunner(healthy_calls=1, error=error)
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=flaky,  # type: ignore[arg-type]
    )
    skills = [_write_skill(tmp_path, f"batch-{index}") for index in range(3)]
    try:
        outcomes = [
            engine.scan(
                skill,
                options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
            )
            for skill in skills
        ]
        # Only the scan that completed may populate the reusable cache.
        cached_entries = store.cache_stats()[0]
    finally:
        engine.close()
        store.close()

    assert [_sandbox(outcome).degraded for outcome in outcomes] == [False, True, True]
    assert outcomes[0].verdict.verdict.value == "SAFE"
    assert all(outcome.verdict.verdict.value != "SAFE" for outcome in outcomes[1:])
    assert cached_entries == 1


def test_sandbox_timeout_fails_closed(tmp_path: Path) -> None:
    config = _config()
    store = SQLiteStore(tmp_path / "timeout.sqlite")
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_TimedOutRunner(),  # type: ignore[arg-type]
    )
    try:
        outcome = engine.scan(
            _write_skill(tmp_path, "timeout-skill"),
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        cached_entries = store.cache_stats()[0]
    finally:
        engine.close()
        store.close()

    assert _sandbox(outcome).degraded is True
    assert outcome.verdict.verdict.value != "SAFE"
    assert cached_entries == 0


def test_model_outage_mid_batch_fails_closed_for_that_scan_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    store = SQLiteStore(tmp_path / "model-batch.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    model_up = {"value": True}
    real_get_model = engine._get_model

    def get_model():  # type: ignore[no-untyped-def]
        return real_get_model() if model_up["value"] else None

    monkeypatch.setattr(engine, "_get_model", get_model)
    skills = [_write_skill(tmp_path, f"model-{index}") for index in range(3)]
    outcomes: list[ScanOutcome] = []
    try:
        for index, skill in enumerate(skills):
            model_up["value"] = index != 1
            outcomes.append(engine.scan(skill, options=ScanOptions(sandbox=False)))
    finally:
        engine.close()
        store.close()

    assert [_semantic(outcome).degraded for outcome in outcomes] == [False, True, False]
    assert outcomes[0].verdict.verdict.value == "SAFE"
    assert outcomes[1].verdict.verdict.value != "SAFE"
    assert outcomes[2].verdict.verdict.value == "SAFE"


def test_storage_failure_returns_no_verdict_and_no_cache_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    store = SQLiteStore(tmp_path / "disk-full.sqlite")

    def disk_full(*args: object, **kwargs: object) -> None:
        raise StoreError("database or disk is full")

    monkeypatch.setattr(store, "finish_scan", disk_full)
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    try:
        with pytest.raises(ScanError) as raised:
            engine.scan(
                _write_skill(tmp_path, "disk-skill"),
                options=ScanOptions(sandbox=False),
            )
        cached_entries = store.cache_stats()[0]
    finally:
        engine.close()
        store.close()

    assert raised.value.code == "storage_error"
    assert raised.value.degraded is True
    assert cached_entries == 0


def test_cli_batch_continues_after_one_skill_fails_and_exits_operational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "skills"
    _write_skill(folder, "alpha")
    _write_skill(folder, "beta")

    def make_engine(config: SkillsEntryConfig, backend: str) -> ScanEngine:
        store = SQLiteStore(tmp_path / "cli-batch.sqlite")
        return ScanEngine(config, store=store, model=MockGemma(profile="benign"))

    monkeypatch.setattr(cli, "_make_engine", make_engine)
    real_scan = ScanEngine.scan
    calls = {"count": 0}

    def fail_first(self: ScanEngine, path: Path, **kwargs: object) -> ScanOutcome:
        calls["count"] += 1
        if calls["count"] == 1:
            raise ScanError("model unavailable mid-batch")
        return real_scan(self, path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ScanEngine, "scan", fail_first)

    result = runner.invoke(
        cli.app,
        ["scan", str(folder), "--format", "json", "--backend", "demo", "--no-sandbox"],
    )

    assert calls["count"] == 2
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload["verdict"] == "SAFE"
