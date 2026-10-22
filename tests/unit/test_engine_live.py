"""Live-engine tests: real pipeline with deterministic model and no Docker."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import SkillsEntryConfig
from skillsentry.core.contracts import ScanOptions, ScanStatus
from skillsentry.core.engine import ScanEngine
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.poisoned_well.canary_gen import generate_canary_set
from skillsentry.core.sandbox.runner import (
    SandboxRequest,
    SandboxResult,
    SandboxUnavailable,
)


def _write_skill(root: Path, name: str = "live-test-skill") -> Path:
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


class _UnavailableRunner:
    def run(self, request: SandboxRequest) -> SandboxResult:
        raise SandboxUnavailable("no Docker daemon in this test environment")


class _EmptyRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, request: SandboxRequest) -> SandboxResult:
        self.calls += 1
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


def test_live_pipeline_runs_all_stages_with_mock_model(tmp_path: Path):
    config = _config()
    store = SQLiteStore(tmp_path / "static.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    skill = _write_skill(tmp_path)

    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=False))
        assert outcome.cached is False
        assert outcome.verdict.verdict.value == "SAFE"
        assert outcome.verdict.risk_score < 30
        assert {result.stage.value for result in outcome.stage_results} == {
            "spec",
            "typosquat",
            "deterministicAnchor",
            "semantic",
            "vision",
            "sandbox",
            "poisonedWell",
            "evasion",
        }
        assert outcome.verdict.cached is False
        assert outcome.verdict.findings
        # The profile/spec note must be present in the detail returned by the
        # live pipeline, not only in the fuse() result.
        assert outcome.detail.static_findings
        # Static-only evidence is not reusable for a later sandbox scan.
        assert store.cache_stats()[0] == 0
    finally:
        engine.close()
        store.close()


def test_live_pipeline_uses_deceptive_model_profile(tmp_path: Path):
    config = _config()
    store = SQLiteStore(tmp_path / "deceptive.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="deceptive"))
    skill = _write_skill(tmp_path)

    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=False))
        assert outcome.verdict.verdict.value == "MALICIOUS"
        assert outcome.verdict.risk_score >= 95
        assert any(
            finding.stage.value == "semantic"
            and finding.severity.value == "critical"
            for finding in outcome.verdict.findings
        )
    finally:
        engine.close()
        store.close()


def test_model_unavailable_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config = _config()
    store = SQLiteStore(tmp_path / "model-down.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    skill = _write_skill(tmp_path)

    def unavailable() -> None:
        return None

    monkeypatch.setattr(engine, "_get_model", unavailable)
    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=False))
        assert outcome.verdict.verdict.value != "SAFE"
        assert outcome.verdict.verdict.value == "SUSPICIOUS"
        semantic = next(
            result for result in outcome.stage_results if result.stage.value == "semantic"
        )
        assert semantic.degraded is True
        assert "unavailable" in (semantic.error or "")
    finally:
        engine.close()
        store.close()


def test_docker_unavailable_fails_closed(tmp_path: Path):
    config = _config()
    store = SQLiteStore(tmp_path / "docker-down.sqlite")
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_UnavailableRunner(),  # type: ignore[arg-type]
    )
    skill = _write_skill(tmp_path)

    try:
        outcome = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        assert outcome.verdict.verdict.value == "SUSPICIOUS"
        sandbox = next(
            result for result in outcome.stage_results if result.stage.value == "sandbox"
        )
        assert sandbox.degraded is True
        assert "Docker unavailable" in (sandbox.error or "")
        # A degraded full scan must not populate the reusable cache.
        assert store.cache_stats()[0] == 0
    finally:
        engine.close()
        store.close()


def test_static_scan_cannot_poison_a_later_full_scan(tmp_path: Path):
    config = _config()
    store = SQLiteStore(tmp_path / "cache.sqlite")
    runner = _EmptyRunner()
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=runner,  # type: ignore[arg-type]
    )
    skill = _write_skill(tmp_path)

    try:
        static = engine.scan(skill, options=ScanOptions(sandbox=False))
        assert static.cached is False
        assert store.cache_stats()[0] == 0

        full = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        assert full.cached is False
        assert runner.calls == 1
        assert any(result.stage.value == "sandbox" for result in full.stage_results)
        assert store.cache_stats()[0] == 1

        cached = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        assert cached.cached is True
        assert cached.status is ScanStatus.CACHED_HIT
        assert runner.calls == 1

        # A static scan must not read the full-scan cache either.
        static_again = engine.scan(skill, options=ScanOptions(sandbox=False))
        assert static_again.cached is False
        assert any(result.stage.value == "sandbox" for result in static_again.stage_results)

        # Different timeout is a different analysis mode and must not reuse the
        # cached evidence from the default-timeout run.
        shorter = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s - 1),
        )
        assert shorter.cached is False
        assert runner.calls == 2
    finally:
        engine.close()
        store.close()


def test_cached_scan_keeps_the_original_skill_id(tmp_path: Path):
    config = _config()
    store = SQLiteStore(tmp_path / "cache-id.sqlite")
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=_EmptyRunner(),  # type: ignore[arg-type]
    )
    skill = _write_skill(tmp_path)

    try:
        first = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        second = engine.scan(
            skill,
            options=ScanOptions(sandbox=True, timeout_s=config.sandbox.timeout_s),
        )
        assert second.cached is True
        assert isinstance(second.skill_id, UUID)
        assert second.skill_id == first.skill_id
        assert second.verdict.scan_id == second.scan_id
        assert second.verdict.cached is True
    finally:
        engine.close()
        store.close()
