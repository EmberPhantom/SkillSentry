"""Sandbox gate: what runs, what is skipped, and what degrades when the plan is incomplete."""

from __future__ import annotations

from pathlib import Path

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import SkillsEntryConfig
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.poisoned_well.canary_gen import generate_canary_set
from skillsentry.core.sandbox.runner import SandboxRequest, SandboxResult


class _CountingRunner:
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


def _skill(root: Path, *, frontmatter: str, files: dict[str, str]) -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        f"---\nname: demo\ndescription: Demo\n{frontmatter}---\nBody\n", encoding="utf-8"
    )
    for relative, body in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return root


def _scan(tmp_path: Path, skill: Path, runner: _CountingRunner):  # type: ignore[no-untyped-def]
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    store = SQLiteStore(tmp_path / "gate.sqlite")
    engine = ScanEngine(
        config,
        store=store,
        model=MockGemma(profile="benign"),
        sandbox_runner=runner,  # type: ignore[arg-type]
    )
    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=True, no_cache=True, timeout_s=30))
    finally:
        engine.close()
        store.close()
    return outcome


def _sandbox(outcome):  # type: ignore[no-untyped-def]
    return next(result for result in outcome.stage_results if result.stage.value == "sandbox")


def test_text_only_skill_is_not_run_and_not_degraded(tmp_path: Path) -> None:
    runner = _CountingRunner()
    skill = _skill(tmp_path / "docs", frontmatter="", files={})

    outcome = _scan(tmp_path, skill, runner)

    assert runner.calls == 0
    assert _sandbox(outcome).degraded is False


def test_scripts_without_a_declared_entrypoint_degrade_and_never_run(tmp_path: Path) -> None:
    runner = _CountingRunner()
    skill = _skill(tmp_path / "noentry", frontmatter="", files={"scripts/run.py": "print('x')\n"})

    outcome = _scan(tmp_path, skill, runner)

    assert runner.calls == 0
    assert _sandbox(outcome).degraded is True
    assert outcome.verdict.verdict.value != "SAFE"


def test_declared_entrypoint_runs_exactly_once(tmp_path: Path) -> None:
    runner = _CountingRunner()
    skill = _skill(
        tmp_path / "entry",
        frontmatter="entrypoint: python scripts/run.py\n",
        files={"scripts/run.py": "print('x')\n"},
    )

    outcome = _scan(tmp_path, skill, runner)

    assert runner.calls == 1
    assert _sandbox(outcome).degraded is False
