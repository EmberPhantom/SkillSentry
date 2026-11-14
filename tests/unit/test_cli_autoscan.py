"""``scan`` with no path, ``discover``, and the report prompt.

Every test runs against a fake home folder (``Path.home`` is patched) and an isolated
database, with the demo model and no sandbox, so no Docker or Ollama is needed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import click
import pytest
from skill_sentry_cli import cli
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]
GOOD = "---\nname: {name}\ndescription: a fine skill\n---\n# {name}\n"
SCAN = ["scan", "--backend", "demo", "--no-sandbox", "--no-cache"]
runner = CliRunner()


class _TtyStream:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def isatty(self) -> bool:
        return True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _TtySys:
    """Stands in for the ``sys`` module inside ``cli``: stdin and stdout report a terminal.

    CliRunner swaps ``sys.stdin`` while it runs, so the patch has to read the streams
    lazily rather than capture them up front.
    """

    def __init__(self, real: ModuleType) -> None:
        self._real = real

    @property
    def stdin(self) -> _TtyStream:
        return _TtyStream(self._real.stdin)

    @property
    def stdout(self) -> _TtyStream:
        return _TtyStream(self._real.stdout)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("SKILLSENTRY_EXTRA_SKILL_PATHS", raising=False)
    monkeypatch.delenv("SKILLSENTRY_CONFIG", raising=False)
    return home


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "sys", _TtySys(sys))


def _skill(path: Path, name: str | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(GOOD.format(name=name or path.name), encoding="utf-8")
    return path


def _invoke(tmp_path: Path, args: list[str], *, input: str | None = None) -> Any:
    return runner.invoke(
        cli.app,
        args,
        input=input,
        env={"SKILLSENTRY_DB": str(tmp_path / "autoscan.sqlite")},
    )


def _report_dirs(home: Path) -> list[Path]:
    base = home / ".skillsentry" / "reports"
    if not base.is_dir():
        return []
    return sorted(child for child in base.iterdir() if child.is_dir())


def _two_installed(home: Path) -> None:
    _skill(home / ".claude" / "skills" / "alpha")
    _skill(home / ".codex" / "skills" / "beta")


# ---------------------------------------------------------------------------
# scan with no path
# ---------------------------------------------------------------------------


def test_no_path_finds_and_scans_every_installed_skill(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert sorted(item["skill"] for item in payload) == ["alpha", "beta"]


def test_no_path_text_prints_found_line_and_summary(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN)

    assert result.exit_code == 0, result.output
    assert "Found 2 skills (Claude Code: 1, Codex: 1; 0 duplicates merged)" in result.output
    assert (
        "Summary: 2 scanned - 2 SAFE, 0 SUSPICIOUS, 0 MALICIOUS, 0 UNSCANNED"
        in result.output.splitlines()
    )


@pytest.mark.parametrize(
    "malicious, fail_on, expected",
    [(False, "safe", 0), (False, "malicious", 0), (True, "malicious", 1), (True, "suspicious", 1)],
)
def test_fail_on_gates_the_whole_batch(
    fake_home: Path, tmp_path: Path, malicious: bool, fail_on: str, expected: int
) -> None:
    _two_installed(fake_home)
    if malicious:
        shutil.copytree(
            ROOT / "fixtures" / "malicious" / "cloud-sync-pro",
            fake_home / ".agents" / "skills" / "cloud-sync-pro",
        )

    result = _invoke(tmp_path, [*SCAN, "--fail-on", fail_on, "--format", "json"])

    assert result.exit_code == expected, result.output


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra rights on Windows")
def test_symlinked_install_is_scanned_once(fake_home: Path, tmp_path: Path) -> None:
    real = _skill(tmp_path / "system" / "gamma")
    for base in (".claude/skills", ".codex/skills", ".agents/skills"):
        link = fake_home / base / "gamma"
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(real, link, target_is_directory=True)

    as_json = _invoke(tmp_path, [*SCAN, "--format", "json"])
    assert as_json.exit_code == 0, as_json.output
    assert json.loads(as_json.stdout)["skill"] == "gamma"

    as_text = _invoke(tmp_path, SCAN)
    assert "Found 1 skill (Claude Code: 1; 2 duplicates merged)" in as_text.output
    assert "installed at ~/.claude/skills/gamma" in as_text.output


def test_no_path_zero_skills_exits_3_with_guidance(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, SCAN)

    assert result.exit_code == int(cli.ExitCode.OPERATIONAL)
    assert "No installed skills found. Looked in:" in result.output
    assert "~/.claude/skills" in result.output
    assert "--project" in result.output
    assert "extra_paths" in result.output
    assert "Traceback" not in result.output


def test_demo_mode_needs_a_path(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, ["scan", "--demo-mode"])

    assert result.exit_code == int(cli.ExitCode.USAGE)


def test_project_and_agent_flags_need_no_path(fake_home: Path, tmp_path: Path) -> None:
    skill = _skill(tmp_path / "solo")

    with_project = _invoke(tmp_path, ["scan", str(skill), "--project", str(tmp_path)])
    with_agent = _invoke(tmp_path, ["scan", str(skill), "--agent", "codex"])
    with_experimental = _invoke(tmp_path, ["scan", str(skill), "--include-experimental"])

    assert with_project.exit_code == int(cli.ExitCode.USAGE), with_project.output
    assert with_agent.exit_code == int(cli.ExitCode.USAGE), with_agent.output
    assert with_experimental.exit_code == int(cli.ExitCode.USAGE)
    assert "apply only when scanning installed skills" in with_project.output


def test_unknown_agent_is_a_usage_error(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    scanned = _invoke(tmp_path, [*SCAN, "--agent", "nope"])
    listed = _invoke(tmp_path, ["discover", "--agent", "nope"])

    assert scanned.exit_code == int(cli.ExitCode.USAGE)
    assert listed.exit_code == int(cli.ExitCode.USAGE)
    assert "unknown --agent 'nope'" in listed.output


def test_agent_filter_limits_scan_and_listing(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    listed = _invoke(tmp_path, ["discover", "--agent", "Codex", "--format", "json"])
    scanned = _invoke(tmp_path, [*SCAN, "--agent", "codex", "--format", "json"])

    assert [item["name"] for item in json.loads(listed.stdout)["skills"]] == ["beta"]
    assert scanned.exit_code == 0, scanned.output
    assert json.loads(scanned.stdout)["skill"] == "beta"


def test_project_folder_skills_are_included(fake_home: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    _skill(project / ".claude" / "skills" / "delta")

    explicit = _invoke(tmp_path, ["discover", "--project", str(project), "--format", "json"])
    entries = json.loads(explicit.stdout)["skills"]
    assert [(item["name"], item["scope"]) for item in entries] == [("delta", "project")]

    # Without --project the current directory is the project.
    previous = Path.cwd()
    os.chdir(project)
    try:
        implicit = _invoke(tmp_path, ["discover", "--format", "json"])
    finally:
        os.chdir(previous)
    assert [item["name"] for item in json.loads(implicit.stdout)["skills"]] == ["delta"]


def test_missing_project_folder_is_a_usage_error(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, ["discover", "--project", str(tmp_path / "nope")])

    assert result.exit_code == int(cli.ExitCode.USAGE)
    assert "--project is not a folder" in result.output


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def test_discover_text_lists_skills_without_scanning(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, ["discover"])

    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0].split() == ["AGENT", "SCOPE", "SKILL", "PATH"]
    assert any(line.split()[:3] == ["claude", "user", "alpha"] for line in lines)
    assert any(line.split()[:3] == ["codex", "user", "beta"] for line in lines)
    assert "Summary" not in result.output
    assert "SkillSentry " not in result.output


def test_discover_json_has_skills_checked_notes_and_count(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, ["discover", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert {item["name"] for item in payload["skills"]} == {"alpha", "beta"}
    first = payload["skills"][0]
    assert {"agent", "scope", "declared_path", "real_path", "is_symlink"} <= set(first)
    assert str(fake_home / ".claude" / "skills") in payload["checked"]
    assert payload["notes"] == []
    assert payload["duplicates_merged"] == 0


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra rights on Windows")
def test_discover_reports_broken_links_as_notes(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)
    link = fake_home / ".claude" / "skills" / "ghost"
    os.symlink(tmp_path / "missing", link, target_is_directory=True)

    text = _invoke(tmp_path, ["discover"])
    as_json = _invoke(tmp_path, ["discover", "--format", "json"])

    assert "notes:" in text.output
    assert "broken symlink" in text.output
    assert any("broken symlink" in note for note in json.loads(as_json.stdout)["notes"])


def test_discover_with_zero_skills_exits_zero(fake_home: Path, tmp_path: Path) -> None:
    text = _invoke(tmp_path, ["discover"])
    as_json = _invoke(tmp_path, ["discover", "--format", "json"])

    assert text.exit_code == 0, text.output
    assert "No installed skills found. Looked in:" in text.output
    assert as_json.exit_code == 0
    payload = json.loads(as_json.stdout)
    assert payload["skills"] == []
    assert str(fake_home / ".codex" / "skills") in payload["checked"]


def test_discover_rejects_an_unknown_format(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, ["discover", "--format", "sarif"])

    assert result.exit_code == int(cli.ExitCode.USAGE)


# ---------------------------------------------------------------------------
# tips and the report prompt
# ---------------------------------------------------------------------------


def test_path_scan_text_prints_the_no_path_tip(fake_home: Path, tmp_path: Path) -> None:
    skill = _skill(tmp_path / "solo")

    text = _invoke(tmp_path, [*SCAN, str(skill)])
    as_json = _invoke(tmp_path, [*SCAN, str(skill), "--format", "json"])
    quiet = _invoke(tmp_path, [*SCAN, str(skill), "-q"])

    assert "with no path to check everything installed" in text.output
    assert "with no path" not in as_json.output
    assert json.loads(as_json.stdout)["skill"] == "solo"
    assert "with no path" not in quiet.output


def test_non_terminal_run_never_prompts_and_prints_a_tip(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN, input="m\n")

    assert "Save a report?" not in result.output
    assert "Tip: add --save-report markdown to keep a report." in result.output
    assert _report_dirs(fake_home) == []


def test_prompt_m_writes_markdown_reports_and_prints_the_path(
    fake_home: Path, tmp_path: Path, tty: None
) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN, input="m\n")

    assert result.exit_code == 0, result.output
    assert "Save a report? [m]arkdown / [s]arif / [n]o (default n)" in result.output
    saved = [line for line in result.output.splitlines() if line.startswith("Saved report to ")]
    assert len(saved) == 1
    folder = Path(saved[0].removeprefix("Saved report to "))
    assert folder.is_dir()
    assert folder.parent == fake_home / ".skillsentry" / "reports"
    names = sorted(item.name for item in folder.iterdir())
    assert "summary.md" in names
    assert len([name for name in names if name.endswith(".md")]) == 3


def test_prompt_s_writes_one_sarif_file(fake_home: Path, tmp_path: Path, tty: None) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN, input="s\n")

    assert result.exit_code == 0, result.output
    (folder,) = _report_dirs(fake_home)
    payload = json.loads((folder / "skills.sarif").read_text(encoding="utf-8"))
    assert len(payload["runs"]) == 2


def test_prompt_n_writes_nothing(fake_home: Path, tmp_path: Path, tty: None) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN, input="n\n")

    assert result.exit_code == 0, result.output
    assert "Saved report" not in result.output
    assert _report_dirs(fake_home) == []


def test_three_bad_answers_mean_no(fake_home: Path, tmp_path: Path, tty: None) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, SCAN, input="x\ny\nz\nm\n")

    assert result.exit_code == 0, result.output
    assert result.output.count("Please answer m, s or n.") == 3
    assert "Saved report" not in result.output
    assert _report_dirs(fake_home) == []


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt, click.exceptions.Abort])
def test_interrupted_prompt_means_no(
    fake_home: Path, tmp_path: Path, tty: None, monkeypatch: pytest.MonkeyPatch, error: type
) -> None:
    _two_installed(fake_home)

    def interrupted(*_args: object, **_kwargs: object) -> str:
        raise error()

    monkeypatch.setattr(cli.typer, "prompt", interrupted)
    result = _invoke(tmp_path, SCAN)

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
    assert _report_dirs(fake_home) == []


@pytest.mark.parametrize(
    "extra",
    [["--no-prompt"], ["-q"], ["--format", "json"], ["--format", "markdown"]],
)
def test_prompt_is_suppressed_by_flags_and_formats(
    fake_home: Path, tmp_path: Path, tty: None, extra: list[str]
) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, *extra], input="m\n")

    assert result.exit_code == 0, result.output
    assert "Save a report?" not in result.output
    assert _report_dirs(fake_home) == []


def test_save_report_markdown_is_non_interactive(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, "--save-report", "markdown"])

    assert result.exit_code == 0, result.output
    assert "Save a report?" not in result.output
    assert "Tip: add --save-report" not in result.output
    (folder,) = _report_dirs(fake_home)
    assert (folder / "summary.md").is_file()


def test_save_report_keeps_json_stdout_clean(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, "--format", "json", "--save-report", "markdown"])

    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 2
    assert len(_report_dirs(fake_home)) == 1


def test_save_report_none_writes_nothing_and_hides_the_tip(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, "--save-report", "none"])

    assert result.exit_code == 0, result.output
    assert "Tip: add --save-report" not in result.output
    assert _report_dirs(fake_home) == []


def test_unknown_save_report_is_a_usage_error(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, [*SCAN, "--save-report", "pdf"])

    assert result.exit_code == int(cli.ExitCode.USAGE)


def test_no_prompt_hides_the_tip_too(fake_home: Path, tmp_path: Path) -> None:
    _two_installed(fake_home)

    result = _invoke(tmp_path, [*SCAN, "--no-prompt"])

    assert result.exit_code == 0, result.output
    assert "Tip: add --save-report" not in result.output


@pytest.mark.parametrize(
    "flags",
    [["--output", "x.txt"], ["--sarif-out", "x.sarif"], ["--report-dir", "rd"], ["--recursive"]],
)
def test_path_only_flags_are_usage_errors_without_a_path(flags, tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLSENTRY_DB", str(tmp_path / "db.sqlite"))
    result = CliRunner().invoke(cli.app, ["scan", *flags])
    assert result.exit_code == 2
    assert "need a skill path" in result.output
