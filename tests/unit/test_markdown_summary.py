"""The Markdown run summary: counts first, most serious verdicts on top, locations shown.

The no-path tests run against a fake home folder with the demo model and no sandbox, so
no Docker or Ollama is needed. Findings, citations and verdicts in the per-skill reports
are covered by ``test_reports.py`` and are not changed here.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.core.engine import ScanEngine, ScanError
from skill_sentry_cli.core.verdict.markdown_report import (
    SummaryRow,
    _cell,
    build_markdown,
    build_summary_markdown,
    status_rank,
)
from skill_sentry_cli.server.demo_data import build_demo_store
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]
GOOD = "---\nname: {name}\ndescription: a fine skill\n---\n# {name}\n"
SCAN = ["scan", "--backend", "demo", "--no-sandbox", "--no-cache"]
runner = CliRunner()


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


def _skill(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(GOOD.format(name=path.name), encoding="utf-8")
    return path


def _malicious(path: Path) -> Path:
    shutil.copytree(ROOT / "fixtures" / "malicious" / "cloud-sync-pro", path)
    return path


def _invoke(tmp_path: Path, args: list[str]) -> Any:
    return runner.invoke(cli.app, args, env={"SKILLSENTRY_DB": str(tmp_path / "summary.sqlite")})


def _verdict(name: str):
    return next(item.verdict for item in build_demo_store() if item.name == name)


# -- the renderer on its own ---------------------------------------------------------------


def test_summary_opens_with_a_counts_table() -> None:
    text = build_summary_markdown(
        [SummaryRow("a", "SAFE", 0)], headline="Summary: 1 scanned", scanned=1
    )

    assert "| Scanned | Failed | Skipped |\n|---:|---:|---:|\n| 1 | 0 | 0 |" in text
    assert text.index("| Scanned |") < text.index("| Skill |")


def test_summary_puts_the_most_serious_verdicts_first() -> None:
    rows = [
        SummaryRow("clean", "SAFE", 0),
        SummaryRow("odd", "SUSPICIOUS", 40),
        SummaryRow("evil-low", "MALICIOUS", 70),
        SummaryRow("evil-high", "MALICIOUS", 95),
        SummaryRow("partial", "UNSCANNED", 0),
    ]

    text = build_summary_markdown(rows, headline="h", scanned=5)

    order = [
        text.index(f"| {name} |") for name in ("evil-high", "evil-low", "odd", "partial", "clean")
    ]
    assert order == sorted(order)


def test_summary_without_skills_says_so() -> None:
    text = build_summary_markdown([], headline="Summary: 0 scanned", scanned=0)

    assert "No skills were scanned." in text
    assert "| 0 | 0 | 0 |" in text
    assert "| Skill |" not in text


def test_summary_lists_failed_skills_and_notes() -> None:
    text = build_summary_markdown(
        [SummaryRow("ok", "SAFE", 0)],
        headline="h",
        scanned=1,
        failed_count=1,
        failed=["/skills/broken"],
        skipped=2,
        notes=["broken symlink ghost"],
    )

    assert "| 1 | 1 | 2 |" in text
    assert "## Failed" in text and "- `/skills/broken`" in text
    assert "## Notes" in text and "- broken symlink ghost" in text


def test_summary_escapes_untrusted_names_and_paths() -> None:
    row = SummaryRow("a|b <x>", "SAFE", 0, agent="Codex", scope="user", path="/p|q")

    text = build_summary_markdown([row], headline="h", scanned=1)

    assert "a\\|b &lt;x&gt;" in text
    assert "/p\\|q" in text


def test_summary_escapes_backslashes_and_pipes_in_a_path() -> None:
    row = SummaryRow("a", "SAFE", 0, agent="Codex", scope="user", path="C:\\Users\\me\\s|k")

    text = build_summary_markdown([row], headline="h", scanned=1)

    assert "C:\\\\Users\\\\me\\\\s\\|k" in text


def test_status_rank_orders_by_severity() -> None:
    ranks = [
        status_rank(s) for s in ("MALICIOUS", "SUSPICIOUS", "UNSCANNED", "INVALID SKILL", "SAFE")
    ]
    assert ranks == sorted(ranks) and len(set(ranks)) == 5


def test_per_skill_report_shows_where_it_was_found() -> None:
    text = build_markdown(
        _verdict("pdf-summarizer"),
        location={"Agent": "Codex", "Scope": "user", "Install path": "/h/.codex/skills/pdf"},
    )

    assert "| Agent | Codex |" in text
    assert "| Scope | user |" in text
    assert "| Install path | /h/.codex/skills/pdf |" in text


def test_per_skill_report_is_unchanged_without_a_location() -> None:
    text = build_markdown(_verdict("pdf-summarizer"))

    assert "| Agent |" not in text and "Install path" not in text


# -- real scans ----------------------------------------------------------------------------


def test_no_path_markdown_orders_by_severity_and_shows_counts(
    fake_home: Path, tmp_path: Path
) -> None:
    _skill(fake_home / ".claude" / "skills" / "aaa-clean")
    _malicious(fake_home / ".codex" / "skills" / "cloud-sync-pro")

    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    # A malicious skill in the batch exits 1; the report is still written.
    assert result.exit_code == 1, result.output
    out = result.stdout
    assert "| Scanned | Failed | Skipped |\n|---:|---:|---:|\n| 2 | 0 | 0 |" in out
    assert out.index("| cloud-sync-pro | MALICIOUS") < out.index("| aaa-clean | SAFE")
    # The per-skill reports follow the same order and say where each skill came from.
    assert out.index("# SkillSentry Triage Report — cloud-sync-pro") < out.index(
        "# SkillSentry Triage Report — aaa-clean"
    )
    assert "| Agent | Codex |" in out and "| Agent | Claude Code |" in out
    # Cell text is escaped (backslashes in a Windows path), so build it the same way.
    codex_path = _cell(fake_home / ".codex" / "skills" / "cloud-sync-pro")
    assert f"| Install path | {codex_path} |" in out


def test_no_path_markdown_for_one_skill_still_has_summary_and_location(
    fake_home: Path, tmp_path: Path
) -> None:
    _skill(fake_home / ".claude" / "skills" / "solo")

    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    assert result.exit_code == 0, result.output
    assert "| 1 | 0 | 0 |" in result.stdout
    assert "| Scope | user |" in result.stdout


def test_no_path_markdown_resolves_the_backend_in_every_footer(
    fake_home: Path, tmp_path: Path
) -> None:
    _skill(fake_home / ".claude" / "skills" / "solo")

    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    assert "backend not recorded" not in result.stdout


def test_empty_no_path_markdown_is_a_report_not_a_blank(fake_home: Path, tmp_path: Path) -> None:
    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    assert result.exit_code == 0, result.output
    assert "# SkillSentry folder summary" in result.stdout
    assert "No skills were scanned." in result.stdout
    assert "| 0 | 0 | 0 |" in result.stdout


def test_failed_skill_is_named_in_the_markdown_summary(
    fake_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _skill(fake_home / ".claude" / "skills" / "good")
    bad = _skill(fake_home / ".codex" / "skills" / "bad")
    real_scan = ScanEngine.scan

    def flaky(self: ScanEngine, path: Any, **kwargs: Any) -> Any:
        if Path(path).name == "bad":
            raise ScanError("boom")
        return real_scan(self, path, **kwargs)

    monkeypatch.setattr(ScanEngine, "scan", flaky)

    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    assert result.exit_code == 3, result.output
    assert "| 1 | 1 | 0 |" in result.stdout
    assert "## Failed" in result.stdout
    assert f"- `{bad}`" in result.stdout
    assert "| good | SAFE" in result.stdout


def test_skipped_folders_are_counted_and_explained(fake_home: Path, tmp_path: Path) -> None:
    _skill(fake_home / ".claude" / "skills" / "good")
    (fake_home / ".codex" / "skills" / "not-a-skill").mkdir(parents=True)

    result = _invoke(tmp_path, [*SCAN, "--format", "markdown"])

    assert result.exit_code == 0, result.output
    assert "| 1 | 0 | 1 |" in result.stdout
    assert "## Notes" in result.stdout


def test_save_report_markdown_summary_has_counts_order_and_location(
    fake_home: Path, tmp_path: Path
) -> None:
    _skill(fake_home / ".claude" / "skills" / "aaa-clean")
    _malicious(fake_home / ".codex" / "skills" / "cloud-sync-pro")

    result = _invoke(tmp_path, [*SCAN, "--save-report", "markdown"])

    # A malicious skill in the batch exits 1; the report is still written.
    assert result.exit_code == 1, result.output
    (folder,) = (fake_home / ".skillsentry" / "reports").iterdir()
    summary = (folder / "summary.md").read_text(encoding="utf-8")
    assert "| 2 | 0 | 0 |" in summary
    assert summary.index("| cloud-sync-pro |") < summary.index("| aaa-clean |")
    detail = next(folder.glob("cloud-sync-pro-*.md")).read_text(encoding="utf-8")
    assert "| Agent | Codex |" in detail
    assert "backend not recorded" not in detail


def test_path_scan_markdown_has_counts_and_severity_order_but_no_location(
    fake_home: Path, tmp_path: Path
) -> None:
    folder = tmp_path / "bundle"
    _skill(folder / "aaa-clean")
    _malicious(folder / "cloud-sync-pro")

    result = _invoke(tmp_path, [*SCAN, str(folder), "--format", "markdown"])

    # A malicious skill in the batch exits 1; the report is still written.
    assert result.exit_code == 1, result.output
    out = result.stdout
    assert "| 2 | 0 | 0 |" in out
    assert out.index("| cloud-sync-pro | MALICIOUS") < out.index("| aaa-clean | SAFE")
    assert "| Agent |" not in out and "Install path" not in out


def test_path_scan_json_and_sarif_are_untouched(fake_home: Path, tmp_path: Path) -> None:
    skill = _skill(tmp_path / "one")

    as_json = _invoke(tmp_path, [*SCAN, str(skill), "--format", "json"])
    as_sarif = _invoke(tmp_path, [*SCAN, str(skill), "--format", "sarif"])

    assert as_json.exit_code == 0 and as_sarif.exit_code == 0
    assert "Scanned" not in as_json.stdout and "Scanned" not in as_sarif.stdout
