"""Scan output: where the report is, nested skills, and format-only (INVALID) packages."""

from __future__ import annotations

from pathlib import Path

from skill_sentry_cli.cli import app
from skill_sentry_cli.core.contracts import Severity, Stage, StageResult
from skill_sentry_cli.core.verdict.status import INVALID, is_invalid, shown_status
from typer.testing import CliRunner

runner = CliRunner()

GOOD = "---\nname: {name}\ndescription: a fine skill\n---\n# {name}\n"
NO_NAME = "---\ndescription: a skill without a name\n---\n# Broken\n"


def _skill(path: Path, body: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(body, encoding="utf-8")
    return path


def _scan(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["scan", *args, "--backend", "demo", "--no-sandbox", "--no-cache"],
        env={"SKILLSENTRY_DB": str(tmp_path / "scan.sqlite")},
    )


def test_missing_name_is_invalid_not_malicious(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "broken", NO_NAME)

    result = _scan(tmp_path, str(skill))

    assert f"- {INVALID} - " in result.output
    assert "missing required field: name" in result.output
    assert "not a malware finding" in result.output
    assert "MALICIOUS" not in result.output


def test_invalid_skill_still_fails_the_default_gate(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "broken", NO_NAME)

    result = _scan(tmp_path, str(skill))

    assert result.exit_code == 1, result.output


def test_single_skill_prints_scope_and_export_command(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "ok", GOOD.format(name="ok"))

    result = _scan(tmp_path, str(skill))

    assert result.output.startswith("Scanning 1 skill:")
    assert "skill-sentry-cli export " in result.output
    assert "--format markdown -o report.md" in result.output


def test_nested_skills_warning_and_recursive_flag(tmp_path: Path) -> None:
    root = _skill(tmp_path / "corpus", GOOD.format(name="parent"))
    _skill(root / "child", GOOD.format(name="child"))

    plain = _scan(tmp_path, str(root))
    recursive = _scan(tmp_path, str(root), "--recursive")

    assert "is a skill itself; its 1 nested skill(s) were not scanned" in plain.output
    assert "Scanning 2 skill(s)" in recursive.output
    assert "child" in recursive.output


def test_report_dir_writes_one_report_per_skill_and_a_summary(tmp_path: Path) -> None:
    folder = tmp_path / "skills"
    _skill(folder / "alpha", GOOD.format(name="alpha"))
    _skill(folder / "beta", NO_NAME)
    reports = tmp_path / "reports"

    result = _scan(tmp_path, str(folder), "--report-dir", str(reports))

    assert result.exit_code == 1, result.output
    written = sorted(path.name for path in reports.iterdir())
    assert "summary.md" in written
    assert sum(name.startswith("alpha-") for name in written) == 1
    assert sum(name.startswith("beta-") for name in written) == 1
    assert "INVALID SKILL" in (reports / "summary.md").read_text(encoding="utf-8")
    assert "Reports:" not in result.output


def test_banner_printed_once_for_a_folder(tmp_path: Path) -> None:
    folder = tmp_path / "skills"
    _skill(folder / "alpha", GOOD.format(name="alpha"))
    _skill(folder / "beta", GOOD.format(name="beta"))

    result = _scan(tmp_path, str(folder))

    assert result.output.count("SkillSentry 2.") == 1


def test_summary_only_lists_invalid_when_present(tmp_path: Path) -> None:
    folder = tmp_path / "skills"
    _skill(folder / "alpha", GOOD.format(name="alpha"))

    result = _scan(tmp_path, str(folder))

    assert "INVALID SKILL" not in result.output.splitlines()[-1]


def test_is_invalid_ignores_behaviour_findings() -> None:
    from skill_sentry_cli.core.contracts import Finding, FindingEvidence, VerdictTier

    manifest = Finding(
        stage=Stage.SPEC,
        severity=Severity.HIGH,
        message="frontmatter is missing required field: name",
        type="manifest-issue",
        evidence=FindingEvidence(file="SKILL.md", line=1),
    )
    exfil = Finding(
        stage=Stage.SANDBOX,
        severity=Severity.HIGH,
        message="outbound connection",
        type="network",
        evidence=FindingEvidence(file="run.py", line=3),
    )
    spec = StageResult(
        stage=Stage.SPEC,
        findings=[manifest],
        degraded=True,
        error="manifest validation failed",
    )

    assert is_invalid(VerdictTier.MALICIOUS, [spec]) is True
    assert shown_status(VerdictTier.MALICIOUS, [spec]) == INVALID
    sandbox = StageResult(stage=Stage.SANDBOX, findings=[exfil])
    assert is_invalid(VerdictTier.MALICIOUS, [spec, sandbox]) is False
    assert shown_status(VerdictTier.MALICIOUS, [spec, sandbox]) == "MALICIOUS"


def test_detect_platform_recognises_wsl(monkeypatch) -> None:
    from skill_sentry_cli import cli

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, **_: "Linux version 6.6.87.2-microsoft-standard-WSL2",
    )

    assert cli.detect_platform() == "WSL"


def test_wsl_warns_when_working_folder_is_on_a_windows_drive(monkeypatch) -> None:
    from skill_sentry_cli import cli

    monkeypatch.setattr(cli, "detect_platform", lambda: "WSL")
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: Path("/mnt/c/Users/me/skills")))

    check = cli._platform_check()

    assert check.required is False
    assert check.ok is False
    assert "Windows drive" in check.detail
