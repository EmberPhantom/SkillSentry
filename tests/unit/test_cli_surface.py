"""CLI surface matches docs/07-cli-reference.md.

Every command and flag the reference documents must appear in ``--help``, the
``--fail-on`` default must be the one documented, and each exit code must mean
what the §7.5 table says.  A failure here means the doc and the code disagree.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from skillsentry import cli
from skillsentry.core.cache import SQLiteStore
from skillsentry.core.exit_codes import ExitCode
from typer.testing import CliRunner

runner = CliRunner()

TOP_LEVEL_COMMANDS = ["serve", "init", "scan", "self-audit", "export", "doctor", "cache", "sandbox"]

SUBCOMMANDS = {
    "cache": ["stats", "list", "clear"],
    "sandbox": ["build"],
}

SCAN_FLAGS = [
    "--format",
    "--fail-on",
    "--quiet",
    "--no-cache",
    "--sandbox",
    "--backend",
    "--timeout",
    "--output",
    "--sarif-out",
    "--demo-mode",
]

SERVE_FLAGS = ["--host", "--port", "--demo-mode", "--speed"]

EXPORT_FLAGS = ["--format", "--output"]


@pytest.fixture
def temp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "surface.sqlite")
    monkeypatch.setattr(cli, "_store", lambda: store)
    return store


def _help(*args: str) -> str:
    result = runner.invoke(cli.app, [*args, "--help"])
    assert result.exit_code == 0, result.output
    return result.output


@pytest.mark.parametrize("command", TOP_LEVEL_COMMANDS)
def test_documented_command_is_registered(command: str) -> None:
    assert command in _help()


@pytest.mark.parametrize(
    "command, subcommand",
    [(group, sub) for group, subs in SUBCOMMANDS.items() for sub in subs],
)
def test_documented_subcommand_is_registered(command: str, subcommand: str) -> None:
    assert subcommand in _help(command)


@pytest.mark.parametrize("flag", SCAN_FLAGS)
def test_documented_scan_flag_is_in_help(flag: str) -> None:
    assert flag in _help("scan")


@pytest.mark.parametrize("flag", SERVE_FLAGS)
def test_documented_serve_flag_is_in_help(flag: str) -> None:
    assert flag in _help("serve")


@pytest.mark.parametrize("flag", EXPORT_FLAGS)
def test_documented_export_flag_is_in_help(flag: str) -> None:
    assert flag in _help("export")


def test_fail_on_defaults_to_suspicious_for_scan_and_self_audit() -> None:
    for command in ("scan", "self-audit"):
        assert "[default: suspicious]" in _help(command), command


def test_exit_codes_match_the_reference_table() -> None:
    # docs/07-cli-reference.md §7.5
    assert int(ExitCode.OK) == 0
    assert int(ExitCode.VERDICT) == 1
    assert int(ExitCode.USAGE) == 2
    assert int(ExitCode.OPERATIONAL) == 3
    assert int(ExitCode.MODEL_UNAVAILABLE) == 4


def test_bad_format_is_a_usage_error_exit_2() -> None:
    result = runner.invoke(cli.app, ["scan", "anything", "--format", "xml"])
    assert result.exit_code == int(ExitCode.USAGE)


def test_missing_skill_path_is_an_operational_error_exit_3(
    tmp_path: Path, temp_store: SQLiteStore
) -> None:
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(cli.app, ["scan", str(missing), "--backend", "demo", "--no-sandbox"])
    assert result.exit_code == int(ExitCode.OPERATIONAL)


def test_export_unknown_scan_is_a_usage_error_exit_2(temp_store: SQLiteStore) -> None:
    result = runner.invoke(
        cli.app, ["export", "00000000-0000-0000-0000-000000000000", "--format", "markdown"]
    )
    assert result.exit_code == int(ExitCode.USAGE)
