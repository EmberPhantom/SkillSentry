"""CLI: cache sub-commands, export, and the --fail-on default."""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.core.cache import SQLiteStore
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def temp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "cli.sqlite")
    monkeypatch.setattr(cli, "_store", lambda: store)
    return store


def test_cache_stats_reports_entries(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["cache", "stats"])

    assert result.exit_code == 0
    assert "entries: 0" in result.output


def test_cache_list_on_empty_store(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["cache", "list"])

    assert result.exit_code == 0
    assert "no scans recorded" in result.output


def test_cache_clear_reports_counts(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["cache", "clear"])

    assert result.exit_code == 0
    assert "deleted: 0" in result.output


def test_cache_clear_rejects_a_bad_age(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["cache", "clear", "--older-than", "soon"])

    assert result.exit_code != 0


def test_export_rejects_an_unknown_format(temp_store: SQLiteStore) -> None:
    result = runner.invoke(
        cli.app,
        ["export", "00000000-0000-0000-0000-000000000000", "--format", "pdf"],
    )

    assert result.exit_code != 0
    assert "unsupported --format" in result.output


def test_export_rejects_a_non_uuid(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["export", "not-a-scan"])

    assert result.exit_code != 0
    assert "not a scan ID" in result.output


def test_export_reports_a_missing_scan(temp_store: SQLiteStore) -> None:
    result = runner.invoke(
        cli.app,
        ["export", "00000000-0000-0000-0000-000000000000"],
    )

    assert result.exit_code != 0
    assert "no stored scan" in result.output


def test_fail_on_defaults_to_suspicious_for_scan_and_self_audit() -> None:
    for command in ("scan", "self-audit"):
        result = runner.invoke(cli.app, [command, "--help"])
        assert result.exit_code == 0
        assert "suspicious" in result.output
        assert "--fail-on" in result.output


def test_cache_list_prints_id_skill_status_and_verdict(
    temp_store: SQLiteStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from skill_sentry_cli.core.contracts import ScanStatus, VerdictTier

    row = {
        "scan_id": "3f9c0000-0000-4000-8000-000000000001",
        "skill": "pdf-summarizer",
        "status": ScanStatus.COMPLETED,
        "verdict": VerdictTier.SAFE,
    }
    monkeypatch.setattr(temp_store, "list_scans", lambda **_: [row])

    result = runner.invoke(cli.app, ["cache", "list"])

    assert result.exit_code == 0
    assert (
        "3f9c0000-0000-4000-8000-000000000001  pdf-summarizer  completed  SAFE"
    ) in result.output
    assert "VerdictTier" not in result.output


def test_cache_stats_reports_file_size_and_hit_rate(temp_store: SQLiteStore) -> None:
    result = runner.invoke(cli.app, ["cache", "stats"])

    assert result.exit_code == 0
    size_line = next(line for line in result.output.splitlines() if line.startswith("size_bytes:"))
    assert int(size_line.split(":", 1)[1]) > 0
    assert "hit_rate: 0.000" in result.output
