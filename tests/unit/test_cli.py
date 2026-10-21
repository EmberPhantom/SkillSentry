"""CLI smoke tests — demo scan, init, version, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

from skillsentry.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "SkillSentry 2.0.0" in result.output
    assert "Powered by Gemma 4" in result.output


def test_init_writes_config(tmp_path: Path):
    target = tmp_path / "skillsentry.toml"
    result = runner.invoke(app, ["init", "--path", str(target)])
    assert result.exit_code == 0
    assert target.is_file()
    assert "wrote" in result.output


def test_demo_scan_malicious_exits_one():
    result = runner.invoke(app, ["scan", "cloud-sync-pro", "--demo-mode", "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["verdict"] == "MALICIOUS"
    assert payload["riskScore"] == 97


def test_demo_scan_safe_exits_zero():
    result = runner.invoke(app, ["scan", "pdf-summarizer", "--demo-mode"])
    assert result.exit_code == 0
    assert "SAFE" in result.output


def test_demo_scan_suspicious_threshold():
    result = runner.invoke(
        app, ["scan", "pdf-summarizer", "--demo-mode", "--fail-on", "suspicious"]
    )
    assert result.exit_code == 0


def test_unknown_demo_skill_exits_usage():
    result = runner.invoke(app, ["scan", "nope", "--demo-mode"])
    assert result.exit_code == 2


def test_live_scan_is_explicitly_operational_error():
    result = runner.invoke(app, ["scan", "cloud-sync-pro"])
    assert result.exit_code == 3
    assert "not wired yet" in result.output


def test_self_audit_is_honest_until_pipeline_lands():
    result = runner.invoke(app, ["self-audit"])
    assert result.exit_code == 3
    assert "SKILL.md" in result.output
