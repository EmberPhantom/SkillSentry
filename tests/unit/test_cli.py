"""CLI smoke tests — demo scan, init, version, and exit codes."""

from __future__ import annotations

import pytest

import json
from pathlib import Path

from skillsentry.cli import app
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture(autouse=True)
def _patch_cli_engine(monkeypatch):
    import skillsentry.cli as cli_mod
    from tests.support.mock_gemma import MockGemma
    from skillsentry.core.engine import ScanEngine
    orig_make_engine = cli_mod._make_engine

    def patched_make_engine(config, backend):
        if backend == 'demo':
            return ScanEngine(config, model=MockGemma())
        return orig_make_engine(config, backend)

    monkeypatch.setattr(cli_mod, '_make_engine', patched_make_engine)


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


def _write_benign_skill(tmp_path: Path) -> Path:
    skill = tmp_path / "pdf-summarizer"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        """---
name: pdf-summarizer
description: Summarize PDF documents locally without network access.
---

# PDF Summarizer

Extract text from a PDF and print a short summary.
""",
        encoding="utf-8",
    )
    return skill


def test_live_scan_uses_the_engine_and_returns_json(tmp_path: Path):
    skill = _write_benign_skill(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            str(skill),
            "--format",
            "json",
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "cli.sqlite")},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "SAFE"
    assert payload["skill"] == "pdf-summarizer"
    assert payload["riskScore"] < 30


def test_live_scan_missing_path_is_operational_error():
    result = runner.invoke(app, ["scan", "definitely-not-a-skill"])
    assert result.exit_code == 3
    assert "does not exist" in result.output
    assert "not wired" not in result.output


def test_self_audit_runs_the_live_pipeline():
    result = runner.invoke(
        app,
        ["self-audit", "--backend", "demo", "--no-sandbox", "--no-cache"],
    )
    assert result.exit_code == 0, result.output
    assert "skillsentry-audit" in result.output


ROOT = Path(__file__).resolve().parents[2]


def test_live_scan_threshold_hit_exits_one(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "malicious" / "cloud-sync-pro"),
            "--format",
            "json",
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
            "--fail-on",
            "malicious",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "threshold.sqlite")},
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "MALICIOUS"


def test_live_scan_clean_folder_recurses_and_exits_zero(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "benign"),
            "--format",
            "json",
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
            "--fail-on",
            "suspicious",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "folder.sqlite")},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert {item["skill"] for item in payload} == {
        "pdf-summarizer",
        "git-helper",
        "image-resizer",
        "weather-fetch",
    }
    assert all(item["verdict"] == "SAFE" for item in payload)


def test_live_scan_writes_json_output_file(tmp_path: Path):
    target = tmp_path / "reports" / "verdict.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "malicious" / "cloud-sync-pro"),
            "--format",
            "json",
            "--output",
            str(target),
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "output.sqlite")},
    )
    assert result.exit_code == 1, result.output
    assert target.is_file()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["verdict"] == "MALICIOUS"


def test_live_scan_writes_sarif_sidecar(tmp_path: Path):
    target = tmp_path / "results.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "malicious" / "cloud-sync-pro"),
            "--format",
            "sarif",
            "--sarif-out",
            str(target),
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "sarif.sqlite")},
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"]
    assert target.is_file()
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_live_scan_invalid_format_is_usage_error():
    result = runner.invoke(app, ["scan", "fixtures", "--format", "xml"])
    assert result.exit_code == 2
    assert "unsupported --format" in result.output
