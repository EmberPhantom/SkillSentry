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
    assert "Fully local analysis" in result.output


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


def test_mock_backend_is_refused_for_real_scans(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SKILLSENTRY_DEV", raising=False)
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "benign" / "git-helper"),
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "refuse.sqlite")},
    )
    assert result.exit_code == 2, result.output
    assert "refused for real scans" in result.output


def test_folder_scan_text_ends_with_a_verdict_count(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "benign"),
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "summary.sqlite")},
    )
    assert result.exit_code == 0, result.output
    assert result.output.rstrip().splitlines()[-1] == (
        "Summary: 4 scanned - 4 SAFE, 0 SUSPICIOUS, 0 MALICIOUS, 0 UNSCANNED"
    )


def test_folder_scan_markdown_starts_with_a_summary_table(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(ROOT / "fixtures" / "benign"),
            "--format",
            "markdown",
            "--backend",
            "demo",
            "--no-sandbox",
            "--no-cache",
        ],
        env={"SKILLSENTRY_DB": str(tmp_path / "summary-md.sqlite")},
    )
    assert result.exit_code == 0, result.output
    assert result.output.startswith("# SkillSentry folder summary")
    assert "| git-helper | SAFE |" in result.output


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


def test_unwritable_output_is_an_operational_error_not_a_traceback(tmp_path: Path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "git-helper",
            "--demo-mode",
            "--output",
            str(blocker / "report.md"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert "could not write" in result.output
    assert "Traceback" not in result.output


def test_init_into_an_unwritable_path_is_reported(tmp_path: Path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    result = runner.invoke(app, ["init", "--path", str(blocker / "skillsentry.toml")])
    assert result.exit_code == 3, result.output
    assert "could not write" in result.output
    assert "Traceback" not in result.output
