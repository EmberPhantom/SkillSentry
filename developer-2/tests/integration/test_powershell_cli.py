"""
Integration Test Suite for SkillSentry Windows PowerShell CLI.

Tests command-line argument parsing, Windows path normalization,
reserved device name blocking, format renderers (text, json, sarif, markdown),
SARIF file export, caching interactions, and exit code contracts.

REQ-D2-PS-01 · REQ-D2-PS-02 · REQ-D2-SBX-01 · REQ-D2-PERF-04
Source: developer-2/03-functional-specifications.md Cap L.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from skillsentry_dev2.cli import build_parser, main, sanitize_and_validate_path


DEV2_ROOT = Path(__file__).resolve().parents[2]
BENIGN_DIR = DEV2_ROOT / "fixtures" / "benign"
MALICIOUS_DIR = DEV2_ROOT / "fixtures" / "malicious"


@pytest.fixture
def temp_cache_db(tmp_path: Path) -> Path:
    """Create a temporary SQLite cache database path."""
    return tmp_path / "test_cache.db"


class TestPowerShellCLIInvocation:
    """Tests basic CLI invocations and help screens."""

    def test_cli_help(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        """Assert that --help displays help and returns exit code 0."""
        code = main(["--help"])
        assert code == 0
        captured = capsys.readouterr()
        assert "SkillSentry" in captured.out
        assert "scan" in captured.out

    def test_cli_no_args_shows_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Assert that running with no arguments returns usage exit code 2."""
        code = main([])
        assert code == 2

    def test_cli_default_subcommand_insertion(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that 'skillsentry <path>' defaults to the 'scan' subcommand."""
        target = str(BENIGN_DIR / "pdf-summarizer")
        code = main([target, "--demo-mode", "--quiet", "--db-path", str(temp_cache_db)])
        assert code == 0
        captured = capsys.readouterr()
        assert "pdf-summarizer: SAFE" in captured.out


class TestWindowsPathSanitization:
    """Tests Windows path sanitization and security boundary validation."""

    def test_reserved_device_con_rejection(self) -> None:
        """Assert that paths containing 'CON' are rejected."""
        with pytest.raises(ValueError, match="reserved Windows MS-DOS device name"):
            sanitize_and_validate_path("CON")

    def test_reserved_device_nul_rejection(self) -> None:
        """Assert that paths containing 'NUL' are rejected."""
        with pytest.raises(ValueError, match="reserved Windows MS-DOS device name"):
            sanitize_and_validate_path("C:\\temp\\NUL\\SKILL.md")

    def test_reserved_device_prn_rejection(self) -> None:
        """Assert that paths containing 'PRN' are rejected."""
        with pytest.raises(ValueError, match="reserved Windows MS-DOS device name"):
            sanitize_and_validate_path("prn.txt")

    def test_alternate_data_stream_rejection(self) -> None:
        """Assert that NTFS Alternate Data Stream colons are rejected."""
        with pytest.raises(ValueError, match="invalid NTFS Alternate Data Stream notation"):
            sanitize_and_validate_path("scripts/sync.py:hidden_stream")

    def test_nonexistent_path_rejection(self) -> None:
        """Assert that non-existent paths raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            sanitize_and_validate_path("D:\\this_path_does_not_exist_at_all")

    def test_cli_exit_code_on_reserved_device(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Assert that CLI returns exit code 2 on reserved device name."""
        code = main(["scan", "CON"])
        assert code == 2
        captured = capsys.readouterr()
        assert "Usage Error" in captured.err

    def test_cli_exit_code_on_nonexistent_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Assert that CLI returns exit code 2 on non-existent path."""
        code = main(["scan", "D:\\nonexistent_skill_xyz"])
        assert code == 2
        captured = capsys.readouterr()
        assert "Usage Error" in captured.err

    def test_cli_exit_code_on_directory_missing_skill_md(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that CLI returns exit code 2 if directory has no SKILL.md."""
        empty_dir = tmp_path / "empty_skill"
        empty_dir.mkdir()
        code = main(["scan", str(empty_dir)])
        assert code == 2
        captured = capsys.readouterr()
        assert "missing SKILL.md" in captured.err


class TestScanExecutionAndExitCodes:
    """Tests scan pipeline execution, output modes, and CI exit codes."""

    def test_benign_skill_scan_pass(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that a benign skill passes with exit code 0."""
        target = str(BENIGN_DIR / "pdf-summarizer")
        code = main([
            "scan", target,
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0
        captured = capsys.readouterr()
        assert "[PASS] SAFE" in captured.out
        assert "pdf-summarizer" in captured.out

    def test_malicious_skill_scan_fail(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that a malicious skill fails with exit code 1 when fail-on is malicious."""
        target = str(MALICIOUS_DIR / "invoice-helper")
        code = main([
            "scan", target,
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 1
        captured = capsys.readouterr()
        assert "MALICIOUS" in captured.out

    def test_fail_on_threshold_suspicious(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that dns-tunneler (SUSPICIOUS) fails when --fail-on is suspicious."""
        target = str(MALICIOUS_DIR / "dns-tunneler")
        code = main([
            "scan", target,
            "--demo-mode",
            "--fail-on", "suspicious",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 1

    def test_fail_on_threshold_malicious_allows_suspicious(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that dns-tunneler (SUSPICIOUS) passes when --fail-on is malicious."""
        target = str(MALICIOUS_DIR / "dns-tunneler")
        code = main([
            "scan", target,
            "--demo-mode",
            "--fail-on", "malicious",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0

    def test_parent_directory_discovery(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that scanning a parent folder discovers and evaluates all child skills."""
        code = main([
            "scan", str(BENIGN_DIR),
            "--demo-mode",
            "--quiet",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().split("\n") if ":" in l]
        # All 12 benign fixtures should be evaluated
        assert len(lines) == 12
        assert all("SAFE" in l for l in lines)


class TestOutputFormatsAndArtifacts:
    """Tests JSON, SARIF, Markdown, and SARIF file export."""

    def test_format_json(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that --format json outputs valid parseable JSON."""
        target = str(BENIGN_DIR / "image-resizer")
        code = main([
            "scan", target,
            "--format", "json",
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["skill_name"] == "image-resizer"
        assert data["verdict"] == "SAFE"
        assert "sandbox_instructions" in data
        assert "content_hash" in data

    def test_format_sarif(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that --format sarif outputs valid SARIF 2.1.0 JSON."""
        target = str(MALICIOUS_DIR / "invoice-helper")
        code = main([
            "scan", target,
            "--format", "sarif",
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 1
        captured = capsys.readouterr()
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "SkillSentry"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_format_markdown(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that --format markdown outputs a markdown table."""
        target = str(BENIGN_DIR / "git-helper")
        code = main([
            "scan", target,
            "--format", "markdown",
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0
        captured = capsys.readouterr()
        assert "| Skill Name | Verdict | Risk Score |" in captured.out
        assert "`git-helper`" in captured.out

    def test_sarif_out_file_export(
        self, tmp_path: Path, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that --sarif-out writes a valid SARIF file to disk."""
        target = str(MALICIOUS_DIR / "invoice-helper")
        sarif_file = tmp_path / "reports" / "report.sarif"
        code = main([
            "scan", target,
            "--sarif-out", str(sarif_file),
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 1
        assert sarif_file.exists()
        sarif_content = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert sarif_content["version"] == "2.1.0"
        assert len(sarif_content["runs"][0]["results"]) > 0


class TestSandboxInstructionsAndPerformance:
    """Tests INT-4 dynamic sandbox action instructions and caching performance."""

    def test_dynamic_sandbox_instructions_generated(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that INT-4 sandbox instructions are generated with required checks."""
        target = str(MALICIOUS_DIR / "dns-tunneler")
        code = main([
            "scan", target,
            "--format", "json",
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        data = json.loads(capsys.readouterr().out)
        instructions = data["sandbox_instructions"]
        categories = {inst["check_category"] for inst in instructions}
        assert "CREDENTIAL_CANARY_MONITOR" in categories
        assert "DNS_SINKHOLE_WATCH" in categories
        for inst in instructions:
            assert inst["check_status"] in ("required", "optional", "blocked", "unsupported")

    def test_no_sandbox_flag_records_degraded_finding(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that --no-sandbox adds a degraded sandbox note finding."""
        target = str(BENIGN_DIR / "pdf-summarizer")
        code = main([
            "scan", target,
            "--no-sandbox",
            "--format", "json",
            "--demo-mode",
            "--db-path", str(temp_cache_db),
        ])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["degraded"] is True
        stages = [f["stage"] for f in data["findings"]]
        assert "sandbox" in stages

    def test_cache_hit_on_rescan(
        self, temp_cache_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Assert that re-scanning an unchanged package triggers a cache hit."""
        target = str(BENIGN_DIR / "pdf-summarizer")
        # First scan -> Cache Miss
        main(["scan", target, "--demo-mode", "--db-path", str(temp_cache_db)])
        capsys.readouterr()

        # Second scan -> Cache Hit
        code = main(["scan", target, "--demo-mode", "--format", "json", "--db-path", str(temp_cache_db)])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["cached"] is True

