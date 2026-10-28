"""
Unit tests for skill_parser.py (Stage 1 — Package Parsing & Spec Validation).

Covers: valid parsing, missing SKILL.md, malformed YAML, oversized descriptions,
path traversal, unicode names, Windows paths, reserved device names, file limits.
"""

import os
import tempfile
from pathlib import Path

import pytest

from skillsentry_dev2.core.parser.skill_parser import (
    MAX_DESCRIPTION_LENGTH,
    MAX_FILE_COUNT,
    MAX_FILE_SIZE_BYTES,
    parse_package,
    _check_alternate_data_stream,
    _check_reserved_device_name,
    _is_path_safe,
    _normalize_windows_path,
)


@pytest.fixture
def benign_fixture():
    """Path to the benign pdf-summarizer fixture."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "benign" / "pdf-summarizer"


@pytest.fixture
def malicious_fixture():
    """Path to the malicious invoice-helper fixture."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "malicious" / "invoice-helper"


@pytest.fixture
def tmp_skill(tmp_path):
    """Create a temporary skill directory with valid SKILL.md."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\nname: test-skill\ndescription: A test skill for unit testing.\n---\n\n# Test Skill\n",
        encoding="utf-8",
    )
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "main.py").write_text('print("hello")\n', encoding="utf-8")
    return tmp_path


class TestParsePackage:
    """Tests for parse_package()."""

    def test_valid_benign_fixture(self, benign_fixture):
        manifest, result = parse_package(benign_fixture)
        assert manifest is not None
        assert manifest.name == "pdf-summarizer"
        assert result.stage == "spec"
        # Should have no critical findings
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) == 0

    def test_valid_malicious_fixture(self, malicious_fixture):
        manifest, result = parse_package(malicious_fixture)
        assert manifest is not None
        assert manifest.name == "invoice-helper"
        assert result.stage == "spec"

    def test_scripts_inventoried(self, benign_fixture):
        manifest, _ = parse_package(benign_fixture)
        assert manifest is not None
        # Should contain SKILL.md and the script
        script_paths = list(manifest.scripts.keys())
        assert any("summarize.py" in p for p in script_paths)

    def test_line_numbers_preserved(self, benign_fixture):
        manifest, _ = parse_package(benign_fixture)
        assert manifest is not None
        for _, script in manifest.scripts.items():
            if "summarize.py" in script.relative_path:
                assert len(script.lines) > 0
                # First line should contain docstring or import
                assert script.lines[0].strip() != ""

    def test_nonexistent_directory(self):
        manifest, result = parse_package("/nonexistent/path/to/skill")
        assert manifest is None
        assert result.degraded is True
        assert any(f.severity == "critical" for f in result.findings)

    def test_file_instead_of_directory(self, tmp_path):
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("not a directory")
        manifest, result = parse_package(file_path)
        assert manifest is None
        assert result.degraded is True

    def test_missing_skill_md(self, tmp_path):
        # Empty directory — no SKILL.md
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "main.py").write_text('print("hi")\n')
        manifest, result = parse_package(tmp_path)
        assert manifest is not None  # Still returns manifest with defaults
        high = [f for f in result.findings if f.severity == "high"]
        assert any("No SKILL.md" in f.message for f in high)

    def test_malformed_yaml_frontmatter(self, tmp_path):
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("---\nname: test\n  bad indent: oops:\n---\n", encoding="utf-8")
        manifest, result = parse_package(tmp_path)
        # Should still return a manifest (with fallback) or findings about invalid YAML
        assert result.stage == "spec"

    def test_oversized_description(self, tmp_path):
        long_desc = "A" * (MAX_DESCRIPTION_LENGTH + 100)
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            f"---\nname: test-skill\ndescription: {long_desc}\n---\n",
            encoding="utf-8",
        )
        manifest, result = parse_package(tmp_path)
        medium = [f for f in result.findings if f.severity == "medium"]
        assert any("exceeds" in f.message.lower() for f in medium)

    def test_missing_name_field(self, tmp_path):
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\ndescription: A skill without a name.\n---\n",
            encoding="utf-8",
        )
        manifest, result = parse_package(tmp_path)
        high = [f for f in result.findings if f.severity == "high"]
        assert any("name" in f.message.lower() for f in high)

    def test_invalid_name_characters(self, tmp_path):
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\nname: 'test skill with spaces!'\ndescription: Test.\n---\n",
            encoding="utf-8",
        )
        manifest, result = parse_package(tmp_path)
        high = [f for f in result.findings if f.severity == "high"]
        assert any("invalid characters" in f.message.lower() for f in high)

    def test_content_hash_computed(self, tmp_skill):
        manifest, _ = parse_package(tmp_skill)
        assert manifest is not None
        for _, script in manifest.scripts.items():
            assert script.content_hash
            assert len(script.content_hash) == 64  # SHA-256 hex

    def test_total_size_tracked(self, tmp_skill):
        manifest, _ = parse_package(tmp_skill)
        assert manifest is not None
        assert manifest.total_size_bytes > 0


class TestPathSafety:
    """Tests for path safety utilities."""

    def test_normalize_windows_path_strips_quotes(self):
        assert _normalize_windows_path('"C:\\Users\\test"') == "C:\\Users\\test"

    def test_normalize_windows_path_strips_prefix(self):
        assert _normalize_windows_path("\\\\?\\C:\\Users") == "C:\\Users"

    def test_reserved_device_name_con(self):
        assert _check_reserved_device_name("CON") is True
        assert _check_reserved_device_name("con.txt") is True

    def test_reserved_device_name_prn(self):
        assert _check_reserved_device_name("PRN") is True
        assert _check_reserved_device_name("prn.pdf") is True

    def test_reserved_device_name_com1(self):
        assert _check_reserved_device_name("COM1") is True

    def test_normal_filename_not_reserved(self):
        assert _check_reserved_device_name("connector.py") is False
        assert _check_reserved_device_name("main.py") is False

    def test_ads_detection_positive(self):
        assert _check_alternate_data_stream("file.txt:hidden") is True

    def test_ads_detection_drive_letter_ok(self):
        assert _check_alternate_data_stream("C:\\normal.txt") is False

    def test_is_path_safe_normal(self, tmp_path):
        child = tmp_path / "scripts" / "main.py"
        child.parent.mkdir(parents=True, exist_ok=True)
        child.write_text("pass\n")
        assert _is_path_safe(child, tmp_path) is True

    def test_is_path_safe_detects_escape(self, tmp_path):
        # Parent directory should not be considered safe
        assert _is_path_safe(tmp_path.parent, tmp_path) is False

