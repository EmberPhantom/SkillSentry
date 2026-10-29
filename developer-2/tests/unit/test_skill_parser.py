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

    def test_symlink_escape_does_not_crash(self, tmp_path):
        """Security DEF-07: Symlink escaping root emits finding without ValueError."""
        pkg = tmp_path / "symlink_skill"
        pkg.mkdir()
        (pkg / "SKILL.md").write_text("---\nname: sym-skill\ndescription: test\n---\n")
        
        # Target outside root
        outside_target = tmp_path / "secret.txt"
        outside_target.write_text("SUPER_SECRET_TOKEN=12345")
        
        symlink_path = pkg / "stolen.txt"
        symlink_created = False
        try:
            symlink_path.symlink_to(outside_target)
            symlink_created = True
        except OSError:
            # On Windows without admin privileges, simulate symlink via mock
            pass

        if not symlink_created:
            symlink_path.write_text("SUPER_SECRET_TOKEN=12345")
            path_cls = type(symlink_path)
            orig_sym = path_cls.is_symlink
            orig_res = path_cls.resolve

            def fake_sym(self):
                return True if self.name == symlink_path.name else orig_sym(self)

            def fake_res(self, *a, **k):
                return outside_target.resolve() if self.name == symlink_path.name else orig_res(self, *a, **k)

            import unittest.mock
            with unittest.mock.patch.object(path_cls, "is_symlink", fake_sym), \
                 unittest.mock.patch.object(path_cls, "resolve", fake_res):
                manifest, result = parse_package(pkg)
        else:
            manifest, result = parse_package(pkg)

        assert result.degraded is True
        crit = [f for f in result.findings if f.severity == "critical"]
        assert any("escapes package root" in f.message for f in crit)

    def test_powershell_and_shebang_scripts_scanned(self, tmp_path):
        """DEF-05: .ps1, .bat, and shebang scripts must be inventoried as scripts."""
        pkg = tmp_path / "script_skill"
        pkg.mkdir()
        (pkg / "SKILL.md").write_text("---\nname: script-skill\ndescription: test\n---\n")
        (pkg / "deploy.ps1").write_text("Write-Output 'hello powershell'\n")
        (pkg / "build.bat").write_text("@echo off\necho building\n")
        
        shebang_file = pkg / "run_tool"
        shebang_file.write_bytes(b"#!/bin/bash\necho running\n")
        
        # Dot directory
        hidden_dir = pkg / ".hooks"
        hidden_dir.mkdir()
        (hidden_dir / "pre-commit.sh").write_text("#!/bin/sh\nexit 0\n")

        manifest, result = parse_package(pkg)
        assert manifest is not None
        assert "deploy.ps1" in manifest.scripts
        assert "build.bat" in manifest.scripts
        assert "run_tool" in manifest.scripts
        assert ".hooks/pre-commit.sh" in manifest.scripts

    def test_oversize_file_sets_degraded(self, tmp_path, monkeypatch):
        """DEF-04: File exceeding MAX_FILE_SIZE_BYTES sets degraded=True."""
        import skillsentry_dev2.core.parser.skill_parser as sp
        monkeypatch.setattr(sp, "MAX_FILE_SIZE_BYTES", 50)

        pkg = tmp_path / "big_skill"
        pkg.mkdir()
        (pkg / "SKILL.md").write_text("---\nname: big-skill\ndescription: test\n---\n")
        (pkg / "large.py").write_text("X" * 100)

        manifest, result = parse_package(pkg)
        assert result.degraded is True
        assert any("truncated" in f.message.lower() for f in result.findings)

    def test_yaml_bomb_depth_limited(self, tmp_path):
        """DEF-14: Highly nested YAML bomb triggers parser error and degraded=True."""
        pkg = tmp_path / "yaml_bomb_skill"
        pkg.mkdir()
        
        # Nest 25 levels (> MAX_YAML_DEPTH of 20)
        nested_yaml = "a:\n"
        for i in range(25):
            nested_yaml += "  " * (i + 1) + f"level_{i}:\n"
        nested_yaml += "  " * 26 + "payload: boom\n"

        (pkg / "SKILL.md").write_text(f"---\n{nested_yaml}---\nBody\n")
        manifest, result = parse_package(pkg)
        assert result.degraded is True
        assert any("nesting depth" in f.message.lower() or "invalid yaml" in f.message.lower() for f in result.findings)


