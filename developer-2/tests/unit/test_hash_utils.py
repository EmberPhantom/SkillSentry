"""
Unit tests for hash_utils.py (Stage 0 — Deterministic Directory Hashing).

Covers: determinism, content change detection, rename detection,
exclusion filters, .skillsentryignore support.
"""

import os
import stat
import tempfile
from pathlib import Path

import pytest

from skillsentry_dev2.core.cache.hash_utils import compute_directory_hash


@pytest.fixture
def simple_skill(tmp_path):
    """Create a simple skill directory for hash testing."""
    (tmp_path / "SKILL.md").write_text(
        "---\nname: test\n---\n# Test\n", encoding="utf-8"
    )
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "main.py").write_text('print("hello")\n', encoding="utf-8")
    return tmp_path


class TestComputeDirectoryHash:
    def test_deterministic(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        h2 = compute_directory_hash(simple_skill)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex length

    def test_content_change_changes_hash(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        (simple_skill / "scripts" / "main.py").write_text('print("changed")\n')
        h2 = compute_directory_hash(simple_skill)
        assert h1 != h2

    def test_rename_changes_hash(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        src = simple_skill / "scripts" / "main.py"
        dst = simple_skill / "scripts" / "renamed.py"
        src.rename(dst)
        h2 = compute_directory_hash(simple_skill)
        assert h1 != h2

    def test_new_file_changes_hash(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        (simple_skill / "scripts" / "extra.py").write_text("pass\n")
        h2 = compute_directory_hash(simple_skill)
        assert h1 != h2

    def test_excludes_pycache(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        cache_dir = simple_skill / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "main.cpython-311.pyc").write_bytes(b"\x00\x01\x02")
        h2 = compute_directory_hash(simple_skill)
        assert h1 == h2

    def test_excludes_git_dir(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        git_dir = simple_skill / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config\n")
        h2 = compute_directory_hash(simple_skill)
        assert h1 == h2

    def test_excludes_ds_store(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        (simple_skill / ".DS_Store").write_bytes(b"\x00\x00\x00")
        h2 = compute_directory_hash(simple_skill)
        assert h1 == h2

    def test_excludes_pyc_files(self, simple_skill):
        h1 = compute_directory_hash(simple_skill)
        (simple_skill / "scripts" / "main.pyc").write_bytes(b"\x00")
        h2 = compute_directory_hash(simple_skill)
        assert h1 == h2

    def test_skillsentryignore_cannot_bypass_hash(self, simple_skill):
        """Security DEF-02: Package-supplied .skillsentryignore must never exclude files."""
        h1 = compute_directory_hash(simple_skill)
        # Attacker tries to ignore all files with a wildcard or dot
        (simple_skill / ".skillsentryignore").write_text(".\n*\n*.py\n")
        h2 = compute_directory_hash(simple_skill)
        assert h1 != h2  # Adding .skillsentryignore changes hash
        # Adding another file MUST change the hash, not be ignored
        (simple_skill / "extra_script.py").write_text("print('pwn')\n")
        h3 = compute_directory_hash(simple_skill)
        assert h2 != h3  # extra_script is hashed, not ignored!

    def test_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            compute_directory_hash("/nonexistent/path")

    def test_not_a_directory_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("not a dir")
        with pytest.raises(NotADirectoryError):
            compute_directory_hash(f)

    def test_empty_directory(self, tmp_path):
        """Empty directories should produce a valid hash (of empty input)."""
        h = compute_directory_hash(tmp_path)
        assert len(h) == 64

    def test_hash_is_lowercase_hex(self, simple_skill):
        h = compute_directory_hash(simple_skill)
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

