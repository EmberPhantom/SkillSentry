"""Packaging and resource loading tests.

Validates Section 8.9:
- defusedxml is installed and importable
- Data resources (known_skills_v1.json, credential_rules.toml) load via importlib.resources
- Scanning works when invoked from an arbitrary working directory outside the repo
"""

import importlib.resources as pkg_res
from pathlib import Path
import subprocess
import sys
import tempfile
import pytest


def test_defusedxml_imported():
    import defusedxml  # noqa: F401
    assert defusedxml is not None


def test_resources_load_via_importlib():
    known_skills = pkg_res.files("skillsentry.data") / "known_skills_v1.json"
    assert known_skills.is_file()
    assert len(known_skills.read_bytes()) > 0

    rules = pkg_res.files("skillsentry.rules") / "credential_rules.toml"
    assert rules.is_file()
    assert len(rules.read_bytes()) > 0


def test_scan_from_outside_working_directory():
    root = Path(__file__).resolve().parents[2]
    fixture = root / "fixtures" / "benign" / "weather-fetch"

    with tempfile.TemporaryDirectory() as td:
        proc = subprocess.run(
            [sys.executable, "-m", "skillsentry", "scan", str(fixture), "--no-cache", "--backend", "demo"],
            cwd=td,
            capture_output=True,
            text=True,
        )
        assert "SkillSentry" in proc.stdout
        assert "weather-fetch" in proc.stdout

