"""Docs hygiene (ported from feature/developer-2, adjusted for main's measured docs)."""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]

if not (ROOT / ".git").exists():
    # These gates read the git-tracked files of a source checkout; an installed copy has none.
    import pytest

    pytest.skip("docs hygiene gates need a source checkout", allow_module_level=True)
DRIVE = re.compile(r"\b[A-Za-z]:\\")
FILE_URL = re.compile(r"file:///")
PASS_COUNT = re.compile(r"\b\d+\s+passed\b")
# Adjust to the root markdown files that exist on origin/main.
ROOT_MD_ALLOWED = {"README.md", "CONTRIBUTING.md", "SECURITY.md"}
# Measured counts are recorded on purpose in these two places.
PASS_COUNT_ALLOWED = ("docs/evidence/", "docs/15-v1-test-results.md")


def tracked(*patterns):
    out = subprocess.run(
        ["git", "ls-files", *patterns], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    return [ROOT / p for p in out if p]


def test_no_machine_specific_paths():
    bad = []
    this_file = ROOT / "tests" / "unit" / "test_docs_hygiene.py"
    for p in tracked("*.md", "*.toml", "*.py", "*.json"):
        if p == this_file:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if DRIVE.search(text) or FILE_URL.search(text):
            bad.append(str(p.relative_to(ROOT)))
    assert not bad, bad


def test_no_stray_root_markdown():
    root_md = {p.name for p in tracked("*.md") if p.parent == ROOT}
    assert root_md <= ROOT_MD_ALLOWED, sorted(root_md - ROOT_MD_ALLOWED)


def test_no_handtyped_pass_counts_outside_evidence():
    bad = []
    for p in tracked("*.md"):
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(PASS_COUNT_ALLOWED):
            continue
        if PASS_COUNT.search(p.read_text(encoding="utf-8", errors="replace")):
            bad.append(rel)
    assert not bad, bad


def test_dashboard_claims_match_tracked_files():
    claims = [
        p
        for p in tracked("*.md")
        if not p.relative_to(ROOT).as_posix().startswith("docs/evidence/")
        and "ui/dist" in p.read_text(encoding="utf-8", errors="replace")
    ]
    if claims:
        assert tracked("ui/dist/index.html"), [str(p.relative_to(ROOT)) for p in claims]
