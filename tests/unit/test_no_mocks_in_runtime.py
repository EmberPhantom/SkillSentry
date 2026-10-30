"""CI Guard: Enforce zero mocks or fixture cheat names in production runtime code."""

import pathlib
import re

BANNED_MOCKS = re.compile(r"\b(MockGemma|MockMode|mock_gemma|MockDecisionClient|FakeModel)\b")

# Developer 1's canned demo/test doubles on origin/main:
DEV1_DEMO_FILES = {
    pathlib.Path("skillsentry/core/models/mock.py"),
    pathlib.Path("skillsentry/core/decisions/mock.py"),
    pathlib.Path("skillsentry/core/decisions/__init__.py"),
}

FIXTURE_NAMES = [
    "cloud-sync-pro",
    "slack-notif-mal",
    "invoice-helper",
    "g1t-translate",
    "dns-tunneler",
    "credential-multi",
]


def test_runtime_has_no_mocks():
    """Asserts that no mock classes or keywords appear in Developer 2 production analyzers."""
    dev2_dirs = [
        pathlib.Path("skillsentry/core/semantic"),
        pathlib.Path("skillsentry/core/anchors"),
        pathlib.Path("skillsentry/core/parser"),
        pathlib.Path("skillsentry/core/vision"),
        pathlib.Path("skillsentry/rules"),
    ]
    offenders = []
    for d in dev2_dirs:
        for p in d.rglob("*.py"):
            text = p.read_text(encoding="utf-8")
            if BANNED_MOCKS.search(text):
                offenders.append(str(p))
    assert not offenders, f"Banned mock symbols found in Dev2 analyzer code: {offenders}"


def test_runtime_has_no_fixture_cheats():
    """Asserts that no fixture names are hardcoded in runtime code to force outcomes."""
    offenders = []
    # Core analyzers and rules must never mention fixtures
    core_dirs = [
        pathlib.Path("skillsentry/core/semantic"),
        pathlib.Path("skillsentry/core/anchors"),
        pathlib.Path("skillsentry/core/parser"),
        pathlib.Path("skillsentry/core/vision"),
        pathlib.Path("skillsentry/rules"),
    ]
    for d in core_dirs:
        for p in d.rglob("*.py"):
            text = p.read_text(encoding="utf-8")
            for fname in FIXTURE_NAMES:
                if fname in text:
                    offenders.append((str(p), fname))
    assert not offenders, f"Fixture name cheats found in runtime logic: {offenders}"
