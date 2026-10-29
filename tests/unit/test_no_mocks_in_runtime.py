"""CI Guard: Enforce zero mocks or fixture cheat names in production runtime code."""

import pathlib
import re

BANNED_MOCKS = re.compile(r"\b(MockGemma|MockMode|mock_gemma|MockDecisionClient|FakeModel)\b")

FIXTURE_NAMES = [
    "cloud-sync-pro",
    "slack-notif-mal",
    "invoice-helper",
    "g1t-translate",
    "dns-tunneler",
    "credential-multi",
]


def test_runtime_has_no_mocks():
    """Asserts that no mock classes or keywords appear anywhere in skillsentry/."""
    offenders = []
    for p in pathlib.Path("skillsentry").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if BANNED_MOCKS.search(text):
            offenders.append(str(p))
    assert not offenders, f"Banned mock symbols found in runtime code: {offenders}"


def test_runtime_has_no_fixture_cheats():
    """Asserts that no fixture names are hardcoded in runtime code to force outcomes."""
    offenders = []
    # demo_data.py is the canned store for demo server; core engine and rules must never mention fixtures
    core_dirs = [
        pathlib.Path("skillsentry/core"),
        pathlib.Path("skillsentry/rules"),
    ]
    for d in core_dirs:
        for p in d.rglob("*.py"):
            text = p.read_text(encoding="utf-8")
            for fname in FIXTURE_NAMES:
                if fname in text:
                    offenders.append((str(p), fname))
    assert not offenders, f"Fixture name cheats found in runtime logic: {offenders}"

