"""The typosquat name list is packaged data and must stay conservative.

Ported from feature/developer-2 (chauhanaman41): the list is a union of the v1
core names and their curation, loaded via importlib.resources so that a wheel
install works.  Benign names must never match.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest
from skill_sentry_cli.core.parser.typosquat import KNOWN_SKILL_NAMES, check_typosquat

ROOT = Path(__file__).resolve().parents[2]
CORE_NAMES = {
    "git-helper",
    "git-translate",
    "pdf-summarizer",
    "image-resizer",
    "weather-fetch",
    "slack-notifier",
    "cloud-sync",
    "notion-sync",
}


def test_known_names_load_from_packaged_data() -> None:
    raw = (
        resources.files("skill_sentry_cli.data").joinpath("known_skills_v1.json").read_text("utf-8")
    )
    entries = json.loads(raw)["entries"]

    assert len(KNOWN_SKILL_NAMES) == len({entry["name"] for entry in entries})
    assert len(KNOWN_SKILL_NAMES) >= 60
    assert set(KNOWN_SKILL_NAMES) >= CORE_NAMES


def test_exact_known_name_is_not_flagged() -> None:
    assert check_typosquat("git-helper") is None


def test_cyrillic_lookalike_of_a_known_name_is_flagged() -> None:
    # U+0435 (Cyrillic small ie) in place of Latin "e" in "git-helper".
    match = check_typosquat("git-hеlper")

    assert match is not None
    assert match.candidate == "git-helper"


def test_case_variant_of_a_known_name_is_flagged() -> None:
    match = check_typosquat("Git-Helper")

    assert match is not None
    assert match.candidate == "git-helper"


@pytest.mark.parametrize(
    "fixture", sorted(p.name for p in (ROOT / "fixtures" / "benign").iterdir())
)
def test_repo_benign_fixture_names_are_not_flagged(fixture: str) -> None:
    assert check_typosquat(fixture) is None, fixture
