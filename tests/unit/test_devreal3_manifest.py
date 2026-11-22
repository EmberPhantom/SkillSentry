"""The second tuning set: the third held-out set after it was measured. Well-formed, no content."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

PATH = ROOT / "tests" / "devreal3" / "manifest.json"
SET = json.loads(PATH.read_text(encoding="utf-8"))
HELD3 = json.loads((ROOT / "tests" / "heldout3" / "manifest.json").read_text(encoding="utf-8"))
ALL = [e for g in ("entries", "reserve") for e in SET[g]]


def test_it_holds_the_third_set_and_every_entry_is_pinned():
    manifest = fh.load_manifest(PATH)
    for which in ("entries", "reserve"):
        for entry in fh.iter_entries(manifest, which):
            assert len(entry.tree_sha256) == 64, entry.id
    held = {e["id"]: e["tree_sha256"] for g in ("entries", "reserve") for e in HELD3[g]}
    assert {e["id"]: e["tree_sha256"] for e in ALL} == held


def test_the_sealed_record_says_where_the_skills_went():
    assert HELD3["moved_to_tuning"]["to"] == "tests/devreal3"
    assert SET["moved_from"]["sealed_checks_git_sha"] == HELD3["seal"]["checks_git_sha"]


def test_it_says_checks_may_be_tuned_on_it_and_stores_no_content():
    assert "MAY be tuned" in SET["description"]
    text = PATH.read_text(encoding="utf-8")
    for marker in ("```", "<<<UNTRUSTED", "name: ", "---\n"):
        assert marker not in text
