"""The tuning set of real skills: well-formed, disjoint from the held-out set, no skill content."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

DEVREAL_PATH = ROOT / "tests" / "devreal" / "manifest.json"
DEVREAL = json.loads(DEVREAL_PATH.read_text(encoding="utf-8"))
HELDOUT = json.loads(fh.DEFAULT_MANIFEST.read_text(encoding="utf-8"))


def _ids(manifest):
    return {e["id"] for g in ("entries", "reserve") for e in manifest[g]}


def test_it_loads_with_the_same_loader_and_every_entry_is_pinned():
    manifest = fh.load_manifest(DEVREAL_PATH)
    entries = list(fh.iter_entries(manifest, "entries"))
    assert len(entries) >= 150
    for entry in entries:
        assert len(entry.tree_sha256) == 64, entry.id


def test_it_is_disjoint_from_the_held_out_set_by_skill_repository_and_hash():
    held_trees = {e["tree_sha256"] for g in ("entries", "reserve") for e in HELDOUT[g]}
    assert not (_ids(DEVREAL) & _ids(HELDOUT))
    assert not ({e["tree_sha256"] for e in DEVREAL["entries"]} & held_trees)
    held_repos = {
        v["url"].lower() for k, v in HELDOUT["sources"].items() if k != "maliciousskillbench"
    }
    mine = {v["url"].lower() for k, v in DEVREAL["sources"].items() if k != "maliciousskillbench"}
    assert not (mine & held_repos)
    held_families = {
        e.get("structural_family")
        for g in ("entries", "reserve")
        for e in HELDOUT[g]
        if e.get("structural_family")
    }
    assert not ({e.get("structural_family") for e in DEVREAL["entries"]} & held_families)


def test_it_has_both_labels_and_the_malicious_ones_carry_a_concrete_payload():
    labels = collections.Counter(e["label"] for e in DEVREAL["entries"])
    assert labels["benign"] >= 140 and labels["malicious"] >= 35
    for e in DEVREAL["entries"]:
        if e["label"] == "malicious":
            assert "concrete_payload" in e["confirmation"], e["id"]
            assert e["payload_kinds"], e["id"]
            assert e["label_quality"] == "payload"


def test_benign_skills_cover_the_categories_and_come_from_many_repositories():
    benign = [e for e in DEVREAL["entries"] if e["label"] == "benign"]
    categories = collections.Counter(e["category"] for e in benign)
    assert len(categories) >= 14 and min(categories.values()) >= 6
    assert len({e["source"] for e in benign}) >= 60


def test_no_skill_content_is_stored():
    text = DEVREAL_PATH.read_text(encoding="utf-8")
    for marker in ("```", "<<<UNTRUSTED", "name: ", "---\n"):
        assert marker not in text
