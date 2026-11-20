"""The sealed second held-out set: well-formed, disjoint from the other sets, sealed, no content."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

PATH = ROOT / "tests" / "heldout2" / "manifest.json"
SET = json.loads(PATH.read_text(encoding="utf-8"))
OTHERS = {
    name: json.loads((ROOT / "tests" / name / "manifest.json").read_text(encoding="utf-8"))
    for name in ("heldout", "devreal")
}
ALL = [e for g in ("entries", "reserve") for e in SET[g]]


def _repos(manifest):
    return {v["url"].lower() for k, v in manifest["sources"].items() if k != "maliciousskillbench"}


def test_it_loads_with_the_same_loader_and_every_entry_is_pinned():
    manifest = fh.load_manifest(PATH)
    for which in ("entries", "reserve"):
        for entry in fh.iter_entries(manifest, which):
            assert len(entry.tree_sha256) == 64, entry.id


def test_it_is_disjoint_from_the_held_out_and_tuning_sets_by_id_repository_hash_and_family():
    mine_trees = {e["tree_sha256"] for e in ALL}
    mine_families = {e["structural_family"] for e in ALL if e.get("structural_family")}
    for name, other in OTHERS.items():
        entries = [e for g in ("entries", "reserve") for e in other[g]]
        assert not ({e["id"] for e in ALL} & {e["id"] for e in entries}), name
        assert not (mine_trees & {e["tree_sha256"] for e in entries}), name
        assert not (_repos(SET) & _repos(other)), name
        theirs = {e["structural_family"] for e in entries if e.get("structural_family")}
        assert not (mine_families & theirs), name


def test_each_repository_gives_at_most_six_benign_skills():
    count = collections.Counter(e["source"] for e in ALL if e["label"] == "benign")
    assert max(count.values()) <= 6


def test_the_labels_and_their_quality_are_consistent():
    for e in ALL:
        if e["label"] == "malicious":
            assert e["label_quality"] == "payload" and "concrete_payload" in e["confirmation"]
            assert e["payload_kinds"], e["id"]
        elif e["label"] == "ambiguous":
            assert e["label_quality"] == "ambiguous"
        else:
            assert e["label"] == "benign" and e["label_quality"] == "reputable_repo"


def test_the_set_has_the_size_and_the_kinds_it_was_built_for():
    entries = SET["entries"]
    labels = collections.Counter(e["label"] for e in entries)
    assert labels["benign"] >= 225 and labels["malicious"] >= 55 and labels["ambiguous"] >= 10
    assert len(SET["reserve"]) >= 30
    categories = {e["category"] for e in entries if e["label"] == "benign"}
    assert len(categories) >= 14
    assert {"large_100plus", "shell_installer", "devops_infra"} <= categories
    assert {"lang_es", "lang_zh", "lang_ja", "lang_de", "lang_fr"} <= categories
    classes = collections.Counter(e["attack_class"] for e in entries if e["label"] == "malicious")
    for needed in ("typosquat_supply_chain", "hidden_text", "social_engineering"):
        assert classes[needed] >= 5, needed


def test_it_is_sealed_with_the_checks_it_was_sealed_against():
    seal = SET["seal"]
    assert len(seal["checks_git_sha"]) == 40
    assert set(seal["checks_trees"]) == {
        "skill_sentry_cli/core",
        "skill_sentry_cli/rules",
        "skill_sentry_cli/data",
    }
    assert all(len(v) == 40 for v in seal["checks_trees"].values())
    assert "final measurement" in seal["rule"] and "fresh set" in seal["rule"]


def test_no_skill_content_is_stored():
    text = PATH.read_text(encoding="utf-8")
    for marker in ("```", "<<<UNTRUSTED", "name: ", "---\n"):
        assert marker not in text
