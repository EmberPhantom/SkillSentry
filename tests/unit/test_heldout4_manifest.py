"""The sealed fourth held-out set: well-formed, disjoint from the others, sealed, no content."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

PATH = ROOT / "tests" / "heldout4" / "manifest.json"
SET = json.loads(PATH.read_text(encoding="utf-8"))
OTHERS = {
    name: json.loads((ROOT / "tests" / name / "manifest.json").read_text(encoding="utf-8"))
    for name in ("heldout", "devreal", "heldout2", "heldout3", "devreal3")
}
ALL = [e for g in ("entries", "reserve") for e in SET[g]]
BENIGN = [e for e in ALL if e["label"] == "benign"]


def _repos(manifest):
    return {
        v["url"].lower()
        for k, v in manifest["sources"].items()
        if k not in {"maliciousskillbench", "toxicskills-goof"}
    }


def test_it_loads_with_the_same_loader_and_every_entry_is_pinned():
    manifest = fh.load_manifest(PATH)
    for which in ("entries", "reserve"):
        for entry in fh.iter_entries(manifest, which):
            assert len(entry.tree_sha256) == 64, entry.id


def test_it_is_disjoint_from_every_other_set_by_id_repository_and_hash():
    mine_trees = {e["tree_sha256"] for e in ALL}
    for name, other in OTHERS.items():
        entries = [e for g in ("entries", "reserve") for e in other[g]]
        assert not ({e["id"] for e in ALL} & {e["id"] for e in entries}), name
        assert not (mine_trees & {e["tree_sha256"] for e in entries}), name
        assert not (_repos(SET) & _repos(other)), name


def test_the_benign_side_is_disjoint_by_dataset_family_and_the_malicious_overlap_is_stated():
    # Family overlap is allowed on the malicious side only, and the document says so.
    for name, other in OTHERS.items():
        theirs = {
            e["structural_family"]
            for g in ("entries", "reserve")
            for e in other[g]
            if e.get("structural_family")
        }
        mine = {e["structural_family"] for e in BENIGN if e.get("structural_family")}
        assert not (mine & theirs), name
    doc = (ROOT / "docs" / "operations" / "heldout4-set.md").read_text(encoding="utf-8")
    assert "dataset family" in doc and "malicious side" in doc


def test_each_repository_gives_at_most_four_benign_skills():
    count = collections.Counter(e["source"] for e in BENIGN)
    assert max(count.values()) <= 4


def test_the_labels_and_their_quality_are_consistent():
    for e in ALL:
        if e["label"] == "malicious":
            assert e["label_quality"] in {"payload", "confirmed"}, e["id"]
            if e["label_quality"] == "payload":
                assert "concrete_payload" in e["confirmation"] and e["payload_kinds"], e["id"]
            else:
                assert e["confirmation"], e["id"]
        elif e["label"] == "ambiguous":
            assert e["label_quality"] == "ambiguous"
        else:
            assert e["label"] == "benign" and e["label_quality"] == "reputable_repo"


def test_the_set_has_the_size_and_the_kinds_it_was_built_for():
    entries = SET["entries"]
    labels = collections.Counter(e["label"] for e in entries)
    assert labels["benign"] >= 240 and labels["malicious"] >= 80 and labels["ambiguous"] >= 10
    assert len(SET["reserve"]) >= 40
    categories = collections.Counter(e["category"] for e in entries if e["label"] == "benign")
    assert categories["large_100plus"] >= 15
    for needed in ("lang_es", "lang_zh", "lang_ja", "lang_de", "lang_fr", "prose_only"):
        assert categories[needed] >= 3, needed
    # The population is meant to be mostly ordinary skills: the hard shapes are about 30%.
    hard = {
        "large_100plus",
        "notebook",
        "web_css_html_svg",
        "office_pdf_archive",
        "shell_installer",
    }
    share = sum(n for c, n in categories.items() if c in hard) / sum(categories.values())
    assert 0.15 <= share <= 0.40, share
    classes = collections.Counter(e["attack_class"] for e in entries if e["label"] == "malicious")
    for needed in ("typosquat_supply_chain", "hidden_text", "social_engineering"):
        assert classes[needed] >= 6, needed
    assert classes["typosquat_supply_chain"] >= 10


def test_the_new_reader_forms_and_the_model_only_skills_are_there():
    entries = [e for e in SET["entries"] if e["label"] == "malicious"]
    forms = [
        e
        for e in entries
        if e.get("remote_resource_hits") or any(v for v in (e.get("forms") or {}).values())
    ]
    assert len(forms) >= 8
    model_only = [
        e
        for e in entries
        if not e.get("payload_kinds")
        and e["label_quality"] == "confirmed"
        and e["attack_class"] == "prompt_injection"
    ]
    assert len(model_only) >= 8


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
    assert seal["sealed_on"]


def test_no_skill_content_is_stored():
    text = PATH.read_text(encoding="utf-8")
    for marker in ("```", "<<<UNTRUSTED", "name: ", "---\n"):
        assert marker not in text
