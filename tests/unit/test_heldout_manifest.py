"""The held-out manifest: well-formed, balanced, and free of skill content."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

MANIFEST = json.loads(fh.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
ENTRIES = list(fh.iter_entries(MANIFEST, "entries"))
RESERVE = list(fh.iter_entries(MANIFEST, "reserve"))
RAW = {r["id"]: r for g in ("entries", "reserve") for r in MANIFEST[g]}

BENIGN_CATEGORIES = {
    "document_office",
    "creative_design",
    "developer_workflow",
    "cloud_devops",
    "data_science",
    "mcp_builders",
    "browser_automation",
    "api_integration",
    "security_education",
    "finance",
    "writing_research",
    "multilingual",
    "large_reference",
    "shell_installer",
}
MALICIOUS_CLASSES = {
    "credential_theft",
    "exfiltration",
    "reverse_shell",
    "persistence",
    "download_and_run",
    "prompt_injection",
    "hidden_text",
    "social_engineering",
    "typosquat_supply_chain",
}


def test_every_entry_is_pinned_and_sources_are_pinned():
    for e in ENTRIES + RESERVE:
        assert len(e.tree_sha256) == 64, e.id
    for name, src in MANIFEST["sources"].items():
        assert len(src["commit"]) == 40, name
        assert src["url"].startswith("https://"), name
        fh.check_source_url(src["url"], allow_file=False)
        assert "licence" in src, name


def test_size_and_balance():
    labels = collections.Counter(e.label for e in ENTRIES)
    assert labels["benign"] >= 180 and labels["malicious"] >= 90
    assert len(RESERVE) >= 25
    assert not {e.id for e in ENTRIES} & {e.id for e in RESERVE}
    assert not {(e.source, e.path) for e in ENTRIES} & {(e.source, e.path) for e in RESERVE}


def test_benign_categories_are_all_covered():
    cats = collections.Counter(RAW[e.id]["category"] for e in ENTRIES if e.label == "benign")
    assert set(cats) == BENIGN_CATEGORIES
    assert min(cats.values()) >= 8


def test_malicious_classes_are_covered_and_labels_are_backed():
    classes = collections.Counter(
        RAW[e.id]["attack_class"] for e in ENTRIES if e.label == "malicious"
    )
    assert set(classes) >= MALICIOUS_CLASSES
    families = [RAW[e.id]["structural_family"] for e in ENTRIES + RESERVE if e.label != "benign"]
    assert len(families) == len(set(families)), "two skills share a structural family"
    for e in ENTRIES + RESERVE:
        raw = RAW[e.id]
        assert raw["label_sources"] and raw["label_basis"], e.id
        if e.label == "malicious":
            assert raw["provenance"] and raw["evidence_type"], e.id


def test_one_skill_per_repo_per_category_and_few_per_repo():
    seen = collections.Counter(
        (e.source, RAW[e.id]["category"]) for e in ENTRIES + RESERVE if e.label == "benign"
    )
    assert max(seen.values()) == 1
    per_repo = collections.Counter(e.source for e in ENTRIES + RESERVE if e.label == "benign")
    assert max(per_repo.values()) <= 3


def test_the_manifest_holds_no_skill_content():
    text = fh.DEFAULT_MANIFEST.read_text(encoding="utf-8")
    assert "​" not in text
    assert all(len(json.dumps(r)) < 3000 for r in RAW.values())
    assert not list((ROOT / "tests" / "heldout").glob("**/SKILL.md"))
