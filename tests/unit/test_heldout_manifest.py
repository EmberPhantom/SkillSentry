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


# -- the label rule: a malicious label needs a published confirmation or a concrete payload --------
CONCRETE_KINDS = {
    "bare_ip_fetch",
    "remote_pipe_shell",
    "encoded_exec",
    "reverse_shell",
    "credential_read_and_send",
    "persistence_write",
    "hidden_text_with_instructions",
    "hidden_comment_instruction",
    "do_not_tell_user_with_action",
    "instruction_override",
}
GROUPS = {"wild", "injected", "mixed_unresolved", "fixture", "synthetic"}


def _malicious():
    return [r for r in RAW.values() if r["label"] == "malicious"]


def test_every_malicious_entry_has_a_published_confirmation_or_a_concrete_payload():
    for raw in _malicious():
        conf = set(raw["confirmation"])
        assert conf and conf <= {"published_study", "concrete_payload"}, raw["id"]
        if "concrete_payload" in conf:
            kinds = set(raw["payload_kinds"])
            assert kinds and kinds <= CONCRETE_KINDS, raw["id"]
            assert set(raw["payload_files"]) == kinds, raw["id"]
        # An evidence type of "static" or "fixture" alone is never enough.
        if conf == {"published_study"}:
            assert "SRC002" in " ".join(raw["label_sources"]), raw["id"]


def test_provenance_is_recorded_so_results_can_be_split():
    for raw in _malicious():
        assert raw["provenance_group"] in GROUPS, raw["id"]
    groups = collections.Counter(
        r["provenance_group"] for r in _malicious() if r in MANIFEST["entries"]
    )
    assert groups["wild"] > 0 and groups["injected"] > 0 and groups["mixed_unresolved"] > 0


def test_no_injection_template_is_over_represented():
    templates = collections.Counter(
        r["template"] for r in MANIFEST["entries"] if r["label"] == "malicious" and r["template"]
    )
    assert max(templates.values()) <= 3


def test_every_ambiguous_entry_says_why_and_stays_out_of_malicious_counts():
    ambiguous = [r for r in RAW.values() if r["label"] == "ambiguous"]
    assert ambiguous
    for raw in ambiguous:
        assert len(raw["label_basis"]) > 30, raw["id"]
        assert "confirmation" in raw


def test_read_first_lists_fifteen_real_malicious_entries():
    ids = MANIFEST["read_first"]["ids"]
    assert len(ids) == 15 and len(set(ids)) == 15
    for i in ids:
        assert RAW[i]["label"] == "malicious"


def test_a_skill_moved_to_the_dev_set_is_no_longer_scored_and_is_replaced():
    moved = MANIFEST.get("moved_to_dev", [])
    assert moved, "one skill moved when the parser was fixed"
    scored = {e["id"] for e in MANIFEST["entries"]} | {e["id"] for e in MANIFEST["reserve"]}
    entries = {e["id"] for e in MANIFEST["entries"]}
    for item in moved:
        assert item["id"] not in scored
        assert item["replaced_by"] in entries
        assert item["reason"]
