"""
Typosquat Dictionary Curation Utility.

CLI tool for managing the versioned known-skills dictionary used by
the typosquat detection engine.

Usage:
    python -m skillsentry_dev2.core.parser.typosquat_curator list
    python -m skillsentry_dev2.core.parser.typosquat_curator add <name> <category>
    python -m skillsentry_dev2.core.parser.typosquat_curator remove <name>
    python -m skillsentry_dev2.core.parser.typosquat_curator add-pair <name1> <name2>
    python -m skillsentry_dev2.core.parser.typosquat_curator dispute <name> <reason>
    python -m skillsentry_dev2.core.parser.typosquat_curator stats

CL-D2-8: Typosquat dictionary curation pipeline.
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path


DICTIONARY_PATH = Path(__file__).resolve().parents[4] / "data" / "known_skills_v1.json"


def _load() -> dict:
    """Load the dictionary file."""
    with open(DICTIONARY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    """Save the dictionary file with consistent formatting."""
    with open(DICTIONARY_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def cmd_list(data: dict) -> None:
    """List all known skills grouped by category."""
    entries = data.get("entries", [])
    by_cat: dict[str, list[str]] = {}
    for e in entries:
        by_cat.setdefault(e["category"], []).append(e["name"])

    for cat in sorted(by_cat):
        print(f"\n[{cat}] ({len(by_cat[cat])} skills)")
        for name in sorted(by_cat[cat]):
            print(f"  - {name}")
    print(f"\nTotal: {len(entries)} skills in {len(by_cat)} categories")


def cmd_add(data: dict, name: str, category: str) -> None:
    """Add a new skill name to the dictionary."""
    existing = {e["name"] for e in data.get("entries", [])}
    if name in existing:
        print(f"Already exists: {name}")
        return

    data["entries"].append({"name": name, "category": category})
    data["entries"].sort(key=lambda e: (e["category"], e["name"]))
    data["dispute_log"].append({
        "date": str(date.today()),
        "action": "add",
        "notes": f"Added '{name}' to category '{category}'.",
    })
    _save(data)
    print(f"Added: {name} ({category})")


def cmd_remove(data: dict, name: str) -> None:
    """Remove a skill name from the dictionary."""
    original_len = len(data["entries"])
    data["entries"] = [e for e in data["entries"] if e["name"] != name]
    if len(data["entries"]) == original_len:
        print(f"Not found: {name}")
        return

    data["dispute_log"].append({
        "date": str(date.today()),
        "action": "remove",
        "notes": f"Removed '{name}' from dictionary.",
    })
    _save(data)
    print(f"Removed: {name}")


def cmd_add_pair(data: dict, name1: str, name2: str) -> None:
    """Add a legitimate pair (non-typosquat pairing)."""
    pair = sorted([name1, name2])
    existing = [sorted(p) for p in data.get("legitimate_pairs", [])]
    if pair in existing:
        print(f"Pair already exists: {pair}")
        return

    data["legitimate_pairs"].append(pair)
    data["dispute_log"].append({
        "date": str(date.today()),
        "action": "add_pair",
        "notes": f"Added legitimate pair: {pair[0]} <-> {pair[1]}.",
    })
    _save(data)
    print(f"Added legitimate pair: {pair[0]} <-> {pair[1]}")


def cmd_dispute(data: dict, name: str, reason: str) -> None:
    """Log a false-positive dispute for a skill name."""
    data["dispute_log"].append({
        "date": str(date.today()),
        "action": "dispute",
        "skill": name,
        "notes": f"False-positive dispute: {reason}",
    })
    _save(data)
    print(f"Dispute logged for: {name}")


def cmd_stats(data: dict) -> None:
    """Print dictionary statistics."""
    entries = data.get("entries", [])
    categories = set(e["category"] for e in entries)
    pairs = data.get("legitimate_pairs", [])
    disputes = [d for d in data.get("dispute_log", []) if d.get("action") == "dispute"]
    print(f"Dictionary version: {data.get('version', '?')}")
    print(f"Total skills:       {len(entries)}")
    print(f"Categories:         {len(categories)}")
    print(f"Legitimate pairs:   {len(pairs)}")
    print(f"Dispute entries:    {len(disputes)}")
    print(f"Last updated:       {data.get('updated', '?')}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    if not DICTIONARY_PATH.exists():
        print(f"Dictionary not found: {DICTIONARY_PATH}", file=sys.stderr)
        return 1

    data = _load()
    cmd = sys.argv[1]

    if cmd == "list":
        cmd_list(data)
    elif cmd == "add" and len(sys.argv) >= 4:
        cmd_add(data, sys.argv[2], sys.argv[3])
    elif cmd == "remove" and len(sys.argv) >= 3:
        cmd_remove(data, sys.argv[2])
    elif cmd == "add-pair" and len(sys.argv) >= 4:
        cmd_add_pair(data, sys.argv[2], sys.argv[3])
    elif cmd == "dispute" and len(sys.argv) >= 4:
        cmd_dispute(data, sys.argv[2], " ".join(sys.argv[3:]))
    elif cmd == "stats":
        cmd_stats(data)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

