#!/usr/bin/env python3
"""Score the static checks on the tuning set of real skills (``tests/devreal/manifest.json``).

This is the set the checks MAY be tuned on. It is disjoint from the held-out set
(``tests/heldout/manifest.json``), which they may not.

    python scripts/fetch_heldout.py --manifest tests/devreal/manifest.json \\
        --cache ~/.cache/skillsentry-devreal fetch
    python scripts/score_devreal.py --json after.json
    python scripts/score_devreal.py --json after.json --compare before.json

Each skill is scanned with the deterministic checks and a model that reports nothing wrong, with
the sandbox off, so the numbers are for the checks alone. A skill the scan could not finish
(UNSCANNED, INVALID SKILL, or an error) is not counted as a false alarm or a hit; the strict rate
counts it. The report gives the false-alarm rate on benign skills and the recall on malicious
skills, each with a Wilson 95% interval, and the false alarms by anchor type. Nothing here runs a
skill: files are read as text.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "tests" / "devreal" / "manifest.json"
DEFAULT_CACHE = Path.home() / ".cache" / "skillsentry-devreal"
POSITIVE = {"SUSPICIOUS", "MALICIOUS"}
NOT_FINISHED = {"UNSCANNED", "INVALID SKILL", "ERROR"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round((c - a) / d, 3), round((c + a) / d, 3)


def scan_all(manifest: Path, cache: Path, *, with_code: bool) -> dict[str, Any]:
    sys.path.insert(0, str(ROOT))
    from skill_sentry_cli.core.cache import SQLiteStore
    from skill_sentry_cli.core.config import SkillsEntryConfig
    from skill_sentry_cli.core.contracts import ScanOptions
    from skill_sentry_cli.core.engine import ScanEngine
    from skill_sentry_cli.core.models.mock import MockGemma

    data = json.loads(manifest.read_text(encoding="utf-8"))
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteStore(Path(tmp) / "scores.sqlite")
        engine = ScanEngine(SkillsEntryConfig(), store=store, model=MockGemma(profile="benign"))
        try:
            for entry in data["entries"]:
                folder = cache / "skills" / entry["id"]
                if not folder.is_dir():
                    folder = cache / entry["id"]
                row: dict[str, Any] = {"label": entry["label"], "category": entry["category"]}
                try:
                    outcome = engine.scan(folder, options=ScanOptions(sandbox=False, no_cache=True))
                except Exception as exc:  # a scan that fails is a result, not a crash
                    row.update(status="ERROR", error=type(exc).__name__, findings=[])
                    results[entry["id"]] = row
                    continue
                verdict = outcome.verdict
                findings = []
                for f in verdict.findings:
                    if f.severity.rank < 1:
                        continue
                    item = {
                        "type": f.finding_type,
                        "severity": f.severity.value,
                        "file": f.evidence.file,
                        "line": f.evidence.line,
                    }
                    if with_code:
                        item["code"] = (f.evidence.code or "")[:200]
                    findings.append(item)
                row.update(status=verdict.status, findings=findings)
                results[entry["id"]] = row
        finally:
            engine.close()
            store.close()
    return results


def summarise(results: dict[str, Any]) -> dict[str, Any]:
    benign = {k: v for k, v in results.items() if v["label"] == "benign"}
    malicious = {k: v for k, v in results.items() if v["label"] == "malicious"}

    def split(group: dict[str, Any]) -> tuple[list[str], list[str]]:
        done = [k for k, v in group.items() if v["status"] not in NOT_FINISHED]
        return done, [k for k in group if k not in done]

    b_done, b_open = split(benign)
    m_done, m_open = split(malicious)
    false_alarms = [k for k in b_done if benign[k]["status"] in POSITIVE]
    hits = [k for k in m_done if malicious[k]["status"] in POSITIVE]
    by_type: collections.Counter[str] = collections.Counter()
    for k in false_alarms:
        kinds = {
            f["type"]
            for f in benign[k]["findings"]
            if f["severity"] in {"medium", "high", "critical"}
        }
        by_type.update(kinds)
    return {
        "benign": {
            "total": len(benign),
            "scanned": len(b_done),
            "not_finished": len(b_open),
            "false_alarms": len(false_alarms),
            "false_alarm_rate": round(len(false_alarms) / len(b_done), 3) if b_done else None,
            "interval": wilson(len(false_alarms), len(b_done)),
            "strict_false_alarm_rate": (
                round((len(false_alarms) + len(b_open)) / len(benign), 3) if benign else None
            ),
            "false_alarm_ids": sorted(false_alarms),
            "false_alarms_by_anchor_type": dict(by_type.most_common()),
        },
        "malicious": {
            "total": len(malicious),
            "scanned": len(m_done),
            "not_finished": len(m_open),
            "flagged": len(hits),
            "recall": round(len(hits) / len(m_done), 3) if m_done else None,
            "interval": wilson(len(hits), len(m_done)),
            "missed_ids": sorted(k for k in m_done if k not in hits),
        },
    }


def show(label: str, s: dict[str, Any]) -> None:
    b, m = s["benign"], s["malicious"]
    print(f"== {label}")
    print(
        f"benign {b['total']}: scanned {b['scanned']}, not finished {b['not_finished']}, "
        f"false alarms {b['false_alarms']} = {b['false_alarm_rate']} {b['interval']}, "
        f"strict {b['strict_false_alarm_rate']}"
    )
    print(f"  by anchor type: {b['false_alarms_by_anchor_type']}")
    print(
        f"malicious {m['total']}: scanned {m['scanned']}, not finished {m['not_finished']}, "
        f"flagged {m['flagged']} = recall {m['recall']} {m['interval']}"
    )
    print(f"  missed: {m['missed_ids']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--json", type=Path, help="write the per-skill results here")
    ap.add_argument("--compare", type=Path, help="per-skill results from an earlier run")
    ap.add_argument("--with-code", action="store_true", help="keep the matched line in the JSON")
    args = ap.parse_args(argv)
    if ROOT in args.cache.resolve().parents or args.cache.resolve() == ROOT:
        print("error: the cache must be outside the repository", file=sys.stderr)
        return 2
    results = scan_all(args.manifest, args.cache, with_code=args.with_code)
    if args.json:
        args.json.write_text(json.dumps(results, indent=1), encoding="utf-8")
    if args.compare:
        show("before", summarise(json.loads(args.compare.read_text(encoding="utf-8"))))
    show("after" if args.compare else "result", summarise(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
