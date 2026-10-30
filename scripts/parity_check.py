#!/usr/bin/env python
"""Parity check: compare root engine static verdicts against developer-2 expected verdicts.

Validates Decision D3 before archiving developer-2 prototype:
- Malicious must be MALICIOUS or SUSPICIOUS (stricter allowed, weaker is a failure)
- Benign must be SAFE
Output table is written to docs/evidence/parity-<UTC date>.md.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine
from tests.support.mock_gemma import MockGemma

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "evidence"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")

    dev2_expected_path = ROOT / "developer-2" / "tests" / "expected_verdicts.json"
    if not dev2_expected_path.exists():
        dev2_expected_path = ROOT / "developer-2" / "expected_verdicts.json"

    expected_data = {}
    if dev2_expected_path.exists():
        with open(dev2_expected_path, encoding="utf-8") as f:
            expected_data = json.load(f)

    skills = expected_data.get("skills", expected_data)
    if not skills:
        print("No dev2 expected verdicts found, skipping parity check")
        return 0

    store = SQLiteStore(":memory:")
    engine = ScanEngine(store=store, model=MockGemma())

    rows = []
    failed = False

    try:
        for skill_rel, spec in sorted(skills.items()):
            expected_tier = spec.get("verdict", "").upper()
            fixture_path = ROOT / "developer-2" / skill_rel
            if not fixture_path.exists():
                fixture_path = ROOT / skill_rel
            if not fixture_path.exists():
                continue

            outcome = engine.scan(
                fixture_path,
                options=ScanOptions(sandbox=False, backend="demo", no_cache=True),
            )
            actual_tier = outcome.verdict.verdict.value.upper()
            actual_risk = outcome.verdict.risk_score

            # Parity rules:
            # - If expected is MALICIOUS, actual must be MALICIOUS (or SUSPICIOUS if acceptable)
            # - If expected is SUSPICIOUS, actual can be SUSPICIOUS or MALICIOUS (stricter allowed)
            # - If expected is SAFE, actual must be SAFE
            ok = True
            if expected_tier == "SAFE":
                ok = (actual_tier == "SAFE")
            elif expected_tier == "SUSPICIOUS":
                ok = (actual_tier in ("SUSPICIOUS", "MALICIOUS"))
            elif expected_tier == "MALICIOUS":
                ok = (actual_tier in ("MALICIOUS", "SUSPICIOUS"))

            if not ok:
                failed = True

            rows.append((skill_rel, expected_tier, actual_tier, actual_risk, "PASS" if ok else "FAIL"))
    finally:
        engine.close()
        store.close()

    lines = [
        f"# Corpus Parity Verification Run ({stamp})",
        "",
        "Validates that root ScanEngine in static mode satisfies developer-2 expected verdicts.",
        "Rule: Malicious/Suspicious fixtures must not demote to SAFE; Benign fixtures must be SAFE.",
        "",
        "| Fixture | Expected Tier | Root Actual Tier | Risk Score | Status |",
        "|---|---|---|---|---|",
    ]
    lines += [f"| `{fix}` | {exp} | {act} | {score} | {st} |" for fix, exp, act, score, st in rows]

    report_path = OUT / f"parity-{stamp}.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {report_path.relative_to(ROOT)}: {'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
