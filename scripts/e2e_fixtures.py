"""End-to-end check of the core fixtures through the configured backends.

Uses the configured model (legacy path by default) and the Docker sandbox, so it
needs Ollama with the model pulled and a running Docker engine.  Exit status is
0 only when every fixture meets its expectation.  Results print as JSON lines.

    python scripts/e2e_fixtures.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import load_config
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine

ROOT = Path(__file__).resolve().parents[1]

# skill name, path, expected verdict, minimum risk score
EXPECTATIONS = [
    ("cloud-sync-pro", ROOT / "fixtures" / "malicious" / "cloud-sync-pro", "MALICIOUS", 91),
    ("slack-notif-mal", ROOT / "fixtures" / "malicious" / "slack-notif-mal", "MALICIOUS", 100),
    ("git-helper", ROOT / "fixtures" / "benign" / "git-helper", "SAFE", 0),
    ("pdf-summarizer", ROOT / "fixtures" / "benign" / "pdf-summarizer", "SAFE", 0),
]
MAX_BENIGN_RISK = 29


def main() -> int:
    config = load_config()
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteStore(Path(tmp) / "e2e.sqlite")
        engine = ScanEngine(config, store=store)
        try:
            for name, path, expected, floor in EXPECTATIONS:
                outcome = engine.scan(
                    path,
                    options=ScanOptions(
                        sandbox=True,
                        no_cache=True,
                        timeout_s=config.sandbox.timeout_s,
                    ),
                )
                verdict = outcome.verdict.verdict.value
                risk = outcome.verdict.risk_score
                degraded = [
                    result.stage.value for result in outcome.stage_results if result.degraded
                ]
                ok = (
                    verdict == expected
                    and risk >= floor
                    and (expected != "SAFE" or risk <= MAX_BENIGN_RISK)
                )
                ok = ok and not degraded
                row = {
                    "skill": name,
                    "verdict": verdict,
                    "expected": expected,
                    "risk": risk,
                    "min_risk": floor,
                    "degraded_stages": degraded,
                    "pass": ok,
                }
                results.append(row)
                print(json.dumps(row), flush=True)
        finally:
            engine.close()
            store.close()
    passed = sum(1 for row in results if row["pass"])
    print(f"E2E {'PASS' if passed == len(results) else 'FAIL'} ({passed}/{len(results)})")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
