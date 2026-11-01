"""End-to-end check of the core fixtures through the configured backends.

Scans the fixtures with the Docker sandbox on.  By default the model comes from
the configuration (Ollama with the model pulled).  ``--model-backend demo`` uses
the deterministic demo model, which tests the sandbox and fusion path on their
own; a demo-model result is not evidence of the real model's accuracy.

    python scripts/e2e_fixtures.py                       # real model from config
    python scripts/e2e_fixtures.py --model-backend demo  # sandbox and fusion only
    python scripts/e2e_fixtures.py --repeat 10           # reproducibility

Exit status is 0 only when every run meets every expectation.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import load_config
from skill_sentry_cli.core.contracts import ScanOptions
from skill_sentry_cli.core.engine import ScanEngine

ROOT = Path(__file__).resolve().parents[1]

# skill name, path, expected verdict, minimum risk score
EXPECTATIONS = [
    ("cloud-sync-pro", ROOT / "fixtures" / "malicious" / "cloud-sync-pro", "MALICIOUS", 91),
    ("slack-notif-mal", ROOT / "fixtures" / "malicious" / "slack-notif-mal", "MALICIOUS", 100),
    ("git-helper", ROOT / "fixtures" / "benign" / "git-helper", "SAFE", 0),
    ("pdf-summarizer", ROOT / "fixtures" / "benign" / "pdf-summarizer", "SAFE", 0),
]
MAX_BENIGN_RISK = 29


def _run_once(config, *, store: SQLiteStore) -> list[dict[str, object]]:  # type: ignore[no-untyped-def]
    engine = ScanEngine(config, store=store)
    rows: list[dict[str, object]] = []
    try:
        for name, path, expected, floor in EXPECTATIONS:
            outcome = engine.scan(
                path,
                options=ScanOptions(
                    sandbox=True, no_cache=True, timeout_s=config.sandbox.timeout_s
                ),
            )
            verdict = outcome.verdict.verdict.value
            risk = outcome.verdict.risk_score
            degraded = [result.stage.value for result in outcome.stage_results if result.degraded]
            ok = verdict == expected and risk >= floor and not degraded
            if expected == "SAFE":
                ok = ok and risk <= MAX_BENIGN_RISK
            rows.append(
                {
                    "skill": name,
                    "verdict": verdict,
                    "expected": expected,
                    "risk": risk,
                    "min_risk": floor,
                    "degraded_stages": degraded,
                    "pass": ok,
                }
            )
    finally:
        engine.close()
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--model-backend", default=None, help="override the configured model backend"
    )
    parser.add_argument("--repeat", type=int, default=1, help="repeat the whole set N times")
    args = parser.parse_args()

    config = load_config()
    if args.model_backend:
        config.model.backend = args.model_backend

    all_rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as tmp:
        for run in range(1, args.repeat + 1):
            store = SQLiteStore(Path(tmp) / f"e2e-{run}.sqlite")
            try:
                rows = _run_once(config, store=store)
            finally:
                store.close()
            for row in rows:
                row["run"] = run
                print(json.dumps(row), flush=True)
            all_rows.extend(rows)

    passed = sum(1 for row in all_rows if row["pass"])
    total = len(all_rows)
    print(
        f"E2E {'PASS' if passed == total else 'FAIL'} ({passed}/{total} across {args.repeat} run(s))"
    )
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
