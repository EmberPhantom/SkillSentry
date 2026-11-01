"""Real Laya + Docker sandbox E2E: scan three fixtures through the full engine.

Run in the laya environment (.venv-laya). Writes nothing outside a temp SQLite file.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from skill_sentry.core.cache import SQLiteStore
from skill_sentry.core.config import DecisionSettings, SkillsEntryConfig
from skill_sentry.core.contracts import ScanOptions
from skill_sentry.core.engine import ScanEngine

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("cloud-sync-pro", ROOT / "fixtures" / "malicious" / "cloud-sync-pro", "MALICIOUS", 91),
    ("slack-notif-mal", ROOT / "fixtures" / "malicious" / "slack-notif-mal", "MALICIOUS", 100),
    ("git-helper", ROOT / "fixtures" / "benign" / "git-helper", "SAFE", 0),
]


def main() -> int:
    config = SkillsEntryConfig()
    config.model.backend = "demo"  # legacy path not used for semantics; vision stays deterministic
    config.sandbox.enabled = True
    config.decision = DecisionSettings(
        backend="laya",
        checkpoint="english",
        device="cpu",
        timeout_s=600,
        max_len=512,
        head_max_len=128,
    )
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteStore(Path(tmp) / "e2e.sqlite")
        engine = ScanEngine(config, store=store)
        try:
            for name, path, expected, min_risk in CASES:
                outcome = engine.scan(
                    path,
                    options=ScanOptions(
                        sandbox=True,
                        no_cache=True,
                        timeout_s=config.sandbox.timeout_s,
                    ),
                )
                stages = {r.stage.value: r for r in outcome.stage_results}
                semantic = stages.get("semantic")
                sandbox = stages.get("sandbox")
                row = {
                    "skill": name,
                    "verdict": outcome.verdict.verdict.value,
                    "risk": outcome.verdict.risk_score,
                    "expected": expected,
                    "risk_floor": min_risk,
                    "semantic_degraded": bool(semantic and semantic.degraded),
                    "semantic_error": (semantic.error if semantic else None),
                    "sandbox_degraded": bool(sandbox and sandbox.degraded),
                    "sandbox_error": (sandbox.error if sandbox else None),
                    "semantic_backend": (semantic.telemetry or {}).get("decision_backend")
                    if semantic
                    else None,
                    "checkpoint": (semantic.telemetry or {}).get("checkpoint")
                    if semantic
                    else None,
                    "calibration": (semantic.telemetry or {}).get("calibration_version")
                    if semantic
                    else None,
                    "sandbox_ran": bool(sandbox and not sandbox.degraded and sandbox.telemetry),
                    "active_defense": bool(
                        outcome.verdict.active_defense and outcome.verdict.active_defense.triggered
                    ),
                    "exfil_channel": (
                        outcome.verdict.active_defense.exfil_channel
                        if outcome.verdict.active_defense
                        else None
                    ),
                    "evasion_detected": bool(
                        outcome.verdict.active_defense
                        and getattr(
                            outcome.verdict.active_defense, "sandbox_evasion_detected", False
                        )
                    ),
                }
                row["pass"] = (
                    row["verdict"] == expected
                    and row["risk"] >= min_risk
                    and (
                        name != "cloud-sync-pro"
                        or (row["active_defense"] and row["exfil_channel"] == "DNS_TUNNELING")
                    )
                    and (
                        name != "slack-notif-mal"
                        or (row["active_defense"] and row["evasion_detected"])
                    )
                    and not row["sandbox_degraded"]
                    and not row["semantic_degraded"]
                )
                results.append(row)
                print(json.dumps(row, default=str), flush=True)
        finally:
            engine.close()
            store.close()
    ok = all(row["pass"] for row in results)
    print("E2E", "PASS" if ok else "FAIL", f"({sum(r['pass'] for r in results)}/{len(results)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
