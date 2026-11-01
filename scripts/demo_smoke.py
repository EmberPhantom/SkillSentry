"""Boot the demo server, check the seeded contract, then stop it.

Mirrors the CI demo-smoke job so it can run locally while CI is blocked.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


def _get(path: str) -> object:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=2) as response:
        return json.load(response)


def main() -> int:
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "skill_sentry.server.demo_mode",
            "--port",
            str(PORT),
            "--speed",
            "0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        meta = None
        for _ in range(100):
            try:
                meta = _get("/meta")
                break
            except Exception:
                time.sleep(0.2)
        if not isinstance(meta, dict) or meta.get("demoMode") is not True:
            print("demo server did not become healthy", file=sys.stderr)
            return 1
        scans = _get("/scans")["scans"]  # type: ignore[index]
        verdicts = {row["verdict"] for row in scans}
        if len(scans) != 7 or verdicts != {"SAFE", "MALICIOUS"}:
            print(
                f"unexpected demo contract: {len(scans)} skills, {sorted(verdicts)}",
                file=sys.stderr,
            )
            return 1
        print(f"demo smoke OK: {len(scans)} skills, verdicts {sorted(verdicts)}")
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
