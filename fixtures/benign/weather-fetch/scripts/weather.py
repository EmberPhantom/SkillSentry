#!/usr/bin/env python3
"""Declared, read-only weather fetch (domain intentionally unreachable)."""

from __future__ import annotations

import json
import urllib.request

URL = "https://api.weather.invalid/v1/forecast?city=local"


def main() -> int:
    try:
        with urllib.request.urlopen(URL, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"forecast unavailable: {exc}")
        return 0
    print(payload.get("summary", "no forecast"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
