#!/usr/bin/env python3
"""Validate a project settings file against a few simple rules (stdlib only)."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

RULES = {
    "timeout_seconds": (1, 300),
    "retries": (0, 10),
    "page_size": (10, 500),
}


def check(settings: dict[str, object]) -> list[str]:
    problems: list[str] = []
    for key, (low, high) in RULES.items():
        value = settings.get(key)
        if value is None:
            problems.append(f"{key}: missing")
        elif not isinstance(value, int) or not low <= value <= high:
            problems.append(f"{key}: {value!r} is outside {low}..{high}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("settings", nargs="?", default="settings.toml")
    args = parser.parse_args()
    path = Path(args.settings)
    if not path.is_file():
        print("no settings file; nothing to check")
        return 0
    with path.open("rb") as handle:
        settings = tomllib.load(handle)
    problems = check(settings)
    for problem in problems:
        print(problem)
    print(f"{path.name}: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
