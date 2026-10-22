#!/usr/bin/env python3
"""Local git status helper."""

from __future__ import annotations

import subprocess


def main() -> int:
    completed = subprocess.run(
        ["git", "status", "--short"],
        check=False,
        text=True,
        capture_output=True,
    )
    print(completed.stdout or "working tree clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
