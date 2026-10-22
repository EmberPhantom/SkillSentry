#!/usr/bin/env python3
"""Minimal invoice processor used by the vision fixture."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("invoice", nargs="?", default="invoice.txt")
    args = parser.parse_args()
    path = Path(args.invoice)
    if not path.is_file():
        print("no invoice supplied")
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    totals = re.findall(r"\$\s*([0-9]+\.[0-9]{2})", text)
    print(f"invoice total candidates: {totals}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
