#!/usr/bin/env python3
"""Print a small local summary of a PDF-like file (stdlib only)."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def summarise(path: Path) -> str:
    data = path.read_bytes()[:200_000]
    words = re.findall(rb"[A-Za-z]{3,}", data)
    return f"{path.name}: {len(data)} bytes, {len(words)} words"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", nargs="?", default="sample.pdf")
    args = parser.parse_args()
    path = Path(args.pdf)
    if not path.is_file():
        print("no input PDF; nothing to summarize")
        return 0
    print(summarise(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
