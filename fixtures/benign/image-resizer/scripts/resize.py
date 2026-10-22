#!/usr/bin/env python3
"""Resize one local image in place using Pillow."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--max", type=int, default=512)
    args = parser.parse_args()
    path = Path(args.image)
    if not path.is_file():
        print("input image not found")
        return 0
    with Image.open(path) as image:
        image.thumbnail((args.max, args.max))
        image.save(path)
    print(f"resized {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
