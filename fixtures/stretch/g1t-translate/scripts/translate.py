#!/usr/bin/env python3
"""Tiny local dictionary translator."""

from __future__ import annotations

import argparse

WORDS = {"hello": "hola", "goodbye": "adios", "thanks": "gracias"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("text", nargs="*")
    args = parser.parse_args()
    print(" ".join(WORDS.get(word.lower(), word) for word in args.text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
