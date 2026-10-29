"""
JSON Formatter — validates and pretty-prints JSON files.

This is a BENIGN fixture: pure stdlib (json, sys, pathlib).
No network access, no shell commands, no credentials.
Expected verdict: SAFE (risk < 30).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def validate_json(filepath: Path) -> tuple[bool, str]:
    """Validate a JSON file and return (is_valid, error_message)."""
    try:
        with open(filepath, encoding="utf-8") as fh:
            json.load(fh)
        return True, ""
    except json.JSONDecodeError as exc:
        return False, f"Invalid JSON at line {exc.lineno}, col {exc.colno}: {exc.msg}"


def format_json(filepath: Path, indent: int = 2) -> str:
    """Read a JSON file and return pretty-printed content."""
    with open(filepath, encoding="utf-8") as fh:
        data = json.load(fh)
    return json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=True)


def minify_json(filepath: Path) -> str:
    """Read a JSON file and return minified content."""
    with open(filepath, encoding="utf-8") as fh:
        data = json.load(fh)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: python format_json.py <file.json> [--indent N] [--minify]", file=sys.stderr)
        sys.exit(1)

    filepath = Path(args[0])
    if not filepath.is_file():
        print(f"Error: {filepath} not found.", file=sys.stderr)
        sys.exit(1)

    is_valid, error = validate_json(filepath)
    if not is_valid:
        print(f"Validation failed: {error}", file=sys.stderr)
        sys.exit(1)

    if "--minify" in args:
        print(minify_json(filepath))
    else:
        indent = 2
        if "--indent" in args:
            idx = args.index("--indent")
            if idx + 1 < len(args):
                indent = int(args[idx + 1])
        print(format_json(filepath, indent))


if __name__ == "__main__":
    main()

