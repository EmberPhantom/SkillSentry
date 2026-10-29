"""
Markdown Formatter — Benign test fixture.

Reads a Markdown file, normalizes heading levels so they increment
sequentially, checks for broken relative links, and outputs the
formatted Markdown to stdout.

Expected verdict: SAFE (risk 0-29).
Uses only Python stdlib: re, pathlib, sys.
No network access, no shell commands, no credentials.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def normalize_headings(lines: list[str]) -> list[str]:
    """Ensure heading levels increment by at most one level at a time."""
    heading_re = re.compile(r"^(#{1,6})\s+(.*)")
    current_level: int = 0
    result: list[str] = []
    for line in lines:
        match = heading_re.match(line)
        if match:
            raw_level = len(match.group(1))
            target_level = min(raw_level, current_level + 1) if current_level else 1
            current_level = target_level
            result.append(f"{'#' * target_level} {match.group(2)}")
        else:
            result.append(line)
    return result


def check_relative_links(content: str, base_dir: Path) -> list[str]:
    """Find relative links that point to missing files."""
    link_re = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
    warnings: list[str] = []
    for match in link_re.finditer(content):
        target = match.group(2)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        resolved = base_dir / target
        if not resolved.exists():
            warnings.append(f"WARNING: broken link [{match.group(1)}]({target})")
    return warnings


def format_document(filepath: Path) -> str:
    """Read, normalize, and return formatted Markdown content."""
    raw = filepath.read_text(encoding="utf-8")
    lines = raw.splitlines()
    normalized = normalize_headings(lines)
    return "\n".join(normalized)


def main() -> None:
    """Entry point — format a Markdown file and report broken links."""
    if len(sys.argv) < 2:
        print("Usage: python formatter.py <file.md>", file=sys.stderr)
        sys.exit(1)

    filepath = Path(sys.argv[1])
    if not filepath.is_file():
        print(f"Error: {filepath} not found.", file=sys.stderr)
        sys.exit(1)

    formatted = format_document(filepath)
    warnings = check_relative_links(formatted, filepath.parent)

    for warning in warnings:
        print(warning, file=sys.stderr)

    print(formatted)


if __name__ == "__main__":
    main()
