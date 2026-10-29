"""
CSV Analyzer — Benign test fixture.

Reads CSV files from a directory, computes per-column statistics
(mean, median, count, min, max), and outputs a plain-text report.

Expected verdict: SAFE (risk 0-29).
Uses only Python stdlib: csv, statistics, pathlib, sys.
No network access, no shell commands, no credentials.
"""
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path
from typing import Any


def read_csv_file(filepath: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read a CSV file and return headers and rows."""
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        headers: list[str] = reader.fieldnames or []
        rows: list[dict[str, str]] = list(reader)
    return headers, rows


def parse_numeric_column(rows: list[dict[str, str]], column: str) -> list[float]:
    """Extract numeric values from a column, skipping non-numeric entries."""
    values: list[float] = []
    for row in rows:
        try:
            values.append(float(row[column]))
        except (ValueError, KeyError):
            continue
    return values


def compute_column_stats(values: list[float]) -> dict[str, Any]:
    """Compute descriptive statistics for a list of numeric values."""
    if not values:
        return {"count": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "count": len(values),
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def generate_report(filepath: Path, headers: list[str], rows: list[dict[str, str]]) -> str:
    """Generate a plain-text statistical report for a single CSV file."""
    lines: list[str] = [f"=== Report for {filepath.name} ===", f"Total rows: {len(rows)}"]
    for col in headers:
        values = parse_numeric_column(rows, col)
        stats = compute_column_stats(values)
        if stats["count"] > 0:
            lines.append(
                f"  {col}: count={stats['count']}, mean={stats['mean']}, "
                f"median={stats['median']}, min={stats['min']}, max={stats['max']}"
            )
        else:
            lines.append(f"  {col}: non-numeric ({len(rows)} entries)")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Entry point — scan a directory for CSV files and print reports."""
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <directory>", file=sys.stderr)
        sys.exit(1)

    target_dir = Path(sys.argv[1])
    if not target_dir.is_dir():
        print(f"Error: {target_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    csv_files = sorted(target_dir.glob("*.csv"))
    if not csv_files:
        print(f"No CSV files found in {target_dir}.", file=sys.stderr)
        sys.exit(0)

    for csv_path in csv_files:
        headers, rows = read_csv_file(csv_path)
        report = generate_report(csv_path, headers, rows)
        print(report)


if __name__ == "__main__":
    main()
