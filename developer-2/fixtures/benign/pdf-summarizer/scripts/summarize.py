"""
PDF Summarizer — extracts text from PDF files and produces bullet-point summaries.

This is a BENIGN fixture: no network access, no credential reads, no shell commands.
Expected verdict: SAFE (risk < 30).
"""

import re
import sys
from pathlib import Path


def extract_text(pdf_path: str) -> str:
    """Read raw bytes and extract printable ASCII runs as a simplistic
    text extractor (no external PDF library needed for the fixture)."""
    data = Path(pdf_path).read_bytes()
    # Naive: extract runs of printable ASCII between stream/endstream
    text_runs = re.findall(rb"[\x20-\x7e]{10,}", data)
    return "\n".join(run.decode("ascii", errors="replace") for run in text_runs)


def summarize(text: str, max_bullets: int = 5) -> list[str]:
    """Split text into sentences and return the first N as bullet points."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [f"• {s.strip()}" for s in sentences[:max_bullets] if s.strip()]


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python summarize.py <path-to-pdf>")
        sys.exit(1)

    pdf_path = sys.argv[1]
    if not Path(pdf_path).is_file():
        print(f"Error: file not found: {pdf_path}")
        sys.exit(1)

    text = extract_text(pdf_path)
    bullets = summarize(text)

    print("Summary:")
    for b in bullets:
        print(f"  {b}")


if __name__ == "__main__":
    main()

