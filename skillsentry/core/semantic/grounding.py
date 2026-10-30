"""Grounding verification for LLM semantic claims against raw source chunks."""

from __future__ import annotations

import re
from typing import Optional, Tuple
from skillsentry.core.semantic.chunker import Chunk


def normalize_code(s: str) -> str:
    """Normalizes code by standardizing quotes, collapsing whitespace, and stripping around punctuation."""
    s = s.replace('"', "'")
    s = re.sub(r"\s+", " ", s).strip().lower()
    s = re.sub(r"\s*([(),=\[\]{}])\s*", r"\1", s)
    return s


def ground_quote(quote: str, chunk: Chunk) -> Optional[Tuple[int, int]]:
    """Locate the verbatim or whitespace/quote-normalized quote inside the chunk.
    
    Returns (start_line, end_line) as 1-based line numbers in the original file,
    or None if the quote cannot be grounded.
    """
    if not quote:
        return None

    norm_q = normalize_code(quote)
    if len(norm_q) < 5:
        return None

    lines = chunk.text.splitlines()
    if not lines:
        return None

    # 1. Exact single-line search
    for i, line in enumerate(lines):
        if quote.strip() in line:
            return chunk.start_line + i, chunk.start_line + i

    # 2. Normalized single-line search
    for i, line in enumerate(lines):
        if norm_q in normalize_code(line):
            return chunk.start_line + i, chunk.start_line + i

    # 3. Multiline search
    first_token = norm_q.split()[0] if norm_q.split() else norm_q
    first_token = re.split(r"[(),=\[\]{}]", first_token)[0] or first_token
    for i in range(len(lines)):
        if first_token and first_token not in normalize_code(lines[i]):
            continue
        acc = ""
        for j in range(i, min(i + 20, len(lines))):
            acc = (acc + " " + lines[j]).strip()
            if norm_q in normalize_code(acc):
                return chunk.start_line + i, chunk.start_line + j

    return None
