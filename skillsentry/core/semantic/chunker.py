"""Source and markdown chunker with token budgeting and AST/heading awareness."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass(frozen=True)
class Chunk:
    """Represents a discrete semantic chunk of a file."""
    chunk_id: str
    file: str
    start_line: int  # 1-based, inclusive
    end_line: int    # 1-based, inclusive
    text: str
    kind: str        # "markdown" | "code" | "other"
    est_tokens: int
    priority: int    # 0 = highest (anchor hit / entrypoint), 1 = core (SKILL.md, scripts), 2 = other


def est_tokens(s: str) -> int:
    """Pessimistic estimation of token count (3 characters per token)."""
    return max(1, int(len(s) / 3.0))


def compute_chunk_budget(
    effective_ctx: int,
    max_new_tokens: int = 1024,
    overhead_tokens: int = 512,
) -> int:
    """Computes the target maximum token size for a chunk."""
    budget = int((effective_ctx - max_new_tokens - overhead_tokens) * 0.80)
    if budget < 512:
        raise ValueError(
            f"Context budget too small ({budget} tokens). Increase effective_ctx."
        )
    return budget


class FileChunker:
    """Splits files into semantic chunks respecting structural boundaries."""

    def __init__(
        self,
        chunk_budget_tokens: int = 2048,
        overlap_lines: int = 3,
    ) -> None:
        self.chunk_budget = chunk_budget_tokens
        self.overlap_lines = overlap_lines

    def chunk_file(
        self,
        rel_path: str,
        content: str,
        anchor_lines: Optional[Set[int]] = None,
        is_entrypoint: bool = False,
    ) -> List[Chunk]:
        """Splits file content into an ordered list of Chunks."""
        if not content:
            return []

        anchor_lines = anchor_lines or set()
        file_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:8]
        lines = content.splitlines()
        total_lines = len(lines)

        if rel_path.lower().endswith((".md", ".markdown")):
            raw_ranges = self._split_markdown(lines)
            kind = "markdown"
        elif rel_path.lower().endswith(".py"):
            raw_ranges = self._split_python(content, lines)
            kind = "code"
        elif any(rel_path.lower().endswith(ext) for ext in [".js", ".ts", ".sh", ".bash", ".ps1", ".rb", ".pl"]):
            raw_ranges = self._split_generic_code(lines)
            kind = "code"
        else:
            raw_ranges = self._split_lines(lines)
            kind = "other"

        chunks: List[Chunk] = []
        for idx, (start_l, end_l) in enumerate(raw_ranges):
            start_l = max(1, min(start_l, total_lines))
            end_l = max(start_l, min(end_l, total_lines))
            # Slice lines (1-based to 0-based indexing)
            chunk_text = "\n".join(lines[start_l - 1:end_l])
            
            # Determine priority:
            # 0 = contains anchor hit or entrypoint
            # 1 = SKILL.md or in scripts/
            # 2 = others
            has_anchor = any(start_l <= al <= end_l for al in anchor_lines)
            if has_anchor or is_entrypoint:
                priority = 0
            elif rel_path.lower() in {"skill.md", "skill.yaml"} or rel_path.startswith("scripts/"):
                priority = 1
            else:
                priority = 2

            chunk_id = f"{file_hash}-{idx:03d}"
            chunks.append(
                Chunk(
                    chunk_id=chunk_id,
                    file=rel_path,
                    start_line=start_l,
                    end_line=end_l,
                    text=chunk_text,
                    kind=kind,
                    est_tokens=est_tokens(chunk_text),
                    priority=priority,
                )
            )

        # Sort primarily by priority, then by starting line number
        return sorted(chunks, key=lambda c: (c.priority, c.start_line))

    def _split_markdown(self, lines: List[str]) -> List[tuple[int, int]]:
        """Splits markdown on headings, respecting fenced code blocks."""
        ranges: List[tuple[int, int]] = []
        in_code_block = False
        current_start = 1
        current_text_len = 0

        heading_pattern = re.compile(r"^#{1,6}\s+")

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block

            is_heading = not in_code_block and bool(heading_pattern.match(stripped))
            current_text_len += len(line) + 1
            current_tokens = int(current_text_len / 3.0)

            # If we hit a heading and we already have content, close previous chunk
            if is_heading and idx > current_start:
                ranges.append((current_start, idx - 1))
                current_start = idx
                current_text_len = len(line) + 1
            elif current_tokens >= self.chunk_budget and idx > current_start:
                # Exceeded budget: break at line boundary
                ranges.append((current_start, idx))
                current_start = max(1, idx - self.overlap_lines + 1)
                current_text_len = 0

        if current_start <= len(lines):
            ranges.append((current_start, len(lines)))

        return self._merge_or_subsplit(ranges, lines)

    def _split_python(self, content: str, lines: List[str]) -> List[tuple[int, int]]:
        """Splits Python files along top-level AST function and class definitions."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._split_lines(lines)

        top_defs: List[tuple[int, int]] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                end_lineno = getattr(node, "end_lineno", node.lineno)
                top_defs.append((node.lineno, end_lineno))

        if not top_defs:
            return self._split_lines(lines)

        ranges: List[tuple[int, int]] = []
        prev_end = 0

        for start_l, end_l in top_defs:
            # If there's module-level code before this definition
            if start_l > prev_end + 1:
                ranges.append((prev_end + 1, start_l - 1))
            ranges.append((start_l, end_l))
            prev_end = end_l

        if prev_end < len(lines):
            ranges.append((prev_end + 1, len(lines)))

        return self._merge_or_subsplit(ranges, lines)

    def _split_generic_code(self, lines: List[str]) -> List[tuple[int, int]]:
        """Splits code files along blank-line blocks with budget checks."""
        ranges: List[tuple[int, int]] = []
        current_start = 1
        current_len = 0

        for idx, line in enumerate(lines, start=1):
            current_len += len(line) + 1
            if not line.strip() and int(current_len / 3.0) >= self.chunk_budget:
                ranges.append((current_start, idx))
                current_start = idx + 1
                current_len = 0

        if current_start <= len(lines):
            ranges.append((current_start, len(lines)))

        return self._merge_or_subsplit(ranges, lines)

    def _split_lines(self, lines: List[str]) -> List[tuple[int, int]]:
        """Fallback line-based chunker with overlap."""
        if not lines:
            return []
        ranges: List[tuple[int, int]] = []
        current_start = 1
        current_len = 0

        for idx, line in enumerate(lines, start=1):
            current_len += len(line) + 1
            if int(current_len / 3.0) >= self.chunk_budget and idx > current_start:
                ranges.append((current_start, idx))
                current_start = max(1, idx - self.overlap_lines + 1)
                current_len = 0

        if current_start <= len(lines):
            ranges.append((current_start, len(lines)))

        return ranges

    def _merge_or_subsplit(
        self, ranges: List[tuple[int, int]], lines: List[str]
    ) -> List[tuple[int, int]]:
        """Ensures very small adjacent ranges are merged and oversize ranges are subsliced."""
        final_ranges: List[tuple[int, int]] = []

        for s, e in ranges:
            # Sub-split if single range is too large
            text = "\n".join(lines[s - 1:e])
            if est_tokens(text) > self.chunk_budget * 1.5 and e > s + 10:
                sub_lines = lines[s - 1:e]
                sub_ranges = self._split_lines(sub_lines)
                for sub_s, sub_e in sub_ranges:
                    final_ranges.append((s + sub_s - 1, s + sub_e - 1))
            else:
                final_ranges.append((s, e))

        return final_ranges

