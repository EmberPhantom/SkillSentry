"""Coverage ledger tracking line ranges analyzed vs unanalyzed across all skill files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class CoverageLedger:
    """Tracks coverage of source code and documentation analysis.
    
    analyzed: map from relative file path to list of (start_line, end_line) ranges (1-based, inclusive).
    unanalyzed: map from relative file path to list of (start_line, end_line) unanalyzed ranges.
    reasons: map from (file, start_line, end_line) tuple to reason why unanalyzed.
    file_total_lines: map from relative file path to total line count.
    """
    analyzed: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)
    unanalyzed: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)
    reasons: Dict[Tuple[str, int, int], str] = field(default_factory=dict)
    file_total_lines: Dict[str, int] = field(default_factory=dict)

    def record_analyzed(self, file_path: str, start_line: int, end_line: int) -> None:
        if file_path not in self.analyzed:
            self.analyzed[file_path] = []
        self.analyzed[file_path].append((start_line, end_line))

    def record_unanalyzed(
        self, file_path: str, start_line: int, end_line: int, reason: str
    ) -> None:
        if file_path not in self.unanalyzed:
            self.unanalyzed[file_path] = []
        self.unanalyzed[file_path].append((start_line, end_line))
        self.reasons[(file_path, start_line, end_line)] = reason

    def record_file_lines(self, file_path: str, total_lines: int) -> None:
        self.file_total_lines[file_path] = max(1, total_lines)

    def is_complete(self) -> bool:
        """True if there are no unanalyzed ranges and every registered file is covered."""
        for file_path, ranges in self.unanalyzed.items():
            if ranges:
                return False

        # If any registered file has total_lines > 0 but no analyzed lines, it's incomplete
        for file_path, total_lines in self.file_total_lines.items():
            analyzed_ranges = self.analyzed.get(file_path, [])
            if not analyzed_ranges:
                return False
            # Check if all lines [1..total_lines] are covered
            covered_lines = set()
            for s, e in analyzed_ranges:
                for line in range(s, e + 1):
                    covered_lines.add(line)
            if len(covered_lines) < total_lines:
                return False

        return True

    def get_coverage_ratio(self) -> float:
        total = sum(self.file_total_lines.values())
        if total == 0:
            return 1.0
        covered = 0
        for file_path, total_lines in self.file_total_lines.items():
            ranges = self.analyzed.get(file_path, [])
            lines = set()
            for s, e in ranges:
                for line in range(s, min(e + 1, total_lines + 1)):
                    lines.add(line)
            covered += len(lines)
        return min(1.0, covered / total)

    def to_dict(self) -> dict:
        return {
            "analyzed": {k: [list(r) for r in v] for k, v in self.analyzed.items()},
            "unanalyzed": {k: [list(r) for r in v] for k, v in self.unanalyzed.items()},
            "reasons": {
                f"{k[0]}:{k[1]}-{k[2]}": v for k, v in self.reasons.items()
            },
            "is_complete": self.is_complete(),
            "coverage_ratio": round(self.get_coverage_ratio(), 4),
        }

