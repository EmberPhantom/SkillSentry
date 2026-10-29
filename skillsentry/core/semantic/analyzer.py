"""Semantic analyzer: declared intent vs. actual behaviour using GemmaAnalyzer.

The model is advisory.  Deterministic anchors are injected as ground truth and
the analyzer keeps an independent prompt-injection floor, so a compromised or
hallucinating model cannot talk a scanner out of an instruction it can read.
Model failures always produce a degraded stage, never a clean result.
"""

from __future__ import annotations

from typing import Any

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
)
from skillsentry.core.models._json import validate_json
from skillsentry.core.models.base import ModelClient
from skillsentry.core.parser import SkillPackage, TextFile
from skillsentry.core.semantic.gemma_analyzer import GemmaAnalyzer
from skillsentry.core.semantic.prompts import SEMANTIC_SCHEMA, SYSTEM_PROMPT

MAX_PROMPT_CHARS = 32_000
MAX_FILES_IN_PROMPT = 30
_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SEVERITY_SCORE = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 72,
    Severity.MEDIUM: 42,
    Severity.LOW: 18,
    Severity.NOTE: 0,
}
_INSTRUCTION_TYPES = frozenset({"instruction-injection", "hidden-instruction"})


def _file_lookup(package: SkillPackage) -> dict[str, TextFile]:
    return {text_file.relative.replace("\\", "/"): text_file for text_file in package.text_files}


def _find_location(
    evidence: str,
    *,
    supplied_file: str | None,
    supplied_line: int | None,
    files: dict[str, TextFile],
) -> tuple[str, int, str]:
    fallback = ("SKILL.md", 1, evidence[:500])
    needle = evidence.strip().splitlines()[0][:200] if evidence.strip() else ""
    if supplied_file:
        relative = supplied_file.replace("\\", "/").lstrip("./")
        text_file = files.get(relative)
        if text_file is not None:
            if supplied_line and 1 <= supplied_line <= text_file.line_count:
                line = text_file.line(supplied_line) or ""
                return relative, supplied_line, line.strip()[:500]
            if needle:
                for number, line in enumerate(text_file.text.splitlines(), start=1):
                    if needle.lower() in line.lower():
                        return relative, number, line.strip()[:500]
            return relative, 1, needle[:500]
    if needle:
        for relative, text_file in files.items():
            for number, line in enumerate(text_file.text.splitlines(), start=1):
                if needle.lower() in line.lower():
                    return relative, number, line.strip()[:500]
    return fallback


def _build_prompt(package: SkillPackage, anchors: StageResult) -> str:
    anchor_lines = []
    for finding in anchors.findings[:40]:
        location = finding.evidence.file or "?"
        if finding.evidence.line:
            location += f":{finding.evidence.line}"
        anchor_lines.append(
            f"- [{finding.severity.value}] {finding.finding_type or 'anchor'} at {location}: "
            f"{finding.message}: {finding.evidence.code or ''}"
        )
    if not anchor_lines:
        anchor_lines.append("- none")

    chunks = [
        "DECLARED INTENT (from frontmatter, untrusted):",
        package.description or "(missing)",
        "",
        "DETERMINISTIC ANCHOR FINDINGS (ground truth - do not contradict):",
        *anchor_lines,
        "",
        "UNTRUSTED SKILL CONTENT BEGINS",
    ]
    used = sum(len(chunk) for chunk in chunks)
    ordered = sorted(
        package.text_files,
        key=lambda item: (item.relative != "SKILL.md", item.relative),
    )[:MAX_FILES_IN_PROMPT]
    for text_file in ordered:
        if used >= MAX_PROMPT_CHARS:
            break
        remaining = MAX_PROMPT_CHARS - used
        body = text_file.text[:remaining]
        chunks.append(f"\n===== FILE: {text_file.relative} =====\n{body}")
        used += len(body) + len(text_file.relative) + 20
    chunks.append("\nUNTRUSTED SKILL CONTENT ENDS")
    return "\n".join(chunks)


def analyze_semantics(
    package: SkillPackage,
    anchors: StageResult,
    model: ModelClient | None,
    *,
    timeout_s: float | None = None,
) -> StageResult:
    """Run semantic analysis using GemmaAnalyzer with coverage tracking and grounding."""
    analyzer = GemmaAnalyzer(model)
    return analyzer.analyze(package, anchors, timeout_s=timeout_s)


__all__ = ["analyze_semantics", "GemmaAnalyzer"]
