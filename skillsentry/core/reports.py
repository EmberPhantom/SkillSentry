"""Report rendering and on-disk persistence (I5).

Files live under ``~/.skillsentry/reports/<scan_id>/`` (docs/03 §3.1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from skillsentry.core.config import reports_dir
from skillsentry.core.contracts import ExportFormat, Verdict
from skillsentry.core.verdict.markdown_report import build_markdown
from skillsentry.core.verdict.sarif_report import build_sarif
from skillsentry.core.verdict.stix_report import NoIOCsError, build_stix

MEDIA_TYPES: dict[ExportFormat, str] = {
    ExportFormat.SARIF: "application/sarif+json",
    ExportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ExportFormat.STIX: "application/stix+json;version=2.1",
}

FILENAMES: dict[ExportFormat, str] = {
    ExportFormat.SARIF: "report.sarif",
    ExportFormat.MARKDOWN: "report.md",
    ExportFormat.STIX: "stix-bundle.json",
}


@dataclass(frozen=True)
class RenderedReport:
    filename: str
    media_type: str
    content: bytes


@dataclass(frozen=True)
class ReportFiles:
    """On-disk report paths (never sent on the wire; use ``ReportLinks``)."""

    sarif: Path
    markdown: Path
    stix: Path | None = None


def render_report(verdict: Verdict, fmt: ExportFormat) -> RenderedReport:
    """Render one report in memory.  Raises ``NoIOCsError`` for empty STIX."""
    if fmt is ExportFormat.SARIF:
        content = json.dumps(build_sarif(verdict), indent=2) + "\n"
    elif fmt is ExportFormat.MARKDOWN:
        content = build_markdown(verdict)
    elif fmt is ExportFormat.STIX:
        content = json.dumps(build_stix(verdict), indent=2) + "\n"
    else:  # pragma: no cover - enum exhaustiveness
        raise ValueError(f"unsupported report format: {fmt}")
    return RenderedReport(
        filename=FILENAMES[fmt],
        media_type=MEDIA_TYPES[fmt],
        content=content.encode("utf-8"),
    )


def write_report_files(verdict: Verdict, *, root: str | Path | None = None) -> ReportFiles:
    """Write SARIF + Markdown (+ STIX when triggered) and return file paths."""
    target = Path(root) if root is not None else reports_dir(str(verdict.scan_id))
    target.mkdir(parents=True, exist_ok=True)

    sarif = render_report(verdict, ExportFormat.SARIF)
    markdown = render_report(verdict, ExportFormat.MARKDOWN)
    (target / sarif.filename).write_bytes(sarif.content)
    (target / markdown.filename).write_bytes(markdown.content)

    stix_path: Path | None = None
    try:
        stix = render_report(verdict, ExportFormat.STIX)
    except NoIOCsError:
        stix = None
    if stix is not None:
        stix_path = target / stix.filename
        stix_path.write_bytes(stix.content)

    return ReportFiles(
        sarif=target / sarif.filename,
        markdown=target / markdown.filename,
        stix=stix_path,
    )


__all__ = [
    "FILENAMES",
    "MEDIA_TYPES",
    "RenderedReport",
    "ReportFiles",
    "render_report",
    "write_report_files",
]
