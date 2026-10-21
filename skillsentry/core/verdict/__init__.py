"""Verdict fusion and report generation."""

from skillsentry.core.verdict.fusion import (
    FusionError,
    FusionResult,
    degradation_findings,
    fuse,
    score_to_verdict,
)
from skillsentry.core.verdict.markdown_report import build_markdown
from skillsentry.core.verdict.sarif_report import build_sarif
from skillsentry.core.verdict.stix_report import NoIOCsError, build_stix

__all__ = [
    "FusionError",
    "FusionResult",
    "NoIOCsError",
    "build_markdown",
    "build_sarif",
    "build_stix",
    "degradation_findings",
    "fuse",
    "score_to_verdict",
]
