"""Verdict fusion and report generation."""

from skill_sentry_cli.core.verdict.fusion import (
    FusionError,
    FusionResult,
    degradation_findings,
    fuse,
    score_to_verdict,
)
from skill_sentry_cli.core.verdict.markdown_report import build_markdown
from skill_sentry_cli.core.verdict.sarif_report import build_sarif
from skill_sentry_cli.core.verdict.stix_report import NoIOCsError, build_stix

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
