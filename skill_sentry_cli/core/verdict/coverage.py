"""The partial-coverage result: what the model read and what only the static checks read."""

from __future__ import annotations

from collections.abc import Sequence

from skill_sentry_cli.core.contracts import CoverageDetail, Stage, StageResult, VerdictTier
from skill_sentry_cli.core.verdict.status import is_unscanned

PARTIAL_REASON = (
    "text or plain code with no risk signal, beyond the model's call budget; read by the static "
    "checks only"
)


def coverage_detail(
    verdict: VerdictTier, stage_results: Sequence[StageResult] | None
) -> CoverageDetail | None:
    """The partial-coverage detail for a finished result, or None when nothing was static-only.

    Never set on an UNSCANNED result: that one is not a result about the text it did not read.
    """

    if is_unscanned(verdict, stage_results):
        return None
    for result in stage_results or ():
        if result.stage != Stage.SEMANTIC or not result.telemetry:
            continue
        static_files = result.telemetry.get("static_only_files") or []
        if not static_files:
            return None
        read_files = result.telemetry.get("model_read_files") or []
        return CoverageDetail(
            files_read_by_model=len(read_files),
            files_read_statically=len(static_files),
            model_read_share=float(result.telemetry.get("model_read_share") or 0.0),
            static_only_share=float(result.telemetry.get("static_only_share") or 0.0),
            static_only_files=[str(name) for name in static_files][:50],
            reasons=[PARTIAL_REASON],
        )
    return None


__all__ = ["PARTIAL_REASON", "coverage_detail"]
