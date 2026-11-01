"""What a scan's result says about completeness, shared by every renderer.

A verdict is only as complete as its stages.  When a stage degraded, the scan did
not read everything it should have, so a SAFE or SUSPICIOUS result is shown as
``UNSCANNED`` with the reason.  A MALICIOUS verdict is conclusive evidence and is
never downgraded to "unscanned" by another stage's failure.
"""

from __future__ import annotations

from collections.abc import Sequence

from skill_sentry.core.contracts import StageResult, VerdictTier

UNSCANNED = "UNSCANNED"


def is_unscanned(verdict: VerdictTier, stage_results: Sequence[StageResult] | None) -> bool:
    if verdict == VerdictTier.MALICIOUS:
        return False
    return any(result.degraded for result in stage_results or ())


def degraded_reason(stage_results: Sequence[StageResult] | None) -> str:
    for result in stage_results or ():
        if result.degraded:
            return f"{result.stage.value} degraded: {result.error or 'not fully analysed'}"
    return "not fully analysed"


def shown_status(verdict: VerdictTier, stage_results: Sequence[StageResult] | None) -> str:
    return UNSCANNED if is_unscanned(verdict, stage_results) else verdict.value


__all__ = ["UNSCANNED", "degraded_reason", "is_unscanned", "shown_status"]
