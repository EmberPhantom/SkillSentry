"""Report metadata for the typed decision layer.

The summary is built from a whitelist of stage-telemetry keys.  It never copies
prompts, routing payloads, or skill text, so a report cannot leak them even if
a backend adds fields to its response.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from skillsentry.core.contracts import StageResult

_SEMANTIC_KEYS = (
    "decision_backend",
    "model_backend",
    "checkpoint",
    "model_version",
    "calibration_version",
    "instruction_floor",
)
_VISION_STATUSES = frozenset({"not_applicable", "evaluated", "partial", "not_evaluated"})


def decision_summary(stage_results: Iterable[StageResult]) -> dict[str, Any]:
    """Return the report-safe decision summary for one scan's stage results."""

    summary: dict[str, Any] = {
        "decision_backend": "legacy",
        "checkpoint": None,
        "model_version": None,
        "calibration_version": "uncalibrated",
        "semantic_degraded": False,
        "semantic_error": None,
        "threshold": None,
        "capabilities": {},
        "vision_status": "not_evaluated",
    }
    for result in stage_results:
        if result.stage.value == "semantic":
            telemetry = result.telemetry or {}
            for key in _SEMANTIC_KEYS:
                if telemetry.get(key) is not None:
                    summary[key] = telemetry[key]
            decisions = telemetry.get("decisions") or {}
            if isinstance(decisions, dict):
                summary["threshold"] = decisions.get("threshold")
                capabilities = decisions.get("capabilities")
                if isinstance(capabilities, dict):
                    summary["capabilities"] = {
                        str(key): round(float(value), 4)
                        for key, value in capabilities.items()
                        if isinstance(value, (int, float))
                    }
            summary["semantic_degraded"] = bool(result.degraded or result.error)
            summary["semantic_error"] = str(result.error)[:300] if result.error else None
        elif result.stage.value == "vision":
            status = (result.telemetry or {}).get("vision_status")
            if status in _VISION_STATUSES:
                summary["vision_status"] = status
    return summary


__all__ = ["decision_summary"]
