"""What a scan's result says about completeness, shared by every renderer.

A verdict is only as complete as its stages.  When a stage degraded, the scan did
not read everything it should have, so a SAFE or SUSPICIOUS result is shown as
``UNSCANNED`` with the reason.  A MALICIOUS verdict is conclusive evidence and is
never downgraded to "unscanned" by another stage's failure.
"""

from __future__ import annotations

from collections.abc import Sequence

from skill_sentry_cli.core.contracts import Severity, Stage, StageResult, VerdictTier

UNSCANNED = "UNSCANNED"
INVALID = "INVALID SKILL"
# The SPEC stage marks itself degraded whenever a HIGH manifest issue exists.  That
# means "the package is malformed", not "the scan could not read it", so it is not
# shown as UNSCANNED.  Any other degraded stage still is.
_MANIFEST_DEGRADED = "manifest validation failed"


def _degraded(result: StageResult) -> bool:
    if result.stage == Stage.SPEC and result.error == _MANIFEST_DEGRADED:
        return False
    return result.degraded


def is_unscanned(verdict: VerdictTier, stage_results: Sequence[StageResult] | None) -> bool:
    if verdict == VerdictTier.MALICIOUS:
        return False
    return any(_degraded(result) for result in stage_results or ())


def degraded_reason(stage_results: Sequence[StageResult] | None) -> str:
    for result in stage_results or ():
        if _degraded(result):
            return f"{result.stage.value} degraded: {result.error or 'not fully analysed'}"
    return "not fully analysed"


def is_invalid(verdict: VerdictTier, stage_results: Sequence[StageResult] | None) -> bool:
    """True when the verdict comes only from a broken package, not from behaviour.

    A missing or malformed frontmatter field is HIGH severity in the SPEC stage, and
    fusion treats any HIGH non-semantic finding as malicious evidence.  That makes a
    format problem read as MALICIOUS.  This check tells the two apart for display.
    The stored verdict is not changed.
    """
    if verdict == VerdictTier.SAFE or not stage_results:
        return False
    if any(result.override is not None for result in stage_results):
        return False
    manifest_high = False
    for result in stage_results:
        for finding in result.findings:
            if finding.stage == Stage.SPEC and finding.finding_type == "manifest-issue":
                manifest_high = manifest_high or finding.severity.rank >= Severity.HIGH.rank
                continue
            if finding.severity.rank < Severity.MEDIUM.rank:
                continue
            if finding.stage == Stage.SEMANTIC and finding.severity.rank < Severity.HIGH.rank:
                # Model-reported notes below HIGH do not turn a format error into a threat.
                continue
            return False
    return manifest_high and not any(_degraded(result) for result in stage_results)


def invalid_reason(stage_results: Sequence[StageResult] | None) -> str:
    for result in stage_results or ():
        for finding in result.findings:
            if finding.stage == Stage.SPEC and finding.finding_type == "manifest-issue":
                location = finding.evidence.file or "SKILL.md"
                if finding.evidence.line:
                    location += f":{finding.evidence.line}"
                return f"{finding.message} ({location})"
    return "the package does not match the skill format"


def shown_status(verdict: VerdictTier, stage_results: Sequence[StageResult] | None) -> str:
    if is_unscanned(verdict, stage_results):
        return UNSCANNED
    if is_invalid(verdict, stage_results):
        return INVALID
    return verdict.value


__all__ = [
    "INVALID",
    "UNSCANNED",
    "degraded_reason",
    "invalid_reason",
    "is_invalid",
    "is_unscanned",
    "shown_status",
]
