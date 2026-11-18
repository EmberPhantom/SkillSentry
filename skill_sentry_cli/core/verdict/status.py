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

# Finding types that mean "the package is malformed", with what to do about each. They are
# all raised by the SPEC stage; any other finding makes the package a real verdict instead.
_INVALID_HINTS: dict[str, str] = {
    "manifest-issue": "Fix the SKILL.md frontmatter, then scan again.",
    "manifest-entrypoint": "Fix the entrypoint: line in the SKILL.md frontmatter, then scan again.",
    "package-symlink": (
        "Remove the symlink from the skill folder, or replace it with a copy of the file. "
        "SkillSentry never follows links. Then scan again."
    ),
    "package-encoding": "Save SKILL.md as UTF-8, then scan again.",
    "package-name": "Rename the file or folder named above, then scan again.",
}
_GENERIC_HINT = "Fix the problem named above in the skill folder, then scan again."


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
            if finding.stage == Stage.SPEC and finding.finding_type in _INVALID_HINTS:
                manifest_high = manifest_high or finding.severity.rank >= Severity.HIGH.rank
                continue
            if finding.severity.rank < Severity.MEDIUM.rank:
                continue
            if finding.stage == Stage.SEMANTIC and finding.severity.rank < Severity.HIGH.rank:
                # Model-reported notes below HIGH do not turn a format error into a threat.
                continue
            return False
    return manifest_high and not any(_degraded(result) for result in stage_results)


def invalid_hint(stage_results: Sequence[StageResult] | None) -> str:
    """What to do about an INVALID SKILL result, for the cause that was reported."""

    for result in stage_results or ():
        for finding in result.findings:
            if finding.stage == Stage.SPEC and finding.finding_type in _INVALID_HINTS:
                return _INVALID_HINTS[finding.finding_type]
    return _GENERIC_HINT


def invalid_reason(stage_results: Sequence[StageResult] | None) -> str:
    for result in stage_results or ():
        for finding in result.findings:
            if finding.stage == Stage.SPEC and finding.finding_type in _INVALID_HINTS:
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
    "invalid_hint",
    "invalid_reason",
    "is_invalid",
    "is_unscanned",
    "shown_status",
]
