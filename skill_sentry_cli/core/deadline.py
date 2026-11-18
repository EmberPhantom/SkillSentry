"""Wall-clock limits for a scan.

A :class:`Deadline` is a point in time on the monotonic clock. :func:`call_within` runs one
blocking call, such as a model request, and gives up on it when the time is gone.

A Python thread cannot be killed, so a call that overruns is abandoned, not stopped: it runs
on in a daemon thread until its own client timeout ends it, and its result is dropped. The
scan itself returns on time.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TypeVar

from skill_sentry_cli.core.contracts import Finding, FindingEvidence, Severity, Stage

T = TypeVar("T")


class TimeLimitExceeded(Exception):
    """A scan, stage or call ran past its wall-clock limit."""


class Deadline:
    """An absolute limit; ``seconds=None`` means no limit."""

    def __init__(
        self,
        seconds: float | None,
        *,
        limit_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        """``limit_s`` is the configured limit shown in messages, when ``seconds`` is what is
        left of it (for example after parsing the skill)."""

        self._clock = clock
        self.seconds = seconds if limit_s is None else limit_s
        self._end = None if seconds is None else clock() + max(0.0, seconds)

    def remaining(self) -> float | None:
        """Seconds left (never negative), or ``None`` when there is no limit."""

        if self._end is None:
            return None
        return max(0.0, self._end - self._clock())

    def expired(self) -> bool:
        left = self.remaining()
        return left is not None and left <= 0.0

    def within(self, seconds: float | None) -> Deadline:
        """A deadline that ends at this one or after ``seconds``, whichever is first."""

        child = Deadline(seconds, clock=self._clock)
        if self._end is not None and (child._end is None or self._end < child._end):
            child._end = self._end
            child.seconds = self.seconds
        return child

    def describe(self) -> str:
        return "no time limit" if self.seconds is None else f"{self.seconds:g} s"


def call_within(deadline: Deadline | None, fn: Callable[[], T]) -> T:
    """Run ``fn``; raise :class:`TimeLimitExceeded` when ``deadline`` passes first.

    With no deadline, ``fn`` runs inline. Exceptions raised by ``fn`` propagate unchanged.
    """

    if deadline is None or deadline.remaining() is None:
        return fn()
    left = deadline.remaining()
    assert left is not None
    if left <= 0.0:
        raise TimeLimitExceeded(f"time limit reached ({deadline.describe()})")

    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # carried back to the caller
            box["error"] = exc

    worker = threading.Thread(target=run, name="skillsentry-call", daemon=True)
    worker.start()
    worker.join(left)
    if worker.is_alive():
        raise TimeLimitExceeded(
            f"call did not finish within the time limit ({deadline.describe()})"
        )
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]  # type: ignore[return-value]


def time_limit_finding(stage: Stage, deadline: Deadline) -> Finding:
    """A NOTE that names the stage that ran out of time, so the report says why it is partial."""

    return Finding(
        stage=stage,
        severity=Severity.NOTE,
        message=(
            f"The scan time limit ({deadline.describe()}) was reached, so the {stage.value} "
            "stage did not finish. Findings from the stages that did finish are kept. "
            "Raise it with --max-time or [scan] max_time_s."
        ),
        finding_type="scan-time-limit",
        evidence=FindingEvidence(file="SKILL.md", line=1),
    )
