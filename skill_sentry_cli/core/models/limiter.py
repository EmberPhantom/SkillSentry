"""A shared limiter for a provider's request and token limits.

Free tiers cap requests a minute, tokens a minute and requests a day, per model. A scan of a folder
sends many requests, so it has to pace itself to those caps instead of failing the first time a
provider says 429. The limiter is shared by every client for the same provider and model, so one
folder scan, or several scans in one server, draw on one budget.

* **Requests a minute and tokens a minute** are sliding windows. A call waits until it fits.
* **Requests a day** is a rolling 24 hours. When it is used up the limiter says so at once and no
  request is sent, so a run ends with one message and not one failure per skill.
* **A provider's answer wins.** After a 429 the limiter holds every caller until ``Retry-After``
  has passed. After a daily-quota answer it refuses until the reset the provider gave.
* **Tokens** are an estimate before a call (``CHARS_PER_TOKEN`` characters to a token) and the
  provider's own ``usage`` figures after it, which replace the estimate.
* **Never past the scan's time limit.** A wait longer than the time left raises
  :class:`ModelThrottled` and sends nothing, so the stage degrades with a note instead of
  sleeping through the scan's deadline.
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from collections.abc import Callable

from skill_sentry_cli.core.deadline import active_deadline
from skill_sentry_cli.core.models.base import ModelQuotaExhausted, ModelThrottled

CHARS_PER_TOKEN = 3.2
MINUTE = 60.0
DAY = 86_400.0


def estimate_tokens(text: str) -> int:
    """A token count for text the provider has not counted yet."""

    return max(1, int(len(text) / CHARS_PER_TOKEN) + 1)


class RateLimiter:
    """Paces calls to a requests-a-minute, tokens-a-minute and requests-a-day budget.

    A limit of ``None`` (or ``0``) is not enforced. The clock and the sleep are injectable.
    """

    def __init__(
        self,
        *,
        rpm: int | None = None,
        tpm: int | None = None,
        rpd: int | None = None,
        label: str = "the provider",
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self.rpm = rpm or None
        self.tpm = tpm or None
        self.rpd = rpd or None
        self.label = label
        self._clock = clock
        self._sleep = sleep
        self._jitter = jitter
        self._lock = threading.Lock()
        self._requests: deque[float] = deque()  # one entry per request, in the last day
        self._tokens: deque[tuple[float, int]] = deque()  # (time, tokens) in the last minute
        self._blocked_until = 0.0
        self._exhausted_until = 0.0
        self._exhausted_reason = ""
        self.waited_s = 0.0
        self.calls = 0

    # -- state --------------------------------------------------------------------------
    @property
    def exhausted(self) -> bool:
        return self._clock() < self._exhausted_until

    def requests_today(self) -> int:
        with self._lock:
            self._expire(self._clock())
            return len(self._requests)

    def _expire(self, now: float) -> None:
        while self._requests and now - self._requests[0] >= DAY:
            self._requests.popleft()
        while self._tokens and now - self._tokens[0][0] >= MINUTE:
            self._tokens.popleft()

    # -- before a call ------------------------------------------------------------------------
    def acquire(self, tokens: int = 0) -> None:
        """Wait until a call of about ``tokens`` fits the budget, then count it.

        Raises :class:`ModelQuotaExhausted` when the daily budget is used up, and
        :class:`ModelThrottled` when the wait would run past the scan's time limit.
        """

        while True:
            with self._lock:
                now = self._clock()
                self._expire(now)
                if now < self._exhausted_until:
                    raise ModelQuotaExhausted(
                        self._exhausted_reason or f"{self.label} quota is used up",
                        retry_after=self._exhausted_until - now,
                    )
                if self.rpd is not None and len(self._requests) >= self.rpd:
                    reset = DAY - (now - self._requests[0])
                    self._exhausted_until = now + reset
                    self._exhausted_reason = (
                        f"the daily limit of {self.rpd} requests to {self.label} is used up"
                    )
                    raise ModelQuotaExhausted(self._exhausted_reason, retry_after=reset)
                wait = max(0.0, self._blocked_until - now)
                if self.rpm is not None:
                    recent = [t for t in self._requests if now - t < MINUTE]
                    if len(recent) >= self.rpm:
                        wait = max(wait, MINUTE - (now - recent[-self.rpm]))
                if self.tpm is not None and tokens:
                    wait = max(wait, self._token_wait(now, min(tokens, self.tpm)))
                if wait <= 0:
                    self._requests.append(now)
                    self._tokens.append((now, tokens))
                    self.calls += 1
                    return
            self._wait(wait + self._jitter() * min(0.25 * wait, 1.0))

    def _token_wait(self, now: float, tokens: int) -> float:
        assert self.tpm is not None
        in_window = sum(count for _, count in self._tokens)
        if in_window + tokens <= self.tpm:
            return 0.0
        needed = in_window + tokens - self.tpm
        freed = 0
        for stamp, count in self._tokens:
            freed += count
            if freed >= needed:
                return max(0.0, MINUTE - (now - stamp))
        return MINUTE

    # -- after a call ----------------------------------------------------------------------------
    def record(self, estimated: int, actual: int | None) -> None:
        """Replace the estimate for the last call with the provider's own token count."""

        if actual is None or actual == estimated:
            return
        with self._lock:
            for index in range(len(self._tokens) - 1, -1, -1):
                stamp, count = self._tokens[index]
                if count == estimated:
                    self._tokens[index] = (stamp, actual)
                    return

    def penalize(self, seconds: float) -> None:
        """A 429 with a wait: hold every caller until it has passed."""

        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + max(0.0, seconds))

    def exhaust(self, reason: str, *, seconds: float | None = None) -> None:
        """A daily-quota answer: refuse every call until the reset (a day when none is given)."""

        with self._lock:
            until = self._clock() + (DAY if seconds is None else max(0.0, seconds))
            self._exhausted_until = max(self._exhausted_until, until)
            self._exhausted_reason = reason

    # -- waiting ---------------------------------------------------------------------------------
    def wait(self, seconds: float) -> None:
        """Sleep ``seconds`` (for a 429 back-off), under the same time-limit rule as pacing."""

        self._wait(seconds)

    def _wait(self, seconds: float) -> None:
        deadline = active_deadline()
        if deadline is not None:
            left = deadline.remaining()
            if left is not None and seconds >= left:
                raise ModelThrottled(
                    f"pacing to {self.label}'s limits needs {seconds:.0f} s and the scan has "
                    f"{left:.0f} s left, so the request was not sent"
                )
        self.waited_s += seconds
        self._sleep(seconds)


_REGISTRY: dict[str, RateLimiter] = {}
_REGISTRY_LOCK = threading.Lock()


def limiter_for(
    key: str,
    *,
    rpm: int | None,
    tpm: int | None,
    rpd: int | None,
    label: str,
) -> RateLimiter:
    """The one limiter for a provider and model, created on first use and shared after."""

    with _REGISTRY_LOCK:
        limiter = _REGISTRY.get(key)
        if limiter is None or (limiter.rpm, limiter.tpm, limiter.rpd) != (
            rpm or None,
            tpm or None,
            rpd or None,
        ):
            limiter = RateLimiter(rpm=rpm, tpm=tpm, rpd=rpd, label=label)
            _REGISTRY[key] = limiter
        return limiter


def reset_limiters() -> None:
    """Forget every shared limiter (tests, and a server that reloads its configuration)."""

    with _REGISTRY_LOCK:
        _REGISTRY.clear()


__all__ = [
    "CHARS_PER_TOKEN",
    "RateLimiter",
    "estimate_tokens",
    "limiter_for",
    "reset_limiters",
]
