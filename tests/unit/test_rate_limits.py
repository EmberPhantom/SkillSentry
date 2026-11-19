"""Pacing to a provider's limits: requests and tokens a minute, requests a day, 429 and quota."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.cli import ExitCode
from skill_sentry_cli.core.config import ModelSettings
from skill_sentry_cli.core.contracts import Severity, Stage
from skill_sentry_cli.core.deadline import Deadline, call_within
from skill_sentry_cli.core.models.base import (
    ModelQuotaExhausted,
    ModelRateLimited,
    ModelThrottled,
)
from skill_sentry_cli.core.models.gemma_cloud import GemmaCloud
from skill_sentry_cli.core.models.limiter import (
    DAY,
    RateLimiter,
    estimate_tokens,
    limiter_for,
    reset_limiters,
)
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.providers import (
    OPENROUTER_FREE_PER_DAY,
    RATE_DEFAULTS,
    ResolvedProvider,
    rate_limits,
)
from skill_sentry_cli.core.models.selector import select_model
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.semantic import analyze_semantics, scan_anchors
from skill_sentry_cli.core.semantic.prompts import SEMANTIC_SCHEMA

KEY = "sk-test-KEY-0123456789abcdef"
GOOD = json.dumps(
    {
        "declared_intent": "x",
        "actual_capabilities": [],
        "suspicious_patterns": [],
        "is_deceptive": False,
        "confidence": 0.5,
    }
)


class Clock:
    """Time that moves only when something sleeps: every wait is exact and instant."""

    def __init__(self) -> None:
        self.now = 10_000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def limiter(self, **limits: Any) -> RateLimiter:
        return RateLimiter(clock=self, sleep=self.sleep, jitter=lambda: 0.0, **limits)


@pytest.fixture(autouse=True)
def _fresh_limiters():
    reset_limiters()
    yield
    reset_limiters()


# -- the limiter ------------------------------------------------------------------------------------
def test_requests_a_minute_wait_until_the_oldest_request_leaves_the_window():
    clock = Clock()
    limiter = clock.limiter(rpm=3)

    for _ in range(3):
        limiter.acquire()
    assert clock.sleeps == []  # three fit
    limiter.acquire()  # the fourth must wait for the first to be a minute old

    assert clock.sleeps == [pytest.approx(60.0)]
    assert limiter.calls == 4


def test_a_request_after_the_window_has_passed_does_not_wait():
    clock = Clock()
    limiter = clock.limiter(rpm=1)
    limiter.acquire()
    clock.now += 61
    limiter.acquire()

    assert clock.sleeps == []


def test_tokens_a_minute_wait_for_enough_to_leave_the_window():
    clock = Clock()
    limiter = clock.limiter(tpm=1000)

    limiter.acquire(600)
    clock.now += 20
    limiter.acquire(300)  # 900 in the window: fits
    assert clock.sleeps == []
    limiter.acquire(400)  # needs the first 600 to leave, which happens 40 s from now

    assert clock.sleeps == [pytest.approx(40.0)]


def test_a_call_bigger_than_the_whole_minute_budget_is_still_sent_alone():
    clock = Clock()
    limiter = clock.limiter(tpm=1000)

    limiter.acquire(5000)  # larger than the budget: it is capped, not refused forever

    assert limiter.calls == 1


def test_the_provider_count_replaces_the_estimate_so_the_budget_is_real():
    clock = Clock()
    limiter = clock.limiter(tpm=1000)
    limiter.acquire(900)
    limiter.record(900, 100)  # the provider says the call really cost 100 tokens

    limiter.acquire(800)  # 100 + 800 fits; with the estimate it would have waited

    assert clock.sleeps == []


def test_requests_a_day_end_at_once_with_one_clear_reason_and_send_nothing_more():
    clock = Clock()
    limiter = clock.limiter(rpd=2, label="Groq")
    limiter.acquire()
    limiter.acquire()

    with pytest.raises(ModelQuotaExhausted, match="daily limit of 2 requests to Groq") as first:
        limiter.acquire()
    with pytest.raises(ModelQuotaExhausted):
        limiter.acquire()

    assert clock.sleeps == []  # it never slept a day
    assert first.value.retry_after == pytest.approx(DAY)
    assert limiter.calls == 2
    assert limiter.exhausted


def test_the_daily_budget_comes_back_a_day_after_the_first_request():
    clock = Clock()
    limiter = clock.limiter(rpd=1)
    limiter.acquire()
    with pytest.raises(ModelQuotaExhausted):
        limiter.acquire()

    clock.now += DAY + 1
    limiter.acquire()

    assert limiter.calls == 2


def test_a_429_holds_every_caller_until_the_wait_has_passed():
    clock = Clock()
    limiter = clock.limiter()
    limiter.penalize(7)

    limiter.acquire()

    assert clock.sleeps == [pytest.approx(7.0)]


def test_a_provider_quota_answer_refuses_until_its_reset():
    clock = Clock()
    limiter = clock.limiter()
    limiter.exhaust("the provider's quota is used up", seconds=120)

    with pytest.raises(ModelQuotaExhausted, match="quota is used up") as caught:
        limiter.acquire()
    assert caught.value.retry_after == pytest.approx(120)
    clock.now += 121
    limiter.acquire()


def test_waiting_never_runs_past_the_scans_time_limit():
    clock = Clock()
    limiter = clock.limiter(rpm=1)
    limiter.acquire()

    with pytest.raises(ModelThrottled, match=r"scan has .* s left, so the request was not sent"):
        call_within(Deadline(10), lambda: limiter.acquire())

    assert clock.sleeps == []  # nothing slept, nothing sent
    assert limiter.calls == 1


def test_a_wait_that_fits_the_time_limit_is_taken():
    clock = Clock()
    limiter = clock.limiter()
    limiter.penalize(2)

    call_within(Deadline(30), lambda: limiter.acquire())

    assert clock.sleeps == [pytest.approx(2.0)]


def test_a_limit_of_none_or_zero_is_not_enforced():
    clock = Clock()
    limiter = clock.limiter(rpm=0, tpm=None, rpd=0)

    for _ in range(500):
        limiter.acquire(100_000)

    assert clock.sleeps == []


def test_the_token_estimate_uses_the_documented_characters_per_token():
    assert estimate_tokens("a" * 320) == 101
    assert estimate_tokens("") == 1


def test_one_limiter_is_shared_per_provider_and_model():
    one = limiter_for("https://a/v1|m", rpm=5, tpm=None, rpd=None, label="A")
    two = limiter_for("https://a/v1|m", rpm=5, tpm=None, rpd=None, label="A")
    other = limiter_for("https://a/v1|n", rpm=5, tpm=None, rpd=None, label="A")
    changed = limiter_for("https://a/v1|m", rpm=9, tpm=None, rpd=None, label="A")

    assert one is two and one is not other and changed is not one


# -- defaults and configuration ---------------------------------------------------------------------------
def test_presets_have_starting_limits_that_the_configuration_can_change_or_turn_off():
    class P:
        requests_per_minute = None
        tokens_per_minute = None
        requests_per_day = None

    groq = rate_limits(P, "groq", "llama", local=False)
    assert groq["requests_per_minute"] == RATE_DEFAULTS["groq"]["requests_per_minute"]
    assert groq["tokens_per_minute"] == RATE_DEFAULTS["groq"]["tokens_per_minute"]
    assert groq["requests_per_day"] is None

    free = rate_limits(P, "openrouter", "vendor/model:free", local=False)
    assert free["requests_per_day"] == OPENROUTER_FREE_PER_DAY
    paid = rate_limits(P, "openrouter", "vendor/model", local=False)
    assert paid["requests_per_day"] is None

    class Set:
        requests_per_minute = 5
        tokens_per_minute = 0  # off
        requests_per_day = 1000

    mine = rate_limits(Set, "groq", "llama", local=False)
    assert mine == {
        "requests_per_minute": 5,
        "tokens_per_minute": None,
        "requests_per_day": 1000,
    }


def test_a_server_on_this_machine_has_no_starting_limits_but_keeps_ones_that_are_set():
    class P:
        requests_per_minute = None
        tokens_per_minute = None
        requests_per_day = None

    assert set(rate_limits(P, "openai", "m", local=True).values()) == {None}

    class Set(P):
        requests_per_day = 7

    assert rate_limits(Set, "openai", "m", local=True)["requests_per_day"] == 7


def test_the_selector_gives_a_provider_client_a_shared_limiter_from_the_configuration(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", KEY)
    settings = ModelSettings.model_validate({"backend": "groq", "provider": {"model": "m-1"}})

    one = select_model(settings, backend="groq", probe=False)
    two = select_model(settings, backend="groq", probe=False)

    assert isinstance(one, OpenAICompat)
    assert one._limiter is two._limiter
    assert one._limiter.rpm == RATE_DEFAULTS["groq"]["requests_per_minute"]
    assert one._limiter.tpm == RATE_DEFAULTS["groq"]["tokens_per_minute"]


@pytest.mark.parametrize("field", ["requests_per_minute", "tokens_per_minute", "requests_per_day"])
def test_negative_limits_are_refused(field):
    with pytest.raises(ValueError):
        ModelSettings.model_validate({"provider": {field: -1}})


# -- the client against a scripted server ---------------------------------------------------------------
def _provider(**overrides: Any) -> ResolvedProvider:
    values: dict[str, Any] = {
        "backend": "groq",
        "label": "Groq",
        "base_url": "https://provider.example/v1",
        "model": "m-1",
        "api_key_env": "TEST_PROVIDER_KEY",
    }
    values.update(overrides)
    return ResolvedProvider(**values)


def _ok(tokens: int = 18) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": GOOD}, "finish_reason": "stop"}],
            "usage": {"total_tokens": tokens},
        },
    )


def _client(handler, clock: Clock, monkeypatch, **limits):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TEST_PROVIDER_KEY", KEY)
    seen: list[httpx.Request] = []

    def transport(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request, len(seen))

    client = OpenAICompat(
        _provider(),
        client=httpx.Client(transport=httpx.MockTransport(transport)),
        limiter=clock.limiter(**limits),
    )
    client.seen = seen  # type: ignore[attr-defined]
    return client


def test_a_free_tier_run_paces_itself_to_the_requests_a_minute_and_never_sees_a_429(monkeypatch):
    clock = Clock()
    client = _client(lambda r, n: _ok(), clock, monkeypatch, rpm=2)

    for _ in range(5):
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert len(client.seen) == 5  # type: ignore[attr-defined]
    assert sum(clock.sleeps) >= 120  # five requests at two a minute take two minutes of waiting


def test_usage_from_the_provider_is_used_for_the_token_budget(monkeypatch):
    clock = Clock()
    client = _client(lambda r, n: _ok(tokens=50), clock, monkeypatch, tpm=6000)

    for _ in range(10):
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    # Each prompt is estimated at several hundred tokens, so the estimates alone would not fit
    # ten calls in a minute. The provider says 50 each, and that is what is counted.
    assert clock.sleeps == []


def test_heavy_usage_from_the_provider_makes_the_next_call_wait(monkeypatch):
    clock = Clock()
    client = _client(lambda r, n: _ok(tokens=5500), clock, monkeypatch, tpm=6000)

    client.generate_json("s", "u", SEMANTIC_SCHEMA)
    client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert clock.sleeps and clock.sleeps[0] == pytest.approx(60.0)


def test_a_daily_quota_answer_stops_the_client_and_later_calls_send_nothing(monkeypatch):
    clock = Clock()
    quota = httpx.Response(
        429, json={"error": {"message": f"Rate limit reached: tokens per day (TPD). key {KEY}"}}
    )
    client = _client(lambda r, n: quota, clock, monkeypatch)

    with pytest.raises(ModelQuotaExhausted, match="quota for m-1 is used up") as first:
        client.generate_json("s", "u", SEMANTIC_SCHEMA)
    with pytest.raises(ModelQuotaExhausted):
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert len(client.seen) == 1  # type: ignore[attr-defined]  # the second call was not sent
    assert KEY not in str(first.value)
    assert clock.sleeps == []


def test_a_retry_after_of_hours_is_a_quota_not_a_wait(monkeypatch):
    clock = Clock()
    client = _client(
        lambda r, n: httpx.Response(429, headers={"Retry-After": "7200"}, json={}),
        clock,
        monkeypatch,
    )

    with pytest.raises(ModelQuotaExhausted, match=r"resets in about 2\.0 hours") as caught:
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert caught.value.retry_after == 7200


def test_the_reset_header_is_read_when_there_is_no_retry_after(monkeypatch):
    clock = Clock()
    reset_ms = int((time.time() + 5400) * 1000)
    client = _client(
        lambda r, n: httpx.Response(
            429,
            headers={"X-RateLimit-Reset": str(reset_ms)},
            json={"error": {"message": "free-models-per-day limit reached"}},
        ),
        clock,
        monkeypatch,
    )

    with pytest.raises(ModelQuotaExhausted) as caught:
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert caught.value.retry_after == pytest.approx(5400, abs=5)


def test_a_429_with_a_short_retry_after_waits_that_long_and_succeeds(monkeypatch):
    clock = Clock()

    def handler(request: httpx.Request, n: int) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "3"}, json={}) if n == 1 else _ok()

    client = _client(handler, clock, monkeypatch)

    assert client.generate_json("s", "u", SEMANTIC_SCHEMA)["declared_intent"] == "x"
    assert clock.sleeps == [pytest.approx(3.0)]


def test_a_429_makes_other_callers_wait_too(monkeypatch):
    clock = Clock()

    def handler(request: httpx.Request, n: int) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "9"}, json={}) if n == 1 else _ok()

    client = _client(handler, clock, monkeypatch)
    client.generate_json("s", "u", SEMANTIC_SCHEMA)
    # The shared limiter holds the penalty it was given, so a second client on it would wait too.
    assert client._limiter.waited_s >= 9


def test_back_off_after_a_429_without_a_wait_is_capped(monkeypatch):
    clock = Clock()
    client = _client(lambda r, n: httpx.Response(429, json={}), clock, monkeypatch)
    client._max_429_retries = 8

    with pytest.raises(ModelRateLimited):
        client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert max(clock.sleeps) <= 30 * 1.25  # the cap, with jitter
    assert len(clock.sleeps) == 8


def test_a_wait_the_scan_cannot_afford_is_not_slept_and_the_request_is_not_sent(monkeypatch):
    clock = Clock()
    client = _client(lambda r, n: _ok(), clock, monkeypatch, rpm=1)
    client.generate_json("s", "u", SEMANTIC_SCHEMA)

    with pytest.raises(ModelThrottled):
        call_within(Deadline(10), lambda: client.generate_json("s", "u", SEMANTIC_SCHEMA))

    assert len(client.seen) == 1  # type: ignore[attr-defined]
    assert clock.sleeps == []


# -- the Gemini client ---------------------------------------------------------------------------------------
def _gemini(handler, clock: Clock, **limits) -> GemmaCloud:
    return GemmaCloud(
        api_key=KEY,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        limiter=clock.limiter(**limits),
    )


def test_the_gemini_client_paces_to_its_limits():
    clock = Clock()
    body = {"candidates": [{"content": {"parts": [{"text": GOOD}]}}]}
    client = _gemini(lambda r: httpx.Response(200, json=body), clock, rpm=1)

    client.generate_json("s", "u", SEMANTIC_SCHEMA)
    client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert clock.sleeps == [pytest.approx(60.0)]


def test_the_gemini_client_stops_on_a_daily_quota_answer():
    clock = Clock()
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(1)
        return httpx.Response(429, json={"error": {"message": "Quota exceeded: requests per day"}})

    client = _gemini(handler, clock)

    for _ in range(2):
        with pytest.raises(ModelQuotaExhausted, match="gemini's quota"):
            client.generate_json("s", "u", SEMANTIC_SCHEMA)

    assert len(seen) == 1


def test_the_gemini_client_reports_a_short_rate_limit_with_its_wait():
    clock = Clock()
    client = _gemini(lambda r: httpx.Response(429, headers={"Retry-After": "12"}, json={}), clock)

    with pytest.raises(ModelRateLimited, match="asked for 12 s"):
        client.generate_json("s", "u", SEMANTIC_SCHEMA)


# -- the semantic stage ---------------------------------------------------------------------------------
def _skill(tmp_path: Path, name: str = "demo") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Print a note.\n---\n\nHello.\n", encoding="utf-8"
    )
    return root


class Stopped:
    """A model whose provider has run out of quota."""

    backend = "groq"
    model_version = "groq:m|test"

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def generate_json(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        raise self.error

    def health(self) -> bool:
        return True


def test_a_quota_stop_degrades_the_stage_with_one_note_and_stops_asking(tmp_path):
    package = parse_skill(_skill(tmp_path))
    model = Stopped(
        ModelQuotaExhausted("Groq's quota for m-1 is used up (it resets in about 2.0 hours)")
    )

    result = analyze_semantics(package, scan_anchors(package), model)

    assert result.degraded
    assert model.calls == 1
    limit = (result.telemetry or {})["provider_limit"]
    assert limit["kind"] == "daily-quota" and limit["provider"] == "groq"
    notes = [f for f in result.findings if f.finding_type == "provider-limit"]
    assert len(notes) == 1 and notes[0].severity is Severity.NOTE
    assert "daily quota" in notes[0].message and "resets in about 2.0 hours" in notes[0].message


def test_throttling_is_recorded_as_throttling_not_as_a_quota(tmp_path):
    package = parse_skill(_skill(tmp_path))
    model = Stopped(ModelThrottled("pacing needs 60 s and the scan has 5 s left"))

    result = analyze_semantics(package, scan_anchors(package), model)

    assert (result.telemetry or {})["provider_limit"]["kind"] == "throttled"
    assert result.stage is Stage.SEMANTIC and result.degraded


# -- the exit code ------------------------------------------------------------------------------------------
class _Verdict:
    verdict = None


class _Outcome:
    def __init__(self, *, limited: bool, fails: bool) -> None:
        self.limited = limited
        self.fails = fails
        self.verdict = _Verdict()
        self.stage_results: list[Any] = []


def test_a_quota_stop_is_its_own_exit_code_and_is_never_a_safe_run(monkeypatch):
    monkeypatch.setattr(
        cli, "_provider_limit", lambda o: {"kind": "daily-quota"} if o.limited else None
    )
    monkeypatch.setattr(cli, "is_unscanned", lambda verdict, stages: True)
    monkeypatch.setattr(
        cli, "_outcome_exit", lambda o, fail_on: ExitCode.VERDICT if o.fails else ExitCode.OK
    )
    cut_short = [_Outcome(limited=True, fails=True), _Outcome(limited=True, fails=True)]

    # Skills the quota cut short are UNSCANNED, which fails --fail-on, but the run says why.
    assert cli._run_exit_code(cut_short, "suspicious", None) is ExitCode.MODEL_UNAVAILABLE
    # A skill the quota did not touch that fails on its own findings still wins: that is unsafe.
    untouched = _Outcome(limited=False, fails=True)
    assert cli._run_exit_code([untouched, *cut_short], "suspicious", None) is ExitCode.VERDICT
    # An operational failure wins over both.
    assert cli._run_exit_code(cut_short, "suspicious", ExitCode.OPERATIONAL) is ExitCode.OPERATIONAL
    # No quota involved: unchanged.
    clean = [_Outcome(limited=False, fails=False)]
    assert cli._run_exit_code(clean, "suspicious", None) is ExitCode.OK
