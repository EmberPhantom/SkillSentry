"""Pacing under a tokens-a-minute limit: a call is reserved at what it really costs."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from skill_sentry_cli.core.models.limiter import RateLimiter, reset_limiters
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.profiles import PROFILES
from skill_sentry_cli.core.models.providers import ResolvedProvider
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
GROQ_TPM = 6000


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def _fresh():
    reset_limiters()
    yield
    reset_limiters()


def _client(handler, clock: Clock, monkeypatch, *, profile: str = "small", **limits):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TEST_KEY", KEY)
    provider = ResolvedProvider(
        backend="groq",
        label="Groq",
        base_url="https://provider.example/v1",
        model="m-1",
        api_key_env="TEST_KEY",
    )
    return OpenAICompat(
        provider,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        limiter=RateLimiter(
            clock=clock, sleep=clock.sleep, jitter=lambda: 0.0, label="Groq", **limits
        ),
        max_tokens=PROFILES[profile].max_output_tokens,
        profile=PROFILES[profile],
    )


def _reply(prompt_tokens: int, completion_tokens: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": GOOD}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        },
    )


# A skill's prompt is long in characters and short in tokens: the character estimate is well
# above what the provider counts, which is what used to make a scan stall.
BIG_PROMPT = "word " * 1600  # 8,000 characters


def test_ten_small_skills_finish_in_seconds_under_a_6000_tokens_a_minute_limit(monkeypatch):
    clock = Clock()
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(1)
        return _reply(prompt_tokens=350, completion_tokens=50)  # 400 tokens each: 4,000 in all

    client = _client(handler, clock, monkeypatch, tpm=GROQ_TPM, rpm=30)

    for _ in range(10):
        client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    assert len(seen) == 10
    # Ten calls of 400 tokens fit the 6,000-token minute. Nothing should wait, let alone a minute.
    assert sum(clock.sleeps) < 5, clock.sleeps


def test_the_reservation_is_not_the_reply_limit(monkeypatch):
    clock = Clock()
    client = _client(lambda r: _reply(350, 50), clock, monkeypatch, tpm=GROQ_TPM)
    assert client.max_tokens >= 1536  # a large reply limit...

    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)
    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)
    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    # ...does not reserve a thousand tokens a call: three calls need no wait.
    assert clock.sleeps == []


def test_the_estimate_is_learned_from_the_providers_usage(monkeypatch):
    clock = Clock()
    client = _client(lambda r: _reply(350, 50), clock, monkeypatch, tpm=GROQ_TPM)

    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)
    first = client._in_ratio
    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    assert first < 0.6  # the provider counted far fewer tokens than the character estimate
    assert client._in_ratio <= first
    assert 30 <= client._out_tokens < 200  # the reply cost is learned, not the cap


def test_a_reasoning_model_reserves_for_its_longer_reply_until_it_has_shown_its_cost(monkeypatch):
    clock = Clock()
    plain = _client(lambda r: _reply(350, 50), clock, monkeypatch, profile="small")
    reasoning = _client(lambda r: _reply(350, 50), clock, monkeypatch, profile="reasoning")

    assert plain._out_tokens == 200 and reasoning._out_tokens == 1200


def test_a_real_overshoot_still_gets_a_429_absorbed_and_every_call_finishes(monkeypatch):
    """The provider counts more than SkillSentry thinks (its limit is 3,000 a minute and it counts
    900 a call, and a call takes 10 s). It answers 429 with the wait; the client waits that long
    and carries on."""

    clock = Clock()
    spent: list[tuple[float, int]] = []  # (time, tokens) the provider has counted
    answered, refused = [], []

    def handler(request: httpx.Request) -> httpx.Response:
        window = [(t, n) for t, n in spent if clock.now - t < 60]
        clock.now += 10  # the call itself takes time
        if sum(n for _, n in window) + 900 > 3000:
            wait = 60 - (clock.now - window[0][0])
            refused.append(wait)
            return httpx.Response(
                429,
                headers={"Retry-After": f"{max(1, round(wait))}"},
                json={"error": {"message": "Rate limit reached for tokens per minute (TPM)"}},
            )
        spent.append((clock.now, 900))
        answered.append(1)
        return _reply(prompt_tokens=800, completion_tokens=100)

    # SkillSentry's own limit is looser than the provider's, so the provider has to push back.
    client = _client(handler, clock, monkeypatch, tpm=100_000)

    for _ in range(6):
        client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    assert len(answered) == 6  # every call finished, none raised
    assert refused, "the provider never pushed back, so the test proves nothing"
    assert clock.sleeps and max(clock.sleeps) <= 30  # waits were the provider's, capped


def test_a_429_gives_back_its_reservation_so_the_retry_is_not_blocked(monkeypatch):
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, json={})
        return _reply(350, 50)

    client = _client(handler, clock, monkeypatch, tpm=3000)

    client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    assert len(calls) == 2
    assert clock.sleeps == [pytest.approx(2.0)]  # the 2 s the provider asked, not a minute


def test_a_request_that_does_not_fit_the_minute_waits_for_what_it_needs(monkeypatch):
    clock = Clock()
    heavy: dict[str, Any] = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        heavy["n"] += 1
        return _reply(prompt_tokens=2400, completion_tokens=300)  # 2,700 a call

    client = _client(handler, clock, monkeypatch, tpm=GROQ_TPM)

    for _ in range(3):
        client.generate_json("s", BIG_PROMPT, SEMANTIC_SCHEMA)

    assert heavy["n"] == 3 and clock.sleeps  # the real cost still paces: 8,100 > 6,000
