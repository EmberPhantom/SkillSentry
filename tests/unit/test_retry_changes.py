"""A retry after a refused reply must change the request, and stop when the reply does not."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from skill_sentry_cli.core.models._json import RETRY_MARKER, retry_prompt
from skill_sentry_cli.core.models.base import ModelUnavailable
from skill_sentry_cli.core.models.gemma_cloud import GemmaCloud
from skill_sentry_cli.core.models.gemma_local import GemmaLocal
from skill_sentry_cli.core.models.limiter import reset_limiters
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.providers import ResolvedProvider
from skill_sentry_cli.core.semantic.prompts import SEMANTIC_SCHEMA

KEY = "sk-test-KEY-0123456789abcdef"
GOOD = {
    "declared_intent": "x",
    "actual_capabilities": [],
    "suspicious_patterns": [],
    "is_deceptive": False,
    "confidence": 0.5,
}
BAD = json.dumps({"declared_intent": "x", "confidence": "high"})  # wrong type, keys missing


@pytest.fixture(autouse=True)
def _fresh():
    reset_limiters()
    yield
    reset_limiters()


class Backend:
    """One kind of client behind a scripted server that records every request body."""

    def __init__(self, kind: str, replies: list[str | int], monkeypatch) -> None:  # type: ignore[no-untyped-def]
        self.kind = kind
        self.replies = list(replies)
        self.prompts: list[str] = []
        monkeypatch.setenv("TEST_KEY", KEY)
        transport = httpx.MockTransport(self._handle)
        client = httpx.Client(transport=transport)
        if kind == "openai":
            provider = ResolvedProvider(
                backend="groq",
                label="Groq",
                base_url="https://p.example/v1",
                model="m",
                api_key_env="TEST_KEY",
            )
            self.model: Any = OpenAICompat(provider, client=client)
        elif kind == "local":
            self.model = GemmaLocal(base_url="http://o.example", client=client)
        else:
            self.model = GemmaCloud(api_key=KEY, client=client)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if self.kind == "openai":
            self.prompts.append(body["messages"][-1]["content"])
        elif self.kind == "local":
            self.prompts.append(body["prompt"])
        else:
            self.prompts.append(body["contents"][0]["parts"][0]["text"])
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, int):
            return httpx.Response(reply, json={})
        if self.kind == "openai":
            return httpx.Response(
                200, json={"choices": [{"message": {"content": reply}, "finish_reason": "stop"}]}
            )
        if self.kind == "local":
            return httpx.Response(
                200, json={"response": reply, "done": True, "done_reason": "stop"}
            )
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": reply}]}}]})


KINDS = ["openai", "local", "cloud"]


@pytest.mark.parametrize("kind", KINDS)
def test_the_retry_says_why_the_reply_was_refused_and_can_recover(kind, monkeypatch):
    backend = Backend(kind, [BAD, json.dumps(GOOD)], monkeypatch)

    result = backend.model.generate_json("s", "the skill", SEMANTIC_SCHEMA)

    assert result["confidence"] == 0.5
    first, second = backend.prompts
    assert RETRY_MARKER not in first
    assert RETRY_MARKER in second and second.startswith(first)  # the same request, plus a reminder
    assert "ONE JSON object only" in second
    assert KEY not in second


@pytest.mark.parametrize("kind", KINDS)
def test_a_byte_identical_refused_reply_stops_further_retries(kind, monkeypatch):
    backend = Backend(kind, [BAD], monkeypatch)  # the same refused reply every time

    with pytest.raises(ModelUnavailable, match="no schema-valid JSON"):
        backend.model.generate_json("s", "the skill", SEMANTIC_SCHEMA, retries=5)

    # The first try, one retry with the reminder, and then it stopped: not six requests.
    assert len(backend.prompts) == 2


@pytest.mark.parametrize("kind", KINDS)
def test_a_different_refused_reply_keeps_trying_up_to_the_retry_count(kind, monkeypatch):
    replies = [json.dumps({"x": i}) for i in range(5)]
    backend = Backend(kind, replies, monkeypatch)

    with pytest.raises(ModelUnavailable):
        backend.model.generate_json("s", "the skill", SEMANTIC_SCHEMA, retries=2)

    assert len(backend.prompts) == 3


@pytest.mark.parametrize("kind", KINDS)
def test_a_server_error_is_retried_with_the_same_request(kind, monkeypatch):
    backend = Backend(kind, [500, json.dumps(GOOD)], monkeypatch)

    assert backend.model.generate_json("s", "the skill", SEMANTIC_SCHEMA)["confidence"] == 0.5

    first, second = backend.prompts
    assert first == second and RETRY_MARKER not in second  # nothing was refused, so nothing to say


@pytest.mark.parametrize("kind", KINDS)
def test_no_retry_is_made_when_none_is_asked_for(kind, monkeypatch):
    backend = Backend(kind, [BAD], monkeypatch)

    with pytest.raises(ModelUnavailable):
        backend.model.generate_json("s", "the skill", SEMANTIC_SCHEMA, retries=0)

    assert len(backend.prompts) == 1


def test_the_reminder_is_short_and_carries_the_reason_on_one_line():
    text = retry_prompt("PROMPT", ValueError("$.confidence:\n  expected number " + "x" * 500))

    assert text.startswith("PROMPT\n\n") and RETRY_MARKER in text
    reason = text.split("(", 1)[1].split(")", 1)[0]
    assert "\n" not in reason and len(reason) <= 200
