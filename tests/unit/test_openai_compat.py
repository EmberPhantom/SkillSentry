"""The OpenAI-compatible client, against a fake server: modes, reasoning text, limits, keys."""

from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from PIL import Image
from skill_sentry_cli.core.models.base import (
    ModelAuthError,
    ModelNotFound,
    ModelRateLimited,
    ModelTimeout,
    ModelTruncated,
    ModelUnavailable,
)
from skill_sentry_cli.core.models.openai_compat import (
    OpenAICompat,
    _strict_compatible,
    strip_reasoning,
)
from skill_sentry_cli.core.models.providers import ResolvedProvider
from skill_sentry_cli.core.semantic.prompts import SEMANTIC_SCHEMA

KEY = "sk-test-KEY-0123456789abcdef"
SCHEMA = {
    "type": "object",
    "required": ["is_deceptive", "confidence"],
    "properties": {
        "is_deceptive": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "additionalProperties": False,
}
GOOD = json.dumps({"is_deceptive": False, "confidence": 0.5})


def _provider(**overrides: Any) -> ResolvedProvider:
    values: dict[str, Any] = {
        "backend": "openrouter",
        "label": "OpenRouter",
        "base_url": "https://provider.example/api/v1",
        "model": "vendor/model-x",
        "api_key_env": "TEST_PROVIDER_KEY",
        "headers": {"X-Title": "SkillSentry"},
        "local": False,
    }
    values.update(overrides)
    return ResolvedProvider(**values)


def _reply(content: Any = GOOD, *, finish: str = "stop", **extra: Any) -> httpx.Response:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    message.update(extra)
    return httpx.Response(
        200,
        json={
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        },
    )


class Server:
    """A scripted OpenAI-compatible server that records what it was sent."""

    def __init__(self, *replies: Any) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.content:
            self.bodies.append(json.loads(request.content))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if callable(reply):
            return reply(request)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _client(
    server: Server, monkeypatch: pytest.MonkeyPatch, *, key: str | None = KEY, **kwargs: Any
):  # type: ignore[no-untyped-def]
    if key is None:
        monkeypatch.delenv("TEST_PROVIDER_KEY", raising=False)
    else:
        monkeypatch.setenv("TEST_PROVIDER_KEY", key)
    sleeps: list[float] = []
    provider = kwargs.pop("provider", None) or _provider()
    client = OpenAICompat(
        provider,
        client=httpx.Client(transport=httpx.MockTransport(server)),
        sleep=sleeps.append,
        **kwargs,
    )
    client.sleeps = sleeps  # type: ignore[attr-defined]
    return client


def _format_of(body: dict[str, Any]) -> str:
    fmt = body.get("response_format")
    return "none" if fmt is None else fmt["type"]


# -- structured output ladder ----------------------------------------------------
def test_json_schema_is_the_first_choice_and_carries_the_schema(monkeypatch):
    server = Server(_reply())
    client = _client(server, monkeypatch)

    assert client.generate_json("system", "user", SCHEMA)["confidence"] == 0.5

    body = server.bodies[0]
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert body["response_format"]["json_schema"]["strict"] is True
    assert (
        body["temperature"] == 0
        and body["max_tokens"] == 2048
        and body["model"] == "vendor/model-x"
    )
    assert body["messages"][0] == {"role": "system", "content": "system"}
    assert client.structured_mode == "json_schema"


def test_a_schema_that_strict_mode_cannot_take_is_sent_non_strict():
    assert _strict_compatible(SCHEMA) is True
    assert _strict_compatible(SEMANTIC_SCHEMA) is False  # optional file/line in the items


def test_a_400_on_json_schema_steps_down_to_json_object_and_remembers(monkeypatch):
    def reject_schema(request: httpx.Request) -> httpx.Response:
        fmt = json.loads(request.content).get("response_format", {}).get("type")
        if fmt == "json_schema":
            return httpx.Response(
                400, json={"error": {"message": "response_format json_schema unsupported"}}
            )
        return _reply()

    server = Server(reject_schema)
    client = _client(server, monkeypatch)

    client.generate_json("s", "u", SCHEMA)
    client.generate_json("s", "u", SCHEMA)

    assert [_format_of(b) for b in server.bodies] == ["json_schema", "json_object", "json_object"]
    assert client.structured_mode == "json_object"


def test_a_400_on_every_response_format_falls_back_to_plain_prompting(monkeypatch):
    def only_plain(request: httpx.Request) -> httpx.Response:
        if "response_format" in json.loads(request.content):
            return httpx.Response(
                400, json={"error": {"message": "unknown parameter response_format"}}
            )
        return _reply("Here you go:\n```json\n" + GOOD + "\n```")

    server = Server(only_plain)
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA)["is_deceptive"] is False

    assert [_format_of(b) for b in server.bodies] == ["json_schema", "json_object", "none"]
    # The schema is in the prompt itself, so a server that enforces nothing still knows it.
    assert "JSON Schema" in server.bodies[-1]["messages"][-1]["content"]
    assert client.structured_mode == "prompt"


def test_a_400_with_no_format_left_is_an_error(monkeypatch):
    server = Server(httpx.Response(400, json={"error": {"message": "bad request"}}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelUnavailable, match="HTTP 400"):
        client.generate_json("s", "u", SCHEMA)

    # The whole ladder was tried, then the call was retried once like any other failure.
    assert [_format_of(b) for b in server.bodies][:3] == ["json_schema", "json_object", "none"]


def test_a_configured_mode_is_where_the_ladder_starts(monkeypatch):
    server = Server(_reply())
    client = _client(server, monkeypatch, structured_output="json_object")

    client.generate_json("s", "u", SCHEMA)

    assert [_format_of(b) for b in server.bodies] == ["json_object"]


def test_a_server_that_ignores_the_schema_is_still_checked(monkeypatch):
    wrong = json.dumps({"is_deceptive": "maybe", "confidence": 7})
    server = Server(_reply(wrong), _reply(GOOD))
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA)["confidence"] == 0.5
    assert len(server.bodies) == 2  # the first reply failed validation and was retried once


# -- reasoning text ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<think>let me see</think>" + GOOD, GOOD),
        ("<think>\nmulti\nline\n</think>\n\n" + GOOD, GOOD),
        ("<THINK>x</THINK>" + GOOD, GOOD),
        ("<thinking>x</thinking>" + GOOD, GOOD),
        ("reasoning without an opening tag</think>" + GOOD, GOOD),
        ("<think>a</think><think>b</think>" + GOOD, GOOD),
        (GOOD, GOOD),
        ("<think>never closed and no answer", ""),
    ],
)
def test_strip_reasoning(raw: str, expected: str):
    assert strip_reasoning(raw) == expected


def test_a_reasoning_model_reply_is_read_after_its_thinking(monkeypatch):
    server = Server(
        _reply('<think>{"decoy": true}</think>\n' + GOOD, reasoning_content="more thinking")
    )
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA) == json.loads(GOOD)


def test_content_that_is_a_list_of_parts_is_joined(monkeypatch):
    server = Server(
        _reply([{"type": "text", "text": GOOD[:10]}, {"type": "text", "text": GOOD[10:]}])
    )

    assert _client(server, monkeypatch).generate_json("s", "u", SCHEMA) == json.loads(GOOD)


def test_only_reasoning_and_no_answer_says_to_raise_max_tokens(monkeypatch):
    server = Server(_reply("", reasoning="thinking out loud"))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelUnavailable, match="only reasoning text: raise max_tokens"):
        client.generate_json("s", "u", SCHEMA, retries=0)


# -- limits and failures -----------------------------------------------------------------
def test_429_with_retry_after_waits_once_and_succeeds(monkeypatch):
    server = Server(httpx.Response(429, headers={"Retry-After": "2"}, json={}), _reply())
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA)["confidence"] == 0.5
    assert client.sleeps == [2.0]  # type: ignore[attr-defined]
    assert len(server.bodies) == 2


def test_429_with_an_http_date_is_honoured(monkeypatch):
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=3), usegmt=True)
    server = Server(httpx.Response(429, headers={"Retry-After": when}, json={}), _reply())
    client = _client(server, monkeypatch)

    client.generate_json("s", "u", SCHEMA)

    assert 0 < client.sleeps[0] <= 3.5  # type: ignore[attr-defined]


def test_429_twice_is_a_rate_limit_error_carrying_the_wait(monkeypatch):
    server = Server(httpx.Response(429, headers={"Retry-After": "1"}, json={}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelRateLimited) as caught:
        client.generate_json("s", "u", SCHEMA)

    assert caught.value.retry_after == 1.0
    assert len(server.bodies) == 2  # one wait, one retry, then it stops


def test_a_wait_longer_than_the_cap_is_not_slept(monkeypatch):
    server = Server(httpx.Response(429, headers={"Retry-After": "600"}, json={}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelRateLimited) as caught:
        client.generate_json("s", "u", SCHEMA)

    assert caught.value.retry_after == 600.0
    assert client.sleeps == []  # type: ignore[attr-defined]
    assert len(server.bodies) == 1


def test_429_without_a_wait_is_not_retried(monkeypatch):
    server = Server(httpx.Response(429, json={}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelRateLimited) as caught:
        client.generate_json("s", "u", SCHEMA)

    assert caught.value.retry_after is None
    assert len(server.bodies) == 1


def test_a_reply_cut_at_max_tokens_fails_at_once(monkeypatch):
    server = Server(_reply('{"is_dec', finish="length"))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelTruncated, match="truncated"):
        client.generate_json("s", "u", SCHEMA, retries=3)

    assert len(server.bodies) == 1


def test_a_timeout_fails_at_once(monkeypatch):
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    server = Server(slow)
    client = _client(server, monkeypatch)

    with pytest.raises(ModelTimeout, match="did not answer within"):
        client.generate_json("s", "u", SCHEMA, retries=3)

    assert len(server.requests) == 1


def test_401_is_an_auth_error_and_names_the_variable_not_the_key(monkeypatch):
    server = Server(httpx.Response(401, json={"error": {"message": f"bad key {KEY}"}}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelAuthError) as caught:
        client.generate_json("s", "u", SCHEMA, retries=3)

    assert "TEST_PROVIDER_KEY" in str(caught.value)
    assert KEY not in str(caught.value)
    assert len(server.requests) == 1


def test_404_is_not_found_and_is_not_retried(monkeypatch):
    server = Server(httpx.Response(404, json={"error": {"message": "model not found"}}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelNotFound, match="vendor/model-x"):
        client.generate_json("s", "u", SCHEMA, retries=3)

    assert len(server.requests) == 1


def test_a_server_error_is_retried_once_and_can_recover(monkeypatch):
    server = Server(httpx.Response(500, json={"error": "boom"}), _reply())
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA)["confidence"] == 0.5
    assert len(server.requests) == 2


def test_a_server_error_that_echoes_the_key_is_scrubbed(monkeypatch):
    server = Server(httpx.Response(502, json={"error": {"message": f"upstream said Bearer {KEY}"}}))
    client = _client(server, monkeypatch)

    with pytest.raises(ModelUnavailable) as caught:
        client.generate_json("s", "u", SCHEMA)

    assert KEY not in str(caught.value)
    assert "***" in str(caught.value)


def test_a_malformed_reply_is_retried_once(monkeypatch):
    server = Server(_reply("not json"), _reply(GOOD))
    client = _client(server, monkeypatch)

    assert client.generate_json("s", "u", SCHEMA)["confidence"] == 0.5
    assert len(server.bodies) == 2


def test_usage_is_recorded(monkeypatch):
    client = _client(Server(_reply()), monkeypatch)

    client.generate_json("s", "u", SCHEMA)

    assert client.last_usage == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


# -- keys ----------------------------------------------------------------------------------
def test_the_key_goes_in_the_authorization_header_and_nowhere_else(monkeypatch):
    server = Server(_reply())
    client = _client(server, monkeypatch)

    client.generate_json("s", "u", SCHEMA)

    request = server.requests[0]
    assert request.headers["Authorization"] == f"Bearer {KEY}"
    assert request.headers["X-Title"] == "SkillSentry"
    assert KEY not in str(request.url)
    assert KEY not in request.content.decode()
    assert KEY not in repr(client) and KEY not in client.model_version and KEY not in client.backend


def test_a_missing_key_is_an_error_that_names_the_variable_and_sends_nothing(monkeypatch):
    server = Server(_reply())
    client = _client(server, monkeypatch, key=None)

    assert client.configured is False
    with pytest.raises(ModelUnavailable, match="TEST_PROVIDER_KEY is not set"):
        client.generate_json("s", "u", SCHEMA)

    assert server.requests == []


def test_a_local_server_needs_no_key_and_sends_none(monkeypatch):
    server = Server(_reply())
    provider = _provider(backend="openai-local", local=True, api_key_env="")
    client = _client(server, monkeypatch, key=None, provider=provider)

    assert client.configured is True
    client.generate_json("s", "u", SCHEMA)

    assert "Authorization" not in server.requests[0].headers


def test_the_key_is_read_when_a_request_is_made_not_when_the_client_is_built(monkeypatch):
    server = Server(_reply())
    client = _client(server, monkeypatch, key=None)
    monkeypatch.setenv("TEST_PROVIDER_KEY", "later-key-value-123")

    client.generate_json("s", "u", SCHEMA)

    assert server.requests[0].headers["Authorization"] == "Bearer later-key-value-123"


# -- health and images ----------------------------------------------------------------------
def test_health_is_true_when_the_model_is_listed(monkeypatch):
    server = Server(httpx.Response(200, json={"data": [{"id": "vendor/model-x"}, {"id": "other"}]}))
    client = _client(server, monkeypatch)

    assert client.health() is True
    assert server.requests[0].url.path.endswith("/models")


def test_health_is_false_when_the_model_is_not_listed(monkeypatch):
    server = Server(httpx.Response(200, json={"data": [{"id": "other"}]}))
    client = _client(server, monkeypatch)

    assert client.health() is False
    assert "does not list the model" in (client.last_health_error or "")


def test_health_is_false_on_401_and_never_raises(monkeypatch):
    client = _client(Server(httpx.Response(401, json={})), monkeypatch)
    assert client.health() is False
    assert "refused the credentials" in (client.last_health_error or "")

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    assert _client(Server(down), monkeypatch).health() is False


def test_health_without_a_key_is_false_and_makes_no_request(monkeypatch):
    server = Server(httpx.Response(200, json={}))
    client = _client(server, monkeypatch, key=None)

    assert client.health() is False
    assert server.requests == []


def test_an_image_is_sent_as_a_data_uri(monkeypatch, tmp_path: Path):
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (255, 255, 255)).save(buffer, "PNG")
    image = tmp_path / "a.png"
    image.write_bytes(buffer.getvalue())
    server = Server(_reply(json.dumps({"ocr": "hello", "bboxes": [], "findings": []})))
    client = _client(server, monkeypatch)

    analysis = client.analyze_image(image, "look")

    assert analysis.ocr == "hello"
    parts = server.bodies[0]["messages"][0]["content"]
    uri = next(p for p in parts if p["type"] == "image_url")["image_url"]["url"]
    assert uri.startswith("data:image/") and base64.b64decode(uri.split(",", 1)[1])
    assert "response_format" not in server.bodies[0]


def test_an_image_request_that_times_out_is_not_retried(monkeypatch, tmp_path: Path):
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16)).save(buffer, "PNG")
    (tmp_path / "a.png").write_bytes(buffer.getvalue())

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    server = Server(slow)
    with pytest.raises(ModelTimeout):
        _client(server, monkeypatch).analyze_image(tmp_path / "a.png", "look")

    assert len(server.requests) == 1
