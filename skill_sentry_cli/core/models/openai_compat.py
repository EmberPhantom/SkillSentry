"""One client for every OpenAI-compatible chat server (I2).

OpenRouter, NVIDIA NIM, Groq, Cerebras, Mistral, GitHub Models, LM Studio, vLLM, llama.cpp and
Ollama's ``/v1`` endpoint all speak the same ``/chat/completions`` protocol. This client talks to
any of them, so a model is chosen by configuration and not by code.

Four things differ between servers, and this client handles each:

* **Structured output.** A server may enforce a JSON schema (``json_schema``), only promise
  valid JSON (``json_object``), or support neither. The client starts with the strongest mode
  allowed, steps down on an HTTP 400 or 422, and remembers what worked. The text is parsed and
  checked against the schema in every mode, so a server that ignores the request is still safe.
* **Reasoning models** write their thinking before the answer, in ``<think>`` tags or a
  separate field. The thinking is removed before the JSON is read.
* **Limits.** HTTP 429 is honoured once, using ``Retry-After``; a timeout and a reply cut at
  the output limit fail at once, because asking again repeats the cost and the result.
* **Keys.** The key is read from the environment variable the configuration names, when a
  request is made. It is sent in the ``Authorization`` header and is never stored on the client,
  put in a URL, logged, or included in an error message.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from skill_sentry_cli.core.contracts import ImageAnalysis
from skill_sentry_cli.core.models._json import parse_json_object, validate_json
from skill_sentry_cli.core.models.base import (
    ModelAuthError,
    ModelError,
    ModelNotFound,
    ModelRateLimited,
    ModelTimeout,
    ModelTruncated,
    ModelUnavailable,
)
from skill_sentry_cli.core.models.gemma_local import _image_prompt, _schema_prompt
from skill_sentry_cli.core.models.image_utils import ImagePreparationError, load_image_for_model
from skill_sentry_cli.core.models.profiles import ModelProfile, resolve_profile
from skill_sentry_cli.core.models.providers import ResolvedProvider

LADDER = ("json_schema", "json_object", "prompt")
_THINK_PAIR = re.compile(r"<(think|thinking|reasoning)>.*?</\1>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"^\s*<(think|thinking|reasoning)>", re.IGNORECASE)
_THINK_CLOSE = re.compile(r"</(think|thinking|reasoning)>", re.IGNORECASE)


class _FormatRejected(Exception):
    """The server refused ``response_format``; try the next, weaker mode."""


def strip_reasoning(text: str) -> str:
    """Remove ``<think>`` blocks, so a reasoning model's thinking is not read as the answer.

    Handles a closed block, a block with no opening tag (some chat templates add it), and an
    opening tag that was never closed (the whole remainder is thinking).
    """

    cleaned = _THINK_PAIR.sub("", text)
    if _THINK_OPEN.match(cleaned) and not _THINK_CLOSE.search(cleaned):
        return ""
    closes = list(_THINK_CLOSE.finditer(cleaned))
    if closes:
        cleaned = cleaned[closes[-1].end() :]
    return cleaned.strip()


def _strict_compatible(schema: Any) -> bool:
    """Strict schema mode needs every property required and no extras, at every level."""

    if not isinstance(schema, dict):
        return True
    if schema.get("type") == "object":
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is not False:
            return False
        if set(schema.get("required", [])) != set(properties):
            return False
        if not all(_strict_compatible(item) for item in properties.values()):
            return False
    return not (schema.get("type") == "array" and not _strict_compatible(schema.get("items")))


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        moment = parsedate_to_datetime(value)
        return max(0.0, moment.timestamp() - time.time())
    except (TypeError, ValueError):
        return None


class OpenAICompat:
    """A :class:`ModelClient` for any OpenAI-compatible chat server."""

    def __init__(
        self,
        provider: ResolvedProvider,
        *,
        timeout_s: float = 180.0,
        max_px: int = 1024,
        max_tokens: int = 2048,
        structured_output: str = "auto",
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retry_after_s: float = 30.0,
        profile: ModelProfile | None = None,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if not provider.model.strip():
            raise ValueError("a model id is required: set [model.provider] model")
        self._provider = provider
        # What this model can be asked for. The provider's own settings win over the profile.
        self.profile = profile or resolve_profile(provider.model)
        self.base_url = provider.base_url.rstrip("/")
        self.model = provider.model
        self.label = provider.label
        self.timeout_s = timeout_s
        self.max_px = max_px
        self.max_tokens = max_tokens
        # A configured mode is where the ladder starts; it only ever steps down from there.
        self._mode = "json_schema" if structured_output == "auto" else structured_output
        self._client = client or httpx.Client(timeout=timeout_s)
        self._owns_client = client is None
        self._sleep = sleep
        self._max_retry_after = max_retry_after_s
        self.last_usage: dict[str, int] = {}
        self.last_health_error: str | None = None

    # -- identity ---------------------------------------------------------------
    @property
    def backend(self) -> str:
        return self._provider.backend

    @property
    def model_version(self) -> str:
        """Cache identity: provider, model, and the options that change what it returns."""

        return (
            f"{self._provider.backend}:{self.model}|profile={self.profile.name}"
            f"|max_tokens={self.max_tokens}|temperature=0"
        )

    @property
    def configured(self) -> bool:
        return not self._provider.needs_key or bool(self._provider.api_key)

    @property
    def key_variable(self) -> str:
        """The name of the environment variable that holds the key (never the key)."""

        return self._provider.api_key_env

    @property
    def structured_mode(self) -> str:
        """The structured-output mode in use now (it can step down after a refusal)."""

        return self._mode

    def __repr__(self) -> str:
        return f"OpenAICompat(provider={self._provider.backend!r}, model={self.model!r})"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OpenAICompat:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- I2 -------------------------------------------------------------------------
    def generate_json(
        self, system: str, user: str, schema: dict[str, Any], retries: int = 1
    ) -> dict[str, Any]:
        self._require_key()
        prompt = _schema_prompt(user, schema)
        last_error: Exception | None = None
        for _ in range(max(0, retries) + 1):
            try:
                text = self._complete_with_ladder(system, prompt, schema)
                parsed = parse_json_object(text)
                validate_json(parsed, schema)
                return parsed
            except (ModelTimeout, ModelTruncated, ModelAuthError, ModelNotFound, ModelRateLimited):
                # Asking again repeats the cost and the result, or cannot succeed.
                raise
            except (ModelError, ValueError) as exc:
                last_error = exc
        if isinstance(last_error, ModelUnavailable):
            raise last_error
        raise ModelUnavailable(
            f"{self.label} returned no schema-valid JSON for {self.model}: {last_error}"
        ) from last_error

    def analyze_image(self, path: str | Path, prompt: str) -> ImageAnalysis:
        self._require_key()
        try:
            mime, encoded = load_image_for_model(path, max_px=self.max_px)
        except ImagePreparationError as exc:
            raise ModelUnavailable(str(exc)) from exc
        content = [
            {"type": "text", "text": _image_prompt(prompt)},
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{encoded}"}},
        ]
        last_error: Exception | None = None
        for _ in range(2):
            try:
                text = self._chat([{"role": "user", "content": content}], response_format=None)
                return ImageAnalysis.model_validate(parse_json_object(text))
            except (ModelTimeout, ModelTruncated, ModelAuthError, ModelNotFound, ModelRateLimited):
                raise
            except _FormatRejected as exc:  # pragma: no cover - no response_format is sent
                last_error = exc
            except (ModelError, ValueError) as exc:
                last_error = exc
        raise ModelUnavailable(
            f"{self.label} returned no valid image analysis for {self.model}"
        ) from last_error

    def health(self) -> bool:
        """Ready when the server answers ``/models`` and lists the configured model."""

        self.last_health_error = None
        if not self.configured:
            self.last_health_error = f"{self._provider.api_key_env} is not set"
            return False
        try:
            response = self._client.get(
                f"{self.base_url}/models",
                headers=self._headers(),
                timeout=min(self.timeout_s, 10.0),
            )
        except (httpx.HTTPError, OSError):
            self.last_health_error = f"cannot reach {self.label} at {self.base_url}"
            return False
        if response.status_code in (401, 403):
            self.last_health_error = f"{self.label} refused the credentials"
            return False
        if response.status_code != 200:
            self.last_health_error = f"{self.label} answered HTTP {response.status_code}"
            return False
        try:
            data = response.json()
        except ValueError:
            return True
        listed = data.get("data") if isinstance(data, dict) else None
        if isinstance(listed, list) and listed:
            ids = {item.get("id") for item in listed if isinstance(item, dict)}
            if ids and self.model not in ids:
                self.last_health_error = f"{self.label} does not list the model {self.model!r}"
                return False
        return True

    # -- internals --------------------------------------------------------------------
    def _require_key(self) -> None:
        if not self.configured:
            raise ModelUnavailable(
                f"{self._provider.api_key_env} is not set (the key for {self.label} is read from "
                "that environment variable)"
            )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", **self._provider.headers}
        key = self._provider.api_key
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def _scrub(self, text: str) -> str:
        """Remove the key from text that may reach a log, a report or the terminal."""

        key = self._provider.api_key
        return text.replace(key, "***") if len(key) >= 6 else text

    def _complete_with_ladder(self, system: str, prompt: str, schema: dict[str, Any]) -> str:
        messages = ([{"role": "system", "content": system}] if system else []) + [
            {"role": "user", "content": prompt}
        ]
        mode = self._mode
        while True:
            try:
                text = self._chat(messages, response_format=self._response_format(mode, schema))
            except _FormatRejected:
                position = LADDER.index(mode)
                if position + 1 >= len(LADDER):
                    raise ModelUnavailable(
                        f"{self.label} rejected the request for {self.model}"
                    ) from None
                mode = LADDER[position + 1]
                continue
            self._mode = mode  # remember what worked, so later calls start here
            return text

    @staticmethod
    def _response_format(mode: str, schema: dict[str, Any]) -> dict[str, Any] | None:
        if mode == "json_schema":
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": "skillsentry",
                    "strict": _strict_compatible(schema),
                    "schema": schema,
                },
            }
        if mode == "json_object":
            return {"type": "json_object"}
        return None

    def _chat(
        self, messages: list[dict[str, Any]], *, response_format: dict[str, Any] | None
    ) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if response_format is not None:
            body["response_format"] = response_format
        response = self._post("/chat/completions", body, has_format=response_format is not None)
        try:
            data = response.json()
        except ValueError as exc:
            raise ModelUnavailable(f"{self.label} sent a reply that is not JSON") from exc
        return self._read_choice(data)

    def _post(self, path: str, body: dict[str, Any], *, has_format: bool) -> httpx.Response:
        waited = False
        while True:
            try:
                response = self._client.post(
                    f"{self.base_url}{path}",
                    headers=self._headers(),
                    json=body,
                    timeout=self.timeout_s,
                )
            except httpx.TimeoutException as exc:
                raise ModelTimeout(
                    f"{self.label} did not answer within {self.timeout_s:g} s for {self.model}"
                ) from exc
            except (httpx.HTTPError, OSError) as exc:
                raise ModelUnavailable(f"cannot reach {self.label} at {self.base_url}") from exc
            status = response.status_code
            if status == 200:
                return response
            if status == 429:
                delay = _retry_after(response)
                if not waited and delay is not None and delay <= self._max_retry_after:
                    waited = True
                    self._sleep(delay)
                    continue
                raise ModelRateLimited(
                    f"{self.label} is rate limiting requests"
                    + (f"; it asked for {delay:g} s" if delay is not None else ""),
                    retry_after=delay,
                )
            detail = self._scrub(_error_message(response))
            if status in (401, 403):
                raise ModelAuthError(
                    f"{self.label} refused the credentials (HTTP {status}). Check the key in "
                    f"{self._provider.api_key_env or 'the provider settings'}"
                )
            if status == 404:
                raise ModelNotFound(
                    f"{self.label} has no such model or endpoint (HTTP 404) for {self.model!r}"
                    + (f": {detail}" if detail else "")
                )
            if status in (400, 422) and has_format:
                raise _FormatRejected()
            raise ModelUnavailable(
                f"{self.label} returned HTTP {status} for {self.model}"
                + (f": {detail}" if detail else "")
            )

    def _read_choice(self, data: Any) -> str:
        if not isinstance(data, dict):
            raise ModelUnavailable(f"{self.label} reply is not a JSON object")
        usage = data.get("usage")
        if isinstance(usage, dict):
            self.last_usage = {
                key: int(usage[key])
                for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                if isinstance(usage.get(key), int)
            }
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ModelUnavailable(f"{self.label} reply contained no choices")
        choice = choices[0]
        if choice.get("finish_reason") == "length":
            # Cut at max_tokens, so the JSON is incomplete: a failure, never a partial result.
            raise ModelTruncated(f"{self.label} output was truncated for {self.model}")
        message = choice.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        text = strip_reasoning(content) if isinstance(content, str) else ""
        if not text:
            reasoned = isinstance(message, dict) and any(
                message.get(key) for key in ("reasoning", "reasoning_content")
            )
            raise ModelUnavailable(
                f"{self.label} returned no answer for {self.model}"
                + (" (only reasoning text: raise max_tokens)" if reasoned else "")
            )
        return text


def _error_message(response: httpx.Response) -> str:
    """The provider's own message from an error body, shortened."""

    try:
        body = response.json()
    except ValueError:
        return ""
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        text = error.get("message")
    elif isinstance(error, str):
        text = error
    else:
        text = body.get("message") if isinstance(body, dict) else None
    return " ".join(str(text).split())[:200] if text else ""


__all__ = ["LADDER", "OpenAICompat", "strip_reasoning"]
