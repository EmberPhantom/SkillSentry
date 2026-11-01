"""Ollama/Gemini I2 clients and backend selection, without live services."""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import httpx
import pytest
from PIL import Image
from skillsentry.core.config import ModelSettings
from skillsentry.core.models.base import ModelUnavailable
from skillsentry.core.models.gemma_cloud import GemmaCloud
from skillsentry.core.models.gemma_local import GemmaLocal
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.models.selector import select_model

SEMANTIC_SCHEMA = {
    "type": "object",
    "required": ["is_deceptive", "confidence"],
    "properties": {
        "is_deceptive": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "additionalProperties": False,
}


def _json_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json=payload)


def _png(path: Path, size: tuple[int, int] = (2048, 1024)) -> Path:
    Image.new("RGB", size, "white").save(path, format="PNG")
    return path


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


def test_local_generate_json_uses_schema_mode_and_validates():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        text = json.dumps({"is_deceptive": False, "confidence": 0.81})
        return _json_response({"response": text})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = gemma.generate_json("system", "analyse this", SEMANTIC_SCHEMA)
    assert result == {"is_deceptive": False, "confidence": 0.81}
    assert seen["path"] == "/api/generate"
    assert seen["body"]["format"] == SEMANTIC_SCHEMA
    assert seen["body"]["stream"] is False
    assert seen["body"]["system"] == "system"


def test_local_generate_json_retries_malformed_output():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        text = "not json" if calls == 1 else '{"is_deceptive": true, "confidence": 0.9}'
        return _json_response({"response": text})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert gemma.generate_json("", "x", SEMANTIC_SCHEMA)["is_deceptive"] is True
    assert calls == 2


def test_local_generate_json_raises_after_invalid_schema():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"response": '{"is_deceptive": "yes", "confidence": 2}'})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ModelUnavailable):
        gemma.generate_json("", "x", SEMANTIC_SCHEMA, retries=1)


def test_local_analyze_image_encodes_and_downscales(tmp_path):
    image = _png(tmp_path / "logo.png")
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen["body"] = body
        return _json_response(
            {
                "response": json.dumps(
                    {
                        "ocr": "hidden text",
                        "bboxes": [[0.1, 0.2, 0.3, 0.4]],
                        "findings": [
                            {
                                "type": "injection",
                                "severity": "critical",
                                "evidence": "hidden text",
                            }
                        ],
                    }
                )
            }
        )

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    analysis = gemma.analyze_image(image, "scan the logo")
    assert analysis.ocr == "hidden text"
    assert analysis.bboxes == [[0.1, 0.2, 0.3, 0.4]]
    assert seen["body"]["images"]
    decoded = base64.b64decode(seen["body"]["images"][0])
    # The payload must be a valid image, and the image dims must respect max_px.
    with Image.open(io.BytesIO(decoded)) as sent:
        assert max(sent.size) <= 1024


def test_local_health_and_model_digest():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return _json_response({"models": [{"name": "gemma4:e4b-it-qat", "digest": "abc123"}]})
        return httpx.Response(404)

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        model="gemma4:e4b-it-qat",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert gemma.health() is True
    assert gemma.refresh_model_version().startswith("gemma4:e4b-it-qat@abc123")
    assert gemma.model_version.startswith("gemma4:e4b-it-qat@abc123")


def test_health_is_false_when_the_model_is_not_pulled():
    # A running server without the configured model must not be healthy:
    # answering with another model would silently change the verdict.
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"models": [{"name": "other:latest", "digest": "x"}]})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        model="gemma4:e4b-it-qat",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert gemma.health() is False


def test_http_failure_keeps_its_status_in_the_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="model failed to load")

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ModelUnavailable, match="HTTP 500"):
        gemma.generate_json("system", "analyse this", SEMANTIC_SCHEMA)


def test_truncated_output_is_a_failure_not_a_result():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"response": '{"claims": [', "done_reason": "length"})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ModelUnavailable):
        gemma._generate(prompt="p", system="", schema=None)


def test_generation_sends_context_and_prediction_limits():
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return _json_response({"response": "{}", "done_reason": "stop"})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        num_ctx=2048,
        num_predict=256,
        keep_alive="5m",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    gemma._generate(prompt="p", system="", schema=None)
    options = seen["options"]
    assert options["num_ctx"] == 2048 and options["num_predict"] == 256
    assert options["seed"] == 0 and options["temperature"] == 0
    assert seen["keep_alive"] == "5m"


def test_local_health_is_false_on_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert gemma.health() is False


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------


def _cloud_text(text: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


def test_cloud_generate_json_uses_header_and_validates():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        seen["body"] = json.loads(request.content)
        return _json_response(
            _cloud_text('```json\n{"is_deceptive": true, "confidence": 0.95}\n```')
        )

    gemma = GemmaCloud(
        api_key="super-secret",
        base_url="https://gemini.test/v1beta",
        model="gemma-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = gemma.generate_json("system", "analyse", SEMANTIC_SCHEMA)
    assert result["is_deceptive"] is True
    assert seen["path"] == "/v1beta/models/gemma-test:generateContent"
    assert seen["key"] == "super-secret"
    assert "super-secret" not in seen["url"]
    assert seen["body"]["generationConfig"]["responseMimeType"] == "application/json"
    assert seen["body"]["systemInstruction"]["parts"][0]["text"] == "system"


def test_cloud_without_key_fails_closed(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    gemma = GemmaCloud(client=httpx.Client(transport=httpx.MockTransport(lambda _: None)))
    assert gemma.configured is False
    assert gemma.health() is False
    with pytest.raises(ModelUnavailable, match="GEMINI_API_KEY"):
        gemma.generate_json("", "x", SEMANTIC_SCHEMA)


def test_cloud_analyze_image_sends_inline_data(tmp_path):
    image = _png(tmp_path / "logo.png", (64, 64))
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _json_response(
            _cloud_text('{"ocr": "hello", "bboxes": [[0.1, 0.2, 0.3, 0.4]], "findings": []}')
        )

    gemma = GemmaCloud(
        api_key="key",
        base_url="https://gemini.test/v1beta",
        model="gemma-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    analysis = gemma.analyze_image(image, "scan")
    assert analysis.ocr == "hello"
    parts = seen["body"]["contents"][0]["parts"]
    assert parts[1]["inlineData"]["mimeType"] == "image/png"
    assert base64.b64decode(parts[1]["inlineData"]["data"]).startswith(b"\x89PNG")


# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, *, healthy: bool, configured: bool = True, backend: str = "fake"):
        self._healthy = healthy
        self.configured = configured
        self.backend = backend
        self.model_version = "fake-v1"

    def health(self) -> bool:
        return self._healthy

    def generate_json(self, *args, **kwargs):  # pragma: no cover - protocol only
        raise NotImplementedError

    def analyze_image(self, *args, **kwargs):  # pragma: no cover - protocol only
        raise NotImplementedError


def test_selector_demo_returns_mock():
    assert isinstance(select_model(backend="demo"), MockGemma)


def test_selector_explicit_local_uses_injected_client():
    local = _FakeClient(healthy=True)
    assert select_model(backend="local", local_client=local) is local


def test_selector_auto_falls_back_to_cloud():
    local = _FakeClient(healthy=False)
    cloud = _FakeClient(healthy=True, backend="gemini-api")
    selected = select_model(backend="auto", local_client=local, cloud_client=cloud)
    assert selected is cloud


def test_selector_auto_fails_closed_when_both_are_down():
    local = _FakeClient(healthy=False)
    cloud = _FakeClient(healthy=False, backend="gemini-api")
    with pytest.raises(ModelUnavailable, match="no model backend"):
        select_model(backend="auto", local_client=local, cloud_client=cloud)


def test_selector_cloud_without_key_is_not_selected(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cloud = _FakeClient(healthy=True, configured=False, backend="gemini-api")
    with pytest.raises(ModelUnavailable, match="GEMINI_API_KEY"):
        select_model(backend="cloud", cloud_client=cloud)


def test_selector_probe_false_skips_health():
    local = _FakeClient(healthy=False)
    assert select_model(backend="local", probe=False, local_client=local) is local


def test_selector_accepts_model_settings_and_backend_aliases():
    local = _FakeClient(healthy=True)
    settings = ModelSettings(backend="local")
    assert select_model(settings, local_client=local) is local
    assert select_model(backend="ollama", local_client=local) is local
    assert select_model(backend="gemini-api", probe=False, cloud_client=_FakeClient(healthy=False))


def test_malformed_output_is_called_malformed_not_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "not json at all"})

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ModelUnavailable, match="no schema-valid JSON"):
        gemma.generate_json("system", "analyse this", SEMANTIC_SCHEMA)


def test_unreachable_server_keeps_its_own_message():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    gemma = GemmaLocal(
        base_url="http://ollama.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ModelUnavailable) as caught:
        gemma.generate_json("system", "analyse this", SEMANTIC_SCHEMA)
    assert "request failed" in str(caught.value)
    assert "schema-valid" not in str(caught.value)


def test_generation_options_are_part_of_the_cache_identity():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": "gemma3:1b", "digest": "abc"}]})

    def client_with(num_ctx: int) -> GemmaLocal:
        return GemmaLocal(
            base_url="http://ollama.test",
            model="gemma3:1b",
            num_ctx=num_ctx,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    small, large = client_with(2048), client_with(8192)
    small.preflight()
    large.preflight()
    assert small.model_version != large.model_version
    assert small.model_version.startswith("gemma3:1b@abc")
