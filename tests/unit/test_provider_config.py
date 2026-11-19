"""Provider settings, presets, selection, and the rule that a key never leaves the environment."""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import ClassVar

import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.core.config import ConfigError, ModelSettings, load_config
from skill_sentry_cli.core.models.base import ModelUnavailable
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.providers import PRESETS, is_local_url, resolve_provider
from skill_sentry_cli.core.models.selector import select_model
from skill_sentry_cli.core.version import badge_for_backend
from typer.testing import CliRunner

KEY = "sk-live-VERYSECRET-0123456789"


def _settings(backend: str = "openai", **provider: str) -> ModelSettings:
    return ModelSettings(backend=backend, provider=provider)  # type: ignore[arg-type]


# -- presets and resolution ----------------------------------------------------------------
@pytest.mark.parametrize(
    ("name", "host", "env"),
    [
        ("openrouter", "openrouter.ai", "OPENROUTER_API_KEY"),
        ("nim", "integrate.api.nvidia.com", "NVIDIA_API_KEY"),
        ("groq", "api.groq.com", "GROQ_API_KEY"),
    ],
)
def test_a_preset_fills_the_address_and_the_variable_name(name: str, host: str, env: str):
    resolved = resolve_provider(_settings(name, model="m"), name)

    assert host in resolved.base_url
    assert resolved.api_key_env == env
    assert resolved.backend == name and resolved.local is False and resolved.needs_key


def test_settings_override_a_preset():
    resolved = resolve_provider(
        _settings(
            "groq",
            model="m",
            base_url="https://proxy.example/v1",
            api_key_env="MY_KEY",
            headers={"X-Team": "a"},
        ),
        "groq",
    )

    assert resolved.base_url == "https://proxy.example/v1"
    assert resolved.api_key_env == "MY_KEY"
    assert resolved.headers == {"X-Team": "a"}


def test_openrouter_sends_a_title_header_by_default():
    assert (
        resolve_provider(_settings("openrouter", model="m"), "openrouter").headers["X-Title"]
        == "SkillSentry"
    )


def test_the_generic_backend_needs_an_address_and_a_model():
    with pytest.raises(ValueError, match="base_url"):
        resolve_provider(_settings("openai", model="m"), "openai")
    with pytest.raises(ValueError, match="model"):
        resolve_provider(_settings("openai", base_url="https://x.example/v1"), "openai")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:1234/v1",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
        "http://llm.localhost/v1",
    ],
)
def test_a_server_on_this_machine_is_local_and_needs_no_key(url: str):
    resolved = resolve_provider(_settings("openai", model="m", base_url=url), "openai")

    assert is_local_url(url) and resolved.backend == "openai-local" and resolved.needs_key is False


def test_a_preset_pointed_at_a_local_proxy_is_local_too():
    resolved = resolve_provider(
        _settings("groq", model="m", base_url="http://localhost:9000/v1"), "groq"
    )

    assert resolved.backend == "openai-local" and not resolved.needs_key


def test_the_remote_generic_backend_is_named_for_privacy():
    resolved = resolve_provider(
        _settings("openai", model="m", base_url="https://api.example.com/v1"), "openai"
    )

    assert resolved.backend == "openai" and resolved.label == "api.example.com"


# -- keys never go in the configuration ----------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        KEY,
        "sk-or-v1-abc",
        "gsk_abcdef123456",
        "nvapi-abcdef",
        "AIzaSyAbcdef",
        "has space",
        "x" * 60,
    ],
)
def test_api_key_env_must_be_a_variable_name_not_a_key(value: str):
    with pytest.raises(ValueError) as caught:
        ModelSettings(provider={"api_key_env": value})  # type: ignore[arg-type]

    assert "name of an environment variable" in str(caught.value)


def test_a_pasted_key_is_not_echoed_in_the_config_error(tmp_path: Path):
    config = tmp_path / "skillsentry.toml"
    config.write_text(
        f'[model]\nbackend = "openrouter"\n[model.provider]\napi_key_env = "{KEY}"\nmodel = "m"\n'
    )

    with pytest.raises(ConfigError) as caught:
        load_config(config)

    assert KEY not in str(caught.value) and "VERYSECRET" not in str(caught.value)
    assert "api_key_env" in str(caught.value)


@pytest.mark.parametrize(
    "name", ["Authorization", "authorization", "X-API-Key", "api-key", "Cookie"]
)
def test_secret_headers_cannot_be_set_in_the_file(name: str):
    with pytest.raises(ValueError, match="may not be set in the configuration file"):
        ModelSettings(provider={"headers": {name: "x"}})  # type: ignore[arg-type]


def test_a_header_value_that_looks_like_a_key_is_refused():
    with pytest.raises(ValueError, match="looks like it holds a key"):
        ModelSettings(provider={"headers": {"X-Anything": KEY}})  # type: ignore[arg-type]


def test_unknown_structured_output_is_refused():
    with pytest.raises(ValueError, match="structured_output"):
        ModelSettings(provider={"structured_output": "xml"})  # type: ignore[arg-type]


def test_the_existing_model_keys_are_unchanged():
    settings = ModelSettings()

    assert settings.backend == "auto"
    assert settings.ollama_model == "gemma4:e4b-it-qat"
    assert settings.gemini_model == "gemma-4-e4b"
    assert settings.provider.base_url == "" and settings.provider.model == ""


# -- selection --------------------------------------------------------------------------------------
def test_a_provider_backend_without_its_key_says_which_variable_is_missing(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    with pytest.raises(ModelUnavailable, match="GROQ_API_KEY is not set"):
        select_model(_settings("groq", model="m"), probe=False)


def test_a_provider_backend_with_a_key_returns_the_client(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", KEY)

    client = select_model(_settings("groq", model="m"), probe=False)

    assert isinstance(client, OpenAICompat) and client.backend == "groq"
    assert KEY not in repr(client)


def test_an_unreachable_provider_is_an_error_not_a_silent_fallback(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", KEY)

    class Down:
        configured = True
        last_health_error = "cannot reach Groq at https://api.groq.com/openai/v1"

        def health(self) -> bool:
            return False

    with pytest.raises(ModelUnavailable, match="cannot reach Groq"):
        select_model(_settings("groq", model="m"), provider_client=Down())  # type: ignore[arg-type]


def test_auto_never_picks_a_provider(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", KEY)
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)

    class Down:
        configured = True

        def health(self) -> bool:
            return False

    with pytest.raises(ModelUnavailable, match="no model backend reachable"):
        select_model(
            ModelSettings(backend="auto", provider={"model": "m"}),  # type: ignore[arg-type]
            local_client=Down(),  # type: ignore[arg-type]
            cloud_client=Down(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("alias", ["nvidia", "NIM", "openai-compatible"])
def test_backend_aliases(alias: str, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", KEY)
    settings = ModelSettings(
        backend=alias,
        provider={
            "model": "m",
            "base_url": "https://x.example/v1",
            "api_key_env": "NVIDIA_API_KEY",
        },  # type: ignore[arg-type]
    )

    assert isinstance(select_model(settings, probe=False), OpenAICompat)


# -- who receives the content is always shown ------------------------------------------------------
def test_the_banner_names_the_provider_that_receives_code():
    assert badge_for_backend("openrouter") == "Cloud analysis · code excerpts sent to OpenRouter"
    assert "NVIDIA NIM" in badge_for_backend("nim")
    assert "Groq" in badge_for_backend("groq")
    assert "remote OpenAI-compatible server" in badge_for_backend("openai")
    assert badge_for_backend("openai-local") == badge_for_backend("local")
    assert "(OpenRouter, cloud)" in cli._backend_label("openrouter")
    assert "local server" in cli._backend_label("openai-local")
    assert set(PRESETS) == {"openrouter", "nim", "groq"}


def test_the_cli_accepts_the_new_backends():
    for backend in ("openai", "openrouter", "nim", "groq"):
        assert backend in cli._BACKENDS


# -- a real process against a real HTTP server --------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []

    def log_message(self, *args) -> None:  # type: ignore[no-untyped-def]
        pass

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.seen.append({"path": self.path, "auth": self.headers.get("Authorization")})
        self._send(200, {"data": [{"id": "test/model"}]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        self.seen.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        )
        if "response_format" in body and body["response_format"]["type"] == "json_schema":
            self._send(400, {"error": {"message": f"unsupported; your key {KEY} is fine"}})
            return
        reply = {
            "is_deceptive": False,
            "suspicious_patterns": [],
            "declared_intent": "x",
            "actual_capabilities": [],
            "confidence": 0.5,
        }
        self._send(
            200,
            {
                "choices": [
                    {
                        "message": {"content": "<think>hmm</think>" + json.dumps(reply)},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 5},
            },
        )


@pytest.fixture
def fake_server():
    _Handler.seen = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def test_a_scan_through_a_provider_in_a_real_process_never_shows_the_key(
    tmp_path: Path, fake_server
):
    port = fake_server.server_address[1]
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: Print a note.\n---\n\nHello.\n")
    config = tmp_path / "skillsentry.toml"
    config.write_text(
        '[model]\nbackend = "openai"\n[model.provider]\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\nmodel = "test/model"\napi_key_env = "MY_PROVIDER_KEY"\n'
        "[sandbox]\nenabled = false\n"
    )
    db = tmp_path / "db.sqlite"
    env = {
        **os.environ,
        "MY_PROVIDER_KEY": KEY,
        "SKILLSENTRY_CONFIG": str(config),
        "SKILLSENTRY_DB": str(db),
        "HOME": str(tmp_path / "home"),
    }
    env.pop("SKILLSENTRY_DEV", None)
    (tmp_path / "home").mkdir()

    outputs = []
    for extra in ([], ["--format", "json"], ["--format", "markdown"], ["--format", "sarif"]):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "skill_sentry_cli",
                "scan",
                str(skill),
                "--no-sandbox",
                "--no-cache",
                *extra,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            cwd=str(tmp_path),
        )
        outputs.append(result)
        assert result.returncode == 0, result.stdout + result.stderr

    assert (
        "openai-compatible (local server)" in outputs[0].stdout or "127.0.0.1" in outputs[0].stdout
    )
    payload = json.loads(outputs[1].stdout)
    assert payload["status"] == "SAFE"
    # The key was sent to the server as a bearer token, once per request, and nowhere else.
    assert any(item["auth"] == f"Bearer {KEY}" for item in _Handler.seen if "body" in item)
    assert any(
        item["body"]["response_format"]["type"] == "json_object"
        for item in _Handler.seen
        if "body" in item
    )
    haystack = "".join(r.stdout + r.stderr for r in outputs) + db.read_bytes().decode("latin-1")
    for path in (tmp_path / "home").rglob("*"):
        if path.is_file():
            haystack += path.read_bytes().decode("latin-1")
    assert KEY not in haystack and "VERYSECRET" not in haystack


def test_the_cli_runner_error_for_a_missing_key_does_not_contain_anything_secret(
    tmp_path: Path, monkeypatch
):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    skill = tmp_path / "s"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: x\n---\n\nHi.\n")
    config = tmp_path / "c.toml"
    config.write_text(
        '[model]\nbackend = "groq"\n[model.provider]\nmodel = "m"\n[sandbox]\nenabled = false\n'
    )

    result = CliRunner().invoke(
        cli.app,
        ["scan", str(skill), "--no-sandbox", "--no-cache", "--format", "json"],
        env={"SKILLSENTRY_CONFIG": str(config), "SKILLSENTRY_DB": str(tmp_path / "d.sqlite")},
    )

    assert "GROQ_API_KEY is not set" in result.output
    assert result.exit_code in (0, 1)  # the scan finishes, UNSCANNED, and says why
