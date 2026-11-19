"""`doctor` checks the configured provider: reachable, model listed, key variable set, no key printed."""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from typing import ClassVar

import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.core.config import SkillsEntryConfig
from typer.testing import CliRunner

runner = CliRunner()
KEY = "sk-doctor-SECRET-0123456789"


class _Models(http.server.BaseHTTPRequestHandler):
    listed: ClassVar[list[str]] = ["test/model"]
    seen: ClassVar[list[str]] = []

    def log_message(self, *args) -> None:  # type: ignore[no-untyped-def]
        pass

    def do_GET(self) -> None:
        self.seen.append(self.path)
        data = json.dumps({"data": [{"id": i} for i in self.listed]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server():
    _Models.listed = ["test/model"]
    _Models.seen = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Models)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def _config(tmp_path: Path, body: str) -> dict[str, str]:
    path = tmp_path / "skillsentry.toml"
    path.write_text(body + "\n[sandbox]\nenabled = false\n", encoding="utf-8")
    return {"SKILLSENTRY_CONFIG": str(path), "SKILLSENTRY_DB": str(tmp_path / "d.sqlite")}


def _local_config(tmp_path: Path, port: int, model: str = "test/model") -> dict[str, str]:
    return _config(
        tmp_path,
        f'[model]\nbackend = "openai"\n[model.provider]\nbase_url = "http://127.0.0.1:{port}/v1"\nmodel = "{model}"\n',
    )


def test_a_local_provider_that_lists_the_model_passes_and_needs_no_key(tmp_path: Path, server):
    result = runner.invoke(
        cli.app, ["doctor"], env=_local_config(tmp_path, server.server_address[1])
    )

    assert "PASS  provider: openai -> http://127.0.0.1" in result.output
    assert "on this machine" in result.output and "(profile: small)" in result.output
    assert "PASS  api key: not needed for a server on this machine" in result.output
    assert "PASS  provider model: test/model is listed by 127.0.0.1" in result.output
    assert "model: " not in result.output.replace("provider model: ", "").replace(
        "; model test/model", ""
    )
    assert _Models.seen == ["/v1/models"]


def test_a_model_the_provider_does_not_list_fails(tmp_path: Path, server):
    result = runner.invoke(
        cli.app, ["doctor"], env=_local_config(tmp_path, server.server_address[1], "missing/model")
    )

    assert result.exit_code == 3
    assert "FAIL  provider model: " in result.output and "does not list the model" in result.output


def test_an_unreachable_provider_fails_without_a_traceback(tmp_path: Path):
    result = runner.invoke(cli.app, ["doctor"], env=_local_config(tmp_path, 1))

    assert result.exit_code == 3
    assert "FAIL  provider model: cannot reach" in result.output
    assert "Traceback" not in result.output


def test_a_remote_provider_without_its_key_names_the_variable_and_sends_nothing(
    tmp_path: Path, monkeypatch
):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    calls: list[str] = []
    monkeypatch.setattr(
        cli, "_provider_client", lambda *a, **k: calls.append("built"), raising=False
    )
    env = _config(
        tmp_path, '[model]\nbackend = "groq"\n[model.provider]\nmodel = "llama-3.3-70b-versatile"\n'
    )

    result = runner.invoke(cli.app, ["doctor"], env=env)

    assert result.exit_code == 3
    assert "FAIL  api key: GROQ_API_KEY is not set" in result.output
    assert "PASS  privacy: skill content is sent to Groq" in result.output
    assert "(profile: large)" in result.output
    assert "provider model" not in result.output  # no request is made without a key
    assert calls == []


def test_a_remote_provider_with_its_key_passes_and_never_prints_the_key(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("GROQ_API_KEY", KEY)

    class Ready:
        last_health_error = None

        def health(self) -> bool:
            return True

        def close(self) -> None:
            pass

    import skill_sentry_cli.core.models.selector as selector

    monkeypatch.setattr(selector, "_provider_client", lambda settings, choice: Ready())
    env = _config(
        tmp_path, '[model]\nbackend = "groq"\n[model.provider]\nmodel = "llama-3.3-70b-versatile"\n'
    )

    result = runner.invoke(cli.app, ["doctor"], env=env)

    assert "PASS  api key: GROQ_API_KEY is set" in result.output
    assert "PASS  provider model: llama-3.3-70b-versatile is listed by Groq" in result.output
    assert KEY not in result.output


def test_the_ollama_check_is_replaced_not_added_when_a_provider_is_configured(
    tmp_path: Path, server
):
    result = runner.invoke(
        cli.app, ["doctor"], env=_local_config(tmp_path, server.server_address[1])
    )

    assert "is not pulled" not in result.output
    assert "cannot reach the model server at http://localhost:11434" not in result.output


def test_without_a_provider_the_ollama_check_is_unchanged(tmp_path: Path, monkeypatch):
    env = _config(tmp_path, '[model]\nbackend = "local"\nollama_url = "http://127.0.0.1:1"\n')

    result = runner.invoke(cli.app, ["doctor"], env=env)

    assert "FAIL  model: cannot reach the model server at http://127.0.0.1:1" in result.output
    assert "provider" not in result.output.split("model:")[0]


def test_a_provider_that_is_not_set_up_says_what_is_missing(tmp_path: Path):
    env = _config(tmp_path, '[model]\nbackend = "openai"\n')

    result = runner.invoke(cli.app, ["doctor"], env=env)

    assert result.exit_code == 3
    assert "FAIL  provider: the openai backend needs a server address" in result.output


def test_doctor_backend_overrides_the_configured_one(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    env = _config(
        tmp_path, '[model]\nbackend = "local"\n[model.provider]\nmodel = "nvidia/some-model-49b"\n'
    )

    result = runner.invoke(cli.app, ["doctor", "--backend", "nim"], env=env)

    assert "FAIL  api key: NVIDIA_API_KEY is not set" in result.output
    assert runner.invoke(cli.app, ["doctor", "--backend", "bogus"], env=env).exit_code == 2


def test_uses_provider():
    config = SkillsEntryConfig()
    assert cli.uses_provider(config) is False
    config.model.backend = "OpenRouter"
    assert cli.uses_provider(config) is True
    config.model.backend = "nvidia"
    assert cli.uses_provider(config) is True
    config.model.backend = "cloud"
    assert cli.uses_provider(config) is False
