"""The local model probe says why the model is unusable, and doctor reports it."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from skillsentry.cli import app
from skillsentry.core.models.gemma_local import GemmaLocal, ProbeResult
from typer.testing import CliRunner

runner = CliRunner()


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_is_ready_when_the_model_is_pulled():
    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "gemma3:1b", "digest": "abc123"}]})

    model = GemmaLocal(base_url="http://ollama.test", model="gemma3:1b", client=_client(handler))
    assert model.probe() == ProbeResult.READY
    assert model.model_version.startswith("gemma3:1b@abc123")


def test_probe_reports_a_missing_model_separately():
    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "other:7b"}]})

    model = GemmaLocal(base_url="http://ollama.test", model="gemma3:1b", client=_client(handler))
    assert model.probe() == ProbeResult.NO_MODEL


def test_probe_reports_an_unreachable_server():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    model = GemmaLocal(base_url="http://ollama.test", model="gemma3:1b", client=_client(handler))
    assert model.probe() == ProbeResult.UNREACHABLE
    assert model.preflight() is False


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _write_config(tmp_path: Path, url: str) -> Path:
    config = tmp_path / "skillsentry.toml"
    config.write_text(
        f'[model]\nbackend = "local"\nollama_url = "{url}"\nollama_model = "gemma3:1b"\n',
        encoding="utf-8",
    )
    return config


def test_doctor_says_the_server_cannot_be_reached(tmp_path: Path, monkeypatch):
    config = _write_config(tmp_path, f"http://127.0.0.1:{_free_port()}")
    monkeypatch.setenv("SKILLSENTRY_CONFIG", str(config))

    result = runner.invoke(app, ["doctor"])

    assert "cannot reach the model server" in result.output
    assert "not pulled" not in result.output


class _TagsOnly(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"models": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_doctor_says_the_model_is_not_pulled(tmp_path: Path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TagsOnly)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = _write_config(tmp_path, f"http://127.0.0.1:{server.server_address[1]}")
        monkeypatch.setenv("SKILLSENTRY_CONFIG", str(config))
        result = runner.invoke(app, ["doctor"])
    finally:
        server.shutdown()
        server.server_close()

    assert "gemma3:1b is not pulled" in result.output
    assert "cannot reach" not in result.output


def test_environment_config_path_must_exist(tmp_path: Path, monkeypatch):
    import pytest as _pytest
    from skillsentry.core.config import ConfigError, load_config

    monkeypatch.setenv("SKILLSENTRY_CONFIG", str(tmp_path / "typo.toml"))
    with _pytest.raises(ConfigError, match="config file not found"):
        load_config()
