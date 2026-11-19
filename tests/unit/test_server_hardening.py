"""Server hardening: no bare 500s, a default scan folder, and an opt-in bearer token."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from skill_sentry_cli import cli
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.server.app import create_app
from skill_sentry_cli.server.demo_backend import DemoBackend
from skill_sentry_cli.server.live_backend import LiveBackend
from starlette.websockets import WebSocketDisconnect
from typer.testing import CliRunner

BASE = "http://localhost"
TOKEN = "s3cret-token-value"
runner = CliRunner()


def _skill(root: Path, name: str) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: test skill\n---\nHi.\n")
    return folder


def _backend(tmp_path: Path, *, roots: list[str] | None = None, default: Path | None = None):
    config = SkillsEntryConfig()
    config.server.allowed_scan_roots = roots or []
    store = SQLiteStore(tmp_path / "h.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    return LiveBackend(
        config=config, engine=engine, default_scan_roots=[default] if default else None
    )


def _client(backend: Any, *, token: str | None = None) -> TestClient:
    # raise_server_exceptions=False: a handler must answer, not propagate to the test.
    return TestClient(
        create_app(backend, token=token), base_url=BASE, raise_server_exceptions=False
    )


def _scan(client: TestClient, path: str, **kwargs: Any):
    return client.post("/scan", json={"path": path}, **kwargs)


# -- filesystem errors -------------------------------------------------------
def test_a_path_outside_the_launch_folder_is_refused_with_json(tmp_path: Path):
    launch = tmp_path / "launch"
    launch.mkdir()
    client = _client(_backend(tmp_path, default=launch))

    response = _scan(client, "/etc")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "path_not_allowed"
    assert "/etc" not in response.text


def test_a_skill_inside_the_launch_folder_is_scanned(tmp_path: Path):
    launch = tmp_path / "launch"
    skill = _skill(launch, "inside")
    client = _client(_backend(tmp_path, default=launch))

    assert _scan(client, str(skill)).status_code == 202


def test_configured_roots_replace_the_launch_folder(tmp_path: Path):
    launch = tmp_path / "launch"
    other = tmp_path / "other"
    skill = _skill(launch, "inside")
    other.mkdir()
    client = _client(_backend(tmp_path, roots=[str(other)], default=launch))

    assert _scan(client, str(skill)).status_code == 403


def test_with_no_roots_and_no_default_any_folder_is_allowed(tmp_path: Path):
    skill = _skill(tmp_path, "free")
    assert _scan(_client(_backend(tmp_path)), str(skill)).status_code == 202


def test_a_file_path_is_a_structured_422(tmp_path: Path):
    launch = tmp_path / "launch"
    launch.mkdir()
    target = launch / "notes.txt"
    target.write_text("x")
    client = _client(_backend(tmp_path, default=launch))

    response = _scan(client, str(target))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_skill"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need extra rights on Windows")
def test_a_symlink_that_escapes_the_launch_folder_is_refused(tmp_path: Path):
    launch = tmp_path / "launch"
    launch.mkdir()
    outside = _skill(tmp_path / "outside", "secret")
    (launch / "link").symlink_to(outside, target_is_directory=True)
    client = _client(_backend(tmp_path, default=launch))

    response = _scan(client, str(launch / "link"))

    assert response.status_code == 403


def test_an_unreadable_folder_is_a_422_not_a_500(tmp_path: Path, monkeypatch):
    launch = tmp_path / "launch"
    folder = launch / "locked"
    folder.mkdir(parents=True)
    client = _client(_backend(tmp_path, default=launch))

    def denied(self):  # type: ignore[no-untyped-def]
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", denied)
    response = _scan(client, str(folder))

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "path_unreadable"
    assert "permission denied" in error["message"]


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions and a non-root user",
)
def test_a_real_unreadable_folder_is_a_422(tmp_path: Path):
    launch = tmp_path / "launch"
    folder = launch / "locked"
    folder.mkdir(parents=True)
    folder.chmod(0o000)
    try:
        response = _scan(_client(_backend(tmp_path, default=launch)), str(folder))
    finally:
        folder.chmod(0o700)

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "path_unreadable"


def test_an_unexpected_error_is_json_and_leaks_nothing(tmp_path: Path, caplog):
    backend = _backend(tmp_path)

    async def boom(**_: Any):
        raise RuntimeError("internal detail /home/secret/path")

    backend.list_scans = boom  # type: ignore[method-assign]
    client = _client(backend)

    with caplog.at_level(logging.ERROR):
        response = client.get("/scans")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"]["code"] == "internal_error"
    assert "secret" not in response.text
    assert "RuntimeError" not in response.text
    assert any(
        "internal detail" in record.getMessage() or record.exc_info for record in caplog.records
    )


# -- token -------------------------------------------------------------------
def test_without_a_token_configured_nothing_changes(tmp_path: Path):
    assert _client(_backend(tmp_path)).get("/scans").status_code == 200


def test_a_missing_token_is_401(tmp_path: Path):
    response = _client(_backend(tmp_path), token=TOKEN).get("/scans")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("header", ["Bearer wrong", "Basic " + TOKEN, TOKEN, "Bearer "])
def test_a_wrong_token_is_401(tmp_path: Path, header: str):
    client = _client(_backend(tmp_path), token=TOKEN)

    assert client.get("/scans", headers={"Authorization": header}).status_code == 401


def test_the_right_token_is_accepted(tmp_path: Path):
    client = _client(_backend(tmp_path), token=TOKEN)

    assert client.get("/scans", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_every_data_route_needs_the_token(tmp_path: Path):
    skill = _skill(tmp_path, "any")
    client = _client(_backend(tmp_path), token=TOKEN)

    assert _scan(client, str(skill)).status_code == 401
    assert client.get("/skills/00000000-0000-0000-0000-000000000000").status_code == 401
    assert client.get("/cache/stats").status_code == 401
    assert client.delete("/cache").status_code == 401
    assert client.get("/scan/00000000-0000-0000-0000-000000000000").status_code == 401


def test_health_meta_and_the_dashboard_stay_open(tmp_path: Path):
    client = _client(_backend(tmp_path), token=TOKEN)

    assert client.get("/health").status_code == 200
    assert client.get("/meta").status_code == 200
    assert client.get("/").status_code == 200


def test_a_scan_with_the_token_starts(tmp_path: Path):
    skill = _skill(tmp_path, "ok")
    client = _client(_backend(tmp_path), token=TOKEN)

    response = _scan(client, str(skill), headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 202


def test_a_websocket_without_the_token_is_refused(tmp_path: Path):
    client = _client(_backend(tmp_path), token=TOKEN)
    path = "ws://localhost/scan/00000000-0000-0000-0000-000000000000/stream"

    with pytest.raises(WebSocketDisconnect), client.websocket_connect(path):
        pass


def test_a_websocket_with_a_wrong_token_is_refused(tmp_path: Path):
    client = _client(_backend(tmp_path), token=TOKEN)
    path = "ws://localhost/scan/00000000-0000-0000-0000-000000000000/stream"

    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(path, headers={"Authorization": "Bearer nope"}),
    ):
        pass


def test_a_websocket_with_the_token_connects(tmp_path: Path):
    client = DemoBackend(speed=0)
    app_client = TestClient(create_app(client, token=TOKEN), base_url=BASE)
    scan = app_client.post(
        "/scan", json={"path": "pdf-summarizer"}, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert scan.status_code == 202
    stream = scan.json()["stream"]

    with app_client.websocket_connect(
        f"ws://localhost{stream}", headers={"Authorization": f"Bearer {TOKEN}"}
    ) as ws:
        assert ws.receive_json()["stage"]


def test_a_websocket_accepts_the_token_as_a_subprotocol(tmp_path: Path):
    backend = DemoBackend(speed=0)
    app_client = TestClient(create_app(backend, token=TOKEN), base_url=BASE)
    scan = app_client.post(
        "/scan", json={"path": "pdf-summarizer"}, headers={"Authorization": f"Bearer {TOKEN}"}
    )

    with app_client.websocket_connect(
        f"ws://localhost{scan.json()['stream']}", subprotocols=[f"bearer.{TOKEN}"]
    ) as ws:
        assert ws.receive_json()["stage"]


def test_the_token_never_appears_in_a_response_or_a_log(tmp_path: Path, caplog):
    client = _client(_backend(tmp_path), token=TOKEN)

    with caplog.at_level(logging.DEBUG):
        bad = client.get("/scans", headers={"Authorization": f"Bearer {TOKEN}x"})
        good = client.get("/scans", headers={"Authorization": f"Bearer {TOKEN}"})

    assert TOKEN not in bad.text + good.text
    assert TOKEN not in caplog.text


# -- serve -------------------------------------------------------------------
@pytest.fixture
def served(monkeypatch):
    """Capture what `serve` would start instead of starting uvicorn."""

    calls: dict[str, Any] = {}

    def fake_run(app, host, port, **_):  # type: ignore[no-untyped-def]
        calls.update(app=app, host=host, port=port)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.delenv("SKILLSENTRY_TOKEN", raising=False)
    monkeypatch.delenv("SKILLSENTRY_CONTAINER", raising=False)
    monkeypatch.delenv("SKILLSENTRY_CONFIG", raising=False)
    return calls


def test_serve_refuses_a_non_loopback_host_without_a_token(served, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0"])

    assert result.exit_code == 2
    assert "without a token" in result.output
    assert not served


def test_serve_accepts_a_non_loopback_host_with_a_token(served, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--token", TOKEN])

    assert result.exit_code == 0, result.output
    assert served["host"] == "0.0.0.0"
    assert TOKEN not in result.output
    assert "API token: required" in result.output


def test_serve_reads_the_token_from_the_environment(served, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli.app, ["serve", "--host", "0.0.0.0"], env={"SKILLSENTRY_TOKEN": TOKEN}
    )

    assert result.exit_code == 0, result.output
    assert TOKEN not in result.output


def test_the_official_container_may_bind_without_a_token(served, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli.app, ["serve", "--host", "0.0.0.0"], env={"SKILLSENTRY_CONTAINER": "1"}
    )

    assert result.exit_code == 0, result.output
    assert "any folder the server can read" in result.output


def test_serve_prints_the_launch_folder_as_the_scan_root(served, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["serve"])

    assert result.exit_code == 0, result.output
    assert "scans are limited to (launch folder)" in result.output
    assert str(tmp_path.resolve()) in result.output or str(tmp_path) in result.output
    assert "API token: none (loopback only)" in result.output


def test_the_websocket_handshake_selects_the_plain_subprotocol_and_never_echoes_the_token():
    # A browser that offers a subprotocol needs the server to select one of them.
    backend = DemoBackend(speed=0)
    app_client = TestClient(create_app(backend, token=TOKEN), base_url=BASE)
    scan = app_client.post(
        "/scan", json={"path": "pdf-summarizer"}, headers={"Authorization": f"Bearer {TOKEN}"}
    )

    with app_client.websocket_connect(
        f"ws://localhost{scan.json()['stream']}",
        subprotocols=["skillsentry.v1", f"bearer.{TOKEN}"],
    ) as ws:
        assert ws.accepted_subprotocol == "skillsentry.v1"
        assert TOKEN not in str(ws.accepted_subprotocol)
        assert ws.receive_json()["stage"]


def test_a_websocket_with_no_subprotocol_is_still_accepted_without_a_token_configured():
    app_client = TestClient(create_app(DemoBackend(speed=0)), base_url=BASE)
    scan = app_client.post("/scan", json={"path": "pdf-summarizer"})

    with app_client.websocket_connect(f"ws://localhost{scan.json()['stream']}") as ws:
        assert ws.accepted_subprotocol is None
        assert ws.receive_json()["stage"]
