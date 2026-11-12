"""Live API hardening: explicit folder errors, cancel races, in-flight listing,
Host/Origin checks, readable validation errors, and cache-clear error mapping.

Scans use the real engine with the mock model and no sandbox, so no Docker is needed.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.contracts import ScanStatus, utc_now
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.server import live_backend
from skill_sentry_cli.server.app import create_app
from skill_sentry_cli.server.demo_backend import DemoBackend
from skill_sentry_cli.server.live_backend import LiveBackend, _LiveScan
from starlette.websockets import WebSocketDisconnect

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
PDF = FIXTURES / "benign" / "pdf-summarizer"
BASE = "http://localhost"


def _wait_for(predicate, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached in time")


def _skill(root: Path, name: str) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: test skill\n---\nHi.\n")
    return folder


@pytest.fixture()
def live(tmp_path, monkeypatch):
    """A live backend whose semantic stage can be held open by the test."""

    store = SQLiteStore(tmp_path / "live.sqlite")
    engine = ScanEngine(store=store, model=MockGemma(profile="benign"))
    backend = LiveBackend(engine=engine)
    entered = threading.Event()
    gate = threading.Event()
    original = ScanEngine._semantic_stage

    def held(self, *args, **kwargs):
        entered.set()
        gate.wait(timeout=30)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ScanEngine, "_semantic_stage", held)
    monkeypatch.setattr(live_backend, "_CANCEL_GRACE_S", 0.05)
    try:
        yield backend, entered, gate
    finally:
        gate.set()
        backend.close()
        store.close()


def _start(client: TestClient, path: Path) -> str:
    response = client.post(
        "/scan", json={"path": str(path), "options": {"sandbox": False, "no_cache": True}}
    )
    assert response.status_code == 202, response.text
    return response.json()["scanId"]


# -- item 2: folder of skills ------------------------------------------------


def test_folder_of_skills_is_refused_with_the_packages_named(tmp_path, live):
    backend, _entered, _gate = live
    root = tmp_path / "bundle"
    _skill(root, "alpha")
    _skill(root, "beta")
    with TestClient(create_app(backend), base_url=BASE) as client:
        response = client.post("/scan", json={"path": str(root)})
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "folder_of_skills"
        assert "alpha" in error["message"] and "beta" in error["message"]
        assert client.get("/scans").json()["scans"] == []


def test_folder_without_any_skill_is_still_no_manifest(tmp_path, live):
    backend, _entered, _gate = live
    empty = tmp_path / "empty"
    empty.mkdir()
    with TestClient(create_app(backend), base_url=BASE) as client:
        response = client.post("/scan", json={"path": str(empty)})
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "no_skill_manifest"


# -- item 3: cancel race -----------------------------------------------------


def test_duplicate_scan_is_refused_while_a_cancelled_worker_still_runs(live):
    backend, entered, gate = live
    with TestClient(create_app(backend), base_url=BASE) as client:
        first = _start(client, PDF)
        assert entered.wait(timeout=15)

        with client.websocket_connect(f"ws://localhost/scan/{first}/stream") as ws:
            ws.send_json({"op": "cancel"})
            with pytest.raises(WebSocketDisconnect):
                while True:
                    ws.receive_json()

        status = client.get(f"/scan/{first}").json()
        assert status["status"] == "failed"
        assert status["error"] == "cancelled by client"

        # The engine thread is still inside the held stage, so the same folder must not
        # start a second, concurrent scan.
        blocked = client.post("/scan", json={"path": str(PDF), "options": {"sandbox": False}})
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "scan_in_progress"

        gate.set()
        _wait_for(
            lambda: (
                client.post(
                    "/scan",
                    json={"path": str(PDF), "options": {"sandbox": False, "no_cache": True}},
                ).status_code
                == 202
            )
        )

        # The worker finished after the cancel; its result must not replace the cancel.
        assert client.get(f"/scan/{first}").json()["status"] == "failed"
        assert client.get(f"/scan/{first}").json()["error"] == "cancelled by client"


def test_terminal_status_is_first_writer_wins():
    item = _LiveScan(scan_id=uuid4(), path=PDF, started_at=utc_now())
    LiveBackend._finish(item, ScanStatus.FAILED, stage=None)
    LiveBackend._finish(item, ScanStatus.COMPLETED, stage=None)
    assert item.status is ScanStatus.FAILED
    assert item.final is True


# -- item 4: in-flight scans are listed --------------------------------------


def test_running_scan_is_listed_while_in_flight(live):
    backend, entered, gate = live
    with TestClient(create_app(backend), base_url=BASE) as client:
        scan_id = _start(client, PDF)
        assert entered.wait(timeout=15)

        listed = client.get("/scans").json()["scans"]
        running = [row for row in listed if row["scanId"] == scan_id]
        assert running, listed
        assert running[0]["status"] == "running"

        filtered = client.get("/scans", params={"status": "running"}).json()["scans"]
        assert [row["scanId"] for row in filtered] == [scan_id]
        gate.set()


# -- item 5: Host and Origin -------------------------------------------------


def test_foreign_host_header_is_refused_over_http():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.get("/meta", headers={"host": "evil.example"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "untrusted_host"


@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
def test_loopback_host_names_are_accepted(host):
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        assert client.get("/meta", headers={"host": host}).status_code == 200


def test_specific_bind_address_is_accepted_and_wildcard_is_not(monkeypatch):
    monkeypatch.delenv("SKILLSENTRY_ALLOWED_HOSTS", raising=False)
    lan = TestClient(create_app(DemoBackend(speed=0), bind_host="192.168.1.5"), base_url=BASE)
    wildcard = TestClient(create_app(DemoBackend(speed=0), bind_host="0.0.0.0"), base_url=BASE)
    with lan, wildcard:
        assert lan.get("/meta", headers={"host": "192.168.1.5:8000"}).status_code == 200
        assert wildcard.get("/meta", headers={"host": "192.168.1.5:8000"}).status_code == 400


def test_extra_names_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("SKILLSENTRY_ALLOWED_HOSTS", "skills.lan, Photos.LAN ")
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        assert client.get("/meta", headers={"host": "photos.lan:8000"}).status_code == 200


def test_websocket_with_a_foreign_origin_is_refused():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        url = "ws://localhost/scan/00000000-0000-4000-8000-000000000000/stream"
        with (
            pytest.raises(WebSocketDisconnect) as refused,
            client.websocket_connect(url, headers={"origin": "https://evil.example"}),
        ):
            pass
        assert refused.value.code == 1008


def test_websocket_with_a_loopback_origin_is_accepted():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        url = "ws://localhost/scan/00000000-0000-4000-8000-000000000000/stream"
        with client.websocket_connect(url, headers={"origin": "http://localhost:5173"}) as ws:
            assert ws.receive_json()["detail"]["code"] == "unknown_scan"


_WS_URL = "ws://localhost/scan/00000000-0000-4000-8000-000000000000/stream"


@pytest.mark.parametrize("origin", ["http://localhost:9999", "http://127.0.0.1:9999", "null"])
def test_websocket_from_another_port_or_null_origin_is_refused(origin):
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        with (
            pytest.raises(WebSocketDisconnect) as refused,
            client.websocket_connect(_WS_URL, headers={"origin": origin}),
        ):
            pass
        assert refused.value.code == 1008


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("localhost", "http://localhost"),
        ("localhost:8000", "http://localhost:8000"),
        ("localhost:5173", "http://localhost:5173"),
        ("localhost:5173", "http://127.0.0.1:5173"),
    ],
)
def test_websocket_from_own_or_dev_origin_is_accepted(host, origin):
    with (
        TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client,
        client.websocket_connect(_WS_URL, headers={"host": host, "origin": origin}) as ws,
    ):
        assert ws.receive_json()["detail"]["code"] == "unknown_scan"


def test_websocket_without_an_origin_is_accepted():
    with (
        TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client,
        client.websocket_connect(_WS_URL) as ws,
    ):
        assert ws.receive_json()["detail"]["code"] == "unknown_scan"


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://localhost:9999",
        "http://127.0.0.1:9999",
        "null",
    ],
)
def test_unsafe_request_from_a_foreign_origin_is_refused(origin):
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.post("/scan", json={}, headers={"origin": origin})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "untrusted_host"
        assert "origin" in error["message"]


def test_unsafe_request_with_a_foreign_origin_does_not_reach_the_handler():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        before = len(client.get("/scans").json()["scans"])
        response = client.post(
            "/scan",
            json={"path": str(PDF), "options": {"sandbox": False}},
            headers={"origin": "http://localhost:9999"},
        )
        assert response.status_code == 400
        assert len(client.get("/scans").json()["scans"]) == before


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_unsafe_methods_with_a_foreign_origin_are_all_refused(method):
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.request(method, "/cache", headers={"origin": "http://localhost:9999"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "untrusted_host"


def test_unsafe_request_without_an_origin_is_accepted():
    # curl and the CLI send no Origin header.
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.post("/scan", json={})
        assert response.status_code == 202


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("localhost", "http://localhost"),
        ("localhost:8000", "http://localhost:8000"),
        ("localhost:5173", "http://localhost:5173"),
        ("127.0.0.1:5173", "http://127.0.0.1:5173"),
        ("localhost:5173", "http://127.0.0.1:5173"),
    ],
)
def test_unsafe_request_from_a_loopback_origin_is_accepted(host, origin):
    # Same origin as the server (packaged dashboard), or a listed dev origin (Vite).
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.post("/scan", json={}, headers={"host": host, "origin": origin})
        assert response.status_code == 202


def test_get_with_a_foreign_origin_is_unaffected():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.get("/meta", headers={"origin": "https://evil.example"})
        assert response.status_code == 200


# -- item 7: validation message and cache clearing ---------------------------


def test_validation_error_is_a_readable_line_not_a_python_repr():
    with TestClient(create_app(DemoBackend(speed=0)), base_url=BASE) as client:
        response = client.post("/scan", json={"options": {"timeout_s": "soon"}})
    error = response.json()["error"]
    assert error["code"] == "schema_violation"
    assert "[{" not in error["message"] and "'loc'" not in error["message"]
    assert "options" in error["message"] and "timeout_s" in error["message"]


def test_unexpected_cache_failure_is_a_server_error_not_a_422(live):
    backend, _entered, _gate = live
    store = backend.store

    def broken(older_than=None):
        raise RuntimeError("disk on fire")

    store.clear_cache = broken
    with TestClient(create_app(backend), base_url=BASE, raise_server_exceptions=False) as client:
        response = client.delete("/cache", params={"older_than": "30d"})
    assert response.status_code == 500


def test_bad_duration_is_still_a_422(live):
    backend, _entered, _gate = live
    with TestClient(create_app(backend), base_url=BASE) as client:
        response = client.delete("/cache", params={"older_than": "soon"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_duration"
