"""WebSocket contract: event names, ordering, heartbeat, cached replay, errors."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.contracts import WSMessage
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.server import live_backend
from skill_sentry_cli.server.app import create_app
from skill_sentry_cli.server.demo_backend import DemoBackend
from skill_sentry_cli.server.live_backend import LiveBackend
from starlette.websockets import WebSocketDisconnect

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _drain(ws, expected_verdicts: int = 1) -> list[dict]:
    events: list[dict] = []
    completed = 0
    while True:
        message = ws.receive_json()
        events.append(message)
        WSMessage.model_validate(message)
        if message["stage"] == "verdict" and message["event"] == "completed":
            completed += 1
            if completed >= expected_verdicts:
                return events


def test_scan_all_streams_every_stage(client: TestClient):
    started = client.post("/scan", json={"options": {"no_cache": True}})
    scan_id = started.json()["scanId"]

    with client.websocket_connect(f"ws://localhost/scan/{scan_id}/stream") as ws:
        events = _drain(ws, expected_verdicts=7)

    stages = {event["stage"] for event in events}
    assert {
        "cache",
        "spec",
        "deterministicAnchor",
        "semantic",
        "vision",
        "sandbox",
        "poisonedWell",
        "evasion",
        "verdict",
    } <= stages

    overrides = [event for event in events if event["event"] == "override"]
    assert any(event["detail"]["kind"] == "poisoned_well" for event in overrides)
    assert any(event["detail"]["kind"] == "evasion" for event in overrides)

    verdicts = [
        event["detail"]["verdict"]
        for event in events
        if event["stage"] == "verdict" and event["event"] == "completed"
    ]
    assert len(verdicts) == 7
    assert {verdict["scanId"] for verdict in verdicts} == {scan_id}
    assert {verdict["skill"] for verdict in verdicts} == {
        "pdf-summarizer",
        "git-helper",
        "image-resizer",
        "weather-fetch",
        "cloud-sync-pro",
        "invoice-helper",
        "slack-notif-mal",
    }

    scan = client.get(f"/scan/{scan_id}").json()
    assert scan["status"] == "completed"
    assert scan["stage"] == "verdict"
    assert scan["skill"] is None

    batch = client.get(f"/scan/{scan_id}/verdicts").json()
    assert len(batch["verdicts"]) == 7


def test_second_scan_is_cached(client: TestClient):
    first = client.post("/scan", json={"options": {"no_cache": True}}).json()
    with client.websocket_connect(f"ws://localhost/scan/{first['scanId']}/stream") as ws:
        _drain(ws)

    second = client.post("/scan", json={"path": "pdf-summarizer"}).json()
    with client.websocket_connect(f"ws://localhost/scan/{second['scanId']}/stream") as ws:
        events = _drain(ws)

    assert [event["stage"] for event in events] == ["cache", "verdict"]
    assert events[0]["event"] == "cached"
    verdict = events[-1]["detail"]["verdict"]
    assert verdict["cached"] is True
    assert client.get(f"/scan/{second['scanId']}").json()["status"] == "cached-hit"


def test_unknown_scan_streams_structured_error(client: TestClient):
    with client.websocket_connect(
        "ws://localhost/scan/00000000-0000-4000-8000-000000000000/stream"
    ) as ws:
        message = ws.receive_json()

    assert message["event"] == "error"
    assert message["detail"]["code"] == "unknown_scan"
    assert message["detail"]["degraded"] is False


def test_single_skill_scan_uses_requested_path(client: TestClient):
    started = client.post("/scan", json={"path": "invoice-helper"}).json()
    with client.websocket_connect(f"ws://localhost/scan/{started['scanId']}/stream") as ws:
        events = _drain(ws)

    verdict = events[-1]["detail"]["verdict"]
    assert verdict["skill"] == "invoice-helper"
    assert verdict["verdict"] == "MALICIOUS"
    assert any(event["stage"] == "vision" and event["event"] == "finding" for event in events)


def test_malformed_client_message_does_not_kill_stream(client: TestClient):
    started = client.post("/scan", json={"options": {"no_cache": True}}).json()
    with client.websocket_connect(f"ws://localhost/scan/{started['scanId']}/stream") as ws:
        ws.send_text("not-json")
        events = _drain(ws, expected_verdicts=7)
    assert len([event for event in events if event["stage"] == "verdict"]) == 7


def test_client_cancel_marks_scan_failed():
    app = create_app(DemoBackend(speed=0.05))
    with TestClient(app, base_url="http://localhost") as cancel_client:
        started = cancel_client.post("/scan", json={"options": {"no_cache": True}}).json()
        scan_id = started["scanId"]
        with cancel_client.websocket_connect(f"ws://localhost/scan/{scan_id}/stream") as ws:
            ws.send_json({"op": "cancel"})
            with pytest.raises(WebSocketDisconnect):
                while True:
                    ws.receive_json()

        status = cancel_client.get(f"/scan/{scan_id}").json()
        assert status["status"] == "failed"
        assert status["error"] == "cancelled by client"


def test_cancel_delivers_the_cancelled_error_before_close(tmp_path, monkeypatch):
    """A client cancel must receive the backend's "cancelled" ERROR, then the close."""

    store = SQLiteStore(tmp_path / "ws-cancel.sqlite")
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
        with TestClient(create_app(backend), base_url="http://localhost") as client:
            started = client.post(
                "/scan",
                json={
                    "path": str(FIXTURES / "benign" / "pdf-summarizer"),
                    "options": {"sandbox": False, "no_cache": True},
                },
            )
            scan_id = started.json()["scanId"]
            assert entered.wait(timeout=15)

            received: list[dict] = []
            with client.websocket_connect(f"ws://localhost/scan/{scan_id}/stream") as ws:
                ws.send_json({"op": "cancel"})
                with pytest.raises(WebSocketDisconnect):
                    while True:
                        received.append(ws.receive_json())

            cancelled = [
                message
                for message in received
                if message["event"] == "error" and message["detail"].get("code") == "cancelled"
            ]
            assert cancelled, received
            # The close comes after the cancelled event, never before it.
            assert received[-1]["event"] == "error"
            assert client.get(f"/scan/{scan_id}").json()["status"] == "failed"
            # Release the held worker before the client exits, or shutdown waits on it.
            gate.set()
    finally:
        gate.set()
        backend.close()
        store.close()
