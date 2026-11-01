"""WebSocket contract: event names, ordering, heartbeat, cached replay, errors."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from skill_sentry.core.contracts import WSMessage
from skill_sentry.server.app import create_app
from skill_sentry.server.demo_backend import DemoBackend
from starlette.websockets import WebSocketDisconnect


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

    with client.websocket_connect(f"/scan/{scan_id}/stream") as ws:
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
    with client.websocket_connect(f"/scan/{first['scanId']}/stream") as ws:
        _drain(ws)

    second = client.post("/scan", json={"path": "pdf-summarizer"}).json()
    with client.websocket_connect(f"/scan/{second['scanId']}/stream") as ws:
        events = _drain(ws)

    assert [event["stage"] for event in events] == ["cache", "verdict"]
    assert events[0]["event"] == "cached"
    verdict = events[-1]["detail"]["verdict"]
    assert verdict["cached"] is True
    assert client.get(f"/scan/{second['scanId']}").json()["status"] == "cached-hit"


def test_unknown_scan_streams_structured_error(client: TestClient):
    with client.websocket_connect("/scan/00000000-0000-4000-8000-000000000000/stream") as ws:
        message = ws.receive_json()

    assert message["event"] == "error"
    assert message["detail"]["code"] == "unknown_scan"
    assert message["detail"]["degraded"] is False


def test_single_skill_scan_uses_requested_path(client: TestClient):
    started = client.post("/scan", json={"path": "invoice-helper"}).json()
    with client.websocket_connect(f"/scan/{started['scanId']}/stream") as ws:
        events = _drain(ws)

    verdict = events[-1]["detail"]["verdict"]
    assert verdict["skill"] == "invoice-helper"
    assert verdict["verdict"] == "MALICIOUS"
    assert any(event["stage"] == "vision" and event["event"] == "finding" for event in events)


def test_malformed_client_message_does_not_kill_stream(client: TestClient):
    started = client.post("/scan", json={"options": {"no_cache": True}}).json()
    with client.websocket_connect(f"/scan/{started['scanId']}/stream") as ws:
        ws.send_text("not-json")
        events = _drain(ws, expected_verdicts=7)
    assert len([event for event in events if event["stage"] == "verdict"]) == 7


def test_client_cancel_marks_scan_failed():
    app = create_app(DemoBackend(speed=0.05))
    with TestClient(app) as cancel_client:
        started = cancel_client.post("/scan", json={"options": {"no_cache": True}}).json()
        scan_id = started["scanId"]
        with cancel_client.websocket_connect(f"/scan/{scan_id}/stream") as ws:
            ws.send_json({"op": "cancel"})
            with pytest.raises(WebSocketDisconnect):
                while True:
                    ws.receive_json()

        status = cancel_client.get(f"/scan/{scan_id}").json()
        assert status["status"] == "failed"
        assert status["error"] == "cancelled by client"
