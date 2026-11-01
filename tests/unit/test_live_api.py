"""Live HTTP/WebSocket smoke test against the real engine, no Docker required."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from skill_sentry.core.cache import SQLiteStore
from skill_sentry.core.engine import ScanEngine
from skill_sentry.core.models.mock import MockGemma
from skill_sentry.server.app import create_app
from skill_sentry.server.live_backend import LiveBackend

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def test_live_api_streams_a_real_scan_and_serves_its_evidence(tmp_path):
    store = SQLiteStore(tmp_path / "live-api.sqlite")
    engine = ScanEngine(store=store, model=MockGemma(profile="benign"))
    backend = LiveBackend(engine=engine)
    try:
        with TestClient(create_app(backend)) as client:
            started = client.post(
                "/scan",
                json={
                    "path": str(FIXTURES / "benign" / "pdf-summarizer"),
                    "options": {"sandbox": False, "no_cache": True},
                },
            )
            assert started.status_code == 202, started.text
            scan_id = started.json()["scanId"]

            events = []
            with client.websocket_connect(f"/scan/{scan_id}/stream") as websocket:
                while True:
                    event = websocket.receive_json()
                    events.append(event)
                    if event["stage"] == "verdict" and event["event"] == "completed":
                        break

            assert events[-1]["detail"]["verdict"]["skill"] == "pdf-summarizer"
            assert events[-1]["detail"]["verdict"]["verdict"] == "SAFE"

            status = client.get(f"/scan/{scan_id}")
            assert status.status_code == 200
            assert status.json()["status"] == "completed"

            verdicts = client.get(f"/scan/{scan_id}/verdicts")
            assert verdicts.status_code == 200
            verdict = verdicts.json()["verdicts"][0]
            assert verdict["skill"] == "pdf-summarizer"
            assert verdict["verdict"] == "SAFE"

            detail = client.get(f"/skills/{verdict['skillId']}")
            assert detail.status_code == 200
            assert detail.json()["verdict"]["scanId"] == scan_id
            assert detail.json()["verdict"]["activeDefense"]["triggered"] is False

            exported = client.get(f"/skills/{verdict['skillId']}/export?format=sarif")
            assert exported.status_code == 200
            assert exported.headers["content-type"].startswith("application/sarif+json")
            assert exported.json()["runs"][0]["properties"]["skill"] == "pdf-summarizer"
    finally:
        backend.close()
        store.close()
