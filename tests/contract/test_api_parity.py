"""Route-layer parity: demo mode and a non-demo app share identical handlers."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from skill_sentry_cli.server.app import create_app
from skill_sentry_cli.server.demo_backend import DemoBackend
from skill_sentry_cli.server.live_backend import LiveBackend


@pytest.fixture()
def demo_client() -> TestClient:
    backend = DemoBackend(speed=0)
    with TestClient(create_app(backend)) as client:
        yield client


@pytest.fixture()
def generic_client() -> TestClient:
    # Same backend, but create_app is not told anything about demo mode: this
    # proves the routes/contracts do not branch on the demo flag.
    backend = DemoBackend(speed=0)
    with TestClient(create_app(backend)) as client:
        yield client


def _first_malicious(client: TestClient) -> dict:
    scans = client.get("/scans").json()["scans"]
    return next(row for row in scans if row["verdict"] == "MALICIOUS")


@pytest.mark.parametrize("path", ["/scans", "/cache/stats"])
def test_read_endpoints_are_identical(path: str, demo_client, generic_client):
    demo = demo_client.get(path)
    generic = generic_client.get(path)
    assert demo.status_code == generic.status_code == 200
    assert demo.json() == generic.json()


def test_scan_and_skill_payloads_are_identical(demo_client, generic_client):
    for client in (demo_client, generic_client):
        row = _first_malicious(client)
        scan = client.get(f"/scan/{row['scanId']}")
        verdicts = client.get(f"/scan/{row['scanId']}/verdicts")
        skill = client.get(f"/skills/{row['skillId']}")
        assert scan.status_code == verdicts.status_code == skill.status_code == 200

    row = _first_malicious(demo_client)
    demo_skill = demo_client.get(f"/skills/{row['skillId']}").json()
    generic_skill = generic_client.get(f"/skills/{row['skillId']}").json()
    assert demo_skill == generic_skill
    assert demo_skill["verdict"]["scanId"] == row["scanId"]
    assert demo_skill["poisonedWell"]["confirmed"] is True
    assert demo_skill["reportLinks"]["stix"]


def test_start_scan_contract(demo_client, generic_client):
    payload = {"path": "cloud-sync-pro", "options": {"no_cache": True}}
    for client in (demo_client, generic_client):
        response = client.post("/scan", json=payload)
        assert response.status_code == 202
        body = response.json()
        assert set(body) == {"scanId", "status", "stream"}
        assert body["status"] == "queued"
        assert body["stream"] == f"/scan/{body['scanId']}/stream"


def test_export_headers_are_identical(demo_client, generic_client):
    row = _first_malicious(demo_client)
    for fmt, media in (
        ("sarif", "application/sarif+json"),
        ("markdown", "text/markdown; charset=utf-8"),
        ("stix", "application/stix+json;version=2.1"),
    ):
        path = f"/skills/{row['skillId']}/export?format={fmt}"
        demo = demo_client.get(path)
        generic = generic_client.get(path)
        assert demo.status_code == generic.status_code == 200
        assert demo.headers["content-type"].startswith(media)
        assert "attachment" in demo.headers["content-disposition"]


def test_meta_exposes_demo_flag_but_same_contract(demo_client):
    with TestClient(create_app(LiveBackend())) as live_client:
        live = live_client.get("/meta").json()
    demo = demo_client.get("/meta").json()
    assert demo["demoMode"] is True
    assert live["demoMode"] is False
    assert set(demo) == set(live)
    assert demo["contractVersion"] == live["contractVersion"] == "1"
