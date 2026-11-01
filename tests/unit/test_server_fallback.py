"""The dashboard fallback never answers an API path with a page."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from skill_sentry.server.app import create_app
from skill_sentry.server.demo_backend import DemoBackend


@pytest.fixture()
def dashboard_client(tmp_path: Path) -> TestClient:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>dashboard</title>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    return TestClient(create_app(DemoBackend(speed=0), static_dir=dist))


def test_dashboard_is_served_at_the_root(dashboard_client: TestClient):
    response = dashboard_client.get("/")
    assert response.status_code == 200
    assert "dashboard" in response.text


def test_unknown_api_path_is_a_json_404_not_a_page(dashboard_client: TestClient):
    response = dashboard_client.get("/skills/..%2F..%2Fetc")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"]["code"] == "not_found"


def test_unknown_sub_path_under_an_api_prefix_is_a_json_404(dashboard_client: TestClient):
    response = dashboard_client.get("/scans/unknown/extra")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_a_built_asset_is_still_served(dashboard_client: TestClient):
    response = dashboard_client.get("/assets/app.js")
    assert response.status_code == 200
    assert "console.log" in response.text


def test_unknown_non_api_path_gets_the_dashboard(dashboard_client: TestClient):
    response = dashboard_client.get("/triage/some-view")
    assert response.status_code == 200
    assert "dashboard" in response.text
