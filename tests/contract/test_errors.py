"""Error envelope contract and fail-safe behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _assert_error(response, status: int, code: str) -> dict:
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "stage", "degraded", "scanId"}
    assert body["error"]["code"] == code
    assert body["error"]["degraded"] in {True, False}
    return body["error"]


def test_unknown_scan_returns_404(client: TestClient):
    error = _assert_error(
        client.get("/scan/00000000-0000-4000-8000-000000000000"),
        404,
        "unknown_scan",
    )
    assert error["message"]


def test_unknown_skill_returns_404(client: TestClient):
    _assert_error(
        client.get("/skills/00000000-0000-4000-8000-000000000000"),
        404,
        "unknown_scan",
    )


def test_unknown_demo_path_returns_404(client: TestClient):
    response = client.post("/scan", json={"path": "not-a-real-skill"})
    _assert_error(response, 404, "no_skill_manifest")


def test_schema_violation_returns_422(client: TestClient):
    _assert_error(client.post("/scan", json={"options": {"timeout_s": 1}}), 422, "schema_violation")


def test_stix_export_without_iocs_returns_409(client: TestClient):
    scans = client.get("/scans").json()["scans"]
    benign = next(row for row in scans if row["verdict"] == "SAFE")
    _assert_error(client.get(f"/skills/{benign['skillId']}/export?format=stix"), 409, "no_iocs")


def test_unknown_export_format_is_422(client: TestClient):
    scans = client.get("/scans").json()["scans"]
    _assert_error(
        client.get(f"/skills/{scans[0]['skillId']}/export?format=pdf"),
        422,
        "schema_violation",
    )


def test_delete_cache_contract(client: TestClient):
    response = client.delete("/cache?older_than=90d")
    assert response.status_code == 200
    assert set(response.json()) == {"deleted", "retained"}
    assert response.json()["deleted"] >= 0
