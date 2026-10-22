"""Tests for the fixture acceptance harness (no Docker required)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_expected_verdicts as harness  # noqa: E402


def test_expected_corpus_covers_all_fixture_kinds():
    expected = harness._expected()
    assert set(expected) == {
        "pdf-summarizer",
        "git-helper",
        "image-resizer",
        "weather-fetch",
        "cloud-sync-pro",
        "invoice-helper",
        "slack-notif-mal",
        "g1t-translate",
    }
    assert expected["cloud-sync-pro"]["e2e"]["active_defense"] is True
    assert expected["slack-notif-mal"]["e2e"]["min_risk"] == 100


def test_static_rows_fail_full_requirements_unless_explicitly_allowed():
    expected = harness._expected()["cloud-sync-pro"]
    static_row = {
        "skill": "cloud-sync-pro",
        "verdict": "MALICIOUS",
        "risk": 90,
        "active_defense": None,
    }
    full_errors = harness._check_row(
        "cloud-sync-pro", expected, static_row, allow_static=False
    )
    assert any("full-scan risk" in error for error in full_errors)
    assert any("Poisoned Well" in error for error in full_errors)

    good_static_row = {**static_row, "risk": 99}
    assert harness._check_row(
        "cloud-sync-pro", expected, good_static_row, allow_static=True
    ) == []
    assert any(
        "Poisoned Well" in error
        for error in harness._check_row(
            "cloud-sync-pro", expected, good_static_row, allow_static=False
        )
    )


def test_static_fixture_harness_passes():
    failures = [result for result in harness.check_static() if result.status == "FAIL"]
    assert not failures, "\n".join(f"{item.skill}: {item.detail}" for item in failures)


def test_full_harness_is_an_explicit_skip_without_docker():
    ready, reason = harness.docker_prerequisites()
    if ready:
        pytest.skip("Docker is available; the full fixture pass is handled by CI")
    results = harness.check_full()
    assert results
    assert all(result.status == "SKIP" for result in results)
    assert all(reason or result.detail for result in results)


def test_report_rows_accept_json_and_sarif_shapes():
    static_row = {
        "skill": "g1t-translate",
        "verdict": "SUSPICIOUS",
        "riskScore": 30,
    }
    assert harness._rows([static_row])[0]["skill"] == "g1t-translate"
    sarif = {"runs": [{"properties": static_row}]}
    assert harness._rows(sarif)[0]["risk"] == 30
