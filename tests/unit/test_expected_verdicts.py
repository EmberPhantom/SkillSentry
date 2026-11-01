"""Tests for the fixture acceptance harness (no Docker required)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tests/, not tests/unit/
import check_expected_verdicts as harness


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
    full_errors = harness._check_row("cloud-sync-pro", expected, static_row, allow_static=False)
    assert any("full-scan risk" in error for error in full_errors)
    assert any("Poisoned Well" in error for error in full_errors)

    good_static_row = {**static_row, "risk": 99}
    assert harness._check_row("cloud-sync-pro", expected, good_static_row, allow_static=True) == []
    assert any(
        "Poisoned Well" in error
        for error in harness._check_row(
            "cloud-sync-pro", expected, good_static_row, allow_static=False
        )
    )


def test_full_row_requires_active_defense_evidence():
    expected = harness._expected()["cloud-sync-pro"]
    good = {
        "skill": "cloud-sync-pro",
        "verdict": "MALICIOUS",
        "risk": 99,
        "active_defense": {
            "triggered": True,
            "exfil_channel": "DNS_TUNNELING",
            "sandbox_evasion_detected": False,
        },
    }
    assert harness._check_row("cloud-sync-pro", expected, good, allow_static=False) == []

    missing = {**good, "active_defense": None}
    errors = harness._check_row("cloud-sync-pro", expected, missing, allow_static=False)
    assert any("Poisoned Well" in error for error in errors)
    assert any("exfil channel" in error for error in errors)


def test_static_fixture_harness_passes():
    failures = [result for result in harness.check_static() if result.status == "FAIL"]
    assert not failures, "\n".join(f"{item.skill}: {item.detail}" for item in failures)


def test_full_harness_is_an_explicit_skip_without_docker():
    ready, reason = harness.docker_prerequisites()
    results = harness.check_full()
    assert results
    if ready:
        failures = [result for result in results if result.status == "FAIL"]
        assert not failures, "\n".join(f"{item.skill}: {item.detail}" for item in failures)
        return
    assert all(result.status == "SKIP" for result in results)
    assert all(reason or result.detail for result in results)
    pytest.skip(f"full-sandbox fixture checks unavailable: {reason}")


def test_report_rows_accept_json_and_sarif_shapes():
    static_row = {
        "skill": "g1t-translate",
        "verdict": "SUSPICIOUS",
        "riskScore": 30,
    }
    assert harness._rows([static_row])[0]["skill"] == "g1t-translate"
    sarif = {"runs": [{"properties": static_row}]}
    assert harness._rows(sarif)[0]["risk"] == 30

    full_row = {
        **static_row,
        "activeDefense": {
            "triggered": True,
            "exfilChannel": "DNS_TUNNELING",
            "sandboxEvasionDetected": False,
        },
    }
    active = harness._rows({"runs": [{"properties": full_row}]})[0]["active_defense"]
    assert active == {
        "triggered": True,
        "exfil_channel": "DNS_TUNNELING",
        "sandbox_evasion_detected": False,
    }
