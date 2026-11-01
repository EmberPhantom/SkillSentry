"""Poisoned Well correlation across DNS and HTTP exfiltration channels."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from skill_sentry.core.contracts import ExfilChannel, Stage, VerdictTier
from skill_sentry.core.poisoned_well.canary_gen import generate_canary_set
from skill_sentry.core.poisoned_well.exfil_tracker import ExfilTracker
from skill_sentry.core.sandbox.monitor import MonitorEvent

SCAN_ID = UUID("33333333-3333-4333-8333-333333333333")
MARKER = "SKS-7f3a9c21"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def _canaries(intent: str = "cloud sync"):
    return generate_canary_set(
        SCAN_ID,
        intent,
        marker=MARKER,
        secondary_marker="SKS-8b2c4d19",
    )


def _read(
    *,
    path: str = "~/.aws/credentials",
    ts: datetime = NOW,
    marker: str | None = MARKER,
) -> MonitorEvent:
    return MonitorEvent(
        ts=ts,
        event_type="canary_read",
        path_or_channel=path,
        marker=marker,
        process="python",
        detail={},
    )


def test_raw_dns_marker_is_confirmed_and_produces_an_override():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    result = tracker.observe_dns("SKS-7f3a9c21.evil-collector.net", ts=NOW + timedelta(seconds=2))
    assert result is not None
    assert result.matched
    assert result.channel is ExfilChannel.DNS_TUNNELING
    assert result.encoding == "raw"
    assert result.marker == MARKER
    assert result.c2_indicators == ("evil-collector.net",)
    assert result.targeted_assets == ("~/.aws/credentials",)
    override = result.to_override()
    assert override is not None
    assert override.verdict is VerdictTier.MALICIOUS
    assert override.confidence == 1.0
    assert override.source is Stage.POISONED_WELL
    assert "Poisoned Well confirmed" in override.reason


def test_base64_dns_payload_is_confirmed():
    canaries = _canaries()
    credentials = next(item for item in canaries.files if item.relative_path == ".aws/credentials")
    access_key = credentials.content.split("aws_access_key_id = ", 1)[1].splitlines()[0]
    payload = base64.urlsafe_b64encode(f"access_key={access_key}".encode()).decode("ascii")
    tracker = ExfilTracker(canaries)
    tracker.record_canary_read(_read())
    result = tracker.observe_dns(f"{payload}.evil-collector.net", ts=NOW + timedelta(seconds=4))
    assert result is not None
    assert result.encoding == "base64"
    assert "AKIA" in (result.decoded_preview or "")
    assert MARKER.replace("-", "").upper() in (result.decoded_preview or "")


def test_hex_dns_payload_is_confirmed():
    payload = MARKER.encode("ascii").hex()
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    result = tracker.observe_dns(f"{payload}.evil-collector.net", ts=NOW + timedelta(seconds=4))
    assert result is not None
    assert result.encoding == "hex"


def test_split_dns_labels_are_reassembled():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    result = tracker.observe_dns("SKS-7f3a.9c21.evil-collector.net", ts=NOW + timedelta(seconds=4))
    assert result is not None
    assert result.encoding == "subdomain"


def test_http_body_base64_is_confirmed():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read(path="~/.ssh/id_rsa", marker=MARKER))
    body = base64.b64encode(b"key=SSH_KEY_PATH SKS-7f3a9c21").decode("ascii").encode("ascii")
    result = tracker.observe_http(
        "POST",
        "https://evil-c2.com/collect",
        body=body,
        ts=NOW + timedelta(seconds=5),
    )
    assert result is not None
    assert result.channel is ExfilChannel.HTTP_POST
    assert result.encoding == "base64"
    assert result.c2_indicators == ("evil-c2.com",)


def test_observation_outside_window_is_not_confirmed():
    tracker = ExfilTracker(_canaries(), window_s=30)
    tracker.record_canary_read(_read())
    result = tracker.observe_dns("SKS-7f3a9c21.evil-collector.net", ts=NOW + timedelta(seconds=31))
    assert result is None
    assert tracker.confirmed is False
    assert len(tracker.observations) == 1


def test_marker_absent_is_not_confirmed():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    assert tracker.observe_dns("harmless.example.com", ts=NOW + timedelta(seconds=1)) is None


def test_read_after_observation_is_not_confirmed():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read(ts=NOW + timedelta(seconds=10)))
    assert tracker.observe_dns("SKS-7f3a9c21.evil-collector.net", ts=NOW) is None


def test_implicit_environment_reads_correlate():
    tracker = ExfilTracker(_canaries("Slack workspace"))
    tracker.record_implicit_env_reads(ts=NOW)
    result = tracker.observe_http(
        "POST",
        "https://evil-c2.com/collect",
        body=b"token=xoxb-SKS-7f3a9c21",
        ts=NOW + timedelta(seconds=3),
    )
    assert result is not None
    assert any(asset.startswith("env:SLACK_") for asset in result.targeted_assets)


def test_asset_hints_narrow_targeted_assets():
    tracker = ExfilTracker(_canaries("Slack workspace"))
    tracker.record_canary_read(_read(path="~/.aws/credentials"))
    tracker.record_canary_read(_read(path="~/.config/slack/token"))
    result = tracker.observe_http(
        "POST",
        "https://evil-c2.com/collect",
        body=b"token=xoxb-SKS-7f3a9c21",
        ts=NOW + timedelta(seconds=2),
    )
    assert result is not None
    assert result.targeted_assets == ("~/.config/slack/token",)


def test_canary_read_normalises_container_paths_and_env():
    canaries = _canaries("Slack workspace")
    tracker = ExfilTracker(canaries)
    file_read = tracker.record_canary_read(
        _read(path="/home/sandbox/.config/slack/token", marker=None)
    )
    assert file_read is not None
    assert file_read.path == "~/.config/slack/token"
    assert file_read.asset == "slack"
    assert file_read.marker == MARKER

    env_read = tracker.record_canary_read(_read(path="env:SLACK_BOT_TOKEN", marker=MARKER.upper()))
    assert env_read is not None
    assert env_read.asset == "slack"
    assert env_read.is_env
    assert env_read.marker == MARKER


def test_duplicate_observations_are_logged_but_not_duplicated():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    first = tracker.observe_dns("SKS-7f3a9c21.evil-collector.net", ts=NOW + timedelta(seconds=1))
    second = tracker.observe_dns("SKS-7f3a9c21.evil-collector.net", ts=NOW + timedelta(seconds=2))
    assert first is not None
    assert second is not None
    assert len(tracker.observations) == 2
    assert len(tracker.results) == 1


def test_c2_recognises_second_level_domains():
    tracker = ExfilTracker(_canaries())
    tracker.record_canary_read(_read())
    result = tracker.observe_http(
        "POST",
        "https://collect.evil-c2.co.uk/drop",
        body=b"SKS-7f3a9c21",
        ts=NOW + timedelta(seconds=1),
    )
    assert result is not None
    assert result.c2_indicators == ("evil-c2.co.uk",)


def test_summary_and_invalid_window():
    with pytest.raises(ValueError):
        ExfilTracker(_canaries(), window_s=0)
    tracker = ExfilTracker(_canaries())
    summary = tracker.summary()
    assert summary["confirmed"] is False
    assert summary["marker"] == MARKER
    assert summary["readCount"] == 0
