"""Tolerant monitor-log parsing and canary path normalisation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from skillsentry.core.poisoned_well.canary_gen import generate_canary_set
from skillsentry.core.sandbox.monitor import (
    event_summary,
    format_events_jsonl,
    normalise_paths,
    parse_monitor_line,
    parse_monitor_log,
    synthetic_event,
    to_contract_events,
)

SCAN_ID = UUID("66666666-6666-4666-8666-666666666666")
MARKER = "SKS-0123abcd"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def _canaries():
    return generate_canary_set(SCAN_ID, "cloud sync", marker=MARKER)


def test_parse_monitor_line_accepts_z_and_naive_timestamps():
    line = (
        '{"ts":"2026-10-21T12:00:00Z","event_type":"canary_read",'
        '"path":"/home/sandbox/.aws/credentials","process":"python"}'
    )
    event = parse_monitor_line(line)
    assert event is not None
    assert event.ts.tzinfo is not None
    assert event.ts.utcoffset() is not None
    assert event.path_or_channel == "/home/sandbox/.aws/credentials"


def test_parse_monitor_line_tolerates_malformed_records():
    assert parse_monitor_line("not json") is None
    assert parse_monitor_line("[]") is None
    assert parse_monitor_line('{"event_type":"canary_read"}') is None
    assert parse_monitor_line('{"ts":"bad","event_type":"canary_read"}') is None


def test_parse_monitor_log_skips_bad_lines_and_sorts():
    text = "\n".join(
        [
            '{"ts":"2026-10-21T12:00:02Z","event_type":"probe_detected","path":"/proc/1/cgroup"}',
            "garbage",
            "",
            '{"ts":"2026-10-21T12:00:01Z","event_type":"canary_read","path":".env"}',
        ]
    )
    parsed = parse_monitor_log(text)
    assert parsed.skipped == 1
    assert [event.event_type for event in parsed.events] == ["canary_read", "probe_detected"]


def test_normalise_paths_maps_container_home_and_fills_marker():
    canaries = _canaries()
    events = [
        synthetic_event(
            "canary_read",
            path_or_channel="/home/sandbox/.aws/credentials",
            ts=NOW,
        ),
        synthetic_event(
            "canary_read",
            path_or_channel="env:AWS_ACCESS_KEY_ID",
            marker=MARKER.upper(),
            ts=NOW,
        ),
    ]
    normalised = normalise_paths(events, canaries)
    assert normalised[0].path_or_channel == "~/.aws/credentials"
    assert normalised[0].marker == MARKER
    assert normalised[1].path_or_channel == "env:AWS_ACCESS_KEY_ID"
    assert normalised[1].marker == MARKER


def test_contract_conversion_and_summary_are_stable():
    canaries = _canaries()
    events = [
        synthetic_event(
            "canary_seeded",
            path_or_channel="~/.aws/credentials",
            marker=MARKER,
            ts=NOW,
        ),
        synthetic_event("probe_detected", path_or_channel="/.dockerenv", ts=NOW),
    ]
    contracts = to_contract_events(events)
    assert contracts[0].event_type == "canary_seeded"
    assert contracts[0].path_or_channel == "~/.aws/credentials"
    assert event_summary(events) == {"canary_seeded": 1, "probe_detected": 1}
    encoded = format_events_jsonl(normalise_paths(events, canaries))
    assert '"event_type":"canary_seeded"' in encoded
    assert encoded.endswith("\n")
