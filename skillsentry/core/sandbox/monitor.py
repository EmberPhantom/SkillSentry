"""Parse and normalise telemetry emitted by the in-container monitor shim.

The ``LD_PRELOAD`` shim writes one JSON object per line to
``/tmp/skillsentry/events.jsonl``.  This module is deliberately tolerant: a
truncated or hostile log line must never break a scan, so malformed records are
skipped and counted rather than raised.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from skillsentry.core.contracts import SandboxEvent, format_utc, utc_now
from skillsentry.core.poisoned_well.canary_gen import CanarySet

CANARY_EVENT_TYPES = frozenset(
    {
        "canary_seeded",
        "canary_read",
        "fake_served",
        "probe_detected",
        "exfil_raw",
        "exfil_decoded",
        "marker_matched",
        "secondary_served",
    }
)


@dataclass(frozen=True)
class MonitorEvent:
    ts: datetime
    event_type: str
    path_or_channel: str | None = None
    marker: str | None = None
    process: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_canary_read(self) -> bool:
        return self.event_type == "canary_read"

    @property
    def is_probe(self) -> bool:
        return self.event_type == "probe_detected"

    def to_contract(self) -> SandboxEvent:
        return SandboxEvent(
            ts=self.ts,
            event_type=self.event_type,
            path_or_channel=self.path_or_channel,
            marker=self.marker,
            process=self.process,
            detail=dict(self.detail) or None,
        )


@dataclass(frozen=True)
class ParseResult:
    events: list[MonitorEvent]
    skipped: int = 0
    error: str | None = None


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_monitor_line(line: str) -> MonitorEvent | None:
    try:
        payload = json.loads(line)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    ts = _parse_ts(payload.get("ts"))
    event_type = payload.get("event_type")
    if ts is None or not isinstance(event_type, str) or not event_type:
        return None
    path = payload.get("path")
    if path is None:
        path = payload.get("path_or_channel")
    marker = payload.get("marker")
    process = payload.get("process")
    detail = payload.get("detail")
    return MonitorEvent(
        ts=ts,
        event_type=event_type,
        path_or_channel=path if isinstance(path, str) else None,
        marker=marker if isinstance(marker, str) and marker else None,
        process=process if isinstance(process, str) else None,
        detail=detail if isinstance(detail, dict) else {},
    )


def parse_monitor_log(text: str | bytes | None) -> ParseResult:
    if text is None:
        return ParseResult(events=[])
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    events: list[MonitorEvent] = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        event = parse_monitor_line(line)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    events.sort(key=lambda event: event.ts)
    return ParseResult(events=events, skipped=skipped)


def normalise_paths(events: list[MonitorEvent], canaries: CanarySet) -> list[MonitorEvent]:
    normalised: list[MonitorEvent] = []
    for event in events:
        path = event.path_or_channel
        if path and path.startswith("/"):
            path = canaries.display_path(path)
        marker = event.marker
        if event.event_type == "canary_read" and path:
            if path.startswith("env:"):
                # The shim preserves the spelling it found in the fake value,
                # which may be uppercase (AWS key ids).  Report the canonical
                # per-scan marker instead.
                marker = canaries.marker
            elif marker is None:
                file = canaries.file_for(path)
                if file is not None:
                    marker = file.marker
        normalised.append(
            MonitorEvent(
                ts=event.ts,
                event_type=event.event_type,
                path_or_channel=path,
                marker=marker,
                process=event.process,
                detail=event.detail,
            )
        )
    return normalised


def canary_reads(events: list[MonitorEvent]) -> list[MonitorEvent]:
    return [event for event in events if event.is_canary_read]


def probe_events(events: list[MonitorEvent]) -> list[MonitorEvent]:
    return [event for event in events if event.is_probe]


def synthetic_event(
    event_type: str,
    *,
    path_or_channel: str | None = None,
    marker: str | None = None,
    process: str | None = None,
    detail: dict[str, Any] | None = None,
    ts: datetime | None = None,
) -> MonitorEvent:
    """Create an event from host-side knowledge (seed/injection events)."""

    return MonitorEvent(
        ts=ts or utc_now(),
        event_type=event_type,
        path_or_channel=path_or_channel,
        marker=marker,
        process=process,
        detail=detail or {},
    )


def to_contract_events(events: list[MonitorEvent]) -> list[SandboxEvent]:
    return [event.to_contract() for event in events]


def event_summary(events: list[MonitorEvent]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.event_type] = counts.get(event.event_type, 0) + 1
    return counts


def format_events_jsonl(events: list[MonitorEvent]) -> str:
    """Serialise events for tests or for pre-seeding a monitor log."""

    lines: list[str] = []
    for event in events:
        lines.append(
            json.dumps(
                {
                    "ts": format_utc(event.ts),
                    "event_type": event.event_type,
                    "path": event.path_or_channel,
                    "marker": event.marker,
                    "process": event.process,
                    "detail": event.detail,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    return "\n".join(lines) + ("\n" if lines else "")
