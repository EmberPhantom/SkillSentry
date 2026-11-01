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

from skill_sentry_cli.core.contracts import SandboxEvent, format_utc, utc_now
from skill_sentry_cli.core.poisoned_well.canary_gen import MARKER_RE, CanarySet

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LOG_LINES = 10_000
MAX_LINE_CHARS = 16_384
MAX_EVENTS = 5_000
MAX_PATH_CHARS = 1_024
MAX_DETAIL_JSON_CHARS = 8_192

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
    if len(line) > MAX_LINE_CHARS:
        return None
    try:
        payload = json.loads(line)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    ts = _parse_ts(payload.get("ts"))
    event_type = payload.get("event_type")
    if ts is None or not isinstance(event_type, str) or event_type not in CANARY_EVENT_TYPES:
        return None
    path = payload.get("path")
    if path is None:
        path = payload.get("path_or_channel")
    if path is not None and (not isinstance(path, str) or len(path) > MAX_PATH_CHARS):
        return None
    marker = payload.get("marker")
    if marker is not None and (not isinstance(marker, str) or not MARKER_RE.fullmatch(marker)):
        # A marker is evidence, not a free-form field.  Drop forged/broken
        # values rather than trusting arbitrary log content.
        marker = None
    process = payload.get("process")
    detail = payload.get("detail")
    if isinstance(detail, dict):
        try:
            if len(json.dumps(detail, sort_keys=True)) > MAX_DETAIL_JSON_CHARS:
                detail = {"truncated": True}
        except (TypeError, ValueError):
            detail = {}
    else:
        detail = {}
    return MonitorEvent(
        ts=ts,
        event_type=event_type,
        path_or_channel=path if isinstance(path, str) else None,
        marker=marker if isinstance(marker, str) and marker else None,
        process=process[:256] if isinstance(process, str) else None,
        detail=detail,
    )


def parse_monitor_log(text: str | bytes | None) -> ParseResult:
    if text is None:
        return ParseResult(events=[])
    if isinstance(text, bytes):
        if len(text) > MAX_LOG_BYTES:
            text = text[-MAX_LOG_BYTES:]
        text = text.decode("utf-8", errors="replace")
    elif len(text) > MAX_LOG_BYTES:
        text = text[-MAX_LOG_BYTES:]
    events: list[MonitorEvent] = []
    skipped = 0
    for index, line in enumerate(text.splitlines()):
        if index >= MAX_LOG_LINES:
            skipped += 1
            break
        line = line.strip()
        if not line:
            continue
        event = parse_monitor_line(line)
        if event is None:
            skipped += 1
        else:
            events.append(event)
            if len(events) >= MAX_EVENTS:
                skipped += 1
                break
    events.sort(key=lambda event: event.ts)
    return ParseResult(events=events, skipped=skipped)


def is_seeded_canary_read(event: MonitorEvent, canaries: CanarySet) -> bool:
    """True only for an exact seeded file or environment canary.

    The LD_PRELOAD shim logs every read under ``/home/sandbox`` because it
    cannot know the host-side seed set.  Treating such a read as canary
    evidence would turn ordinary cache/config reads into false positives.
    """

    if event.event_type != "canary_read":
        return False
    path = event.path_or_channel
    if not path:
        return False
    if path.startswith("env:"):
        return path.removeprefix("env:") in canaries.env
    return canaries.file_for(path) is not None


def normalise_paths(events: list[MonitorEvent], canaries: CanarySet) -> list[MonitorEvent]:
    normalised: list[MonitorEvent] = []
    for event in events:
        path = event.path_or_channel
        if path and path.startswith("/"):
            path = canaries.display_path(path)
        marker = event.marker
        if event.event_type == "canary_read":
            # Drop shim reads that do not hit a seeded canary.  This is the
            # host-side source of truth; the shim's broader path heuristic must
            # never become a finding by itself.
            if not path:
                continue
            if path.startswith("env:"):
                if path.removeprefix("env:") not in canaries.env:
                    continue
                marker = canaries.marker
            else:
                file = canaries.file_for(path)
                if file is None:
                    continue
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
