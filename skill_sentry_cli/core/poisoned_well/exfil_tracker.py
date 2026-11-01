"""Poisoned Well correlation engine.

Event A is a canary read (file access or an injected env var); Event B is a DNS
query or HTTP request observed by the sinkhole.  A correlation is confirmed only
when B falls inside the configured window and contains the canary marker in one
of its supported encodings: raw, base64 (standard or URL-safe), hex, or split
across DNS labels.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import unquote_plus, urlsplit

from skill_sentry_cli.core.contracts import (
    ExfilChannel,
    OverrideSignal,
    Stage,
    VerdictTier,
    format_utc,
    utc_now,
)
from skill_sentry_cli.core.poisoned_well.canary_gen import CanarySet
from skill_sentry_cli.core.sandbox.monitor import MonitorEvent

_BASE64_RE = re.compile(r"[A-Za-z0-9+/_=-]{8,}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Hints used to narrow a confirmed observation to the canary source(s) that
# actually appear in the decoded payload.  If none match, the tracker keeps all
# in-window reads and reports the broader set rather than losing evidence.
_ASSET_HINTS: dict[str, tuple[str, ...]] = {
    "aws": (
        "AKIA",
        "aws_access_key_id",
        "aws_secret_access_key",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ),
    "github": ("ghp_", "oauth_token", "GITHUB_TOKEN", "GH_TOKEN", "github.com"),
    "slack": ("xoxb-", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "hooks.slack"),
    "ssh": ("BEGIN OPENSSH PRIVATE KEY", "id_rsa", "SSH_KEY_PATH"),
    "generic": (
        "OPENAI_API_KEY",
        "DATABASE_URL",
        "NPM_TOKEN",
        "passwords.kdbx",
        "npm_",
        "postgres://",
    ),
}


@dataclass(frozen=True)
class CanaryRead:
    ts: datetime
    path: str
    asset: str
    marker: str
    process: str | None = None
    implicit: bool = False

    @property
    def is_env(self) -> bool:
        return self.path.startswith("env:")


@dataclass(frozen=True)
class NetObservation:
    ts: datetime
    protocol: Literal["dns", "http"]
    query_or_url: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    client: str | None = None
    method: str | None = None
    responder_action: str | None = None

    @property
    def channel(self) -> ExfilChannel:
        return ExfilChannel.DNS_TUNNELING if self.protocol == "dns" else ExfilChannel.HTTP_POST

    @property
    def body_b64(self) -> str | None:
        if not self.body:
            return None
        return base64.b64encode(self.body).decode("ascii")

    def as_text(self) -> str:
        header_text = "\n".join(f"{key}: {value}" for key, value in sorted(self.headers.items()))
        body_text = self.body.decode("utf-8", errors="replace")
        return "\n".join(part for part in (self.query_or_url, header_text, body_text) if part)


@dataclass(frozen=True)
class Correlation:
    matched: bool
    reads: tuple[CanaryRead, ...]
    observation: NetObservation
    marker: str | None = None
    encoding: str | None = None
    c2_indicators: tuple[str, ...] = ()
    decoded_preview: str | None = None
    confidence: float = 0.0

    @property
    def channel(self) -> ExfilChannel:
        return self.observation.channel

    @property
    def targeted_assets(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(read.path for read in self.reads))

    def to_override(self) -> OverrideSignal | None:
        if not self.matched:
            return None
        assets = ", ".join(self.targeted_assets) or "a seeded canary"
        encoding = self.encoding or "raw"
        return OverrideSignal(
            verdict=VerdictTier.MALICIOUS,
            confidence=1.0,
            reason=(
                f"Poisoned Well confirmed exfiltration: {assets} was read and its "
                f"marker appeared in {self.channel.value} traffic ({encoding})."
            ),
            source=Stage.POISONED_WELL,
            evidence={
                "canaryMarker": self.marker,
                "encoding": encoding,
                "exfilChannel": self.channel.value,
                "targetedAssets": list(self.targeted_assets),
                "c2Indicators": list(self.c2_indicators),
                "observation": self.observation.query_or_url,
            },
        )


def _decode_base64(value: str) -> bytes | None:
    candidate = value.strip()
    if not candidate:
        return None
    # URL-safe alphabet, then pad to a multiple of four.
    candidate = candidate.replace("-", "+").replace("_", "/")
    candidate = candidate.rstrip("=")
    candidate += "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(candidate, validate=False)
    except (binascii.Error, ValueError):
        return None


def _decode_hex(value: str) -> bytes | None:
    candidate = value.strip()
    if len(candidate) % 2:
        candidate = candidate[:-1]
    if len(candidate) < 16:
        return None
    try:
        return bytes.fromhex(candidate)
    except ValueError:
        return None


def _registered_domain(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        return host
    if _IPV4_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    second_level = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if len(labels[-1]) == 2 and labels[-2] in second_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _c2_from_observation(observation: NetObservation) -> tuple[str, ...]:
    if observation.protocol == "dns":
        domain = _registered_domain(observation.query_or_url)
        return (domain,) if domain else ()
    try:
        parsed = urlsplit(observation.query_or_url)
    except ValueError:
        return ()
    host = parsed.hostname
    if not host:
        return ()
    return (_registered_domain(host),)


def _dns_prefixes(qname: str) -> list[str]:
    labels = [label for label in qname.split(".") if label]
    prefixes: list[str] = []
    for index in range(1, len(labels) + 1):
        prefixes.append("".join(labels[:index]))
        prefixes.append(".".join(labels[:index]))
    return prefixes


def _candidate_texts(observation: NetObservation) -> list[tuple[str, str]]:
    """Return ``(encoding, decoded_text)`` candidates for marker matching."""

    raw = observation.as_text()
    candidates: list[tuple[str, str]] = [("raw", raw)]
    decoded_url = unquote_plus(raw)
    if decoded_url != raw:
        candidates.append(("raw", decoded_url))

    if observation.protocol == "dns":
        for variant in _dns_prefixes(observation.query_or_url):
            candidates.append(("subdomain", variant))
            decoded = _decode_base64(variant)
            if decoded is not None:
                candidates.append(("base64", decoded.decode("utf-8", errors="replace")))
            decoded_hex = _decode_hex(variant)
            if decoded_hex is not None:
                candidates.append(("hex", decoded_hex.decode("utf-8", errors="replace")))

    tokens = [raw, decoded_url, *[value for _encoding, value in candidates]]
    for value in tokens:
        for match in _BASE64_RE.findall(value):
            decoded = _decode_base64(match)
            if decoded is not None:
                candidates.append(("base64", decoded.decode("utf-8", errors="replace")))
        for match in _HEX_RE.findall(value):
            decoded = _decode_hex(match)
            if decoded is not None:
                candidates.append(("hex", decoded.decode("utf-8", errors="replace")))

    # De-duplicate while preserving the first (most direct) encoding.
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for encoding, value in candidates:
        key = (encoding, value)
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def _find_marker(
    observation: NetObservation, canaries: CanarySet
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return ``(marker, encoding, preview, matched_text)`` for a token hit."""

    tokens = canaries.search_tokens
    for encoding, text in _candidate_texts(observation):
        for token in tokens:
            if token in text:
                preview = text[:300] if encoding != "raw" else None
                matched_encoding = encoding
                if encoding == "subdomain" and token in observation.query_or_url:
                    matched_encoding = "raw"
                return canaries.marker, matched_encoding, preview, text
    return None, None, None, None


def _filter_reads(reads: list[CanaryRead], matched_text: str) -> list[CanaryRead]:
    """Prefer the canary sources whose provider hints appear in the payload."""

    matched = [
        read
        for read in reads
        if any(hint in matched_text for hint in _ASSET_HINTS.get(read.asset, ()))
    ]
    return matched or reads


class ExfilTracker:
    """Stateful per-scan correlator; safe to call from one scan worker."""

    def __init__(
        self,
        canaries: CanarySet,
        *,
        window_s: float = 30.0,
        clock_skew_s: float = 2.0,
    ) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self.canaries = canaries
        self.window_s = window_s
        self.clock_skew_s = max(0.0, clock_skew_s)
        self._reads: list[CanaryRead] = []
        self._observations: list[NetObservation] = []
        self._results: list[Correlation] = []
        self._seen: set[tuple[str, str, str]] = set()

    @property
    def reads(self) -> tuple[CanaryRead, ...]:
        return tuple(self._reads)

    @property
    def observations(self) -> tuple[NetObservation, ...]:
        return tuple(self._observations)

    @property
    def results(self) -> tuple[Correlation, ...]:
        return tuple(self._results)

    @property
    def confirmed(self) -> bool:
        return bool(self._results)

    def record_canary_read(self, event: MonitorEvent) -> CanaryRead | None:
        if event.event_type != "canary_read" or not event.path_or_channel:
            return None
        path = event.path_or_channel
        asset = "generic"
        marker = event.marker or self.canaries.marker
        if path.startswith("env:"):
            key = path.removeprefix("env:")
            asset = self.canaries.env_assets.get(key, "generic")
            marker = self.canaries.marker
        else:
            file = self.canaries.file_for(path)
            if file is not None:
                asset = file.asset
                marker = file.marker
        implicit = bool(event.detail.get("implicit"))
        read = CanaryRead(
            ts=event.ts,
            path=self.canaries.display_path(path),
            asset=asset,
            marker=marker,
            process=event.process,
            implicit=implicit,
        )
        self._reads.append(read)
        return read

    def record_implicit_env_reads(self, *, ts: datetime | None = None) -> list[CanaryRead]:
        """Treat injected env canaries as exposed at process start.

        Shell expansion of ``$SLACK_BOT_TOKEN`` is not observable through
        ``getenv``, so the environment itself is the exposure event.  The
        within-window and marker-match requirements still apply to Event B.
        """

        moment = ts or utc_now()
        reads: list[CanaryRead] = []
        for key in self.canaries.env_canary_keys:
            event = MonitorEvent(
                ts=moment,
                event_type="canary_read",
                path_or_channel=f"env:{key}",
                marker=self.canaries.marker,
                detail={"implicit": True, "channel": "env"},
            )
            read = self.record_canary_read(event)
            if read is not None:
                reads.append(read)
        return reads

    def _matching_reads(self, observation: NetObservation) -> list[CanaryRead]:
        lower = observation.ts - timedelta(seconds=self.window_s)
        upper = observation.ts + timedelta(seconds=self.clock_skew_s)
        return [read for read in self._reads if lower <= read.ts <= upper]

    def observe(
        self,
        *,
        protocol: Literal["dns", "http"],
        query_or_url: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        ts: datetime | None = None,
        client: str | None = None,
        method: str | None = None,
        responder_action: str | None = None,
    ) -> Correlation | None:
        observation = NetObservation(
            ts=ts or utc_now(),
            protocol=protocol,
            query_or_url=query_or_url,
            body=body,
            headers=headers or {},
            client=client,
            method=method,
            responder_action=responder_action,
        )
        self._observations.append(observation)
        reads = self._matching_reads(observation)
        if not reads:
            return None
        marker, encoding, preview, matched_text = _find_marker(observation, self.canaries)
        if marker is None or matched_text is None:
            return None
        targeted = tuple(_filter_reads(reads, matched_text))
        c2 = _c2_from_observation(observation)
        result = Correlation(
            matched=True,
            reads=targeted,
            observation=observation,
            marker=marker,
            encoding=encoding,
            c2_indicators=c2,
            decoded_preview=preview,
            confidence=1.0,
        )
        key = (
            marker,
            observation.protocol,
            hashlib.sha256(observation.query_or_url.encode("utf-8")).hexdigest(),
        )
        if key not in self._seen:
            self._seen.add(key)
            self._results.append(result)
        return result

    def observe_dns(
        self,
        qname: str,
        *,
        ts: datetime | None = None,
        client: str | None = None,
        responder_action: str | None = None,
    ) -> Correlation | None:
        return self.observe(
            protocol="dns",
            query_or_url=qname,
            ts=ts,
            client=client,
            responder_action=responder_action,
        )

    def observe_http(
        self,
        method: str,
        url: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        ts: datetime | None = None,
        client: str | None = None,
        responder_action: str | None = None,
    ) -> Correlation | None:
        return self.observe(
            protocol="http",
            query_or_url=url,
            body=body,
            headers=headers,
            ts=ts,
            client=client,
            method=method,
            responder_action=responder_action,
        )

    def summary(self) -> dict[str, Any]:
        result = self._results[-1] if self._results else None
        return {
            "confirmed": result is not None,
            "marker": result.marker if result else self.canaries.marker,
            "encoding": result.encoding if result else None,
            "channel": result.channel.value if result else None,
            "targetedAssets": list(result.targeted_assets) if result else [],
            "c2Indicators": list(result.c2_indicators) if result else [],
            "readCount": len(self._reads),
            "observationCount": len(self._observations),
            "lastObservedAt": format_utc(self._observations[-1].ts) if self._observations else None,
        }
