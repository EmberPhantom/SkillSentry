"""Per-scan sinkhole sidecar attached to the isolated Docker network.

The sidecar is the only component that receives sandbox egress.  It is a
separate container on an ``internal`` bridge (no NAT), with a static address
used as the sandbox's DNS resolver.  DNS A answers point back at the sidecar;
HTTP requests get an inert 200 response.  Observations are emitted as JSON
lines on stdout and collected before teardown.

TLS is intentionally not intercepted in M1.  A self-signed certificate would
require installing a trust anchor inside the skill image, which changes the
threat model; HTTPS fixtures must use HTTP or remain explicitly unverified.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

MAX_SIDECAR_LOG_BYTES = 8 * 1024 * 1024
MAX_SIDECAR_EVENTS = 10_000
_SIDECAR_SCRIPT_PATH = Path(__file__).resolve().parent / "assets" / "sinkhole_sidecar.py"
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


class SidecarError(RuntimeError):
    """The sinkhole sidecar could not be started or its evidence is unusable."""


@dataclass(frozen=True)
class SinkholeObservation:
    ts: datetime
    protocol: str
    query_or_url: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    client: str = ""
    responder_action: str = "fake"

    @property
    def body_b64(self) -> str | None:
        if not self.body:
            return None
        return base64.b64encode(self.body).decode("ascii")


@dataclass(frozen=True)
class SinkholeConfig:
    image: str = "python:3.11-slim"
    ip: str = "172.30.77.2"
    subnet: str = "172.30.77.0/24"
    dns_port: int = 53
    http_port: int = 80
    timeout_s: float = 15.0


class SidecarController(Protocol):
    @property
    def ip(self) -> str: ...

    def start(self, client: Any, network: Any, scan_id: UUID) -> SinkholeSidecar: ...


class SinkholeSidecar:
    """Docker lifecycle plus observation parsing for one scan."""

    def __init__(self, client: Any, config: SinkholeConfig | None = None) -> None:
        self.client = client
        self.config = config or SinkholeConfig()
        self.container: Any | None = None
        self._ip = self.config.ip

    @property
    def ip(self) -> str:
        return self._ip

    def start(self, network: Any, scan_id: UUID, *, image: str | None = None) -> SinkholeSidecar:
        if self.container is not None:
            return self
        network_name = getattr(network, "name", None) or str(network)
        labels = {
            "skillsentry": "true",
            "skillsentry.role": "sinkhole-sidecar",
            "skillsentry.scan_id": str(scan_id),
        }
        try:
            container = self.client.containers.create(
                image=image or self.config.image,
                command=["python", "-u", "/tmp/skillsentry_sidecar.py"],
                detach=True,
                read_only=True,
                user="0:0",
                working_dir="/tmp",
                tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=16m,mode=1777"},
                cap_drop=["ALL"],
                cap_add=["NET_BIND_SERVICE"],
                security_opt=["no-new-privileges"],
                environment={
                    "SKILLSENTRY_SIDECAR_IP": self._ip,
                    "SKILLSENTRY_DNS_PORT": str(self.config.dns_port),
                    "SKILLSENTRY_HTTP_PORT": str(self.config.http_port),
                },
                labels=labels,
                auto_remove=False,
                network=network_name,
                networking_config={
                    "EndpointsConfig": {
                        network_name: {"IPAMConfig": {"IPv4Address": self._ip}}
                    }
                },
            )
            script = _SIDECAR_SCRIPT_PATH.read_bytes()
            import io
            import tarfile

            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                info = tarfile.TarInfo("skillsentry_sidecar.py")
                info.size = len(script)
                info.mode = 0o755
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                archive.addfile(info, io.BytesIO(script))
            container.put_archive("/tmp", buffer.getvalue())
            container.start()
            self.container = container
            return self
        except Exception as exc:
            self.stop(collect=False)
            raise SidecarError(f"could not start sinkhole sidecar: {exc}") from exc

    def stop(self, *, collect: bool = True) -> list[SinkholeObservation]:
        observations: list[SinkholeObservation] = []
        container = self.container
        self.container = None
        if container is None:
            return observations
        if collect:
            try:
                raw = container.logs(stdout=True, stderr=False)
                if isinstance(raw, bytes):
                    observations = parse_sidecar_log(raw)
            except Exception:
                observations = []
        try:
            container.stop(timeout=1)
        except Exception:
            pass
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass
        return observations


def parse_sidecar_log(raw: bytes | str) -> list[SinkholeObservation]:
    if isinstance(raw, bytes):
        raw = raw[-MAX_SIDECAR_LOG_BYTES:].decode("utf-8", errors="replace")
    elif len(raw) > MAX_SIDECAR_LOG_BYTES:
        raw = raw[-MAX_SIDECAR_LOG_BYTES:]
    observations: list[SinkholeObservation] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            # Docker may prefix non-TTY streams with a multiplexing header.
            brace = line.find("{")
            if brace == -1:
                continue
            line = line[brace:]
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        protocol = payload.get("protocol")
        url = payload.get("query_or_url")
        if protocol not in {"dns", "http"} or not isinstance(url, str) or not url:
            continue
        ts_raw = payload.get("ts")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            continue
        body_b64 = payload.get("body_b64")
        body = b""
        if isinstance(body_b64, str):
            try:
                body = base64.b64decode(body_b64, validate=False)[:2_000_000]
            except (ValueError, TypeError):
                body = b""
        headers = payload.get("headers")
        observations.append(
            SinkholeObservation(
                ts=ts,
                protocol=protocol,
                query_or_url=url[:4096],
                body=body,
                headers=(
                    {str(k)[:100]: str(v)[:1000] for k, v in headers.items()}
                    if isinstance(headers, dict)
                    else {}
                ),
                client=str(payload.get("client") or "")[:200],
                responder_action=str(payload.get("responder_action") or "fake")[:200],
            )
        )
        if len(observations) >= MAX_SIDECAR_EVENTS:
            break
    return observations


__all__ = [
    "MAX_SIDECAR_EVENTS",
    "SidecarController",
    "SidecarError",
    "SinkholeConfig",
    "SinkholeObservation",
    "SinkholeSidecar",
    "parse_sidecar_log",
]
