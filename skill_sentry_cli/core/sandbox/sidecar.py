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
import contextlib
import io
import json
import re
import tarfile
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from skill_sentry_cli.core.sandbox.images import SIDECAR_BASE_IMAGE

MAX_SIDECAR_LOG_BYTES = 8 * 1024 * 1024
MAX_SIDECAR_EVENTS = 10_000
MAX_SIDECAR_TAIL_LINES = 10_000
_SIDECAR_SCRIPT_PATH = Path(__file__).resolve().parent / "assets" / "sinkhole_sidecar.py"
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")
_READY_MARKER = b'"event":"ready"'


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
    image: str = SIDECAR_BASE_IMAGE
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
        self._lock = threading.RLock()

    @property
    def ip(self) -> str:
        return self._ip

    def start(self, network: Any, scan_id: UUID, *, image: str | None = None) -> SinkholeSidecar:
        # A sidecar is per-scan state.  Serialise lifecycle calls so a
        # concurrent teardown cannot remove a container while it is starting.
        with self._lock:
            if self.container is not None:
                return self
            network_name = getattr(network, "name", None) or str(network)
            labels = {
                "skillsentry": "true",
                "skillsentry.role": "sinkhole-sidecar",
                "skillsentry.scan_id": str(scan_id),
            }
            container = None
            try:
                container = self.client.containers.create(
                    image=image or self.config.image,
                    # Keep the script outside the /tmp tmpfs: files copied into
                    # a tmpfs-backed path are hidden when the container starts.
                    command=["python", "-u", "/opt/skillsentry_sidecar.py"],
                    detach=True,
                    # The rootfs must be writable long enough for put_archive()
                    # to copy the trusted sidecar script before start; Docker's
                    # archive endpoint rejects a read-only rootfs.  /tmp is still
                    # a bounded tmpfs and all capabilities are dropped below.
                    read_only=False,
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
                        "EndpointsConfig": {network_name: {"IPAMConfig": {"IPv4Address": self._ip}}}
                    },
                    # The sidecar only needs enough memory for two small
                    # stdlib servers.  Cap it independently from the skill so
                    # a compromised sidecar cannot exhaust the host.
                    mem_limit="64m",
                    memswap_limit="64m",
                    pids_limit=32,
                    nano_cpus=250_000_000,
                )
                self.container = container
                script = _SIDECAR_SCRIPT_PATH.read_bytes()
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w") as archive:
                    info = tarfile.TarInfo("skillsentry_sidecar.py")
                    info.size = len(script)
                    info.mode = 0o755
                    info.uid = 0
                    info.gid = 0
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(script))
                # Copy the trusted script into the stopped container before it
                # can execute anything.  No host mount is exposed.
                if container.put_archive("/opt", buffer.getvalue()) is False:
                    raise SidecarError("could not copy sidecar script into container")
                self.container = container
                container.start()
                self._wait_until_ready(container)
                return self
            except Exception as exc:
                self.stop(collect=False)
                if isinstance(exc, SidecarError):
                    raise
                raise SidecarError(f"could not start sinkhole sidecar: {exc}") from exc

    def _wait_until_ready(self, container: Any) -> None:
        """Wait for both DNS and HTTP listeners to report readiness.

        Docker marks a container ``running`` before the Python process has
        bound its sockets.  Starting the skill at that point produces an
        evidence hole (the first exfil attempt gets connection refused).  The
        sidecar therefore emits one ``{"event":"ready"}`` line after binding,
        and the runner waits for it with a hard deadline.
        """

        deadline = time.monotonic() + max(0.1, self.config.timeout_s)
        while time.monotonic() < deadline:
            status = ""
            try:
                reload = getattr(container, "reload", None)
                if reload is not None:
                    reload()
                status = str(getattr(container, "status", ""))
            except Exception:
                status = ""
            if status in {"exited", "dead"}:
                raise SidecarError(f"sinkhole sidecar exited during startup ({status})")
            logs = _read_logs(container, tail=64)
            if _READY_MARKER in logs:
                return
            time.sleep(0.05)
        raise SidecarError(
            f"sinkhole sidecar did not become ready within {self.config.timeout_s:.1f}s"
        )

    def stop(self, *, collect: bool = True) -> list[SinkholeObservation]:
        observations: list[SinkholeObservation] = []
        with self._lock:
            container = self.container
            self.container = None
            if container is None:
                return observations
            # Stop first so a log stream terminates promptly and a hostile
            # sidecar cannot keep writing while evidence is collected.
            with contextlib.suppress(Exception):
                container.stop(timeout=1)
            if collect:
                try:
                    raw = _read_logs(container, stream=True)
                    observations = parse_sidecar_log(raw)
                except Exception:
                    observations = []
            with contextlib.suppress(Exception):
                container.remove(force=True, v=True)
        return observations


def _read_logs(
    container: Any,
    *,
    tail: int | None = None,
    stream: bool = False,
    limit: int = MAX_SIDECAR_LOG_BYTES,
) -> bytes:
    """Read Docker logs without allowing an unbounded response into memory."""

    kwargs: dict[str, Any] = {"stdout": True, "stderr": False}
    if tail is not None:
        kwargs["tail"] = max(1, min(int(tail), MAX_SIDECAR_TAIL_LINES))
    if stream:
        kwargs["stream"] = True
    try:
        raw = container.logs(**kwargs)
    except TypeError:
        # A minimal fake client may not implement stream/tail kwargs.
        raw = container.logs(stdout=True, stderr=False)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)[-limit:]
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")[-limit:]
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in raw:
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            if not isinstance(chunk, (bytes, bytearray)):
                continue
            chunks.append(bytes(chunk))
            total += len(chunk)
            if total >= limit:
                break
    finally:
        close = getattr(raw, "close", None)
        if close is not None:
            with contextlib.suppress(Exception):
                close()
    return b"".join(chunks)[-limit:]


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
