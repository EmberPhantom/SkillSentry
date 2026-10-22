"""Docker sandbox lifecycle: limits, masquerade, canary seeding, teardown.

This module is deliberately usable without a Docker daemon in unit tests: pass
a fake client to :class:`SandboxRunner`.  The real client is created lazily, so
importing the server does not require Docker.

Security invariants:
* host mounts are the skill directory (read-only), ``/dev/null`` for
  ``/.dockerenv``, and per-scan fake cgroup/mountinfo files (read-only);
* the network is an ``internal`` bridge (no NAT);
* the container is read-only, non-root, cap-drop ALL, no-new-privileges;
* teardown runs in ``finally`` even on timeout or exceptions.
"""

from __future__ import annotations

import io
import ipaddress
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    NetLog,
    SandboxTrace,
    Severity,
    Stage,
    StageResult,
    utc_now,
)
from skillsentry.core.poisoned_well.canary_gen import CANARY_ROOT, CanarySet, generate_canary_set
from skillsentry.core.sandbox.canary_fs import build_canary_tar
from skillsentry.core.sandbox.context_honeypot import runtime_environment
from skillsentry.core.sandbox.masquerade import (
    FAKE_CGROUP_CONTENT,
    FAKE_MOUNTINFO_CONTENT,
    MasqueradeCheck,
    MasqueradeConfig,
    MasqueradeError,
    require_masquerade,
    run_script_text,
    verify_container,
)
from skillsentry.core.sandbox.monitor import (
    MonitorEvent,
    normalise_paths,
    parse_monitor_log,
    synthetic_event,
)
from skillsentry.core.sandbox.sidecar import SinkholeObservation, SinkholeSidecar

LABEL_KEY = "skillsentry"
LABEL_VALUE = "true"
CANARY_HOME = CANARY_ROOT


class SandboxUnavailable(RuntimeError):
    """Docker is not installed, or its daemon is unreachable."""


class SandboxError(RuntimeError):
    """A sandbox operation failed; the caller must not synthesise a SAFE verdict."""


@dataclass(frozen=True)
class SandboxRequest:
    scan_id: UUID
    skill_dir: Path
    declared_intent: str = ""
    command: tuple[str, ...] | None = None
    canary_marker: str | None = None
    secondary_canary: str | None = None
    timeout_s: float | None = None


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "skillsentry-sandbox:local"
    user: str = "65534:65534"
    network_name: str = "skillsentry-sinkhole"
    home: str = CANARY_HOME
    skill_mount: str = "/skill"
    memory_mb: int = 512
    cpus: float = 1.0
    pids_limit: int = 128
    timeout_s: float = 60.0
    poll_interval_s: float = 0.1
    stop_timeout_s: float = 1.0
    # None means "no explicit resolver": the live engine supplies the
    # per-scan sinkhole sidecar's internal address.  Never default to loopback;
    # a container's loopback is not a sinkhole and would hide egress.
    dns_server: str | None = None
    sidecar_subnet: str = "172.30.77.0/24"
    sidecar_ip: str = "172.30.77.2"
    sidecar_image: str = "python:3.11-slim"
    verify_masquerade: bool = True
    cleanup_stale: bool = True
    cleanup_network: bool = True
    labels: dict[str, str] = field(default_factory=dict)
    masquerade: MasqueradeConfig = field(default_factory=MasqueradeConfig)

    def __post_init__(self) -> None:
        if not self.image.strip():
            raise ValueError("sandbox image must not be empty")
        if not (128 <= self.memory_mb <= 4096):
            raise ValueError("memory_mb must be between 128 and 4096")
        if self.cpus <= 0:
            raise ValueError("cpus must be positive")
        if self.pids_limit < 16:
            raise ValueError("pids_limit must be at least 16")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if self.dns_server:
            try:
                if ipaddress.ip_address(self.dns_server).is_loopback:
                    raise ValueError("sandbox DNS server must not be loopback")
            except ValueError:
                # Hostnames are not valid Docker --dns targets in this design.
                raise
        try:
            network = ipaddress.ip_network(self.sidecar_subnet, strict=False)
            if ipaddress.ip_address(self.sidecar_ip) not in network:
                raise ValueError("sidecar_ip must belong to sidecar_subnet")
        except ValueError:
            raise

    @property
    def all_labels(self) -> dict[str, str]:
        labels = {LABEL_KEY: LABEL_VALUE}
        labels.update(self.labels)
        return labels


@dataclass
class SandboxResult:
    scan_id: UUID
    container_id: str
    canaries: CanarySet
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    stdout: str
    stderr: str
    started_at: datetime = field(default_factory=utc_now)
    events: list[MonitorEvent] = field(default_factory=list)
    net_logs: list[NetLog] = field(default_factory=list)
    sinkhole_observations: list[SinkholeObservation] = field(default_factory=list)
    resource_usage: dict[str, Any] | None = None
    masquerade: MasqueradeCheck | None = None
    cleanup_ok: bool = True
    error: str | None = None

    @property
    def canary_reads(self) -> list[MonitorEvent]:
        return [event for event in self.events if event.event_type == "canary_read"]

    @property
    def probes(self) -> list[MonitorEvent]:
        return [event for event in self.events if event.event_type == "probe_detected"]

    def add_net_log(self, log: NetLog) -> None:
        self.net_logs.append(log)

    def to_trace(self) -> SandboxTrace:
        return SandboxTrace(
            events=[event.to_contract() for event in self.events],
            net_logs=self.net_logs,
            resource_usage=self.resource_usage,
        )

    def sandbox_signal(self) -> float:
        if self.probes:
            return 100.0
        if self.canary_reads:
            return 75.0
        if self.timed_out:
            return 40.0
        if self.exit_code not in (0, None):
            return 20.0
        return 0.0

    def findings(self) -> list[Finding]:
        findings: list[Finding] = []
        seen_paths: set[str] = set()
        for event in self.canary_reads:
            path = event.path_or_channel or "unknown canary"
            if path in seen_paths:
                continue
            seen_paths.add(path)
            findings.append(
                Finding(
                    stage=Stage.SANDBOX,
                    severity=Severity.HIGH,
                    message=f"Sandboxed skill read a canary credential: {path}.",
                    finding_type="canary-read",
                    evidence=FindingEvidence(
                        path=path,
                        process=event.process,
                        marker=event.marker,
                    ),
                )
            )
        if self.timed_out:
            findings.append(
                Finding(
                    stage=Stage.SANDBOX,
                    severity=Severity.MEDIUM,
                    message=f"Sandbox execution exceeded {self.duration_ms} ms and was killed.",
                    finding_type="sandbox-timeout",
                )
            )
        if self.exit_code not in (0, None) and not self.timed_out:
            findings.append(
                Finding(
                    stage=Stage.SANDBOX,
                    severity=Severity.LOW,
                    message=f"Skill exited with status {self.exit_code} inside the sandbox.",
                    finding_type="sandbox-exit",
                )
            )
        if not self.cleanup_ok:
            findings.append(
                Finding(
                    stage=Stage.SANDBOX,
                    severity=Severity.NOTE,
                    message="Sandbox teardown reported an error; inspect the engine log.",
                    finding_type="sandbox-cleanup",
                )
            )
        return findings

    def to_stage_result(self) -> StageResult:
        trace = self.to_trace()
        return StageResult(
            stage=Stage.SANDBOX,
            findings=self.findings(),
            signals={"sandbox": self.sandbox_signal()},
            telemetry={
                "sandboxTrace": trace.model_dump(by_alias=True, mode="json"),
                "startedAt": self.started_at.isoformat(),
                "exitCode": self.exit_code,
                "timedOut": self.timed_out,
                "cleanupOk": self.cleanup_ok,
                "masquerade": self.masquerade.to_dict() if self.masquerade else None,
            },
            degraded=self.timed_out or not self.cleanup_ok,
        )


class SandboxRunner:
    """Synchronous Docker lifecycle wrapper.

    The orchestrator should call :meth:`run` in a worker thread.  A fake client
    only needs ``containers``, ``networks``, ``api``, and (optionally) ``ping``.
    """

    def __init__(
        self,
        client: Any | None = None,
        config: SandboxConfig | None = None,
        *,
        sidecar_factory: Callable[[Any], SinkholeSidecar] | None = None,
    ) -> None:
        self.config = config or SandboxConfig()
        self._client = client
        self._cleaned = False
        self._sidecar_factory = sidecar_factory
        self._active_dns_server: str | None = self.config.dns_server

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                import docker
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise SandboxUnavailable("the docker Python SDK is not installed") from exc
            try:
                self._client = docker.from_env()
            except Exception as exc:  # pragma: no cover - daemon-specific
                raise SandboxUnavailable(f"Docker is unavailable: {exc}") from exc
        return self._client

    def available(self) -> bool:
        try:
            ping = getattr(self.client, "ping", None)
            if ping is None:
                return True
            return bool(ping())
        except Exception:
            return False

    def cleanup_stale(self) -> int:
        """Remove labelled containers left by a crashed previous run."""

        removed = 0
        client = self.client
        with suppress(Exception):
            for container in client.containers.list(
                all=True, filters={"label": f"{LABEL_KEY}={LABEL_VALUE}"}
            ):
                status = getattr(container, "status", "")
                if status not in {"created", "exited", "dead"}:
                    continue
                with suppress(Exception):
                    container.remove(force=True, v=True)
                    removed += 1
        with suppress(Exception):
            for network in client.networks.list(filters={"label": f"{LABEL_KEY}={LABEL_VALUE}"}):
                with suppress(Exception):
                    network.remove()
        self._cleaned = True
        return removed

    def run(self, request: SandboxRequest) -> SandboxResult:
        skill_dir = Path(request.skill_dir).resolve()
        if not skill_dir.is_dir():
            raise SandboxError(f"skill directory does not exist: {skill_dir}")
        timeout_s = request.timeout_s if request.timeout_s is not None else self.config.timeout_s
        if timeout_s <= 0:
            raise SandboxError("sandbox timeout must be positive")

        client = self.client
        if self.config.cleanup_stale and not self._cleaned:
            self.cleanup_stale()

        canaries = generate_canary_set(
            request.scan_id,
            request.declared_intent,
            marker=request.canary_marker,
            secondary_marker=request.secondary_canary,
        )
        network = None
        network_created = False
        container = None
        sidecar: SinkholeSidecar | None = None
        result: SandboxResult | None = None
        masquerade_dir: Path | None = None
        masquerade_config = self.config.masquerade
        started_at = utc_now()
        started = time.monotonic()

        try:
            masquerade_dir, masquerade_config = self._prepare_masquerade_files()
            network, network_created = self._ensure_network(client)
            if self._sidecar_factory is not None:
                sidecar = self._sidecar_factory(client)
                sidecar.start(network, request.scan_id, image=self.config.sidecar_image)
                self._active_dns_server = sidecar.ip
            container = self._create_container(
                client, request, skill_dir, canaries, network, masquerade_config
            )
            container.start()
            self._seed_canaries(container, canaries)
            self._seed_setup(container)
            if self.config.verify_masquerade:
                check = verify_container(container, config=masquerade_config, user=self.config.user)
                require_masquerade(check)
            else:
                check = None
            self._clear_monitor_log(container)
            exec_result, stdout, stderr = self._execute(container, request, canaries, timeout_s)
            duration_ms = int((time.monotonic() - started) * 1000)
            events = normalise_paths(
                parse_monitor_log(
                    self._read_text(container, "/tmp/skillsentry/events.jsonl")
                ).events,
                canaries,
            )
            seed_events = [
                synthetic_event(
                    "canary_seeded",
                    path_or_channel=file.display_path,
                    marker=file.marker,
                    detail={"asset": file.asset},
                    ts=started_at,
                )
                for file in canaries.files
            ]
            result = SandboxResult(
                scan_id=request.scan_id,
                container_id=str(getattr(container, "id", "")),
                canaries=canaries,
                exit_code=exec_result["exit_code"],
                timed_out=exec_result["timed_out"],
                duration_ms=duration_ms,
                stdout=_truncate(stdout),
                stderr=_truncate(stderr),
                started_at=started_at,
                events=[*seed_events, *events],
                resource_usage=self._resource_usage(container, duration_ms),
                masquerade=check,
                error=exec_result.get("error"),
            )
            return result
        except MasqueradeError:
            raise
        except SandboxUnavailable:
            raise
        except Exception as exc:
            raise SandboxError(f"sandbox execution failed: {exc}") from exc
        finally:
            sidecar_observations: list[SinkholeObservation] = []
            if sidecar is not None:
                try:
                    sidecar_observations = sidecar.stop()
                except Exception as exc:  # teardown must never mask the verdict
                    if result is not None and result.error is None:
                        result.error = f"sinkhole sidecar teardown failed: {exc}"
            cleanup_ok, cleanup_errors = self._teardown(container, network, network_created)
            if masquerade_dir is not None:
                shutil.rmtree(masquerade_dir, ignore_errors=True)
            if result is not None:
                result.cleanup_ok = cleanup_ok
                if cleanup_errors and result.error is None:
                    result.error = "; ".join(cleanup_errors)
                result.sinkhole_observations = sidecar_observations
                result.net_logs = [_net_log(observation) for observation in sidecar_observations]

    # -- Docker pieces ------------------------------------------------------
    def _prepare_masquerade_files(self) -> tuple[Path, MasqueradeConfig]:
        directory = Path(tempfile.mkdtemp(prefix="skillsentry-masquerade-"))
        cgroup = directory / "cgroup"
        mountinfo = directory / "mountinfo"
        cgroup.write_text(FAKE_CGROUP_CONTENT, encoding="utf-8")
        mountinfo.write_text(FAKE_MOUNTINFO_CONTENT, encoding="utf-8")
        config = replace(
            self.config.masquerade,
            cgroup_host_path=str(cgroup),
            mountinfo_host_path=str(mountinfo),
        )
        return directory, config

    def _ensure_network(self, client: Any) -> tuple[Any, bool]:
        network = None
        try:
            network = client.networks.get(self.config.network_name)
        except Exception as exc:
            if not _is_not_found(exc):
                raise
        if network is not None:
            attrs = getattr(network, "attrs", {}) or {}
            if not attrs.get("Internal", False):
                raise SandboxError(
                    f"existing network {self.config.network_name!r} is not internal; "
                    "refusing to run with NAT"
                )
            return network, False
        kwargs: dict[str, Any] = {
            "driver": "bridge",
            "internal": True,
            "attachable": False,
            "enable_ipv6": False,
            "labels": {**self.config.all_labels, f"{LABEL_KEY}.role": "sinkhole"},
        }
        if self._sidecar_factory is not None:
            kwargs["ipam"] = {
                "Driver": "default",
                "Config": [{"Subnet": self.config.sidecar_subnet}],
            }
        network = client.networks.create(self.config.network_name, **kwargs)
        return network, True

    def _create_container(
        self,
        client: Any,
        request: SandboxRequest,
        skill_dir: Path,
        canaries: CanarySet,
        network: Any,
        masquerade: MasqueradeConfig,
    ) -> Any:
        labels = {
            **self.config.all_labels,
            f"{LABEL_KEY}.scan_id": str(request.scan_id),
            f"{LABEL_KEY}.skill": skill_dir.name,
        }
        volumes = {
            str(skill_dir): {"bind": self.config.skill_mount, "mode": "ro"},
            **masquerade.volumes(),
        }
        tmpfs = {
            "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
            self.config.home: "rw,nosuid,nodev,noexec,size=16m,uid=65534,gid=65534,mode=700",
            **masquerade.tmpfs(),
        }
        environment = {
            "HOME": self.config.home,
            "PYTHONUNBUFFERED": "1",
            **masquerade.environment(),
        }
        kwargs: dict[str, Any] = {
            "image": self.config.image,
            "entrypoint": ["/bin/sh", "-c"],
            "command": ["trap 'exit 0' TERM INT; while :; do sleep 3600; done"],
            "detach": True,
            "user": self.config.user,
            "working_dir": self.config.skill_mount,
            "hostname": "devbox",
            "network": self.config.network_name,
            "mem_limit": f"{self.config.memory_mb}m",
            "memswap_limit": f"{self.config.memory_mb}m",
            "nano_cpus": int(self.config.cpus * 1_000_000_000),
            "pids_limit": self.config.pids_limit,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "volumes": volumes,
            "tmpfs": tmpfs,
            "environment": environment,
            "labels": labels,
            "auto_remove": False,
            "init": True,
            "stdin_open": False,
            "tty": False,
        }
        dns_server = self._active_dns_server or self.config.dns_server
        if dns_server:
            kwargs["dns"] = [dns_server]
        return client.containers.create(**kwargs)

    def _seed_canaries(self, container: Any, canaries: CanarySet) -> None:
        container.put_archive(self.config.home, build_canary_tar(canaries))

    def _seed_setup(self, container: Any) -> None:
        created = container.exec_run(
            ["mkdir", "-p", "/tmp/skillsentry"],
            user=self.config.user,
        )
        if created.exit_code not in (0, None):
            raise SandboxError("could not create the sandbox setup directory")
        setup = _setup_tar()
        container.put_archive("/tmp/skillsentry", setup)

    def _clear_monitor_log(self, container: Any) -> None:
        cleared = container.exec_run(
            ["/bin/sh", "-c", ": > /tmp/skillsentry/events.jsonl"],
            user=self.config.user,
        )
        if cleared.exit_code not in (0, None):
            raise SandboxError("could not reset the monitor log after masquerade verification")

    def _execute(
        self,
        container: Any,
        request: SandboxRequest,
        canaries: CanarySet,
        timeout_s: float,
    ) -> tuple[dict[str, Any], str, str]:
        command = (
            list(request.command)
            if request.command
            else [
                "/bin/sh",
                "/tmp/skillsentry/run_skill.sh",
            ]
        )
        environment = runtime_environment(canaries)
        environment.update(self.config.masquerade.environment())
        environment["PYTHONUNBUFFERED"] = "1"
        wrapped = [
            "/bin/sh",
            "-c",
            'exec "$@" > /tmp/skillsentry/stdout.log 2> /tmp/skillsentry/stderr.log',
            "skillsentry",
            *command,
        ]
        client = self.client
        exec_id = client.api.exec_create(
            container.id,
            wrapped,
            stdout=False,
            stderr=False,
            stdin=False,
            tty=False,
            privileged=False,
            user=self.config.user,
            environment=environment,
            workdir=self.config.skill_mount,
        )["Id"]
        client.api.exec_start(exec_id, detach=True)

        deadline = time.monotonic() + timeout_s
        exit_code: int | None = None
        timed_out = False
        while True:
            info = client.api.exec_inspect(exec_id)
            if not info.get("Running", False):
                exit_code = info.get("ExitCode")
                break
            if time.monotonic() >= deadline:
                timed_out = True
                with suppress(Exception):
                    container.stop(timeout=max(1, round(self.config.stop_timeout_s)))
                with suppress(Exception):
                    container.kill()
                exit_code = 124
                break
            time.sleep(max(0.01, self.config.poll_interval_s))

        stdout = self._read_text(container, "/tmp/skillsentry/stdout.log")
        stderr = self._read_text(container, "/tmp/skillsentry/stderr.log")
        return (
            {
                "exit_code": exit_code,
                "timed_out": timed_out,
                "error": f"sandbox timed out after {timeout_s:g}s" if timed_out else None,
            },
            stdout,
            stderr,
        )

    def _read_text(self, container: Any, path: str) -> str:
        with suppress(Exception):
            result = container.exec_run(["cat", path], user=self.config.user)
            if result.exit_code in (0, None) and result.output:
                if isinstance(result.output, bytes):
                    return result.output.decode("utf-8", errors="replace")
                return str(result.output)
        return ""

    def _resource_usage(self, container: Any, duration_ms: int) -> dict[str, Any] | None:
        with suppress(Exception):
            stats = container.stats(stream=False)
            if not isinstance(stats, dict):
                return None
            memory = stats.get("memory_stats", {}) or {}
            used = int(memory.get("usage", 0) or 0)
            peak = int(memory.get("max_usage", used) or used)
            cpu = stats.get("cpu_stats", {}) or {}
            previous = stats.get("precpu_stats", {}) or {}
            cpu_total = int((cpu.get("cpu_usage") or {}).get("total_usage", 0) or 0)
            previous_total = int((previous.get("cpu_usage") or {}).get("total_usage", 0) or 0)
            system_total = int(cpu.get("system_cpu_usage", 0) or 0)
            previous_system = int(previous.get("system_cpu_usage", 0) or 0)
            online = int(cpu.get("online_cpus", 1) or 1)
            cpu_delta = cpu_total - previous_total
            system_delta = system_total - previous_system
            cpu_percent = (
                round((cpu_delta / system_delta) * online * 100.0, 1)
                if cpu_delta > 0 and system_delta > 0
                else 0.0
            )
            return {
                "durationMs": duration_ms,
                "peakMemoryMb": round(peak / (1024 * 1024), 1),
                "cpuPercent": cpu_percent,
            }
        return None

    def _teardown(
        self,
        container: Any | None,
        network: Any | None,
        network_created: bool,
    ) -> tuple[bool, list[str]]:
        ok = True
        errors: list[str] = []
        if container is not None:
            with suppress(Exception):
                container.stop(timeout=max(1, round(self.config.stop_timeout_s)))
            try:
                container.remove(force=True, v=True)
            except Exception as exc:
                ok = False
                errors.append(f"container remove failed: {exc}")
        if network is not None and network_created and self.config.cleanup_network:
            try:
                network.remove()
            except Exception as exc:
                ok = False
                errors.append(f"network remove failed: {exc}")
        return ok, errors


def _setup_tar() -> bytes:
    """Build the per-scan /tmp/skillsentry archive (script + fake proc views)."""

    entries: list[tuple[str, bytes, int]] = [
        ("run_skill.sh", run_script_text().encode("utf-8"), 0o755),
        ("cgroup", FAKE_CGROUP_CONTENT.encode("utf-8"), 0o644),
        ("mountinfo", FAKE_MOUNTINFO_CONTENT.encode("utf-8"), 0o644),
        ("events.jsonl", b"", 0o600),
    ]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload, mode in entries:
            info = tarfile.TarInfo(name=f"./{name}")
            info.size = len(payload)
            info.mode = mode
            info.uid = 65534
            info.gid = 65534
            info.uname = "nobody"
            info.gname = "nogroup"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _net_log(observation: SinkholeObservation) -> NetLog:
    return NetLog(
        ts=observation.ts,
        protocol=observation.protocol,  # type: ignore[arg-type]
        query_or_url=observation.query_or_url,
        body_b64=observation.body_b64,
        responder_action=observation.responder_action,
    )


def _truncate(value: str, limit: int = 100_000) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}\n... [truncated {len(value) - limit} chars]"


def _is_not_found(exc: Exception) -> bool:
    return getattr(exc, "status_code", None) == 404 or exc.__class__.__name__ in {
        "NotFound",
        "NetworkNotFound",
        "ImageNotFound",
    }
