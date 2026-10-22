"""Sandbox runner lifecycle tests using a fake Docker client (no daemon)."""

from __future__ import annotations

import base64
import io
import json
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from skillsentry.core.sandbox.masquerade import (
    FAKE_CGROUP_CONTENT,
    FAKE_MOUNTINFO_CONTENT,
    MasqueradeError,
)
from skillsentry.core.sandbox.runner import (
    SandboxConfig,
    SandboxError,
    SandboxRequest,
    SandboxRunner,
)

SCAN_ID = UUID("55555555-5555-4555-8555-555555555555")
MARKER = "SKS-7f3a9c21"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


class FakeNotFound(Exception):
    status_code = 404


@dataclass
class FakeExecResult:
    exit_code: int | None = 0
    output: bytes = b""


class FakeApi:
    def __init__(self, client: FakeDocker) -> None:
        self.client = client
        self.execs: dict[str, dict] = {}
        self.started: list[str] = []
        self._counter = 0

    def exec_create(self, container_id: str, cmd: list[str], **kwargs):
        self._counter += 1
        exec_id = f"exec-{self._counter}"
        self.execs[exec_id] = {
            "container_id": container_id,
            "cmd": cmd,
            "kwargs": kwargs,
            "Running": True,
            "ExitCode": None,
        }
        self.client.exec_create_calls.append((exec_id, cmd, kwargs))
        return {"Id": exec_id}

    def exec_start(self, exec_id: str, detach: bool = False):
        self.started.append(exec_id)
        self.client.exec_start_calls.append((exec_id, detach))
        if self.client.fail_exec_start:
            raise RuntimeError("exec start failed")

    def exec_inspect(self, exec_id: str):
        self.client.exec_inspect_calls.append(exec_id)
        info = dict(self.execs[exec_id])
        if self.client.running_forever:
            info.update({"Running": True, "ExitCode": None})
            return info
        info.update({"Running": False, "ExitCode": self.client.exit_code})
        return info


class FakeContainer:
    def __init__(self, client: FakeDocker, kwargs: dict) -> None:
        self.client = client
        self.kwargs = kwargs
        self.id = "container-" + "a" * 32
        self.status = "created"
        self.started = 0
        self.stopped = 0
        self.killed = 0
        self.removed = 0
        self.archives: list[tuple[str, bytes]] = []
        self.exec_calls: list[tuple[list[str], dict]] = []
        self.events_log = b""

    def start(self):
        self.started += 1
        if self.client.fail_start:
            raise RuntimeError("container start failed")
        self.status = "running"
        return self

    def put_archive(self, path: str, data: bytes):
        self.archives.append((path, data))
        if self.client.fail_put_archive:
            raise RuntimeError("put archive failed")
        return True

    def exec_run(self, cmd, **kwargs):
        self.exec_calls.append((list(cmd), kwargs))
        if cmd[:1] == ["mkdir"]:
            return FakeExecResult()
        if cmd[:2] == ["/bin/sh", "-c"] and ": > /tmp/skillsentry/events.jsonl" in cmd[2]:
            self.events_log = self.client.events_after_clear
            return FakeExecResult()
        if cmd[:2] == ["/bin/sh", "-c"] and "SKILLSENTRY_DOCKERENV" in cmd[2]:
            return FakeExecResult(output=self.client.verify_output)
        if cmd[:1] == ["cat"]:
            path = cmd[1]
            if path.endswith("events.jsonl"):
                return FakeExecResult(output=self.events_log)
            if path.endswith("stdout.log"):
                return FakeExecResult(output=self.client.stdout)
            if path.endswith("stderr.log"):
                return FakeExecResult(output=self.client.stderr)
            return FakeExecResult(output=b"")
        return FakeExecResult()

    def stats(self, stream: bool = False):
        return self.client.stats

    def stop(self, timeout: float | None = None):
        self.stopped += 1
        if self.client.fail_stop:
            raise RuntimeError("stop failed")
        self.status = "exited"

    def kill(self):
        self.killed += 1
        self.status = "exited"

    def remove(self, force: bool = False, v: bool = False):
        self.removed += 1
        if self.client.fail_remove:
            raise RuntimeError("remove failed")
        self.status = "removed"


class FakeNetwork:
    def __init__(self, client: FakeDocker, name: str, kwargs: dict) -> None:
        self.client = client
        self.name = name
        self.kwargs = kwargs
        self.attrs = {
            "Internal": bool(kwargs.get("internal", False)),
            "Labels": kwargs.get("labels", {}),
        }
        self.removed = 0

    def remove(self):
        self.removed += 1
        if self.client.fail_network_remove:
            raise RuntimeError("network remove failed")


class FakeNetworks:
    def __init__(self, client: FakeDocker) -> None:
        self.client = client
        self.created: list[FakeNetwork] = []
        self.existing: dict[str, FakeNetwork] = {}
        self.stale: list[FakeNetwork] = []

    def get(self, name: str):
        if name in self.existing:
            return self.existing[name]
        raise FakeNotFound(name)

    def create(self, name: str, **kwargs):
        network = FakeNetwork(self.client, name, kwargs)
        self.created.append(network)
        return network

    def list(self, filters=None):
        return list(self.stale)


class FakeContainers:
    def __init__(self, client: FakeDocker) -> None:
        self.client = client
        self.created: list[FakeContainer] = []
        self.stale: list[FakeContainer] = []

    def create(self, **kwargs):
        container = FakeContainer(self.client, kwargs)
        self.created.append(container)
        return container

    def list(self, all: bool = True, filters=None):
        return list(self.stale)


class FakeDocker:
    def __init__(
        self,
        *,
        ping_result: bool = True,
        running_forever: bool = False,
        exit_code: int = 0,
        events_after_clear: bytes = b"",
        verify_output: bytes | None = None,
    ) -> None:
        self.ping_result = ping_result
        self.running_forever = running_forever
        self.exit_code = exit_code
        self.events_after_clear = events_after_clear
        self.verify_output = verify_output or _verification_output()
        self.stdout = b"skill stdout\n"
        self.stderr = b"skill stderr\n"
        self.stats = {
            "memory_stats": {"usage": 104857600, "max_usage": 125829120},
            "cpu_stats": {
                "cpu_usage": {"total_usage": 200},
                "system_cpu_usage": 1000,
                "online_cpus": 1,
            },
            "precpu_stats": {
                "cpu_usage": {"total_usage": 100},
                "system_cpu_usage": 900,
            },
        }
        self.fail_start = False
        self.fail_stop = False
        self.fail_remove = False
        self.fail_network_remove = False
        self.fail_put_archive = False
        self.fail_exec_start = False
        self.containers = FakeContainers(self)
        self.networks = FakeNetworks(self)
        self.api = FakeApi(self)
        self.exec_create_calls: list[tuple[str, list[str], dict]] = []
        self.exec_start_calls: list[tuple[str, bool]] = []
        self.exec_inspect_calls: list[str] = []

    def ping(self) -> bool:
        return self.ping_result


def _verification_output(
    *,
    dockerenv: str = "absent",
    cgroup: str = FAKE_CGROUP_CONTENT,
    mountinfo: str = FAKE_MOUNTINFO_CONTENT,
    shim: str = "present",
) -> bytes:
    return "\n".join(
        [
            f"SKILLSENTRY_DOCKERENV={dockerenv}",
            f"SKILLSENTRY_SHIM={shim}",
            f"SKILLSENTRY_CGROUP={base64.b64encode(cgroup.encode()).decode()}",
            f"SKILLSENTRY_MOUNTINFO={base64.b64encode(mountinfo.encode()).decode()}",
        ]
    ).encode()


def _event(event_type: str, path: str, marker: str | None = None) -> bytes:
    return (
        json.dumps(
            {
                "ts": NOW.isoformat(),
                "event_type": event_type,
                "path": path,
                "marker": marker,
                "process": "python",
                "detail": {},
            }
        ).encode()
        + b"\n"
    )


def _config(**overrides) -> SandboxConfig:
    values = {
        "cleanup_stale": False,
        "poll_interval_s": 0.005,
        "stop_timeout_s": 0.01,
        "timeout_s": 2.0,
    }
    values.update(overrides)
    return SandboxConfig(**values)


def _request(tmp_path: Path, **overrides) -> SandboxRequest:
    skill = tmp_path / "skill"
    skill.mkdir(exist_ok=True)
    values = {
        "scan_id": SCAN_ID,
        "skill_dir": skill,
        "declared_intent": "cloud sync",
        "canary_marker": MARKER,
        "secondary_canary": "SKS-8b2c4d19",
    }
    values.update(overrides)
    return SandboxRequest(**values)


def _tar_names(data: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return archive.getnames()


def test_run_creates_isolated_container_and_returns_events(tmp_path):
    client = FakeDocker(
        events_after_clear=_event("canary_read", "/home/sandbox/.aws/credentials")
        + _event("probe_detected", "/proc/1/cgroup"),
    )
    runner = SandboxRunner(client=client, config=_config())
    result = runner.run(_request(tmp_path))

    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.cleanup_ok is True
    assert result.stdout == "skill stdout\n"
    assert result.stderr == "skill stderr\n"
    assert result.started_at.tzinfo is not None
    assert result.masquerade is not None and result.masquerade.ok

    container = client.containers.created[0]
    assert container.started == 1
    assert container.removed == 1
    assert container.stopped >= 1

    kwargs = container.kwargs
    assert kwargs["image"] == "skillsentry-sandbox:local"
    assert kwargs["user"] == "65534:65534"
    assert kwargs["read_only"] is True
    assert kwargs["init"] is True
    assert kwargs["auto_remove"] is False
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["pids_limit"] == 128
    assert kwargs["mem_limit"] == "512m"
    assert kwargs["memswap_limit"] == "512m"
    assert kwargs["nano_cpus"] == 1_000_000_000
    assert kwargs["network"] == "skillsentry-sinkhole"
    # No explicit resolver is supplied without a per-scan sinkhole sidecar.
    # Loopback must never be used as a fake sinkhole.
    assert "dns" not in kwargs
    assert kwargs["working_dir"] == "/skill"
    assert kwargs["hostname"] == "devbox"
    assert kwargs["environment"]["LD_PRELOAD"] == "/opt/skillsentry/masquerade.so"
    assert kwargs["labels"]["skillsentry"] == "true"
    assert kwargs["labels"]["skillsentry.scan_id"] == str(SCAN_ID)
    assert kwargs["volumes"][str((tmp_path / "skill").resolve())] == {
        "bind": "/skill",
        "mode": "ro",
    }
    assert kwargs["volumes"]["/dev/null"] == {"bind": "/.dockerenv", "mode": "ro"}
    assert kwargs["tmpfs"]["/tmp"].startswith("rw,")
    assert kwargs["tmpfs"]["/home/sandbox"].startswith("rw,")
    assert "/proc/1/cgroup" not in kwargs["tmpfs"]
    cgroup_mounts = {
        source: spec
        for source, spec in kwargs["volumes"].items()
        if spec.get("bind") == "/proc/1/cgroup"
    }
    assert len(cgroup_mounts) == 1
    cgroup_source, cgroup_spec = next(iter(cgroup_mounts.items()))
    assert cgroup_spec["mode"] == "ro"
    assert not Path(cgroup_source).exists()

    network = client.networks.created[0]
    assert network.kwargs["internal"] is True
    assert network.kwargs["enable_ipv6"] is False
    assert network.kwargs["driver"] == "bridge"
    assert network.attrs["Internal"] is True
    assert network.removed == 1

    canary_archive = next(data for path, data in container.archives if path == "/home/sandbox")
    assert "./.aws/credentials" in _tar_names(canary_archive)
    setup_archive = next(data for path, data in container.archives if path == "/tmp/skillsentry")
    assert "./run_skill.sh" in _tar_names(setup_archive)
    assert "./cgroup" in _tar_names(setup_archive)

    assert any(event.event_type == "canary_seeded" for event in result.events)
    assert result.canary_reads
    assert result.canary_reads[0].path_or_channel == "~/.aws/credentials"
    assert result.canary_reads[0].marker == MARKER
    assert result.probes
    assert result.sandbox_signal() == 100.0
    stage = result.to_stage_result()
    assert stage.stage.value == "sandbox"
    assert stage.signals["sandbox"] == 100.0
    assert stage.degraded is False
    assert stage.findings
    assert result.resource_usage == {
        "durationMs": result.duration_ms,
        "peakMemoryMb": 120.0,
        "cpuPercent": 100.0,
    }

    exec_create = client.exec_create_calls[0]
    assert exec_create[2]["user"] == "65534:65534"
    assert exec_create[2]["environment"]["HOME"] == "/home/sandbox"
    assert exec_create[2]["environment"]["AWS_ACCESS_KEY_ID"]
    assert exec_create[2]["environment"]["LD_PRELOAD"] == "/opt/skillsentry/masquerade.so"
    assert "/tmp/skillsentry/run_skill.sh" in exec_create[1]
    assert client.exec_start_calls == [("exec-1", True)]


def test_run_accepts_an_explicit_command(tmp_path):
    client = FakeDocker()
    runner = SandboxRunner(client=client, config=_config())
    runner.run(_request(tmp_path, command=("python", "main.py", "--flag")))
    exec_create = client.exec_create_calls[0]
    assert exec_create[1][-3:] == ["python", "main.py", "--flag"]


def test_timeout_stops_container_and_tears_down(tmp_path):
    client = FakeDocker(running_forever=True)
    runner = SandboxRunner(client=client, config=_config())
    result = runner.run(_request(tmp_path, timeout_s=0.03))
    assert result.timed_out is True
    assert result.exit_code == 124
    assert result.error and "timed out" in result.error
    assert result.cleanup_ok is True
    assert result.masquerade is not None
    container = client.containers.created[0]
    assert container.stopped >= 1
    assert container.killed == 1
    assert container.removed == 1
    assert client.networks.created[0].removed == 1
    assert result.sandbox_signal() == 40.0
    assert result.to_stage_result().degraded is True


def test_zero_timeout_is_rejected_before_container_creation(tmp_path):
    client = FakeDocker()
    runner = SandboxRunner(client=client, config=_config())
    with pytest.raises(SandboxError):
        runner.run(_request(tmp_path, timeout_s=0))
    assert client.containers.created == []


def test_existing_network_must_be_internal(tmp_path):
    client = FakeDocker()
    network = FakeNetwork(
        client,
        "skillsentry-sinkhole",
        {"internal": False, "labels": {"skillsentry": "true"}},
    )
    client.networks.existing["skillsentry-sinkhole"] = network
    runner = SandboxRunner(client=client, config=_config())
    with pytest.raises(SandboxError, match="not internal"):
        runner.run(_request(tmp_path))
    assert client.containers.created == []
    assert network.removed == 0


def test_existing_internal_network_is_reused_and_not_removed(tmp_path):
    client = FakeDocker()
    network = FakeNetwork(
        client,
        "skillsentry-sinkhole",
        {"internal": True, "labels": {"skillsentry": "true"}},
    )
    client.networks.existing["skillsentry-sinkhole"] = network
    runner = SandboxRunner(client=client, config=_config())
    result = runner.run(_request(tmp_path))
    assert result.cleanup_ok is True
    assert network.removed == 0
    assert client.containers.created[0].kwargs["network"] == "skillsentry-sinkhole"


def test_masquerade_failure_is_engine_error_and_tears_down(tmp_path):
    client = FakeDocker(verify_output=_verification_output(dockerenv="present"))
    runner = SandboxRunner(client=client, config=_config())
    with pytest.raises(MasqueradeError):
        runner.run(_request(tmp_path))
    container = client.containers.created[0]
    assert container.removed == 1
    assert client.networks.created[0].removed == 1


def test_start_failure_is_engine_error_and_tears_down(tmp_path):
    client = FakeDocker()
    client.fail_start = True
    runner = SandboxRunner(client=client, config=_config())
    with pytest.raises(SandboxError):
        runner.run(_request(tmp_path))
    container = client.containers.created[0]
    assert container.removed == 1
    assert client.networks.created[0].removed == 1


def test_cleanup_failure_is_reported_in_result(tmp_path):
    client = FakeDocker()
    client.fail_remove = True
    client.fail_network_remove = True
    runner = SandboxRunner(client=client, config=_config())
    result = runner.run(_request(tmp_path))
    assert result.cleanup_ok is False
    assert result.error is not None
    assert "container remove failed" in result.error
    assert "network remove failed" in result.error
    assert result.to_stage_result().degraded is True
    assert any(finding.finding_type == "sandbox-cleanup" for finding in result.findings())


def test_exec_start_failure_tears_down(tmp_path):
    client = FakeDocker()
    client.fail_exec_start = True
    runner = SandboxRunner(client=client, config=_config())
    with pytest.raises(SandboxError):
        runner.run(_request(tmp_path))
    assert client.containers.created[0].removed == 1
    assert client.networks.created[0].removed == 1


def test_cleanup_stale_removes_only_dead_labelled_ranges(tmp_path):
    client = FakeDocker()
    dead = FakeContainer(client, {})
    dead.status = "exited"
    running = FakeContainer(client, {})
    running.status = "running"
    client.containers.stale = [dead, running]
    network = FakeNetwork(client, "skillsentry-sinkhole", {"internal": True})
    client.networks.stale = [network]
    runner = SandboxRunner(client=client, config=_config(cleanup_stale=False))
    removed = runner.cleanup_stale()
    assert removed == 1
    assert dead.removed == 1
    assert running.removed == 0
    assert network.removed == 1


def test_available_uses_ping():
    assert SandboxRunner(client=FakeDocker()).available() is True
    assert SandboxRunner(client=FakeDocker(ping_result=False)).available() is False


def test_request_requires_an_existing_skill_directory(tmp_path):
    runner = SandboxRunner(client=FakeDocker(), config=_config())
    with pytest.raises(SandboxError):
        runner.run(SandboxRequest(scan_id=SCAN_ID, skill_dir=tmp_path / "missing"))
