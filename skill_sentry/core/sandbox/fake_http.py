"""Inert fake HTTP responder for the Poisoned Well sinkhole.

Every request is recorded (method, URL, headers, body) and answered with a
fixed ``200 {"status":"ok","data":"<secondary canary>"}``.  It never proxies,
resolves, or serves attacker-controlled content.  Bind it to loopback for tests
or to the internal sinkhole network in the Docker integration.
"""

from __future__ import annotations

import base64
import contextlib
import json
import threading
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import monotonic
from typing import Any

from skill_sentry.core.contracts import utc_now


@dataclass(frozen=True)
class HttpObservation:
    ts: datetime
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client: str = ""
    responder_action: str = "200+secondary"

    @property
    def body_b64(self) -> str | None:
        if not self.body:
            return None
        return base64.b64encode(self.body).decode("ascii")

    @property
    def query_or_url(self) -> str:
        return f"{self.method} {self.url}"


class _FakeHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: FakeHttpResponder) -> None:
        self.app = app
        super().__init__(address, _FakeHttpHandler)


class _FakeHttpHandler(BaseHTTPRequestHandler):
    server: _FakeHttpServer

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep test output quiet; the responder has its own structured log.
        return

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = max(0, min(int(raw_length), 1_048_576))
        except ValueError:
            length = 0
        return self.rfile.read(length) if length else b""

    def _handle(self) -> None:
        body = self._read_body()
        observation = HttpObservation(
            ts=utc_now(),
            method=self.command,
            url=self.path,
            headers={key: value for key, value in self.headers.items()},
            body=body,
            client=f"{self.client_address[0]}:{self.client_address[1]}",
        )
        app = self.server.app
        action = app._record(observation)
        status = 429 if action == "429-rate-limited" else 200
        payload = (
            {"error": "rate limited"}
            if status == 429
            else {"status": "ok", "data": app.secondary_canary}
        )
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle


class FakeHttpResponder:
    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        secondary_canary: str = "SKS-00000000",
        rate_limit_per_minute: int = 120,
        on_request: Callable[[HttpObservation], None] | None = None,
    ) -> None:
        if rate_limit_per_minute <= 0:
            raise ValueError("rate_limit_per_minute must be positive")
        self.host = host
        self.port = port
        self.secondary_canary = secondary_canary
        self.rate_limit_per_minute = rate_limit_per_minute
        self.on_request = on_request
        self._server: _FakeHttpServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._requests: list[HttpObservation] = []
        self._client_windows: dict[str, deque[float]] = defaultdict(deque)

    @property
    def address(self) -> tuple[str, int] | None:
        if self._server is None:
            return None
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def requests(self) -> tuple[HttpObservation, ...]:
        with self._lock:
            return tuple(self._requests)

    def start(self) -> FakeHttpResponder:
        if self._server is not None:
            return self
        self._server = _FakeHttpServer((self.host, self.port), self)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="skillsentry-http",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def __enter__(self) -> FakeHttpResponder:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def _record(self, observation: HttpObservation) -> str:
        with self._lock:
            # The ephemeral source port changes for every connection, so limit
            # by host address rather than by "host:port".
            client_key = observation.client.rsplit(":", 1)[0] if observation.client else "unknown"
            window = self._client_windows[client_key]
            now = monotonic()
            while window and now - window[0] >= 60.0:
                window.popleft()
            if len(window) >= self.rate_limit_per_minute:
                action = "429-rate-limited"
            else:
                window.append(now)
                action = "200+secondary"
            recorded = HttpObservation(
                ts=observation.ts,
                method=observation.method,
                url=observation.url,
                headers=observation.headers,
                body=observation.body,
                client=observation.client,
                responder_action=action,
            )
            self._requests.append(recorded)
        if self.on_request is not None:
            with contextlib.suppress(Exception):
                self.on_request(recorded)
        return action
