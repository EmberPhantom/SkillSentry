"""Host and Origin checks for the local API.

The server returns code excerpts and can start scans of local folders. A web page
can reach a loopback server through DNS rebinding: it resolves a name it controls to
127.0.0.1, and the browser then sends that name in ``Host``. Rejecting any ``Host``
outside an allowlist blocks this. Browsers do not apply CORS to WebSocket handshakes,
so an ``Origin`` check is also needed there.

The allowlist is loopback names plus the bind address when it is a specific host.
Extra names can be added with ``SKILLSENTRY_ALLOWED_HOSTS`` (comma-separated), for
example a LAN name for a server bound to all interfaces.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_WILDCARD_BINDS = frozenset({"", "0.0.0.0", "::"})
ALLOWED_HOSTS_ENV = "SKILLSENTRY_ALLOWED_HOSTS"


def _normalise(name: str) -> str:
    return name.strip().strip("[]").lower()


def allowed_hostnames(bind_host: str | None, extra: Iterable[str] = ()) -> frozenset[str]:
    """Hostnames (no port, no brackets) the server accepts in Host and Origin."""

    names = set(LOOPBACK_HOSTS)
    if bind_host is not None and _normalise(bind_host) not in _WILDCARD_BINDS:
        names.add(_normalise(bind_host))
    names.update(_normalise(name) for name in extra if name.strip())
    return frozenset(names)


def allowed_hostnames_from_env(bind_host: str | None) -> frozenset[str]:
    extra = os.getenv(ALLOWED_HOSTS_ENV, "").split(",")
    return allowed_hostnames(bind_host, extra)


def hostname_from_authority(authority: str) -> str:
    """Hostname from a Host header value: ``localhost:8000`` and ``[::1]:8000`` both work."""

    authority = authority.strip()
    if authority.startswith("["):
        end = authority.find("]")
        return authority[1:end].lower() if end > 0 else ""
    if authority.count(":") == 1:
        return authority.split(":", 1)[0].lower()
    return authority.lower()


_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class TrustedHostMiddleware:
    """Reject requests whose Host is not allowed, and cross-origin state changes.

    An ``Origin`` header on a WebSocket handshake or on an HTTP request with an unsafe
    method must name the server's own origin (the same scheme, host and port as
    ``Host``) or one of ``allowed_origins``. Hostnames alone are not enough: another
    page on ``http://localhost:9999`` is a different origin. ``null`` is refused.
    Requests without an ``Origin`` header (curl, the CLI) and safe HTTP methods are
    not affected.

    Pure ASGI, so WebSocket handshakes can be refused before they are accepted.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: frozenset[str],
        allowed_origins: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.allowed_origins = frozenset(origin.strip().lower() for origin in allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        is_websocket = scope["type"] == "websocket"
        host_header = headers.get("host", "")
        host = hostname_from_authority(host_header)
        if host not in self.allowed_hosts:
            await self._reject(
                scope, send, is_websocket, f"host {host or '(missing)'!r} is not allowed"
            )
            return

        origin = headers.get("origin")
        checks_origin = is_websocket or scope.get("method", "GET").upper() in _UNSAFE_METHODS
        if origin is not None and checks_origin and not self._origin_allowed(origin, host_header):
            await self._reject(scope, send, is_websocket, "origin is not allowed")
            return

        await self.app(scope, receive, send)

    def _origin_allowed(self, origin: str, host_header: str) -> bool:
        """True when an Origin on an unsafe request is the server's own or a listed dev origin."""

        value = origin.strip().lower()
        if value == "null":
            return False
        if value in self.allowed_origins:
            return True
        try:
            parts = urlsplit(value)
        except ValueError:
            return False
        if parts.scheme not in {"http", "https"} or parts.hostname not in self.allowed_hosts:
            return False
        return parts.netloc == host_header.strip().lower()

    @staticmethod
    async def _reject(scope: Scope, send: Send, is_websocket: bool, reason: str) -> None:
        if is_websocket:
            # Closing before accept makes the server answer the handshake with 403.
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps(
            {
                "error": {
                    "code": "untrusted_host",
                    "message": f"request refused: {reason}",
                    "stage": None,
                    "degraded": False,
                    "scan_id": None,
                }
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


__all__ = [
    "ALLOWED_HOSTS_ENV",
    "LOOPBACK_HOSTS",
    "TrustedHostMiddleware",
    "allowed_hostnames",
    "allowed_hostnames_from_env",
    "hostname_from_authority",
]
