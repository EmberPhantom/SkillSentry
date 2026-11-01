"""Inert DNS + HTTP sinkhole sidecar (stdlib only, runs inside Docker)."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import struct
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ANSWER_IP = os.environ.get("SKILLSENTRY_SIDECAR_IP", "172.30.77.2")
DNS_PORT = int(os.environ.get("SKILLSENTRY_DNS_PORT", "53"))
HTTP_PORT = int(os.environ.get("SKILLSENTRY_HTTP_PORT", "80"))
MAX_BODY = 2_000_000


def _stamp() -> str:
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _question_end(data: bytes) -> int | None:
    if len(data) < 12:
        return None
    offset = 12
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            return offset + 4 if offset + 4 <= len(data) else None
        if length & 0xC0 or offset + length > len(data):
            return None
        offset += length
    return None


def _qname(data: bytes) -> str:
    labels: list[str] = []
    offset = 12
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(data):
            return ""
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels) or "."


def _response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    end = _question_end(query)
    if end is None:
        return b""
    qtype = struct.unpack("!H", query[end - 4 : end - 2])[0]
    answer = b""
    ancount = 0
    if qtype == 1:
        try:
            packed = socket.inet_aton(ANSWER_IP)
        except OSError:
            packed = b"\xac\x1eM\x02"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + packed
        ancount = 1
    flags = 0x8000 | 0x0100 | 0x0080
    return query[:2] + struct.pack("!HHHHH", flags, 1, ancount, 0, 0) + query[12:end] + answer


def dns_loop(sock: socket.socket | None = None) -> None:
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", DNS_PORT))
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except OSError:
            continue
        qname = _qname(data)
        if not qname:
            continue
        end = _question_end(data)
        qtype = struct.unpack("!H", data[end - 4 : end - 2])[0] if end else 0
        _emit(
            {
                "ts": _stamp(),
                "protocol": "dns",
                "query_or_url": qname[:4096],
                "body_b64": base64.b64encode(data[:MAX_BODY]).decode("ascii"),
                "headers": {},
                "client": f"{peer[0]}:{peer[1]}",
                "responder_action": "fake-A" if qtype == 1 else "NOERROR",
            }
        )
        with contextlib.suppress(OSError):
            sock.sendto(_response(data), peer)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _handle(self) -> None:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = max(0, min(int(raw_length), MAX_BODY))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        host = self.headers.get("Host", "")
        url = f"http://{host}{self.path}" if host else self.path
        _emit(
            {
                "ts": _stamp(),
                "protocol": "http",
                "query_or_url": f"{self.command} {url}"[:4096],
                "body_b64": base64.b64encode(body).decode("ascii") if body else None,
                "headers": {str(k)[:100]: str(v)[:1000] for k, v in self.headers.items()},
                "client": f"{self.client_address[0]}:{self.client_address[1]}",
                "responder_action": "200+secondary",
            }
        )
        encoded = b'{"status":"ok","data":"inert"}'
        self.send_response(200)
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


def main() -> None:
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_sock.bind(("0.0.0.0", DNS_PORT))
    threading.Thread(target=dns_loop, args=(dns_sock,), daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    server.daemon_threads = True
    _emit(
        {
            "event": "ready",
            "dns_port": DNS_PORT,
            "http_port": HTTP_PORT,
            "ip": ANSWER_IP,
        }
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
