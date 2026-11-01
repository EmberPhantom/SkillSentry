"""Minimal, dependency-free DNS sinkhole and query codec.

The sinkhole answers A queries with a loopback address and returns an empty
NOERROR response for other types.  It never forwards a query upstream.  The
default bind address is loopback; the Docker integration binds the sidecar on
the internal sinkhole network only.
"""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from skill_sentry_cli.core.contracts import utc_now

_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


@dataclass(frozen=True)
class DnsQuery:
    ts: datetime
    qname: str
    qtype: int
    client: str
    raw_b64: str
    qclass: int = 1

    @property
    def qtype_name(self) -> str:
        return _QTYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


def parse_dns_query(
    data: bytes, *, ts: datetime | None = None, client: str = ""
) -> DnsQuery | None:
    if len(data) < 12:
        return None
    _ident, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000 or qdcount < 1:
        return None
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            # Compression pointers are legal in messages but not in the
            # question section of a query; reject rather than risk a loop.
            return None
        if length > 63 or offset + length > len(data):
            return None
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    qname = ".".join(labels) or "."
    return DnsQuery(
        ts=ts or utc_now(),
        qname=qname,
        qtype=qtype,
        qclass=qclass,
        client=client,
        raw_b64=base64.b64encode(data).decode("ascii"),
    )


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


def build_dns_response(
    query: bytes,
    *,
    answer_ip: str = "127.0.0.1",
    rcode: int = 0,
) -> bytes:
    if len(query) < 12:
        raise ValueError("DNS query is shorter than its header")
    ident = query[:2]
    question_end = _question_end(query)
    if question_end is None:
        raise ValueError("DNS query has no complete question section")
    qtype = struct.unpack("!H", query[question_end - 4 : question_end - 2])[0]
    answer = b""
    ancount = 0
    if rcode == 0 and qtype == 1:
        try:
            packed_ip = ipaddress.IPv4Address(answer_ip).packed
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"answer_ip must be an IPv4 address: {answer_ip!r}") from exc
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + packed_ip
        ancount = 1
    flags = 0x8000 | 0x0100 | 0x0080 | (rcode & 0xF)  # QR, RD, RA
    header = ident + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    return header + query[12:question_end] + answer


class DnsSinkhole:
    """Threaded UDP DNS responder that records every query it receives."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        answer_ip: str = "127.0.0.1",
        on_query: Callable[[DnsQuery], None] | None = None,
        max_queries: int = 5000,
    ) -> None:
        self.host = host
        self.port = port
        self.answer_ip = answer_ip
        self.on_query = on_query
        self.max_queries = max_queries
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._queries: list[DnsQuery] = []

    @property
    def address(self) -> tuple[str, int] | None:
        if self._sock is None:
            return None
        host, port = self._sock.getsockname()[:2]
        return str(host), int(port)

    @property
    def queries(self) -> tuple[DnsQuery, ...]:
        with self._lock:
            return tuple(self._queries)

    def start(self) -> DnsSinkhole:
        if self._sock is not None:
            return self
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.2)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="skillsentry-dns", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def __enter__(self) -> DnsSinkhole:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def _serve(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                data, peer = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            query = parse_dns_query(data, client=f"{peer[0]}:{peer[1]}")
            if query is None:
                continue
            with self._lock:
                if len(self._queries) >= self.max_queries:
                    continue
                self._queries.append(query)
            if self.on_query is not None:
                # A telemetry callback must never kill the responder.
                with contextlib.suppress(Exception):
                    self.on_query(query)
            with contextlib.suppress(OSError, ValueError):
                sock.sendto(build_dns_response(data, answer_ip=self.answer_ip), peer)
