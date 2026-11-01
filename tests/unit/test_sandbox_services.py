"""Local DNS sinkhole and inert HTTP responder tests (real loopback sockets)."""

from __future__ import annotations

import http.client
import json
import socket
import struct

import pytest
from skill_sentry_cli.core.contracts import utc_now
from skill_sentry_cli.core.sandbox.dns_sinkhole import (
    DnsSinkhole,
    build_dns_response,
    parse_dns_query,
)
from skill_sentry_cli.core.sandbox.fake_http import FakeHttpResponder, HttpObservation


def _query(qname: str, *, qtype: int = 1, ident: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in qname.split("."))
    return (
        struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", qtype, 1)
    )


def test_dns_query_codec_and_response():
    query = parse_dns_query(_query("SKS-7f3a9c21.evil-collector.net"), client="1.2.3.4:53")
    assert query is not None
    assert query.qname == "SKS-7f3a9c21.evil-collector.net"
    assert query.qtype == 1
    assert query.qtype_name == "A"
    assert query.qclass == 1
    assert query.client == "1.2.3.4:53"

    response = build_dns_response(_query("SKS-7f3a9c21.evil-collector.net"))
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", response[:12])
    assert ident == 0x1234
    assert flags & 0x8000
    assert flags & 0x0100
    assert (qd, an, ns, ar) == (1, 1, 0, 0)
    assert socket.inet_ntoa(response[-4:]) == "127.0.0.1"


def test_dns_non_a_query_has_no_answer():
    response = build_dns_response(_query("example.invalid", qtype=28))
    _ident, _flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", response[:12])
    assert an == 0


def test_dns_rejects_response_and_malformed_queries():
    response = build_dns_response(_query("example.invalid"))
    assert parse_dns_query(response) is None
    assert parse_dns_query(b"short") is None
    assert parse_dns_query(struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0)) is None


def test_dns_sinkhole_answers_and_records_queries():
    with DnsSinkhole(answer_ip="127.0.0.53") as sink:
        address = sink.address
        assert address is not None
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        try:
            client.sendto(_query("SKS-7f3a9c21.evil-collector.net"), address)
            payload, _peer = client.recvfrom(4096)
        finally:
            client.close()

    assert socket.inet_ntoa(payload[-4:]) == "127.0.0.53"
    assert len(sink.queries) == 1
    assert sink.queries[0].qname == "SKS-7f3a9c21.evil-collector.net"
    assert sink.queries[0].qtype_name == "A"


def test_dns_sinkhole_survives_garbage_packets():
    with DnsSinkhole() as sink:
        address = sink.address
        assert address is not None
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        try:
            client.sendto(b"not a dns query", address)
            client.sendto(_query("still.alive.invalid"), address)
            payload, _peer = client.recvfrom(4096)
        finally:
            client.close()
    assert payload
    assert sink.queries[0].qname == "still.alive.invalid"


def test_http_responder_records_and_returns_secondary_canary():
    observed: list[HttpObservation] = []
    with FakeHttpResponder(
        secondary_canary="SKS-8b2c4d19",
        on_request=observed.append,
    ) as responder:
        address = responder.address
        assert address is not None
        host, port = address
        connection = http.client.HTTPConnection(host, port, timeout=2)
        try:
            connection.request(
                "POST",
                "/collect",
                body=b"token=xoxb-SKS-8b2c4d19",
                headers={"Content-Type": "text/plain"},
            )
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()

    assert response.status == 200
    assert json.loads(payload) == {"status": "ok", "data": "SKS-8b2c4d19"}
    assert len(responder.requests) == 1
    recorded = responder.requests[0]
    assert recorded.method == "POST"
    assert recorded.url == "/collect"
    assert recorded.body == b"token=xoxb-SKS-8b2c4d19"
    assert recorded.body_b64
    assert recorded.responder_action == "200+secondary"
    assert observed and observed[0].query_or_url == "POST /collect"


def test_http_responder_rate_limits_by_client_host():
    with FakeHttpResponder(rate_limit_per_minute=2) as responder:
        address = responder.address
        assert address is not None
        host, port = address
        statuses = []
        for index in range(3):
            connection = http.client.HTTPConnection(host, port, timeout=2)
            try:
                connection.request("GET", f"/probe/{index}")
                response = connection.getresponse()
                statuses.append(response.status)
                response.read()
            finally:
                connection.close()

    assert statuses == [200, 200, 429]
    assert responder.requests[-1].responder_action == "429-rate-limited"


def test_http_responder_rejects_invalid_rate_limit():
    with pytest.raises(ValueError):
        FakeHttpResponder(rate_limit_per_minute=0)


def test_http_observation_time_is_utc():
    observation = HttpObservation(ts=utc_now(), method="GET", url="/")
    assert observation.ts.tzinfo is not None
