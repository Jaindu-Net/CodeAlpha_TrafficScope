"""Application-layer protocol dispatcher."""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from typing import Any

from parser.protocols.dns_parser import parse_dns
from parser.protocols.http_parser import parse_http
from parser.protocols.tls_parser import is_tls_record, parse_tls_client_hello

DEFAULT_HTTP_PORTS: frozenset[int] = frozenset({80, 8080, 3000, 8000, 8008})
DEFAULT_DNS_PORTS: frozenset[int] = frozenset({53, 5353})
DEFAULT_TLS_PORTS: frozenset[int] = frozenset({443, 8443})


def _dispatch_tcp_app(
    ports: set[int],
    payload: bytes,
    http_ports: AbstractSet[int],
    tls_ports: AbstractSet[int],
) -> tuple[str | None, dict[str, Any] | None]:
    """Dissect TCP application protocols (TLS or HTTP) based on port matches."""
    if ports & tls_ports:
        tls_data = parse_tls_client_hello(payload)
        if tls_data is not None:
            return "TLS", tls_data
        return ("TLS", None) if is_tls_record(payload) else (None, None)

    if ports & http_ports:
        http_data = parse_http(payload)
        return ("HTTP", http_data) if http_data is not None else (None, None)

    return None, None


def parse_application(
    transport_proto: str | None,
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
    *,
    http_ports: AbstractSet[int] = DEFAULT_HTTP_PORTS,
    dns_ports: AbstractSet[int] = DEFAULT_DNS_PORTS,
    tls_ports: AbstractSet[int] = DEFAULT_TLS_PORTS,
) -> tuple[str | None, dict[str, Any] | None]:
    """Dispatch payload bytes to HTTP, DNS, or TLS parsers based on port heuristics."""
    if not payload or transport_proto not in ("TCP", "UDP"):
        return None, None

    ports = {p for p in (src_port, dst_port) if p is not None}
    if ports & dns_ports:
        dns_data = parse_dns(payload, is_tcp=(transport_proto == "TCP"))
        return ("DNS", dns_data) if dns_data is not None else (None, None)

    if transport_proto == "TCP":
        return _dispatch_tcp_app(ports, payload, http_ports, tls_ports)

    return None, None
