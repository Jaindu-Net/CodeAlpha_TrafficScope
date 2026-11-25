"""Layer-by-layer Scapy packet dissector returning immutable ParsedPacket objects."""

from __future__ import annotations

import time
from collections.abc import Set as AbstractSet
from typing import Any

from scapy.packet import Packet

from parser.layers.application import (
    DEFAULT_DNS_PORTS,
    DEFAULT_HTTP_PORTS,
    DEFAULT_TLS_PORTS,
    parse_application,
)
from parser.layers.ethernet import parse_ethernet
from parser.layers.ip import parse_ip, parse_ipv6
from parser.layers.transport import parse_icmp, parse_tcp, parse_udp
from parser.parsed_packet import ParsedPacket


class PacketParser:
    """Stateless packet dissector transforming raw Scapy packets into ParsedPacket."""

    def __init__(
        self,
        *,
        http_ports: AbstractSet[int] = DEFAULT_HTTP_PORTS,
        dns_ports: AbstractSet[int] = DEFAULT_DNS_PORTS,
        tls_ports: AbstractSet[int] = DEFAULT_TLS_PORTS,
    ) -> None:
        """Initialize parser with optional custom application-layer port sets."""
        self.http_ports = frozenset(http_ports)
        self.dns_ports = frozenset(dns_ports)
        self.tls_ports = frozenset(tls_ports)

    def parse(self, raw_pkt: Packet) -> ParsedPacket:
        """Dissect a Scapy Packet through link, network, transport, and app layers.

        Never raises on malformed input; returns a partial ParsedPacket with
        ``error=True`` and ``error_message`` populated instead.
        """
        timestamp = float(getattr(raw_pkt, "time", time.time()))
        try:
            raw_bytes = bytes(raw_pkt)
        except Exception as exc:
            return ParsedPacket(
                timestamp=timestamp,
                raw_bytes=b"",
                error=True,
                error_message=f"Failed to serialize packet bytes: {exc}",
            )

        fields: dict[str, Any] = {
            "timestamp": timestamp,
            "raw_bytes": raw_bytes,
        }

        try:
            fields.update(parse_ethernet(raw_pkt))

            ip_fields = parse_ip(raw_pkt) or parse_ipv6(raw_pkt)
            fields.update(ip_fields)

            frag_offset = fields.get("ip_frag_offset", 0)
            ip_len = fields.get("ip_len")
            ip_header_len = fields.get("ip_header_len")

            # Only the first IP fragment (offset == 0) contains a valid transport header.
            if ip_fields and frag_offset == 0:
                transport_fields = (
                    parse_tcp(raw_pkt, ip_len=ip_len, ip_header_len=ip_header_len)
                    or parse_udp(raw_pkt, ip_len=ip_len)
                    or parse_icmp(raw_pkt)
                )
                fields.update(transport_fields)

                payload = fields.get("payload_bytes", b"")
                # Non-first/unreassembled fragmented datagrams hold partial app payloads;
                # skip app dissection if MF is set on first fragment.
                if payload and "MF" not in fields.get("ip_flags", ()):
                    app_proto, app_data = parse_application(
                        fields.get("transport_proto"),
                        fields.get("src_port"),
                        fields.get("dst_port"),
                        payload,
                        http_ports=self.http_ports,
                        dns_ports=self.dns_ports,
                        tls_ports=self.tls_ports,
                    )
                    fields["app_protocol"] = app_proto
                    fields["app_layer_data"] = app_data

            fields["checksum_valid"] = _combine_checksums(
                fields.get("ip_checksum_valid"),
                fields.get("transport_checksum_valid"),
            )
            return ParsedPacket(**fields)
        except Exception as exc:
            fields["error"] = True
            fields["error_message"] = str(exc)
            return ParsedPacket(**fields)


def _combine_checksums(
    ip_valid: bool | None,
    transport_valid: bool | None,
) -> bool | None:
    """Combine IP and transport checksum flags into a single boolean or None."""
    if ip_valid is False or transport_valid is False:
        return False
    if ip_valid is True or transport_valid is True:
        return True
    return None
