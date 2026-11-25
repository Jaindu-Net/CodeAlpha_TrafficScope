"""Transport-layer (TCP / UDP / ICMP) dissection and pseudo-header checksum validation."""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
)
from scapy.packet import Packet, Padding

from parser.layers.ip import ones_complement_sum


def _verify_transport_checksum(
    pkt: Packet,
    proto_num: int,
    segment_bytes: bytes,
    ip_len: int | None,
) -> bool | None:
    """Validate TCP/UDP checksum using IPv4 or IPv6 pseudo-header."""
    if not segment_bytes:
        return None

    # Skip verification when payload was truncated/stripped (--no-payload / --payload-bytes)
    # or when packet is fragmented (checksum spans the full reassembled datagram).
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        if int(ip_layer.flags or 0) & 0x01 or int(ip_layer.frag or 0) > 0:
            return None
        if ip_len is not None and len(bytes(ip_layer)) < ip_len:
            return None
        if proto_num == 17 and len(segment_bytes) >= 8:
            udp_wire_chksum = struct.unpack_from("!H", segment_bytes, 6)[0]
            if udp_wire_chksum == 0:
                return None
        src_bytes = ipaddress.IPv4Address(str(ip_layer.src)).packed
        dst_bytes = ipaddress.IPv4Address(str(ip_layer.dst)).packed
        pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, proto_num, len(segment_bytes))
        return ones_complement_sum(pseudo + segment_bytes) == 0xFFFF

    if pkt.haslayer(IPv6):
        ip6_layer = pkt[IPv6]
        if ip_len is not None and len(bytes(ip6_layer)) < ip_len:
            return None
        src_bytes = ipaddress.IPv6Address(str(ip6_layer.src)).packed
        dst_bytes = ipaddress.IPv6Address(str(ip6_layer.dst)).packed
        # IPv6 pseudo-header places 3 zero bytes before next-header byte.
        pseudo = (
            src_bytes
            + dst_bytes
            + struct.pack("!IBBBB", len(segment_bytes), 0, 0, 0, proto_num)
        )
        return ones_complement_sum(pseudo + segment_bytes) == 0xFFFF

    return None


def _strip_ethernet_padding(raw_payload: bytes, expected_len: int | None) -> bytes:
    """Trim trailing Ethernet frame padding when IP/UDP total length specifies fewer bytes."""
    if expected_len is None or expected_len < 0:
        return raw_payload
    if len(raw_payload) > expected_len:
        return raw_payload[:expected_len]
    return raw_payload


def _payload_without_padding(layer: Packet) -> bytes:
    """Serialize a transport layer's payload while excluding explicit Scapy Padding."""
    payload = layer.payload
    if not payload or isinstance(payload, Padding):
        return b""
    raw = bytes(payload)
    if payload.haslayer(Padding):
        pad_len = len(bytes(payload[Padding]))
        if 0 < pad_len <= len(raw):
            raw = raw[:-pad_len]
    return raw


def parse_tcp(
    pkt: Packet,
    *,
    ip_len: int | None = None,
    ip_header_len: int | None = None,
) -> dict[str, Any]:
    """Extract TCP header fields, options, payload bytes, and checksum validity."""
    if not pkt.haslayer(TCP):
        return {}

    tcp = pkt[TCP]
    raw_tcp = bytes(tcp)
    data_offset = (int(tcp.dataofs) * 4) if tcp.dataofs is not None else 20
    data_offset = max(20, min(data_offset, 60))

    expected_payload_len: int | None = None
    if ip_len is not None and ip_header_len is not None:
        expected_payload_len = max(0, ip_len - ip_header_len - data_offset)

    # Trim Ethernet padding from segment_bytes before pseudo-header checksum check.
    expected_tcp_len = (
        data_offset + expected_payload_len if expected_payload_len is not None else None
    )
    segment_for_chksum = _strip_ethernet_padding(raw_tcp, expected_tcp_len)
    payload_bytes = _strip_ethernet_padding(_payload_without_padding(tcp), expected_payload_len)

    options = tuple((str(kind), value) for kind, value in (tcp.options or ()))
    chksum_valid = _verify_transport_checksum(pkt, 6, segment_for_chksum, ip_len)

    return {
        "transport_proto": "TCP",
        "src_port": int(tcp.sport),
        "dst_port": int(tcp.dport),
        "tcp_flags": int(tcp.flags),
        "tcp_reserved": int(tcp.reserved or 0),
        "tcp_window": int(tcp.window),
        "tcp_seq": int(tcp.seq),
        "tcp_ack": int(tcp.ack),
        "tcp_options": options,
        "transport_checksum_valid": chksum_valid,
        "payload_bytes": payload_bytes,
    }


def parse_udp(pkt: Packet, *, ip_len: int | None = None) -> dict[str, Any]:
    """Extract UDP header fields, payload bytes, and checksum validity."""
    if not pkt.haslayer(UDP):
        return {}

    udp = pkt[UDP]
    raw_udp = bytes(udp)
    udp_len = int(udp.len) if udp.len is not None else len(raw_udp)
    expected_payload_len = max(0, udp_len - 8) if udp.len is not None else None

    segment_for_chksum = _strip_ethernet_padding(raw_udp, udp_len if udp.len is not None else None)
    payload_bytes = _strip_ethernet_padding(_payload_without_padding(udp), expected_payload_len)
    chksum_valid = _verify_transport_checksum(pkt, 17, segment_for_chksum, ip_len)

    return {
        "transport_proto": "UDP",
        "src_port": int(udp.sport),
        "dst_port": int(udp.dport),
        "udp_len": udp_len,
        "transport_checksum_valid": chksum_valid,
        "payload_bytes": payload_bytes,
    }


def parse_icmp(pkt: Packet) -> dict[str, Any]:
    """Extract ICMPv4 or ICMPv6 type, code, checksum, and payload."""
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        raw_icmp = bytes(icmp)
        # Reuse ones_complement_sum for ICMPv4 header+payload check.
        chksum_valid = ones_complement_sum(raw_icmp) == 0xFFFF if raw_icmp else None
        return {
            "transport_proto": "ICMP",
            "icmp_type": int(icmp.type),
            "icmp_code": int(icmp.code),
            "transport_checksum_valid": chksum_valid,
            "payload_bytes": _payload_without_padding(icmp),
        }

    for v6_cls in (ICMPv6EchoRequest, ICMPv6EchoReply):
        if pkt.haslayer(v6_cls):
            icmp6 = pkt[v6_cls]
            return {
                "transport_proto": "ICMPv6",
                "icmp_type": int(icmp6.type),
                "icmp_code": int(icmp6.code),
                "transport_checksum_valid": None,
                "payload_bytes": _payload_without_padding(icmp6),
            }

    return {}
