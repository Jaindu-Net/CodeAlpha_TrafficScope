"""Network-layer (IPv4 / IPv6) dissection and RFC 1071 checksum helpers."""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import Packet


def ones_complement_sum(data: bytes) -> int:
    """Compute the 16-bit one's complement sum over an arbitrary byte buffer."""
    if len(data) % 2 == 1:
        data = data + b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) | data[idx + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def verify_ipv4_checksum(header_bytes: bytes) -> bool:
    """Return True if an IPv4 header passes RFC 1071 checksum verification."""
    if len(header_bytes) < 20:
        return False
    return ones_complement_sum(header_bytes) == 0xFFFF


def _extract_ipv4_flags(raw_flags: Any) -> tuple[str, ...]:
    """Normalize Scapy IP flags value into an ordered tuple of flag names."""
    if raw_flags is None:
        return ()
    flag_int = int(raw_flags)
    names: list[str] = []
    if flag_int & 0x04:
        names.append("EVIL")
    if flag_int & 0x02:
        names.append("DF")
    if flag_int & 0x01:
        names.append("MF")
    return tuple(names)


def parse_ip(pkt: Packet) -> dict[str, Any]:
    """Extract IPv4 header fields and checksum validity from a Scapy packet."""
    if not pkt.haslayer(IP):
        return {}

    ip_layer = pkt[IP]
    header_len = int(ip_layer.ihl) * 4 if ip_layer.ihl is not None else 20
    header_len = max(20, min(header_len, 60))

    raw_ip = bytes(ip_layer)
    ip_len = int(ip_layer.len) if ip_layer.len is not None else len(raw_ip)
    chksum_valid = verify_ipv4_checksum(raw_ip[:header_len])
    ip_flags = _extract_ipv4_flags(ip_layer.flags)
    frag_offset = int(ip_layer.frag or 0) * 8
    is_fragment = frag_offset > 0 or "MF" in ip_flags

    return {
        "ip_version": 4,
        "ip_src": str(ip_layer.src),
        "ip_dst": str(ip_layer.dst),
        "ip_ttl": int(ip_layer.ttl) if ip_layer.ttl is not None else None,
        "ip_proto": int(ip_layer.proto) if ip_layer.proto is not None else None,
        "ip_len": ip_len,
        "ip_flags": ip_flags,
        "ip_frag_offset": frag_offset,
        "ip_id": int(ip_layer.id) if ip_layer.id is not None else None,
        "ip_header_len": header_len,
        "ip_header_bytes": raw_ip[:header_len] if is_fragment else b"",
        "ip_fragment_data": raw_ip[header_len:ip_len] if is_fragment else b"",
        "ip_checksum_valid": chksum_valid,
    }


def parse_ipv6(pkt: Packet) -> dict[str, Any]:
    """Extract IPv6 header fields (and fragment extension header if present)."""
    if not pkt.haslayer(IPv6):
        return {}

    ip6 = pkt[IPv6]
    raw_ip6 = bytes(ip6)
    ip_len = (int(ip6.plen) + 40) if ip6.plen is not None else len(raw_ip6)

    ip_flags: tuple[str, ...] = ()
    frag_offset = 0
    frag_id: int | None = None
    next_proto = int(ip6.nh) if ip6.nh is not None else None

    if pkt.haslayer(IPv6ExtHdrFragment):
        frag_hdr = pkt[IPv6ExtHdrFragment]
        frag_offset = int(frag_hdr.offset or 0) * 8
        frag_id = int(frag_hdr.id) if frag_hdr.id is not None else None
        if frag_hdr.m:
            ip_flags = ("MF",)
        if frag_hdr.nh is not None:
            next_proto = int(frag_hdr.nh)

    return {
        "ip_version": 6,
        "ip_src": str(ip6.src),
        "ip_dst": str(ip6.dst),
        "ip_ttl": int(ip6.hlim) if ip6.hlim is not None else None,
        "ip_proto": next_proto,
        "ip_len": ip_len,
        "ip_flags": ip_flags,
        "ip_frag_offset": frag_offset,
        "ip_id": frag_id,
        "ip_header_len": 40,
        "ip_checksum_valid": None,
    }
