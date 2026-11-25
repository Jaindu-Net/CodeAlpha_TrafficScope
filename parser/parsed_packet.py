"""Canonical immutable packet representation produced by PacketParser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

FlowKey = tuple[str, int, str, int, str]

_TCP_FLAG_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """Immutable, layer-dissected representation of a captured network packet."""

    timestamp: float
    raw_bytes: bytes
    eth_src: str | None = None
    eth_dst: str | None = None
    ethertype: int | None = None
    ip_version: int | None = None
    ip_src: str | None = None
    ip_dst: str | None = None
    ip_ttl: int | None = None
    ip_proto: int | None = None
    ip_len: int | None = None
    ip_flags: tuple[str, ...] = ()
    ip_frag_offset: int = 0
    ip_id: int | None = None
    ip_header_len: int | None = None
    ip_header_bytes: bytes = b""
    ip_fragment_data: bytes = b""
    transport_proto: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_reserved: int = 0
    tcp_window: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_options: tuple[tuple[str, Any], ...] = ()
    udp_len: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    checksum_valid: bool | None = None
    ip_checksum_valid: bool | None = None
    transport_checksum_valid: bool | None = None
    payload_bytes: bytes = b""
    app_protocol: str | None = None
    app_layer_data: dict[str, Any] | None = None
    error: bool = False
    error_message: str | None = None

    @property
    def packet_len(self) -> int:
        """Return total packet length in bytes."""
        return len(self.raw_bytes)

    @property
    def flow_key(self) -> FlowKey | None:
        """Return canonical bidirectional 5-tuple (a_ip, a_port, b_ip, b_port, proto)."""
        if self.ip_src is None or self.ip_dst is None or self.transport_proto is None:
            return None
        sport = self.src_port or 0
        dport = self.dst_port or 0
        ep_a = (self.ip_src, sport)
        ep_b = (self.ip_dst, dport)
        if ep_a <= ep_b:
            return (ep_a[0], ep_a[1], ep_b[0], ep_b[1], self.transport_proto)
        return (ep_b[0], ep_b[1], ep_a[0], ep_a[1], self.transport_proto)

    @property
    def directed_flow_key(self) -> FlowKey | None:
        """Return directed 5-tuple (ip_src, src_port, ip_dst, dst_port, proto)."""
        if self.ip_src is None or self.ip_dst is None or self.transport_proto is None:
            return None
        return (
            self.ip_src,
            self.src_port or 0,
            self.ip_dst,
            self.dst_port or 0,
            self.transport_proto,
        )

    @property
    def tcp_flag_names(self) -> tuple[str, ...]:
        """Return human-readable names of active TCP flag bits."""
        if self.tcp_flags is None:
            return ()
        return tuple(name for mask, name in _TCP_FLAG_BITS if self.tcp_flags & mask)

    @property
    def effective_protocol(self) -> str:
        """Return the highest dissected protocol label for statistics display."""
        if self.app_protocol:
            return self.app_protocol
        if self.transport_proto:
            return self.transport_proto
        if self.ip_version is not None:
            return f"IPv{self.ip_version}"
        if self.ethertype == 0x0806:
            return "ARP"
        return "OTHER"

    def __repr__(self) -> str:
        proto = self.effective_protocol
        src = f"{self.ip_src}:{self.src_port}" if self.src_port is not None else self.ip_src
        dst = f"{self.ip_dst}:{self.dst_port}" if self.dst_port is not None else self.ip_dst
        flags = f" [{','.join(self.tcp_flag_names)}]" if self.tcp_flag_names else ""
        err = f" ERROR={self.error_message!r}" if self.error else ""
        return f"<ParsedPacket {proto} {src} -> {dst} len={self.packet_len}{flags}{err}>"
