"""IPv4 datagram defragmenter handling out-of-order and overlapping fragments."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from parser.packet_parser import PacketParser
from parser.parsed_packet import ParsedPacket

logger = logging.getLogger(__name__)

FragKey = tuple[int, str, str, int]


@dataclass
class _FragmentAssembly:
    """In-flight collection of IPv4 fragments belonging to a single datagram."""

    created_at: float
    last_seen: float
    first_header: bytes = b""
    eth_src: str | None = None
    eth_dst: str | None = None
    ip_src: str = ""
    ip_dst: str = ""
    ip_ttl: int = 64
    ip_proto: int = 0
    ip_id: int = 0
    total_len: int | None = None
    fragments: dict[int, bytes] = field(default_factory=dict)
    overlap_detected: bool = False


class IPDefragmenter:
    """Thread-safe IPv4 defragmenter using a first-seen overlap policy."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        parser: PacketParser | None = None,
    ) -> None:
        """Initialize the defragmenter with a stale-fragment timeout."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        self.timeout_seconds = timeout_seconds
        self._parser = parser or PacketParser()
        self._lock = threading.Lock()
        self._assemblies: dict[FragKey, _FragmentAssembly] = {}
        self.overlap_count = 0
        self.expired_count = 0

    @property
    def active_count(self) -> int:
        """Return the number of incomplete fragment assemblies currently tracked."""
        with self._lock:
            return len(self._assemblies)

    def prune_expired(self, now: float) -> int:
        """Remove incomplete fragment sets older than timeout_seconds."""
        with self._lock:
            return self._prune_locked(now)

    def _prune_locked(self, now: float) -> int:
        expired_keys = [
            key
            for key, assembly in self._assemblies.items()
            if (now - assembly.last_seen) > self.timeout_seconds
        ]
        for key in expired_keys:
            del self._assemblies[key]
        self.expired_count += len(expired_keys)
        return len(expired_keys)

    def _get_or_create_assembly_locked(self, pkt: ParsedPacket, key: FragKey) -> _FragmentAssembly:
        """Look up or initialize a fragment assembly record while holding self._lock."""
        assembly = self._assemblies.get(key)
        if assembly is not None:
            return assembly
        assert pkt.ip_src is not None and pkt.ip_dst is not None
        assert pkt.ip_proto is not None and pkt.ip_id is not None
        assembly = _FragmentAssembly(
            created_at=pkt.timestamp,
            last_seen=pkt.timestamp,
            eth_src=pkt.eth_src,
            eth_dst=pkt.eth_dst,
            ip_src=pkt.ip_src,
            ip_dst=pkt.ip_dst,
            ip_ttl=pkt.ip_ttl if pkt.ip_ttl is not None else 64,
            ip_proto=pkt.ip_proto,
            ip_id=pkt.ip_id,
        )
        self._assemblies[key] = assembly
        return assembly

    def _record_fragment_locked(
        self,
        assembly: _FragmentAssembly,
        pkt: ParsedPacket,
        frag_data: bytes,
        key: FragKey,
    ) -> None:
        """Store fragment payload and metadata inside assembly while holding self._lock."""
        assembly.last_seen = pkt.timestamp
        if pkt.ip_frag_offset == 0 and pkt.ip_header_bytes:
            assembly.first_header = pkt.ip_header_bytes

        offset = pkt.ip_frag_offset
        if _detect_overlap(assembly.fragments, offset, len(frag_data)):
            assembly.overlap_detected = True
            self.overlap_count += 1
            logger.warning("IP fragment overlap detected for %s at offset %d", key, offset)

        if offset not in assembly.fragments:
            assembly.fragments[offset] = frag_data
        if "MF" not in pkt.ip_flags:
            assembly.total_len = offset + len(frag_data)

    def add_fragment(self, pkt: ParsedPacket) -> ParsedPacket | None:
        """Process a ParsedPacket, returning a reassembled ParsedPacket when complete."""
        if pkt.ip_frag_offset == 0 and "MF" not in pkt.ip_flags:
            return pkt
        if None in (pkt.ip_id, pkt.ip_src, pkt.ip_dst, pkt.ip_proto):
            return None

        assert pkt.ip_id is not None and pkt.ip_src is not None
        assert pkt.ip_dst is not None and pkt.ip_proto is not None
        frag_data = pkt.ip_fragment_data or pkt.payload_bytes
        key: FragKey = (pkt.ip_id, pkt.ip_src, pkt.ip_dst, pkt.ip_proto)

        with self._lock:
            self._prune_locked(pkt.timestamp)
            assembly = self._get_or_create_assembly_locked(pkt, key)
            self._record_fragment_locked(assembly, pkt, frag_data, key)
            if not _is_complete(assembly):
                return None

            reassembled_payload = _assemble_first_seen(assembly.fragments, assembly.total_len or 0)
            del self._assemblies[key]

        rebuilt_scapy = self._build_reassembled_packet(assembly, reassembled_payload, pkt.timestamp)
        return self._parser.parse(rebuilt_scapy)

    def _build_reassembled_packet(
        self,
        assembly: _FragmentAssembly,
        payload: bytes,
        timestamp: float,
    ) -> Packet:
        """Construct and dissect a Scapy Ethernet/IP packet from reassembled payload."""
        ip_pkt = IP(
            src=assembly.ip_src,
            dst=assembly.ip_dst,
            ttl=assembly.ip_ttl,
            proto=assembly.ip_proto,
            id=assembly.ip_id,
            flags=0,
            frag=0,
        ) / Raw(payload)

        if assembly.eth_src and assembly.eth_dst:
            raw_bytes = bytes(Ether(src=assembly.eth_src, dst=assembly.eth_dst) / ip_pkt)
            full_pkt: Packet = Ether(raw_bytes)
        else:
            full_pkt = IP(bytes(ip_pkt))
        full_pkt.time = timestamp
        return full_pkt


def _detect_overlap(existing: dict[int, bytes], offset: int, length: int) -> bool:
    """Return True if [offset, offset + length) overlaps any stored fragment."""
    new_end = offset + length
    return any(
        offset < (ex_start + len(ex_data)) and ex_start < new_end
        for ex_start, ex_data in existing.items()
    )


def _is_complete(assembly: _FragmentAssembly) -> bool:
    """Return True if fragments cover every byte in [0, total_len) without gaps."""
    if assembly.total_len is None or assembly.total_len <= 0:
        return False
    cursor = 0
    for start in sorted(assembly.fragments):
        if start > cursor:
            return False
        cursor = max(cursor, start + len(assembly.fragments[start]))
        if cursor >= assembly.total_len:
            return True
    return cursor >= assembly.total_len


def _assemble_first_seen(fragments: dict[int, bytes], total_len: int) -> bytes:
    """Assemble fragment map into a contiguous byte buffer using first-seen ordering."""
    buf = bytearray(total_len)
    covered = bytearray(total_len)
    for start in sorted(fragments):
        data = fragments[start]
        for idx, byte_val in enumerate(data):
            pos = start + idx
            if pos >= total_len:
                break
            if not covered[pos]:
                buf[pos] = byte_val
                covered[pos] = 1
    return bytes(buf)
