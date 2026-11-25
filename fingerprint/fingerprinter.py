"""Purely passive OS/device fingerprinter operating on TCP SYN packets."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fingerprint.loader import FingerprintDB
from parser.parsed_packet import ParsedPacket

_SYN = 0x02
_ACK = 0x10

_OPTION_ALIASES: dict[str, str] = {
    "MSS": "MSS",
    "NOP": "NOP",
    "EOL": "EOL",
    "WScale": "WS",
    "WS": "WS",
    "SAckOK": "SACK",
    "SAck": "SACK",
    "SACK": "SACK",
    "Timestamp": "TS",
    "TS": "TS",
}


def normalize_tcp_options(
    raw_options: tuple[tuple[str, Any], ...] | list[tuple[str, Any]],
) -> list[str]:
    """Convert Scapy TCP option tuples into canonical fingerprint option names."""
    return [_OPTION_ALIASES.get(str(kind), str(kind).upper()) for kind, _ in raw_options]


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    """Cached passive OS identification result for a source IP address."""

    src_ip: str
    os_guess: str
    confidence: int
    ttl_seen: int
    window_seen: int
    options_seen: tuple[str, ...]


class Fingerprinter:
    """Maps observed TCP SYN header characteristics against a local JSON DB."""

    def __init__(
        self,
        db: FingerprintDB | None = None,
        *,
        db_path: str | Path | None = None,
    ) -> None:
        """Initialize the passive fingerprinter."""
        self.db = db or FingerprintDB(db_path=db_path)
        self._lock = threading.Lock()
        self._cache: dict[str, FingerprintResult] = {}

    def fingerprint(self, pkt: ParsedPacket) -> FingerprintResult | None:
        """Inspect a ParsedPacket and return a FingerprintResult on TCP SYN packets."""
        if pkt.transport_proto != "TCP" or pkt.ip_src is None:
            return None
        if pkt.tcp_flags is None or pkt.ip_ttl is None or pkt.tcp_window is None:
            return None

        # Only fingerprint the initiating SYN (not SYN-ACK or established traffic).
        is_syn_only = bool(pkt.tcp_flags & _SYN) and not bool(pkt.tcp_flags & _ACK)
        if not is_syn_only:
            return None

        options_order = normalize_tcp_options(pkt.tcp_options)
        sig = (pkt.ip_ttl, pkt.tcp_window, tuple(options_order))

        with self._lock:
            cached = self._cache.get(pkt.ip_src)
            if cached is not None and (
                cached.ttl_seen,
                cached.window_seen,
                cached.options_seen,
            ) == sig:
                return cached

        matches = self.db.match(pkt.ip_ttl, pkt.tcp_window, options_order)
        if not matches:
            return None

        best = matches[0]
        # Combine structural match score (0-100) with entry base confidence.
        confidence = min(100, round(best.score * (best.entry_confidence / 100.0)))
        result = FingerprintResult(
            src_ip=pkt.ip_src,
            os_guess=best.os,
            confidence=confidence,
            ttl_seen=pkt.ip_ttl,
            window_seen=pkt.tcp_window,
            options_seen=tuple(options_order),
        )
        with self._lock:
            self._cache[pkt.ip_src] = result
        return result

    def get_os_guess(self, ip: str) -> str | None:
        """Return cached OS guess string for a source IP, if available."""
        with self._lock:
            res = self._cache.get(ip)
            return res.os_guess if res is not None else None

    def get_all_results(self) -> dict[str, FingerprintResult]:
        """Return a snapshot dictionary of all cached host fingerprint results."""
        with self._lock:
            return dict(self._cache)
