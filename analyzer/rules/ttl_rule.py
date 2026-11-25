"""Impossible/anomalous IP TTL detection rule."""

from __future__ import annotations

import ipaddress

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket


def _is_legitimate_low_ttl_dest(dst_ip: str | None) -> bool:
    """Return True if dst_ip is multicast, broadcast, or link-local (TTL=1 normal)."""
    if dst_ip is None:
        return False
    if dst_ip == "255.255.255.255":
        return True
    try:
        addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    return addr.is_multicast or addr.is_link_local


class TTLRule:
    """Flags packets arriving with illegal TTL=0 or unexpected TTL=1."""

    def evaluate(self, pkt: ParsedPacket) -> list[Alert]:
        """Inspect IP TTL / IPv6 hop limit for impossible values."""
        if pkt.ip_ttl is None:
            return []

        if pkt.ip_ttl == 0:
            return [
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.TTL_ANOMALY,
                    severity=Severity.HIGH,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail="Illegal packet with TTL=0 observed on wire",
                    raw_context={"ttl": pkt.ip_ttl, "ip_version": pkt.ip_version},
                )
            ]

        if pkt.ip_ttl <= 1 and not _is_legitimate_low_ttl_dest(pkt.ip_dst):
            return [
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.TTL_ANOMALY,
                    severity=Severity.MEDIUM,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"Suspicious low TTL={pkt.ip_ttl} on unicast packet",
                    raw_context={"ttl": pkt.ip_ttl, "ip_version": pkt.ip_version},
                )
            ]

        return []
