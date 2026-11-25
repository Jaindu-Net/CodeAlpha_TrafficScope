"""TCP flag anomaly and stealth scan signature rule."""

from __future__ import annotations

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket

_FIN = 0x01
_SYN = 0x02
_PSH = 0x08
_ACK = 0x10
_URG = 0x20
_ECE = 0x40
_CWR = 0x80


def _detect_scan_flag_alert(
    pkt: ParsedPacket,
    classic: int,
    ctx: dict[str, object],
) -> Alert | None:
    """Detect NULL, XMAS, or FIN-only stealth TCP scan signatures."""
    if classic == 0:
        return Alert(
            timestamp=pkt.timestamp,
            type=AlertType.SCAN_NULL,
            severity=Severity.MEDIUM,
            src_ip=pkt.ip_src,
            dst_ip=pkt.ip_dst,
            detail=f"TCP NULL scan packet (no flags set) -> port {pkt.dst_port}",
            raw_context=ctx,
        )
    if (classic & (_FIN | _PSH | _URG)) == (_FIN | _PSH | _URG) and not (classic & _ACK):
        return Alert(
            timestamp=pkt.timestamp,
            type=AlertType.SCAN_XMAS,
            severity=Severity.HIGH,
            src_ip=pkt.ip_src,
            dst_ip=pkt.ip_dst,
            detail=f"TCP XMAS scan packet (FIN+PSH+URG) -> port {pkt.dst_port}",
            raw_context=ctx,
        )
    if classic == _FIN:
        return Alert(
            timestamp=pkt.timestamp,
            type=AlertType.SCAN_FIN,
            severity=Severity.MEDIUM,
            src_ip=pkt.ip_src,
            dst_ip=pkt.ip_dst,
            detail=f"TCP FIN-only scan packet -> port {pkt.dst_port}",
            raw_context=ctx,
        )
    return None


class FlagRule:
    """Detects malformed or scan-indicative TCP flag combinations."""

    def __init__(
        self,
        *,
        check_reserved_bits: bool = True,
        check_half_ecn: bool = True,
    ) -> None:
        """Configure reserved-bit and malformed-ECN checks."""
        self.check_reserved_bits = check_reserved_bits
        self.check_half_ecn = check_half_ecn

    def evaluate(self, pkt: ParsedPacket) -> list[Alert]:
        """Inspect TCP flags and reserved bits on a ParsedPacket."""
        if pkt.transport_proto != "TCP" or pkt.tcp_flags is None:
            return []

        alerts: list[Alert] = []
        classic = pkt.tcp_flags & 0x3F
        ctx = {
            "tcp_flags": pkt.tcp_flags,
            "tcp_flag_names": pkt.tcp_flag_names,
            "tcp_reserved": pkt.tcp_reserved,
            "dst_port": pkt.dst_port,
        }

        scan_alert = _detect_scan_flag_alert(pkt, classic, ctx)
        if scan_alert is not None:
            alerts.append(scan_alert)

        if (classic & (_SYN | _FIN)) == (_SYN | _FIN):
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.SYN_FIN_ILLEGAL,
                    severity=Severity.HIGH,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"Illegal TCP SYN+FIN combination -> port {pkt.dst_port}",
                    raw_context=ctx,
                )
            )

        is_half_ecn_syn = (
            self.check_half_ecn
            and bool(classic & _SYN)
            and not bool(classic & _ACK)
            and (pkt.tcp_flags & (_ECE | _CWR)) == _ECE
        )
        if (self.check_reserved_bits and pkt.tcp_reserved != 0) or is_half_ecn_syn:
            reason = (
                f"Non-zero TCP reserved bits ({pkt.tcp_reserved:#x}) set"
                if pkt.tcp_reserved != 0
                else "Malformed ECN SYN (ECE set without CWR)"
            )
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.RESERVED_FLAG,
                    severity=Severity.MEDIUM,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=reason,
                    raw_context=ctx,
                )
            )

        return alerts
