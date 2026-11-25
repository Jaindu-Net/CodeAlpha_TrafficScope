"""TCP flag anomaly and stealth scan signature rule."""

from __future__ import annotations

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket

_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_PSH = 0x08
_ACK = 0x10
_URG = 0x20


class FlagRule:
    """Detects malformed or scan-indicative TCP flag combinations."""

    def __init__(self, *, check_reserved_bits: bool = True) -> None:
        """Configure whether non-zero TCP reserved bits trigger alerts."""
        self.check_reserved_bits = check_reserved_bits

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

        if classic == 0:
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.SCAN_NULL,
                    severity=Severity.MEDIUM,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"TCP NULL scan packet (no flags set) -> port {pkt.dst_port}",
                    raw_context=ctx,
                )
            )
        elif (classic & (_FIN | _PSH | _URG)) == (_FIN | _PSH | _URG) and not (classic & _ACK):
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.SCAN_XMAS,
                    severity=Severity.HIGH,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"TCP XMAS scan packet (FIN+PSH+URG) -> port {pkt.dst_port}",
                    raw_context=ctx,
                )
            )
        elif classic == _FIN:
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.SCAN_FIN,
                    severity=Severity.MEDIUM,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"TCP FIN-only scan packet -> port {pkt.dst_port}",
                    raw_context=ctx,
                )
            )

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

        if self.check_reserved_bits and pkt.tcp_reserved != 0:
            alerts.append(
                Alert(
                    timestamp=pkt.timestamp,
                    type=AlertType.RESERVED_FLAG,
                    severity=Severity.MEDIUM,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    detail=f"Non-zero TCP reserved bits ({pkt.tcp_reserved:#x}) set",
                    raw_context=ctx,
                )
            )

        return alerts
