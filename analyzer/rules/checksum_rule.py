"""Checksum anomaly detection rule."""

from __future__ import annotations

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket


class ChecksumRule:
    """Flags packets with invalid IP or transport-layer checksums."""

    def evaluate(self, pkt: ParsedPacket) -> list[Alert]:
        """Inspect checksum validation flags on a ParsedPacket."""
        if pkt.checksum_valid is not False:
            return []

        failed_layers: list[str] = []
        if pkt.ip_checksum_valid is False:
            failed_layers.append("IPv4 header")
        if pkt.transport_checksum_valid is False:
            failed_layers.append(pkt.transport_proto or "transport")

        layer_desc = " and ".join(failed_layers) if failed_layers else "packet"
        return [
            Alert(
                timestamp=pkt.timestamp,
                type=AlertType.INVALID_CHECKSUM,
                severity=Severity.LOW,
                src_ip=pkt.ip_src,
                dst_ip=pkt.ip_dst,
                detail=f"Invalid {layer_desc} checksum detected",
                raw_context={
                    "ip_checksum_valid": pkt.ip_checksum_valid,
                    "transport_checksum_valid": pkt.transport_checksum_valid,
                    "transport_proto": pkt.transport_proto,
                    "src_port": pkt.src_port,
                    "dst_port": pkt.dst_port,
                },
            )
        ]
