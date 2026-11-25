"""Stateful sliding-window passive SYN-flood and port-sweep detector."""

from __future__ import annotations

import threading
from collections import defaultdict, deque

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket

_SYN = 0x02
_ACK = 0x10


class ScanDetector:
    """Detects high-volume SYN-without-ACK bursts and multi-port sweeps passively."""

    def __init__(
        self,
        *,
        window_seconds: float = 10.0,
        syn_threshold: int = 20,
        port_threshold: int = 15,
    ) -> None:
        """Initialize sliding-window scan thresholds."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if syn_threshold < 1 or port_threshold < 1:
            raise ValueError("syn_threshold and port_threshold must be >= 1")

        self.window_seconds = window_seconds
        self.syn_threshold = syn_threshold
        self.port_threshold = port_threshold
        self._lock = threading.Lock()
        self._syn_windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._port_windows: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)

    def evaluate(self, pkt: ParsedPacket) -> list[Alert]:
        """Update sliding windows for the packet source and emit scan alerts if crossed."""
        if pkt.ip_src is None or pkt.ip_dst is None:
            return []
        if pkt.transport_proto not in ("TCP", "UDP") or pkt.dst_port is None:
            return []

        now = pkt.timestamp
        cutoff = now - self.window_seconds
        alerts: list[Alert] = []

        with self._lock:
            is_tcp_syn_only = (
                pkt.transport_proto == "TCP"
                and pkt.tcp_flags is not None
                and (pkt.tcp_flags & _SYN)
                and not (pkt.tcp_flags & _ACK)
            )

            if is_tcp_syn_only:
                syn_key = (pkt.ip_src, pkt.ip_dst)
                syn_dq = self._syn_windows[syn_key]
                syn_dq.append(now)
                while syn_dq and syn_dq[0] < cutoff:
                    syn_dq.popleft()
                if len(syn_dq) > self.syn_threshold:
                    alerts.append(
                        Alert(
                            timestamp=now,
                            type=AlertType.SYN_FLOOD,
                            severity=Severity.HIGH,
                            src_ip=pkt.ip_src,
                            dst_ip=pkt.ip_dst,
                            detail=(
                                f"High SYN-without-ACK rate from {pkt.ip_src} to {pkt.ip_dst}: "
                                f"{len(syn_dq)} SYNs in {self.window_seconds:.0f}s"
                            ),
                            raw_context={
                                "syn_count": len(syn_dq),
                                "window_seconds": self.window_seconds,
                            },
                        )
                    )

            # Track unique destination ports touched by src_ip for TCP SYNs or UDP datagrams.
            track_port = is_tcp_syn_only or pkt.transport_proto == "UDP"
            if track_port:
                port_key = (pkt.ip_src, pkt.transport_proto)
                port_dq = self._port_windows[port_key]
                port_dq.append((now, pkt.dst_port))
                while port_dq and port_dq[0][0] < cutoff:
                    port_dq.popleft()

                unique_ports = {port for _, port in port_dq}
                if len(unique_ports) > self.port_threshold:
                    alerts.append(
                        Alert(
                            timestamp=now,
                            type=AlertType.PORT_SWEEP,
                            severity=Severity.HIGH,
                            src_ip=pkt.ip_src,
                            dst_ip=pkt.ip_dst,
                            detail=(
                                f"{pkt.transport_proto} port sweep from {pkt.ip_src}: "
                                f"{len(unique_ports)} distinct ports in {self.window_seconds:.0f}s"
                            ),
                            raw_context={
                                "protocol": pkt.transport_proto,
                                "unique_port_count": len(unique_ports),
                                "window_seconds": self.window_seconds,
                            },
                        )
                    )

        return alerts
