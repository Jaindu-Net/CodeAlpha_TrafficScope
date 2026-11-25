"""Stateful sliding-window passive SYN-flood and port-sweep detector."""

from __future__ import annotations

import threading
from collections import defaultdict, deque

from analyzer.alert import Alert, AlertType, Severity
from parser.parsed_packet import ParsedPacket

_SYN = 0x02
_ACK = 0x10


def _prune_timestamps(dq: deque[float], cutoff: float) -> None:
    """Drop timestamps older than cutoff from the left of a deque."""
    while dq and dq[0] < cutoff:
        dq.popleft()


def _prune_port_events(dq: deque[tuple[float, int]], cutoff: float) -> None:
    """Drop (timestamp, port) tuples older than cutoff from the left of a deque."""
    while dq and dq[0][0] < cutoff:
        dq.popleft()


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

    def _check_syn_flood_locked(self, pkt: ParsedPacket, cutoff: float) -> Alert | None:
        """Update per-pair SYN window and emit SYN_FLOOD alert when threshold is crossed."""
        assert pkt.ip_src is not None and pkt.ip_dst is not None
        syn_dq = self._syn_windows[(pkt.ip_src, pkt.ip_dst)]
        syn_dq.append(pkt.timestamp)
        _prune_timestamps(syn_dq, cutoff)
        if len(syn_dq) <= self.syn_threshold:
            return None

        return Alert(
            timestamp=pkt.timestamp,
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

    def _check_port_sweep_locked(self, pkt: ParsedPacket, cutoff: float) -> Alert | None:
        """Update per-source unique port window and emit PORT_SWEEP alert when crossed."""
        assert pkt.ip_src is not None and pkt.transport_proto is not None
        assert pkt.dst_port is not None
        port_dq = self._port_windows[(pkt.ip_src, pkt.transport_proto)]
        port_dq.append((pkt.timestamp, pkt.dst_port))
        _prune_port_events(port_dq, cutoff)

        unique_ports = {port for _, port in port_dq}
        if len(unique_ports) <= self.port_threshold:
            return None

        return Alert(
            timestamp=pkt.timestamp,
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

    def evaluate(self, pkt: ParsedPacket) -> list[Alert]:
        """Update sliding windows for the packet source and emit scan alerts if crossed."""
        if pkt.ip_src is None or pkt.ip_dst is None or pkt.dst_port is None:
            return []
        if pkt.transport_proto not in ("TCP", "UDP"):
            return []

        is_tcp_syn_only = (
            pkt.transport_proto == "TCP"
            and pkt.tcp_flags is not None
            and bool(pkt.tcp_flags & _SYN)
            and not bool(pkt.tcp_flags & _ACK)
        )
        if not is_tcp_syn_only and pkt.transport_proto != "UDP":
            return []

        cutoff = pkt.timestamp - self.window_seconds
        alerts: list[Alert] = []
        with self._lock:
            if is_tcp_syn_only:
                syn_alert = self._check_syn_flood_locked(pkt, cutoff)
                if syn_alert is not None:
                    alerts.append(syn_alert)
            sweep_alert = self._check_port_sweep_locked(pkt, cutoff)
            if sweep_alert is not None:
                alerts.append(sweep_alert)
        return alerts
