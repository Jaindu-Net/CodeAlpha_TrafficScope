"""Textual live TUI dashboard and thread-safe shared telemetry bridge."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header

from analyzer.alert import Alert, AlertType
from dashboard.widgets.anomaly_feed import AnomalyFeed
from dashboard.widgets.entropy_panel import EntropyPanel
from dashboard.widgets.protocol_table import ProtocolTable
from dashboard.widgets.top_talkers import TopTalkers
from fingerprint.fingerprinter import Fingerprinter
from parser.parsed_packet import ParsedPacket
from profiler.flow_tracker import FlowTracker


class DashboardState:
    """Thread-safe shared metrics bridge between worker threads and dashboard UI."""

    def __init__(
        self,
        source_label: str,
        *,
        flow_tracker: FlowTracker | None = None,
        fingerprinter: Fingerprinter | None = None,
    ) -> None:
        """Initialize shared counters and component references."""
        self.source_label = source_label
        self.flow_tracker = flow_tracker
        self.fingerprinter = fingerprinter

        self._lock = threading.Lock()
        self.start_time = time.monotonic()
        self.end_time: float | None = None
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped_packets = 0
        self.kernel_dropped: int | None = None
        self.protocol_counts: Counter[str] = Counter()
        self.dst_port_counts: Counter[int] = Counter()
        self.anomaly_counts: Counter[AlertType] = Counter()
        self.alerts: deque[Alert] = deque(maxlen=500)
        self._alert_seq = 0
        self._pps_timestamps: deque[float] = deque()
        self.peak_pps = 0.0
        self.capture_complete = False

    def record_packet(self, pkt: ParsedPacket) -> None:
        """Update packet, byte, protocol, port, and instantaneous PPS metrics."""
        now = time.monotonic()
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt.packet_len
            self.protocol_counts[pkt.effective_protocol] += 1
            if pkt.dst_port is not None:
                self.dst_port_counts[pkt.dst_port] += 1

            self._pps_timestamps.append(now)
            cutoff = now - 1.0
            while self._pps_timestamps and self._pps_timestamps[0] < cutoff:
                self._pps_timestamps.popleft()
            current_pps = float(len(self._pps_timestamps))
            if current_pps > self.peak_pps:
                self.peak_pps = current_pps

    def record_alerts(self, alerts: list[Alert]) -> None:
        """Append emitted anomaly alerts into the shared ring buffer."""
        if not alerts:
            return
        with self._lock:
            for alert in alerts:
                self.alerts.append(alert)
                self.anomaly_counts[alert.type] += 1
                self._alert_seq += 1

    def update_drop_stats(
        self,
        dropped_packets: int,
        kernel_dropped: int | None = None,
    ) -> None:
        """Update latest drop counters reported by CaptureEngine/OfflineReader."""
        with self._lock:
            self.dropped_packets = dropped_packets
            self.kernel_dropped = kernel_dropped

    def mark_complete(self) -> None:
        """Record capture/replay completion timestamp."""
        with self._lock:
            if self.end_time is None:
                self.end_time = time.monotonic()
            self.capture_complete = True

    def _core_snapshot_locked(self, now: float, since_alert_seq: int) -> dict[str, Any]:
        """Build core counters and delta alerts while holding self._lock."""
        end_ref = self.end_time if self.end_time is not None else now
        elapsed_s = max(0.0, end_ref - self.start_time)

        cutoff = now - 1.0
        while self._pps_timestamps and self._pps_timestamps[0] < cutoff:
            self._pps_timestamps.popleft()
        current_pps = float(len(self._pps_timestamps))
        avg_pps = self.total_packets / elapsed_s if elapsed_s > 0 else 0.0

        unseen_count = max(0, self._alert_seq - since_alert_seq)
        new_alerts = list(self.alerts)[-unseen_count:] if unseen_count > 0 else []

        return {
            "source_label": self.source_label,
            "elapsed_s": elapsed_s,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "dropped_packets": self.dropped_packets,
            "kernel_dropped": self.kernel_dropped,
            "current_pps": current_pps,
            "avg_pps": avg_pps,
            "peak_pps": max(self.peak_pps, avg_pps),
            "protocol_counts": dict(self.protocol_counts),
            "top_ports": self.dst_port_counts.most_common(10),
            "anomaly_counts": dict(self.anomaly_counts),
            "total_anomalies": sum(self.anomaly_counts.values()),
            "alert_seq": self._alert_seq,
            "new_alerts": new_alerts,
            "capture_complete": self.capture_complete,
        }

    def _collect_hosts(self) -> list[dict[str, Any]]:
        """Gather top host summaries enriched with passive OS fingerprints."""
        if self.flow_tracker is None:
            return []
        top_hosts = self.flow_tracker.get_host_summary(n=10)
        if self.fingerprinter is None:
            return top_hosts
        for host in top_hosts:
            host["os_guess"] = self.fingerprinter.get_os_guess(host["ip"])
        return top_hosts

    def _collect_entropy(self) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Summarize payload entropy distributions and top high-entropy flows."""
        summary = {"plaintext": 0, "compressed/mixed": 0, "likely encrypted": 0}
        if self.flow_tracker is None:
            return [], summary

        entropy_flows: list[dict[str, Any]] = []
        for rec in self.flow_tracker.get_top_entropy_flows(n=100):
            summary[rec.entropy_label] = summary.get(rec.entropy_label, 0) + 1
            if len(entropy_flows) < 10:
                entropy_flows.append(
                    {
                        "src_ip": rec.src_ip,
                        "src_port": rec.src_port,
                        "dst_ip": rec.dst_ip,
                        "dst_port": rec.dst_port,
                        "protocol": rec.protocol,
                        "mean_entropy": rec.mean_entropy,
                        "entropy_label": rec.entropy_label,
                    }
                )
        return entropy_flows, summary

    def snapshot(self, *, since_alert_seq: int = 0) -> dict[str, Any]:
        """Return a consistent telemetry snapshot for UI rendering or exit reporting."""
        now = time.monotonic()
        with self._lock:
            snap = self._core_snapshot_locked(now, since_alert_seq)

        entropy_flows, entropy_summary = self._collect_entropy()
        snap["top_hosts"] = self._collect_hosts()
        snap["entropy_flows"] = entropy_flows
        snap["entropy_summary"] = entropy_summary
        return snap


class TrafficScopeApp(App):
    """Live Textual terminal dashboard for TrafficScope."""

    TITLE = "TrafficScope"
    BINDINGS = [Binding("q", "quit_app", "Quit", priority=True)]

    CSS = """
    Screen {
        layout: vertical;
    }
    #top-row {
        height: 2fr;
    }
    #protocol-panel {
        width: 28;
        border: solid cyan;
    }
    #main-column {
        width: 1fr;
    }
    #talkers-panel {
        height: 1fr;
        border: solid green;
    }
    #entropy-panel {
        height: 1fr;
        border: solid magenta;
        padding: 0 1;
    }
    #anomaly-panel {
        height: 1fr;
        border: solid red;
    }
    """

    def __init__(
        self,
        state: DashboardState,
        *,
        stop_event: threading.Event | None = None,
        refresh_interval: float = 1.0,
    ) -> None:
        """Initialize the Textual dashboard application."""
        super().__init__()
        self._state = state
        self._stop_event = stop_event
        self._refresh_interval = refresh_interval
        self._seen_alert_seq = 0

    def compose(self) -> ComposeResult:
        """Mount header, tables, entropy heatmap, anomaly log, and footer."""
        yield Header(show_clock=True)
        with Horizontal(id="top-row"):
            yield ProtocolTable(id="protocol-panel")
            with Vertical(id="main-column"):
                yield TopTalkers(id="talkers-panel")
                yield EntropyPanel(id="entropy-panel")
        yield AnomalyFeed(id="anomaly-panel")
        yield Footer()

    def on_mount(self) -> None:
        """Start periodic UI refresh timer."""
        self.set_interval(self._refresh_interval, self._refresh_dashboard)
        self._refresh_dashboard()

    def _refresh_dashboard(self) -> None:
        """Poll DashboardState snapshot and refresh all widgets."""
        snap = self._state.snapshot(since_alert_seq=self._seen_alert_seq)
        self._seen_alert_seq = snap["alert_seq"]

        status = "COMPLETE (press q)" if snap["capture_complete"] else "LIVE"
        self.sub_title = (
            f"{snap['source_label']} | {status} | "
            f"{snap['elapsed_s']:.0f}s | {snap['current_pps']:.0f} pps | "
            f"pkts={snap['total_packets']:,} | drops={snap['dropped_packets']}"
        )

        self.query_one("#protocol-panel", ProtocolTable).update_data(snap["protocol_counts"])
        self.query_one("#talkers-panel", TopTalkers).update_data(snap["top_hosts"])
        self.query_one("#entropy-panel", EntropyPanel).update_data(snap["entropy_flows"])
        if snap["new_alerts"]:
            self.query_one("#anomaly-panel", AnomalyFeed).append_alerts(snap["new_alerts"])

    def action_quit_app(self) -> None:
        """Signal pipeline stop and exit Textual event loop."""
        if self._stop_event is not None:
            self._stop_event.set()
        self.exit()
