"""Tests for DashboardState telemetry, widgets, and Rich exit report."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from analyzer import AnomalyDetector
from dashboard import DashboardState, TrafficScopeApp, print_exit_report, print_followed_streams
from dashboard.widgets.anomaly_feed import AnomalyFeed
from dashboard.widgets.entropy_panel import EntropyPanel, _entropy_heat_bar
from dashboard.widgets.protocol_table import ProtocolTable
from dashboard.widgets.top_talkers import TopTalkers, format_bytes
from fingerprint import Fingerprinter
from parser import PacketParser
from profiler import FlowTracker
from tests.conftest import make_http_request_pkt, make_tcp_syn, make_xmas_scan_pkt


def test_dashboard_state_and_exit_report_rendering() -> None:
    parser = PacketParser()
    tracker = FlowTracker()
    fp = Fingerprinter()
    detector = AnomalyDetector(cooldown_seconds=0.0)
    state = DashboardState("MockNIC", flow_tracker=tracker, fingerprinter=fp)

    for raw in (make_tcp_syn(), make_http_request_pkt(), make_xmas_scan_pkt()):
        parsed = parser.parse(raw)
        tracker.update(parsed)
        fp.fingerprint(parsed)
        alerts = detector.inspect(parsed)
        state.record_packet(parsed)
        state.record_alerts(alerts)

    state.update_drop_stats(dropped_packets=1, kernel_dropped=0)
    state.mark_complete()

    snap = state.snapshot()
    assert snap["total_packets"] == 3
    assert snap["dropped_packets"] == 1
    assert snap["total_anomalies"] >= 1
    assert len(snap["top_hosts"]) >= 2

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    print_exit_report(snap, console=console)
    print_followed_streams(
        [(("192.168.1.10", 52000, "93.184.216.34", 80, "TCP"), "[→ CLIENT]\nGET / HTTP/1.1")],
        console=console,
    )
    rendered = buf.getvalue()
    assert "TrafficScope Session Summary" in rendered
    assert "Protocol Breakdown" in rendered
    assert "Top Talkers" in rendered
    assert "SCAN_XMAS" in rendered
    assert "Windows 10/11" in rendered
    assert "Follow TCP Stream" in rendered


def test_dashboard_widgets_and_app_init_synchronously() -> None:
    state = DashboardState("MockNIC")
    app = TrafficScopeApp(state, refresh_interval=0.5)
    assert app.TITLE == "TrafficScope"

    assert format_bytes(512) == "512 B"
    assert format_bytes(2048) == "2.0 KB"
    assert "[green]" in _entropy_heat_bar(2.0)
    assert "[yellow]" in _entropy_heat_bar(4.5)
    assert "[red]" in _entropy_heat_bar(7.8)

    proto_table = ProtocolTable()
    assert isinstance(proto_table, ProtocolTable)

    talkers = TopTalkers()
    assert isinstance(talkers, TopTalkers)

    feed = AnomalyFeed()
    feed.on_mount()
    assert feed.auto_scroll is True

    panel = EntropyPanel()
    panel.update_data(
        [
            {
                "src_ip": "192.168.1.10",
                "src_port": 52000,
                "dst_ip": "93.184.216.34",
                "dst_port": 443,
                "protocol": "TLS",
                "mean_entropy": 7.9,
                "entropy_label": "likely encrypted",
            }
        ]
    )
