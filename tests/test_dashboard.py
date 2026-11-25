"""Tests for DashboardState telemetry aggregation and Rich exit report."""

from __future__ import annotations

import asyncio
from io import StringIO

from rich.console import Console

from analyzer import AnomalyDetector
from dashboard import DashboardState, TrafficScopeApp, print_exit_report
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
    rendered = buf.getvalue()
    assert "TrafficScope Session Summary" in rendered
    assert "Protocol Breakdown" in rendered
    assert "Top Talkers" in rendered
    assert "SCAN_XMAS" in rendered
    assert "Windows 10/11" in rendered


def test_textual_dashboard_mounts_and_refreshes_cleanly() -> None:
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

    async def _run() -> None:
        app = TrafficScopeApp(state, refresh_interval=0.1)
        async with app.run_test() as pilot:
            await pilot.pause(0.25)
            await pilot.press("q")

    asyncio.run(_run())
