"""End-to-end tests for TrafficScope Cyber SOC Web Dashboard and API."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from scapy.sendrecv import IterSocket
from scapy.utils import rdpcap, wrpcap

from capture import InterfaceInfo
from dashboard.web import CaptureSessionManager, create_app
from main import build_arg_parser, run_session
from pipeline import start_pipeline
from tests.conftest import (
    make_dns_query,
    make_http_request_pkt,
    make_http_response_pkt,
    make_tcp_syn,
    make_tls_client_hello_pkt,
    make_xmas_scan_pkt,
)


def _sample_soc_packets() -> list[Any]:
    """Create a rich packet sequence exercising all telemetry views and stream sanitization."""
    return [
        make_tcp_syn(src="192.168.1.10", dst="93.184.216.34"),
        make_http_request_pkt(
            src="192.168.1.10",
            dst="93.184.216.34",
            sport=52000,
            dport=80,
            seq=1001,
            ack=2001,
            path="/soc-check",
        ),
        make_http_response_pkt(
            src="93.184.216.34",
            dst="192.168.1.10",
            sport=80,
            dport=52000,
            seq=2001,
            ack=1090,
            body=b"ok-\x1b[31mcolored\x1b[0m-payload",
        ),
        make_dns_query(name="threat-feed.example.org"),
        make_tls_client_hello_pkt(sni="soc.example.org"),
        make_xmas_scan_pkt(src="10.0.0.99", dst="192.168.1.10"),
    ]


def _make_test_manager(
    *,
    tmp_path: Path | None = None,
    elevated: bool = False,
    opened_socket: Any | None = None,
) -> CaptureSessionManager:
    """Build an isolated CaptureSessionManager with deterministic NIC stubs."""
    fake_nic = InterfaceInfo(
        index=1,
        name="MockNIC",
        description="Intel Test Ethernet Adapter",
        ip="192.168.1.10",
        mac="00:11:22:33:44:55",
        network_name=r"\Device\NPF_{MOCK}",
    )

    def _starter(config: Any, *, console: Any = None, opened_socket: Any = None) -> Any:
        effective_socket = opened_socket if opened_socket is not None else default_socket
        return start_pipeline(config, console=console, opened_socket=effective_socket)

    default_socket = opened_socket
    extra: dict[str, Any] = {}
    if tmp_path is not None:
        extra["pcap_dir"] = tmp_path / "out_pcap"
        extra["json_dir"] = tmp_path / "out_json"
    return CaptureSessionManager(
        pipeline_starter=_starter,
        elevation_checker=lambda: elevated,
        interface_lister=lambda: [fake_nic],
        interface_selector=lambda *_args, **_kwargs: fake_nic,
        **extra,
    )


def _wait_telemetry_complete(client: Any, timeout_s: float = 4.0) -> dict[str, Any]:
    """Poll /api/telemetry until capture_complete turns True."""
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = client.get("/api/telemetry")
        assert resp.status_code == 200
        last = resp.get_json()
        if last.get("capture_complete") and not last.get("running"):
            return last
        time.sleep(0.05)
    return last


def test_web_index_headers_and_interfaces() -> None:
    manager = _make_test_manager(elevated=False)
    try:
        app = create_app(manager)
        client = app.test_client()

        home = client.get("/")
        assert home.status_code == 200
        assert b"TrafficScope" in home.data
        assert home.headers["X-Content-Type-Options"] == "nosniff"
        assert home.headers["X-Frame-Options"] == "DENY"
        assert home.headers["Referrer-Policy"] == "no-referrer"
        assert "Content-Security-Policy" in home.headers

        ifaces = client.get("/api/interfaces")
        assert ifaces.status_code == 200
        iface_data = ifaces.get_json()
        assert iface_data["elevated"] is False
        assert iface_data["interfaces"][0]["name"] == "MockNIC"

        # Non-admin live capture must fail cleanly with 403
        blocked = client.post("/api/capture/start", json={"iface": "MockNIC"})
        assert blocked.status_code == 403
        assert "Administrator" in blocked.get_json()["error"]
    finally:
        manager.close()


def test_web_replay_upload_telemetry_streams_and_exports(tmp_path: Path) -> None:
    pcap_path = tmp_path / "soc_sample.pcap"
    wrpcap(str(pcap_path), _sample_soc_packets())

    manager = _make_test_manager(tmp_path=tmp_path, elevated=False)
    try:
        app = create_app(manager)
        client = app.test_client()

        with pcap_path.open("rb") as handle:
            replay_resp = client.post(
                "/api/replay",
                data={
                    "file": (handle, "soc_sample.pcap"),
                    "threads": "2",
                    "baseline_seconds": "60",
                },
                content_type="multipart/form-data",
            )
        assert replay_resp.status_code == 200
        assert replay_resp.get_json()["mode"] == "replay"

        telemetry = _wait_telemetry_complete(client)
        assert telemetry["total_packets"] == 6
        assert telemetry["total_anomalies"] >= 1
        assert telemetry["alerts_serialized"][0]["type"] == "SCAN_XMAS"
        assert telemetry["http_exchange_count"] == 1
        assert any("threat-feed.example.org" in d["query"] for d in telemetry["dns_records"])
        assert any(s["sni"] == "soc.example.org" for s in telemetry["tls_sessions"])
        assert any(p["protocol"] == "HTTP" for p in telemetry["recent_packets"])
        assert len(telemetry["timeline"]) >= 1
        assert "pps" in telemetry["timeline"][0]
        assert "has_pcap_export" in telemetry

        # Verify raw ANSI escape characters were stripped from HTTP body preview
        http_ex = telemetry["http_exchanges"][0]
        assert "\x1b" not in http_ex["response"]["body_preview"]
        assert "colored" in http_ex["response"]["body_preview"]

        flows_resp = client.get("/api/flows?limit=50")
        assert flows_resp.status_code == 200
        flows = flows_resp.get_json()["flows"]
        assert len(flows) >= 3
        stream_flow = next(
            f for f in flows if f["has_stream"] and 80 in (f["src_port"], f["dst_port"])
        )
        assert "Windows 10/11" in (stream_flow["src_os"], stream_flow["dst_os"])

        stream_resp = client.get(f"/api/streams/{stream_flow['flow_id']}")
        assert stream_resp.status_code == 200
        stream_data = stream_resp.get_json()
        assert "/soc-check" in stream_data["transcript"]
        assert "\x1b" not in stream_data["transcript"]
        assert stream_data["http_exchange"]["response"]["status_code"] == 200

        export_pcap = client.get("/api/export/pcap")
        assert export_pcap.status_code == 200
        exported_file = tmp_path / "downloaded.pcap"
        exported_file.write_bytes(export_pcap.data)
        assert len(rdpcap(str(exported_file))) == 6

        export_flows = client.get("/api/export/flows")
        assert export_flows.status_code == 200
        flow_json = json.loads(export_flows.data.decode("utf-8"))
        assert flow_json["_schema_version"] == "1.0"
        assert flow_json["flow_count"] >= 3
    finally:
        manager.close()


def test_web_live_start_and_stop_with_iter_socket(tmp_path: Path) -> None:
    pkts = _sample_soc_packets()[:3]
    manager = _make_test_manager(
        tmp_path=tmp_path,
        elevated=True,
        opened_socket=IterSocket(pkts),
    )
    try:
        status = manager.start_live({"iface": "MockNIC", "threads": 1})
        assert status["mode"] == "live"

        app = create_app(manager)
        client = app.test_client()
        telemetry = _wait_telemetry_complete(client)
        assert telemetry["total_packets"] == 3

        stopped = client.post("/api/capture/stop")
        assert stopped.status_code == 200
        assert stopped.get_json()["running"] is False
        assert len(list((tmp_path / "out_pcap").glob("*.pcap"))) == 1
        assert len(list((tmp_path / "out_json").glob("*_flows.json"))) == 1
    finally:
        manager.close()


def test_web_error_handling_and_validation(tmp_path: Path) -> None:
    manager = _make_test_manager(tmp_path=tmp_path, elevated=True)
    try:
        app = create_app(manager)
        client = app.test_client()

        assert client.get("/api/export/pcap").status_code == 404
        assert client.get("/api/export/flows").status_code == 404
        assert client.get("/api/export/report").status_code == 404
        assert client.get("/api/export/csv?kind=alerts").status_code == 404
        assert client.get("/api/unknown-endpoint").status_code == 404
        assert client.get("/api/flows?limit=abc").status_code == 400
        assert client.get("/api/streams/bad-flow-id").status_code == 400
        missing_resp = client.post("/api/replay", json={"path": str(tmp_path / "missing.pcap")})
        assert missing_resp.status_code == 404

        bad_ext = tmp_path / "notes.txt"
        bad_ext.write_text("not a pcap", encoding="utf-8")
        with bad_ext.open("rb") as handle:
            bad_upload = client.post(
                "/api/replay",
                data={"file": (handle, "notes.txt")},
                content_type="multipart/form-data",
            )
        assert bad_upload.status_code == 400

        valid_pcap = tmp_path / "empty_ok.pcap"
        wrpcap(str(valid_pcap), _sample_soc_packets()[:1])
        bad_ports = client.post(
            "/api/replay",
            json={"path": str(valid_pcap), "http_ports": "not-a-port"},
        )
        assert bad_ports.status_code == 400
    finally:
        manager.close()


def test_cli_web_flags_dispatch(monkeypatch: Any) -> None:
    called: dict[str, Any] = {}

    def _fake_server(**kwargs: Any) -> None:
        called.update(kwargs)

    monkeypatch.setattr("main.run_web_server", _fake_server)
    args = build_arg_parser().parse_args(["--web", "--port", "5055", "--no-browser"])
    res = run_session(args)

    assert res == {"web_mode": True, "port": 5055}
    assert called["port"] == 5055
    assert called["open_browser"] is False


def test_web_export_report_json_and_csv_options(tmp_path: Path) -> None:
    pkts = _sample_soc_packets()
    pcap_path = tmp_path / "export_test.pcap"
    wrpcap(str(pcap_path), pkts)

    manager = _make_test_manager(tmp_path=tmp_path, elevated=False)
    try:
        app = create_app(manager)
        client = app.test_client()

        replay = client.post("/api/replay", json={"path": str(pcap_path), "threads": 1})
        assert replay.status_code == 200
        _wait_telemetry_complete(client)

        report_resp = client.get("/api/export/report")
        assert report_resp.status_code == 200
        report = json.loads(report_resp.data.decode("utf-8"))
        assert report["kpis"]["total_packets"] == 6
        assert len(report["alerts"]) >= 1
        assert len(report["flows"]) >= 3

        for kind, expected_header in (
            ("alerts", "time,severity,type,src_ip,dst_ip,detail"),
            ("flows", "src_ip,src_port,dst_ip,dst_port,protocol"),
            ("packets", "id,time,src_ip,src_port,dst_ip,dst_port,protocol,length,info"),
        ):
            csv_resp = client.get(f"/api/export/csv?kind={kind}")
            assert csv_resp.status_code == 200
            assert "text/csv" in csv_resp.content_type
            text = csv_resp.data.decode("utf-8-sig")
            assert expected_header in text.splitlines()[0]
            assert len(text.splitlines()) >= 2

        assert client.get("/api/export/csv?kind=unknown").status_code == 400
    finally:
        manager.close()


def test_csv_formula_injection_escaping() -> None:
    from dashboard.web.controller import _safe_csv_cell

    assert _safe_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert _safe_csv_cell("+1+1") == "'+1+1"
    assert _safe_csv_cell("-2+3") == "'-2+3"
    assert _safe_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert _safe_csv_cell("normal\nhost") == "normal host"
