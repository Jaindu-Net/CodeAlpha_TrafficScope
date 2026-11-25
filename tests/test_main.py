"""End-to-end CLI and pipeline integration tests (offline PCAP mode)."""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from scapy.utils import rdpcap, wrpcap

from main import build_arg_parser, main, run_session
from tests.conftest import (
    make_dns_query,
    make_http_request_pkt,
    make_http_response_pkt,
    make_tcp_syn,
    make_xmas_scan_pkt,
)


def _extract_top_level_imports(py_file: Path) -> set[str]:
    """Return top-level module names imported inside a Python source file."""
    imports: set[str] = set()
    tree = ast.parse(py_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return imports


def test_main_offline_read_and_export_roundtrip(tmp_path: Path) -> None:
    in_pcap = tmp_path / "input.pcap"
    out_pcap = tmp_path / "saved.pcap"
    pkts = [
        make_tcp_syn(),
        make_http_request_pkt(),
        make_http_response_pkt(),
        make_dns_query(),
        make_xmas_scan_pkt(),
    ]
    wrpcap(str(in_pcap), pkts)

    args = build_arg_parser().parse_args(
        ["--read", str(in_pcap), "--save", str(out_pcap), "--threads", "2"]
    )
    buf = StringIO()
    summary = run_session(args, console=Console(file=buf, force_terminal=False, width=100))

    assert summary["total_packets"] == 5
    assert summary["dropped_packets"] == 0
    assert summary["total_anomalies"] >= 1
    assert out_pcap.is_file()
    assert len(rdpcap(str(out_pcap))) == 5

    flows_json = tmp_path / "saved_flows.json"
    assert flows_json.is_file()
    flow_data = json.loads(flows_json.read_text(encoding="utf-8"))
    assert flow_data["_schema_version"] == "1.0"
    assert flow_data["flow_count"] >= 3


def test_main_list_interfaces_and_missing_file_exit_codes(tmp_path: Path) -> None:
    assert main(["--iface", "?"]) == 0
    assert main(["--read", str(tmp_path / "missing.pcap")]) == 1


def test_analyzer_module_has_zero_forbidden_imports() -> None:
    """Verify analyzer/ stays strictly decoupled from capture, reassembly, and dashboard."""
    forbidden = {"capture", "reassembly", "dashboard", "export"}
    for py_file in Path("analyzer").rglob("*.py"):
        found = _extract_top_level_imports(py_file)
        assert not (found & forbidden), f"{py_file}: forbidden imports {found & forbidden}"
