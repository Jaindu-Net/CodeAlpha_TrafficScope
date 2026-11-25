"""Integration tests for PCAP and NetFlow-style JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from scapy.utils import rdpcap

from export import FlowExporter, PcapWriter
from parser import PacketParser
from profiler import FlowTracker
from tests.conftest import make_dns_query, make_http_request_pkt, make_tcp_syn


def test_pcap_writer_writes_valid_wireshark_readable_pcap(tmp_path: Path) -> None:
    out_pcap = tmp_path / "nested" / "test_out.pcap"
    pkts = [
        make_tcp_syn(),
        make_http_request_pkt(),
        make_dns_query(),
    ]

    with PcapWriter(out_pcap) as writer:
        for pkt in pkts:
            writer.write(pkt)

    assert writer.written_count == 3
    assert out_pcap.is_file()

    # Standard libpcap magic bytes check (little-endian 0xa1b2c3d4 or big-endian)
    magic = out_pcap.read_bytes()[:4]
    assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")

    loaded = rdpcap(str(out_pcap))
    assert len(loaded) == 3


def test_flow_exporter_writes_valid_versioned_json(tmp_path: Path) -> None:
    parser = PacketParser()
    tracker = FlowTracker()
    for pkt in (make_http_request_pkt(), make_dns_query()):
        tracker.update(parser.parse(pkt))

    out_json = tmp_path / "flows.json"
    exporter = FlowExporter(tracker.export_flows())
    exporter.export_json(out_json)

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["_schema_version"] == "1.0"
    assert data["flow_count"] == 2
    assert len(data["flows"]) == 2
    assert {"src_ip", "dst_ip", "protocol", "packet_count", "byte_count", "mean_entropy"}.issubset(
        data["flows"][0].keys()
    )
