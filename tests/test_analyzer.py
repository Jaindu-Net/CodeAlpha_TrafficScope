"""Unit tests for the decoupled TrafficScope analyzer module."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from analyzer import AlertType, AnomalyDetector, Severity
from parser import PacketParser
from tests.conftest import (
    DEFAULT_DST_MAC,
    DEFAULT_SRC_MAC,
    make_http_request_pkt,
    make_tcp_segment,
    make_tcp_syn,
    make_xmas_scan_pkt,
)


def test_checksum_rule_triggers_on_bad_checksum() -> None:
    parser = PacketParser()
    detector = AnomalyDetector(cooldown_seconds=0.0)

    bad_pkt = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", chksum=0xDEAD)
        / TCP(sport=1234, dport=80, flags="S")
    )
    alerts = detector.inspect(parser.parse(bad_pkt))
    assert any(a.type == AlertType.INVALID_CHECKSUM for a in alerts)


def test_ttl_rule_triggers_on_zero_and_skips_multicast() -> None:
    parser = PacketParser()
    detector = AnomalyDetector(cooldown_seconds=0.0)

    ttl_zero = parser.parse(make_tcp_syn(ttl=0))
    alerts = detector.inspect(ttl_zero)
    assert any(a.type == AlertType.TTL_ANOMALY and a.severity == Severity.HIGH for a in alerts)

    # LAN-local multicast with TTL=1 (e.g., mDNS) must NOT false-positive.
    mdns_pkt = parser.parse(make_tcp_segment(dst="224.0.0.251", ttl=1, dport=5353, flags=""))
    # Strip NULL flag by using UDP-like packet instead
    assert not any(a.type == AlertType.TTL_ANOMALY for a in detector.inspect(mdns_pkt))


def test_flag_rules_trigger_on_null_fin_xmas_synfin_and_reserved() -> None:
    parser = PacketParser()
    detector = AnomalyDetector(cooldown_seconds=0.0)

    null_alerts = detector.inspect(parser.parse(make_tcp_segment(flags="")))
    assert any(a.type == AlertType.SCAN_NULL for a in null_alerts)

    fin_alerts = detector.inspect(parser.parse(make_tcp_segment(flags="F")))
    assert any(a.type == AlertType.SCAN_FIN for a in fin_alerts)

    xmas_alerts = detector.inspect(parser.parse(make_xmas_scan_pkt()))
    assert any(a.type == AlertType.SCAN_XMAS and a.severity == Severity.HIGH for a in xmas_alerts)

    synfin_alerts = detector.inspect(parser.parse(make_tcp_segment(flags="SF")))
    assert any(a.type == AlertType.SYN_FIN_ILLEGAL for a in synfin_alerts)

    reserved_pkt = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.5", dst="10.0.0.6", ttl=64)
        / TCP(sport=1111, dport=80, flags="S", reserved=2)
    )
    res_alerts = detector.inspect(parser.parse(reserved_pkt))
    assert any(a.type == AlertType.RESERVED_FLAG for a in res_alerts)


def test_scan_detector_flags_syn_flood_and_port_sweep() -> None:
    parser = PacketParser()
    detector = AnomalyDetector(
        cooldown_seconds=60.0,
        window_seconds=10.0,
        syn_threshold=5,
        port_threshold=4,
    )

    emitted_types: set[AlertType] = set()
    for idx in range(7):
        pkt = make_tcp_syn(src="10.0.0.77", dst="192.168.1.10", sport=40000 + idx, dport=20 + idx)
        pkt.time = 1000.0 + idx * 0.2
        alerts = detector.inspect(parser.parse(pkt))
        emitted_types.update(a.type for a in alerts)

    assert AlertType.PORT_SWEEP in emitted_types
    assert AlertType.SYN_FLOOD in emitted_types
    # Cooldown suppresses flood repeats within 60s
    counts = detector.get_counts()
    assert counts[AlertType.SYN_FLOOD] == 1
    assert counts[AlertType.PORT_SWEEP] == 1


def test_normal_http_packet_triggers_no_anomalies() -> None:
    parser = PacketParser()
    detector = AnomalyDetector()

    parsed = parser.parse(make_http_request_pkt())
    assert detector.inspect(parsed) == []
