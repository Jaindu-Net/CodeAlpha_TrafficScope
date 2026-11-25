"""Unit tests for statistical profiling, flow tracking, and Shannon entropy."""

from __future__ import annotations

import os

import pytest

from parser import PacketParser
from profiler import FlowTracker, HostProfiler, classify_entropy, shannon_entropy
from tests.conftest import make_http_request_pkt, make_tcp_segment


def test_shannon_entropy_values_and_classification() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 512) == 0.0
    assert classify_entropy(0.0) == "plaintext"

    ascii_sample = (
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    ) * 4
    ascii_e = shannon_entropy(ascii_sample)
    assert 3.5 <= ascii_e <= 5.5
    assert classify_entropy(ascii_e) == "compressed/mixed"

    random_bytes = os.urandom(4096)
    rand_e = shannon_entropy(random_bytes)
    assert rand_e > 7.5
    assert classify_entropy(rand_e) == "likely encrypted"


def test_flow_tracker_updates_top_talkers_and_export() -> None:
    parser = PacketParser()
    tracker = FlowTracker(entropy_sample_interval=2)

    p1 = parser.parse(make_http_request_pkt(sport=51001, body=b"A" * 100))
    p2 = parser.parse(make_http_request_pkt(sport=51002, body=b"B" * 300))

    tracker.update(p1)
    tracker.update(p2)

    top = tracker.get_top_talkers(n=1)
    assert len(top) == 1
    assert top[0].src_port == 51002
    assert top[0].protocol == "HTTP"
    assert len(top[0].entropy_samples) == 1

    exported = tracker.export_flows()
    assert len(exported) == 2
    required = {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "start_time",
        "duration_s",
        "packet_count",
        "byte_count",
        "mean_entropy",
    }
    assert required.issubset(exported[0].keys())


def test_host_profiler_respects_learning_period_and_flags_spike() -> None:
    parser = PacketParser()
    profiler = HostProfiler(
        baseline_seconds=20.0,
        window_seconds=60,
        z_threshold=2.5,
        min_history_seconds=5,
    )

    # During baseline learning (< 20s): even a spike must NOT flag.
    for sec in range(10):
        pkt = parser.parse(
            make_tcp_segment(src="10.0.0.10", payload=b"hi", timestamp=1000.0 + sec)
        )
        assert profiler.update(pkt) is None

    spike_early = parser.parse(
        make_tcp_segment(src="10.0.0.10", payload=b"hi", timestamp=1010.0)
    )
    for _ in range(30):
        assert profiler.update(spike_early) is None

    # After 20s baseline learning completes, feed normal 1 pps traffic up to sec 25
    for sec in range(11, 26):
        pkt = parser.parse(
            make_tcp_segment(src="10.0.0.10", payload=b"hi", timestamp=1000.0 + sec)
        )
        assert profiler.update(pkt) is None

    # Now inject a massive traffic spike at sec 26 -> should flag with high z-score.
    flagged_event = None
    for idx in range(100):
        pkt = parser.parse(
            make_tcp_segment(
                src="10.0.0.10", payload=b"x" * 64, timestamp=1026.0 + idx * 0.001
            )
        )
        res = profiler.update(pkt)
        if res is not None:
            flagged_event = res

    assert flagged_event is not None
    assert flagged_event["flagged"] is True
    assert flagged_event["z_score"] == pytest.approx(flagged_event["z_score"])
    assert flagged_event["z_score"] > 2.5
