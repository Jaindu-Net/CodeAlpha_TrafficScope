"""Unit tests for IP defragmentation and TCP stream reassembly."""

from __future__ import annotations

from parser import PacketParser
from reassembly import IPDefragmenter, StreamStore, TCPReassembler
from tests.conftest import (
    make_fragmented_ip_pkts,
    make_http_request_pkt,
    make_http_response_pkt,
    make_tcp_segment,
    make_tcp_syn,
)


def test_tcp_in_order_and_out_of_order_reassembly() -> None:
    parser = PacketParser()
    reassembler = TCPReassembler()

    src, dst, sport, dport = "192.168.1.10", "93.184.216.34", 50001, 80
    syn = parser.parse(make_tcp_syn(src=src, dst=dst, sport=sport, dport=dport, seq=100))
    syn_ack = parser.parse(
        make_tcp_segment(src=dst, dst=src, sport=dport, dport=sport, seq=500, ack=101, flags="SA")
    )
    ack = parser.parse(
        make_tcp_segment(src=src, dst=dst, sport=sport, dport=dport, seq=101, ack=501, flags="A")
    )

    seg1 = parser.parse(
        make_tcp_segment(
            src=src, dst=dst, sport=sport, dport=dport, seq=101, ack=501, payload=b"HELLO "
        )
    )
    seg2 = parser.parse(
        make_tcp_segment(
            src=src, dst=dst, sport=sport, dport=dport, seq=107, ack=501, payload=b"WORLD!"
        )
    )
    seg3 = parser.parse(
        make_tcp_segment(
            src=src, dst=dst, sport=sport, dport=dport, seq=113, ack=501, payload=b" BYE"
        )
    )

    reassembler.add_segment(syn)
    reassembler.add_segment(syn_ack)
    reassembler.add_segment(ack)

    # Deliver seg3 and seg2 BEFORE seg1 (out-of-order).
    reassembler.add_segment(seg3)
    reassembler.add_segment(seg2)
    assert reassembler.get_stream_data(syn.flow_key, direction="client") == b""

    state = reassembler.add_segment(seg1)
    assert state is not None
    assert state.state == "ESTABLISHED"
    assert reassembler.get_stream_data(syn.flow_key, direction="client") == b"HELLO WORLD! BYE"


def test_tcp_retransmissions_are_deduplicated() -> None:
    parser = PacketParser()
    reassembler = TCPReassembler()

    seg1 = parser.parse(make_tcp_segment(seq=10, flags="PA", payload=b"ABCD"))
    seg2_dup = parser.parse(make_tcp_segment(seq=10, flags="PA", payload=b"ABCD"))
    seg3_partial_overlap = parser.parse(make_tcp_segment(seq=12, flags="PA", payload=b"CDEF"))

    reassembler.add_segment(seg1)
    reassembler.add_segment(seg2_dup)
    state = reassembler.add_segment(seg3_partial_overlap)

    assert state is not None
    assert state.client_buffer.retransmissions >= 1
    assert reassembler.get_stream_data(seg1.flow_key, direction="client") == b"ABCDEF"


def test_tcp_follow_stream_and_http_exchange_reconstruction() -> None:
    parser = PacketParser()
    reassembler = TCPReassembler()

    req1 = parser.parse(
        make_tcp_segment(
            src="192.168.1.10",
            dst="93.184.216.34",
            sport=52000,
            dport=80,
            seq=1001,
            ack=2001,
            payload=b"GET /hello HTTP/1.1\r\nHost: ",
        )
    )
    req2 = parser.parse(
        make_tcp_segment(
            src="192.168.1.10",
            dst="93.184.216.34",
            sport=52000,
            dport=80,
            seq=1028,
            ack=2001,
            payload=b"example.com\r\n\r\n",
        )
    )
    resp = parser.parse(
        make_http_response_pkt(status_code=200, reason="OK", body=b"ok-body")
    )
    full_req_only = make_http_request_pkt()  # sanity check fixture doesn't collide
    assert full_req_only is not None

    reassembler.add_segment(req2)  # out of order
    reassembler.add_segment(req1)
    reassembler.add_segment(resp)

    conv = reassembler.follow_stream(req1.flow_key)
    assert "→ CLIENT" in conv
    assert "← SERVER" in conv
    assert "GET /hello HTTP/1.1" in conv
    assert "ok-body" in conv

    exchange = reassembler.get_http_exchange(req1.flow_key)
    assert exchange is not None
    assert exchange["request"]["method"] == "GET"
    assert exchange["request"]["host"] == "example.com"
    assert exchange["response"]["status_code"] == 200
    assert exchange["response"]["body"] == b"ok-body"

    all_exchanges = reassembler.get_all_http_exchanges()
    assert len(all_exchanges) == 1
    assert all_exchanges[0]["flow_key"] == req1.flow_key


def test_tcp_three_chunk_reverse_midstream_reassembly() -> None:
    parser = PacketParser()
    reassembler = TCPReassembler()

    s1 = parser.parse(make_tcp_segment(sport=53333, seq=100, payload=b"PART1-"))
    s2 = parser.parse(make_tcp_segment(sport=53333, seq=106, payload=b"PART2-"))
    s3 = parser.parse(make_tcp_segment(sport=53333, seq=112, payload=b"PART3"))

    # Deliver s3, then detached s1 (gap before s3), then s2 closing the gap.
    reassembler.add_segment(s3)
    reassembler.add_segment(s1)
    reassembler.add_segment(s2)

    assert reassembler.get_stream_data(s1.flow_key, direction="client") == b"PART1-PART2-PART3"


def test_tcp_stream_idle_expiry() -> None:
    parser = PacketParser()
    store = StreamStore(idle_timeout_seconds=10.0)
    reassembler = TCPReassembler(store=store)

    p1 = parser.parse(make_tcp_segment(seq=1, payload=b"early", timestamp=100.0))
    reassembler.add_segment(p1)
    assert store.count() == 1

    # Different flow arriving 20s later should prune the idle stream.
    p2 = parser.parse(make_tcp_segment(sport=55555, seq=1, payload=b"late", timestamp=120.0))
    reassembler.add_segment(p2)
    assert store.get(p1.flow_key) is None
    assert store.expired_count == 1


def test_ip_defragmentation_out_of_order_and_expiry() -> None:
    parser = PacketParser()
    defrag = IPDefragmenter(timeout_seconds=15.0, parser=parser)

    payload = b"0123456789ABCDEF" * 4
    frags = make_fragmented_ip_pkts(payload=payload, fragsize=24, ip_id=9001)
    assert len(frags) >= 3

    parsed_frags = [parser.parse(f) for f in frags]
    # Deliver in reverse order
    for frag in reversed(parsed_frags[1:]):
        assert defrag.add_fragment(frag) is None

    reassembled = defrag.add_fragment(parsed_frags[0])
    assert reassembled is not None
    assert reassembled.transport_proto == "ICMP"
    assert reassembled.payload_bytes == payload
    assert defrag.active_count == 0

    # Test stale fragment expiry
    stale_frags = make_fragmented_ip_pkts(payload=payload, fragsize=24, ip_id=9002)
    stale_frags[0].time = 100.0
    assert defrag.add_fragment(parser.parse(stale_frags[0])) is None
    assert defrag.active_count == 1
    assert defrag.prune_expired(120.0) == 1
    assert defrag.active_count == 0
