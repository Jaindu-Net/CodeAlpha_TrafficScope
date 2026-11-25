"""Unit tests for the TrafficScope parser module."""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether, Loopback
from scapy.packet import Padding, Raw

from parser import PacketParser, ParsedPacket
from tests.conftest import (
    DEFAULT_DST_MAC,
    DEFAULT_SRC_MAC,
    make_dns_query,
    make_dns_response,
    make_http_request_pkt,
    make_http_response_pkt,
    make_ipv6_udp_pkt,
    make_tcp_syn,
    make_tls_client_hello_pkt,
)


def test_parse_tcp_syn_populates_all_fields() -> None:
    parser = PacketParser()
    pkt = make_tcp_syn(ttl=128, window=65535, seq=4242)
    parsed = parser.parse(pkt)

    assert isinstance(parsed, ParsedPacket)
    assert parsed.error is False
    assert parsed.eth_src == DEFAULT_SRC_MAC
    assert parsed.eth_dst == DEFAULT_DST_MAC
    assert parsed.ip_version == 4
    assert parsed.ip_src == "192.168.1.10"
    assert parsed.ip_dst == "93.184.216.34"
    assert parsed.ip_ttl == 128
    assert parsed.transport_proto == "TCP"
    assert parsed.src_port == 51515
    assert parsed.dst_port == 443
    assert parsed.tcp_window == 65535
    assert parsed.tcp_seq == 4242
    assert parsed.tcp_flag_names == ("SYN",)
    assert parsed.tcp_options[0] == ("MSS", 1460)
    assert parsed.checksum_valid is True
    assert parsed.flow_key == ("192.168.1.10", 51515, "93.184.216.34", 443, "TCP")


def test_parse_udp_and_icmp() -> None:
    parser = PacketParser()

    udp_pkt = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / UDP(sport=4000, dport=5000)
        / Raw(b"hello-udp")
    )
    parsed_udp = parser.parse(udp_pkt)
    assert parsed_udp.transport_proto == "UDP"
    assert parsed_udp.src_port == 4000
    assert parsed_udp.dst_port == 5000
    assert parsed_udp.payload_bytes == b"hello-udp"
    assert parsed_udp.checksum_valid is True

    icmp_pkt = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / ICMP(type=8, code=0)
        / Raw(b"ping")
    )
    parsed_icmp = parser.parse(icmp_pkt)
    assert parsed_icmp.transport_proto == "ICMP"
    assert parsed_icmp.icmp_type == 8
    assert parsed_icmp.icmp_code == 0
    assert parsed_icmp.payload_bytes == b"ping"
    assert parsed_icmp.checksum_valid is True


def test_parse_http_request_and_response() -> None:
    parser = PacketParser()

    req_pkt = make_http_request_pkt(
        method="POST", host="api.example.com", path="/login", body=b"a=1"
    )
    req = parser.parse(req_pkt)
    assert req.app_protocol == "HTTP"
    assert req.app_layer_data is not None
    assert req.app_layer_data["message_type"] == "request"
    assert req.app_layer_data["method"] == "POST"
    assert req.app_layer_data["host"] == "api.example.com"
    assert req.app_layer_data["path"] == "/login"
    assert req.app_layer_data["body"] == b"a=1"
    assert req.app_layer_data["complete"] is True

    resp_pkt = make_http_response_pkt(status_code=200, reason="OK", body=b"done")
    resp = parser.parse(resp_pkt)
    assert resp.app_protocol == "HTTP"
    assert resp.app_layer_data is not None
    assert resp.app_layer_data["message_type"] == "response"
    assert resp.app_layer_data["status_code"] == 200
    assert resp.app_layer_data["body"] == b"done"
    assert resp.app_layer_data["complete"] is True


def test_parse_dns_query_and_response() -> None:
    parser = PacketParser()

    q_parsed = parser.parse(make_dns_query(name="openai.com", qtype="A"))
    assert q_parsed.app_protocol == "DNS"
    assert q_parsed.app_layer_data is not None
    assert q_parsed.app_layer_data["is_response"] is False
    assert q_parsed.app_layer_data["questions"][0]["name"] == "openai.com"
    assert q_parsed.app_layer_data["questions"][0]["qtype"] == "A"

    r_parsed = parser.parse(make_dns_response(name="openai.com", answer_ip="1.2.3.4"))
    assert r_parsed.app_protocol == "DNS"
    assert r_parsed.app_layer_data is not None
    assert r_parsed.app_layer_data["is_response"] is True
    assert r_parsed.app_layer_data["response_ips"] == ["1.2.3.4"]
    assert r_parsed.app_layer_data["answers"][0]["ttl"] == 300


def test_parse_tls_client_hello_extracts_sni_and_alpn() -> None:
    parser = PacketParser()
    tls_pkt = make_tls_client_hello_pkt(sni="github.com")
    parsed = parser.parse(tls_pkt)

    assert parsed.app_protocol == "TLS"
    assert parsed.app_layer_data is not None
    assert parsed.app_layer_data["handshake_type"] == "ClientHello"
    assert parsed.app_layer_data["sni"] == "github.com"
    assert parsed.app_layer_data["alpn"] == ["h2", "http/1.1"]
    assert "0x1301" in parsed.app_layer_data["cipher_suites"]


def test_parse_ipv6_and_loopback_and_arp() -> None:
    parser = PacketParser()

    v6 = parser.parse(make_ipv6_udp_pkt())
    assert v6.ip_version == 6
    assert v6.ip_ttl == 64
    assert v6.transport_proto == "UDP"
    assert v6.payload_bytes == b"ipv6-test"

    loop_pkt = Loopback(type=2) / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=11, dport=22)
    loop_parsed = parser.parse(loop_pkt)
    assert loop_parsed.ethertype == 0x0800
    assert loop_parsed.ip_src == "127.0.0.1"

    arp_pkt = Ether(src=DEFAULT_SRC_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.1")
    arp_parsed = parser.parse(arp_pkt)
    assert arp_parsed.effective_protocol == "ARP"


def test_checksum_failure_detected_and_ethernet_padding_trimmed() -> None:
    parser = PacketParser()

    bad_ip = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", chksum=0xDEAD)
        / TCP(sport=100, dport=80, flags="S")
    )
    parsed_bad_ip = parser.parse(bad_ip)
    assert parsed_bad_ip.ip_checksum_valid is False
    assert parsed_bad_ip.checksum_valid is False

    bad_tcp = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=100, dport=80, flags="S", chksum=0xBEEF)
    )
    parsed_bad_tcp = parser.parse(bad_tcp)
    assert parsed_bad_tcp.ip_checksum_valid is True
    assert parsed_bad_tcp.transport_checksum_valid is False
    assert parsed_bad_tcp.checksum_valid is False

    # Short TCP ACK padded to Ethernet minimum frame size must report empty payload.
    padded_ack = Ether(
        bytes(
            Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=100, dport=80, flags="A")
            / Padding(b"\x00" * 10)
        )
    )
    parsed_ack = parser.parse(padded_ack)
    assert parsed_ack.payload_bytes == b""
    assert parsed_ack.checksum_valid is True


def test_malformed_packet_returns_error_without_raising() -> None:
    parser = PacketParser()

    class BrokenPacket:
        time = 1234.5

        def __bytes__(self) -> bytes:
            raise ValueError("corrupted frame")

    parsed = parser.parse(BrokenPacket())  # type: ignore[arg-type]
    assert parsed.error is True
    assert parsed.error_message is not None
