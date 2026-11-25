"""Shared synthetic Scapy packet factories for admin-free TrafficScope tests."""

from __future__ import annotations

import struct
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

DEFAULT_SRC_MAC = "00:11:22:33:44:55"
DEFAULT_DST_MAC = "66:77:88:99:aa:bb"


def make_tcp_syn(
    src: str = "192.168.1.10",
    dst: str = "93.184.216.34",
    sport: int = 51515,
    dport: int = 443,
    ttl: int = 128,
    window: int = 65535,
    options: list[tuple[str, Any]] | None = None,
    seq: int = 1000,
) -> Packet:
    """Build a synthetic IPv4/TCP SYN packet."""
    opts = options if options is not None else [
        ("MSS", 1460),
        ("NOP", None),
        ("WScale", 8),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b""),
    ]
    return (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src=src, dst=dst, ttl=ttl)
        / TCP(sport=sport, dport=dport, flags="S", window=window, seq=seq, options=opts)
    )


def make_tcp_segment(
    src: str = "192.168.1.10",
    dst: str = "93.184.216.34",
    sport: int = 50000,
    dport: int = 80,
    seq: int = 1,
    ack: int = 1,
    flags: str = "PA",
    payload: bytes = b"",
    window: int = 65535,
    ttl: int = 64,
    timestamp: float | None = None,
) -> Packet:
    """Build a synthetic IPv4/TCP segment with optional payload and timestamp."""
    pkt = (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src=src, dst=dst, ttl=ttl)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window)
    )
    if payload:
        pkt = pkt / Raw(payload)
    if timestamp is not None:
        pkt.time = timestamp
    return pkt


def make_http_request_pkt(
    method: str = "GET",
    host: str = "example.com",
    path: str = "/index.html",
    src: str = "192.168.1.10",
    dst: str = "93.184.216.34",
    sport: int = 52000,
    dport: int = 80,
    seq: int = 1001,
    ack: int = 2001,
    body: bytes = b"",
) -> Packet:
    """Build an Ethernet/IP/TCP packet carrying an HTTP/1.1 request."""
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: TrafficScope-Test/1.0\r\n"
    )
    if body:
        headers += f"Content-Length: {len(body)}\r\n"
    headers += "\r\n"
    payload = headers.encode("ascii") + body
    return make_tcp_segment(
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags="PA",
        payload=payload,
    )


def make_http_response_pkt(
    status_code: int = 200,
    reason: str = "OK",
    body: bytes = b"hello",
    src: str = "93.184.216.34",
    dst: str = "192.168.1.10",
    sport: int = 80,
    dport: int = 52000,
    seq: int = 2001,
    ack: int = 1050,
) -> Packet:
    """Build an Ethernet/IP/TCP packet carrying an HTTP/1.1 response."""
    raw = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body
    return make_tcp_segment(
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags="PA",
        payload=raw,
    )


def make_dns_query(
    name: str = "example.com",
    qtype: str = "A",
    src: str = "192.168.1.10",
    dst: str = "8.8.8.8",
    sport: int = 54000,
    tx_id: int = 0x1234,
) -> Packet:
    """Build a synthetic UDP DNS query packet."""
    return (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src=src, dst=dst, ttl=64)
        / UDP(sport=sport, dport=53)
        / DNS(id=tx_id, rd=1, qd=DNSQR(qname=name, qtype=qtype))
    )


def make_dns_response(
    name: str = "example.com",
    answer_ip: str = "93.184.216.34",
    src: str = "8.8.8.8",
    dst: str = "192.168.1.10",
    dport: int = 54000,
    tx_id: int = 0x1234,
) -> Packet:
    """Build a synthetic UDP DNS A-record response packet."""
    return (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IP(src=src, dst=dst, ttl=56)
        / UDP(sport=53, dport=dport)
        / DNS(
            id=tx_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=name, qtype="A"),
            an=DNSRR(rrname=name, type="A", ttl=300, rdata=answer_ip),
        )
    )


def make_tls_client_hello_bytes(
    sni: str = "example.com",
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
    cipher_suites: tuple[int, ...] = (0x1301, 0x1302, 0xC02F),
) -> bytes:
    """Build valid TLS ClientHello wire bytes containing SNI and ALPN extensions."""
    # SNI extension (0x0000)
    sni_bytes = sni.encode("utf-8")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_ext_data = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # ALPN extension (0x0010)
    alpn_items = b"".join(struct.pack("!B", len(p)) + p.encode("ascii") for p in alpn)
    alpn_ext_data = struct.pack("!H", len(alpn_items)) + alpn_items
    alpn_ext = struct.pack("!HH", 0x0010, len(alpn_ext_data)) + alpn_ext_data

    extensions = sni_ext + alpn_ext
    suites_bytes = b"".join(struct.pack("!H", cs) for cs in cipher_suites)

    hello_body = (
        struct.pack("!H", 0x0303)
        + (b"\x11" * 32)
        + b"\x00"  # session_id_len = 0
        + struct.pack("!H", len(suites_bytes))
        + suites_bytes
        + b"\x01\x00"  # compression methods: 1 method (null)
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def make_tls_client_hello_pkt(
    sni: str = "example.com",
    src: str = "192.168.1.10",
    dst: str = "93.184.216.34",
) -> Packet:
    """Build an Ethernet/IP/TCP packet carrying a TLS ClientHello."""
    return make_tcp_segment(
        src=src,
        dst=dst,
        sport=53000,
        dport=443,
        seq=1,
        ack=1,
        flags="PA",
        payload=make_tls_client_hello_bytes(sni=sni),
    )


def make_fragmented_ip_pkts(
    payload: bytes = b"A" * 48,
    src: str = "192.168.1.10",
    dst: str = "192.168.1.20",
    fragsize: int = 24,
    ip_id: int = 4242,
) -> list[Packet]:
    """Build fragmented IPv4 packets carrying an ICMP payload."""
    base_ip = IP(src=src, dst=dst, id=ip_id, ttl=64) / ICMP(type=8, code=0) / Raw(payload)
    frags = fragment(base_ip, fragsize=fragsize)
    return [Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / frag for frag in frags]


def make_xmas_scan_pkt(
    src: str = "10.0.0.99",
    dst: str = "192.168.1.10",
    dport: int = 22,
) -> Packet:
    """Build a synthetic TCP XMAS scan packet (FIN+PSH+URG)."""
    return make_tcp_segment(src=src, dst=dst, sport=44444, dport=dport, flags="FPU")


def make_ipv6_udp_pkt(
    src: str = "fe80::1",
    dst: str = "fe80::2",
    sport: int = 5000,
    dport: int = 9999,
    payload: bytes = b"ipv6-test",
) -> Packet:
    """Build a synthetic IPv6/UDP packet."""
    return (
        Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC)
        / IPv6(src=src, dst=dst, hlim=64)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )
