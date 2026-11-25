"""Link-layer (Ethernet / Loopback) dissection."""

from __future__ import annotations

from typing import Any

from scapy.layers.l2 import Ether, Loopback
from scapy.packet import Packet

_LOOPBACK_ETHERTYPES: dict[int, int] = {
    2: 0x0800,   # AF_INET -> IPv4
    24: 0x86DD,  # AF_INET6 (OpenBSD/Windows)
    28: 0x86DD,  # AF_INET6 (FreeBSD)
    30: 0x86DD,  # AF_INET6 (macOS)
}


def parse_ethernet(pkt: Packet) -> dict[str, Any]:
    """Extract link-layer MAC addresses and EtherType from a Scapy packet."""
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return {
            "eth_src": str(eth.src) if eth.src is not None else None,
            "eth_dst": str(eth.dst) if eth.dst is not None else None,
            "ethertype": int(eth.type) if eth.type is not None else None,
        }

    if pkt.haslayer(Loopback):
        loop = pkt[Loopback]
        family = int(loop.type) if loop.type is not None else None
        ethertype = _LOOPBACK_ETHERTYPES.get(family) if family is not None else None
        return {
            "eth_src": None,
            "eth_dst": None,
            "ethertype": ethertype,
        }

    return {}
