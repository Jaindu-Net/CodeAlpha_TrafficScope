"""Protocol dissection package for TrafficScope."""

from parser.packet_parser import PacketParser
from parser.parsed_packet import ParsedPacket

__all__ = ["PacketParser", "ParsedPacket"]
