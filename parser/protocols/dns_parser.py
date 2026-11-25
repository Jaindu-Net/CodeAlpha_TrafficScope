"""Wire-format DNS query and response parser (UDP and TCP)."""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

_RECORD_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def _read_qname(data: bytes, offset: int) -> tuple[str, int] | None:
    """Decode a DNS domain name supporting RFC 1035 compression pointers."""
    labels: list[str] = []
    pos = offset
    next_offset: int | None = None
    visited_pointers: set[int] = set()

    while pos < len(data):
        length = data[pos]
        if length == 0:
            if next_offset is None:
                next_offset = pos + 1
            return ".".join(labels) if labels else ".", next_offset

        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                return None
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if ptr >= len(data) or ptr in visited_pointers:
                return None
            visited_pointers.add(ptr)
            if next_offset is None:
                next_offset = pos + 2
            pos = ptr
            continue

        if length & 0xC0:
            return None

        end = pos + 1 + length
        if end > len(data):
            return None
        labels.append(data[pos + 1:end].decode("ascii", errors="replace"))
        pos = end

    return None


def _parse_rdata(data: bytes, rdata_offset: int, rdlength: int, qtype: int) -> str:
    """Format DNS answer RDATA based on record type."""
    rdata_end = rdata_offset + rdlength
    if rdata_end > len(data):
        return ""
    raw_rdata = data[rdata_offset:rdata_end]

    if qtype == 1 and rdlength == 4:
        return str(ipaddress.IPv4Address(raw_rdata))
    if qtype == 28 and rdlength == 16:
        return str(ipaddress.IPv6Address(raw_rdata))
    if qtype in (2, 5, 12):
        decoded = _read_qname(data, rdata_offset)
        return decoded[0] if decoded is not None else raw_rdata.hex()
    if qtype == 15 and rdlength >= 3:
        pref = struct.unpack_from("!H", data, rdata_offset)[0]
        exchange = _read_qname(data, rdata_offset + 2)
        target = exchange[0] if exchange is not None else raw_rdata[2:].hex()
        return f"{pref} {target}"
    if qtype == 16:
        parts: list[str] = []
        idx = 0
        while idx < len(raw_rdata):
            txt_len = raw_rdata[idx]
            idx += 1
            parts.append(raw_rdata[idx:idx + txt_len].decode("utf-8", errors="replace"))
            idx += txt_len
        return "".join(parts)
    return raw_rdata.hex()


def parse_dns(payload: bytes, *, is_tcp: bool = False) -> dict[str, Any] | None:
    """Parse a DNS packet from raw UDP or TCP payload bytes."""
    data = payload
    if is_tcp:
        if len(data) < 2:
            return None
        msg_len = struct.unpack_from("!H", data, 0)[0]
        if len(data) < 2 + msg_len:
            return None
        data = data[2:2 + msg_len]

    if len(data) < 12:
        return None

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    is_response = bool((flags >> 15) & 0x01)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F

    # Reject garbage payloads claiming absurd counts relative to packet size.
    if qdcount > 32 or ancount > 128:
        return None

    offset = 12
    questions: list[dict[str, Any]] = []
    for _ in range(qdcount):
        name_res = _read_qname(data, offset)
        if name_res is None:
            return None
        qname, offset = name_res
        if offset + 4 > len(data):
            return None
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append(
            {
                "name": qname,
                "qtype": _RECORD_TYPES.get(qtype, str(qtype)),
                "qclass": qclass,
            }
        )

    answers: list[dict[str, Any]] = []
    response_ips: list[str] = []
    for _ in range(ancount):
        name_res = _read_qname(data, offset)
        if name_res is None:
            break
        rname, offset = name_res
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata_str = _parse_rdata(data, offset, rdlength, rtype)
        offset += rdlength

        type_name = _RECORD_TYPES.get(rtype, str(rtype))
        answers.append(
            {
                "name": rname,
                "type": type_name,
                "class": rclass,
                "ttl": ttl,
                "rdata": rdata_str,
            }
        )
        if rtype in (1, 28) and rdata_str:
            response_ips.append(rdata_str)

    return {
        "transaction_id": tx_id,
        "is_response": is_response,
        "opcode": opcode,
        "rcode": rcode,
        "questions": questions,
        "answers": answers,
        "response_ips": response_ips,
        "authority_count": nscount,
        "additional_count": arcount,
    }
