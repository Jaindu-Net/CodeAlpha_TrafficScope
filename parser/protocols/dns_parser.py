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


def _follow_pointer(
    data: bytes,
    pos: int,
    visited: set[int],
) -> tuple[int, int] | None:
    """Resolve a 2-byte RFC 1035 label compression pointer safely."""
    if pos + 1 >= len(data):
        return None
    ptr = ((data[pos] & 0x3F) << 8) | data[pos + 1]
    if ptr >= len(data) or ptr in visited:
        return None
    visited.add(ptr)
    return ptr, pos + 2


def _step_qname(
    data: bytes,
    pos: int,
    next_offset: int | None,
    visited: set[int],
    labels: list[str],
) -> tuple[bool, int, int | None]:
    """Process one DNS label or pointer step; returns (done, new_pos, next_offset)."""
    length = data[pos]
    if length == 0:
        final_next = next_offset if next_offset is not None else pos + 1
        return True, final_next, final_next

    if (length & 0xC0) == 0xC0:
        res = _follow_pointer(data, pos, visited)
        if res is None:
            return True, -1, None
        new_pos, jump_after = res
        return False, new_pos, (next_offset if next_offset is not None else jump_after)

    if (length & 0xC0) or (pos + 1 + length > len(data)):
        return True, -1, None

    labels.append(data[pos + 1:pos + 1 + length].decode("ascii", errors="replace"))
    return False, pos + 1 + length, next_offset


def _read_qname(data: bytes, offset: int) -> tuple[str, int] | None:
    """Decode a DNS domain name supporting RFC 1035 compression pointers."""
    labels: list[str] = []
    pos = offset
    next_offset: int | None = None
    visited: set[int] = set()

    while pos < len(data):
        done, pos, next_offset = _step_qname(data, pos, next_offset, visited, labels)
        if pos < 0:
            return None
        if done:
            return ("." if not labels else ".".join(labels)), pos

    return None


def _decode_txt_rdata(raw_rdata: bytes) -> str:
    """Concatenate length-prefixed strings inside a DNS TXT record."""
    parts: list[str] = []
    idx = 0
    while idx < len(raw_rdata):
        txt_len = raw_rdata[idx]
        idx += 1
        parts.append(raw_rdata[idx:idx + txt_len].decode("utf-8", errors="replace"))
        idx += txt_len
    return "".join(parts)


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
        return _decode_txt_rdata(raw_rdata)
    return raw_rdata.hex()


def _parse_questions(
    data: bytes,
    offset: int,
    qdcount: int,
) -> tuple[list[dict[str, Any]], int] | None:
    """Parse DNS question entries starting at offset."""
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
    return questions, offset


def _parse_answers(
    data: bytes,
    offset: int,
    ancount: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse DNS answer resource records starting at offset."""
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

        answers.append(
            {
                "name": rname,
                "type": _RECORD_TYPES.get(rtype, str(rtype)),
                "class": rclass,
                "ttl": ttl,
                "rdata": rdata_str,
            }
        )
        if rtype in (1, 28) and rdata_str:
            response_ips.append(rdata_str)
    return answers, response_ips


def _extract_dns_message_bytes(payload: bytes, is_tcp: bool) -> bytes | None:
    """Strip TCP 2-byte length prefix when parsing DNS-over-TCP."""
    if not is_tcp:
        return payload if len(payload) >= 12 else None
    if len(payload) < 2:
        return None
    msg_len = struct.unpack_from("!H", payload, 0)[0]
    if len(payload) < 2 + msg_len or msg_len < 12:
        return None
    return payload[2:2 + msg_len]


def parse_dns(payload: bytes, *, is_tcp: bool = False) -> dict[str, Any] | None:
    """Parse a DNS packet from raw UDP or TCP payload bytes."""
    data = _extract_dns_message_bytes(payload, is_tcp)
    if data is None:
        return None

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    if qdcount > 32 or ancount > 128:
        return None

    q_res = _parse_questions(data, 12, qdcount)
    if q_res is None:
        return None
    questions, offset = q_res
    answers, response_ips = _parse_answers(data, offset, ancount)

    return {
        "transaction_id": tx_id,
        "is_response": bool((flags >> 15) & 0x01),
        "opcode": (flags >> 11) & 0x0F,
        "rcode": flags & 0x0F,
        "questions": questions,
        "answers": answers,
        "response_ips": response_ips,
        "authority_count": nscount,
        "additional_count": arcount,
    }
