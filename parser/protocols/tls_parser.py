"""TLS ClientHello metadata parser (SNI and cipher suites only; never decrypts)."""

from __future__ import annotations

import struct
from typing import Any

_TLS_CONTENT_TYPES = frozenset({20, 21, 22, 23})
_VALID_RECORD_VERSIONS = frozenset({0x0300, 0x0301, 0x0302, 0x0303, 0x0304})


def is_tls_record(payload: bytes) -> bool:
    """Return True if bytes look like a standard TLS record header."""
    if len(payload) < 5:
        return False
    content_type = payload[0]
    record_ver = struct.unpack_from("!H", payload, 1)[0]
    return content_type in _TLS_CONTENT_TYPES and record_ver in _VALID_RECORD_VERSIONS


def _parse_sni_extension(ext_data: bytes) -> str | None:
    """Extract the first host_name entry from a TLS Server Name Indication extension."""
    if len(ext_data) < 2:
        return None
    list_len = struct.unpack_from("!H", ext_data, 0)[0]
    pos = 2
    end = min(len(ext_data), 2 + list_len)
    while pos + 3 <= end:
        name_type = ext_data[pos]
        name_len = struct.unpack_from("!H", ext_data, pos + 1)[0]
        pos += 3
        if pos + name_len > end:
            return None
        if name_type == 0:
            return ext_data[pos:pos + name_len].decode("utf-8", errors="replace")
        pos += name_len
    return None


def _parse_alpn_extension(ext_data: bytes) -> list[str]:
    """Extract protocol names from an ALPN extension payload."""
    if len(ext_data) < 2:
        return []
    list_len = struct.unpack_from("!H", ext_data, 0)[0]
    pos = 2
    end = min(len(ext_data), 2 + list_len)
    protocols: list[str] = []
    while pos < end:
        proto_len = ext_data[pos]
        pos += 1
        if pos + proto_len > end:
            break
        protocols.append(ext_data[pos:pos + proto_len].decode("ascii", errors="replace"))
        pos += proto_len
    return protocols


def parse_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    """Extract unencrypted handshake metadata from a TLS ClientHello record.

    Never attempts decryption. Returns None for non-ClientHello records,
    truncated frames, or UDP QUIC Initial packets.
    """
    if len(payload) < 43:
        return None

    content_type = payload[0]
    record_version = struct.unpack_from("!H", payload, 1)[0]
    record_length = struct.unpack_from("!H", payload, 3)[0]
    if content_type != 0x16 or record_version not in _VALID_RECORD_VERSIONS:
        return None

    record_end = min(len(payload), 5 + record_length)
    pos = 5
    if pos + 4 > record_end:
        return None

    handshake_type = payload[pos]
    handshake_len = int.from_bytes(payload[pos + 1:pos + 4], "big")
    if handshake_type != 0x01:
        return None

    pos += 4
    hello_end = min(record_end, pos + handshake_len)
    if pos + 34 > hello_end:
        return None

    client_version = struct.unpack_from("!H", payload, pos)[0]
    pos += 2 + 32  # Skip client_version + 32-byte client random

    # Session ID
    if pos >= hello_end:
        return None
    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > hello_end:
        return None

    # Cipher Suites
    cipher_suites_len = struct.unpack_from("!H", payload, pos)[0]
    pos += 2
    if cipher_suites_len % 2 != 0 or pos + cipher_suites_len > hello_end:
        return None
    cipher_suites = [
        f"0x{struct.unpack_from('!H', payload, pos + idx)[0]:04x}"
        for idx in range(0, cipher_suites_len, 2)
    ]
    pos += cipher_suites_len

    # Compression Methods
    if pos >= hello_end:
        return None
    comp_len = payload[pos]
    pos += 1
    if pos + comp_len > hello_end:
        return None
    compression_methods = list(payload[pos:pos + comp_len])
    pos += comp_len

    # Extensions (optional in older SSL/TLS)
    sni: str | None = None
    alpn: list[str] = []
    extensions: list[int] = []

    if pos + 2 <= hello_end:
        exts_len = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        exts_end = min(hello_end, pos + exts_len)
        while pos + 4 <= exts_end:
            ext_type, ext_len = struct.unpack_from("!HH", payload, pos)
            pos += 4
            if pos + ext_len > exts_end:
                break
            extensions.append(ext_type)
            ext_data = payload[pos:pos + ext_len]
            if ext_type == 0x0000 and sni is None:
                sni = _parse_sni_extension(ext_data)
            elif ext_type == 0x0010 and not alpn:
                alpn = _parse_alpn_extension(ext_data)
            pos += ext_len

    return {
        "handshake_type": "ClientHello",
        "record_version": f"0x{record_version:04x}",
        "handshake_version": f"0x{client_version:04x}",
        "session_id_len": session_id_len,
        "cipher_suites": cipher_suites,
        "compression_methods": compression_methods,
        "extensions": extensions,
        "sni": sni,
        "alpn": alpn,
    }
