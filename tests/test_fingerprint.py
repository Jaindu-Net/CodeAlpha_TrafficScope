"""Unit tests for passive OS fingerprinting and database loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from fingerprint import FingerprintDB, Fingerprinter
from parser import PacketParser
from tests.conftest import make_tcp_segment, make_tcp_syn


def test_fingerprint_windows_and_linux_matches() -> None:
    parser = PacketParser()
    fp = Fingerprinter()

    win_syn = parser.parse(
        make_tcp_syn(
            src="192.168.1.50",
            ttl=128,
            window=65535,
            options=[
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 8),
                ("NOP", None),
                ("NOP", None),
                ("SAckOK", b""),
            ],
        )
    )
    win_res = fp.fingerprint(win_syn)
    assert win_res is not None
    assert "Windows 10/11" in win_res.os_guess
    assert win_res.confidence >= 90

    linux_syn = parser.parse(
        make_tcp_syn(
            src="10.0.0.20",
            ttl=64,
            window=29200,
            options=[
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (12345, 0)),
                ("NOP", None),
                ("WScale", 7),
            ],
        )
    )
    linux_res = fp.fingerprint(linux_syn)
    assert linux_res is not None
    assert "Linux" in linux_res.os_guess
    assert fp.get_os_guess("10.0.0.20") == linux_res.os_guess


def test_fingerprint_ignores_non_syn_and_unknown_combos() -> None:
    parser = PacketParser()
    fp = Fingerprinter()

    ack_pkt = parser.parse(make_tcp_segment(flags="A"))
    assert fp.fingerprint(ack_pkt) is None

    # Impossible TTL=5 won't fall inside any OS ttl_range epoch.
    unknown_syn = parser.parse(make_tcp_syn(src="172.16.0.9", ttl=5, window=1234, options=[]))
    assert fp.fingerprint(unknown_syn) is None


def test_fingerprint_db_rejects_malformed_json(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad_fp.json"
    bad_json.write_text("{broken json", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed fingerprint DB"):
        FingerprintDB(bad_json)

    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text('[{"os": "X"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="missing keys"):
        FingerprintDB(bad_schema)
