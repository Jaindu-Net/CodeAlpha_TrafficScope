"""Tests for the capture module (offline without Administrator privileges)."""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import IterSocket
from scapy.utils import wrpcap

from capture import (
    CaptureEngine,
    InterfaceInfo,
    OfflineReader,
    is_elevated,
    list_interfaces,
    sanitize_payload,
    select_interface,
    warn_if_not_elevated,
)


def _sample_tcp_packet(payload: bytes = b"GET / HTTP/1.1\r\n\r\n") -> Ether:
    return (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=54321, dport=80)
        / Raw(payload)
    )


def test_is_elevated_windows_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("capture.interface.sys.platform", "win32")
    fake_shell32 = SimpleNamespace(IsUserAnAdmin=lambda: 1)
    monkeypatch.setattr(
        "capture.interface.ctypes.windll",
        SimpleNamespace(shell32=fake_shell32),
        raising=False,
    )
    assert is_elevated() is True

    fake_shell32_non_admin = SimpleNamespace(IsUserAnAdmin=lambda: 0)
    monkeypatch.setattr(
        "capture.interface.ctypes.windll",
        SimpleNamespace(shell32=fake_shell32_non_admin),
        raising=False,
    )
    assert is_elevated() is False


def test_warn_if_not_elevated_exits_when_unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("capture.interface.is_elevated", lambda: False)
    assert warn_if_not_elevated(exit_on_fail=False) is False
    with pytest.raises(SystemExit) as exc_info:
        warn_if_not_elevated(exit_on_fail=True)
    assert exc_info.value.code == 1


def test_list_and_select_interface_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ifaces = {
        "dev1": SimpleNamespace(
            index=1,
            name="Wi-Fi",
            description="Intel Wi-Fi 6",
            ip="192.168.1.50",
            mac="aa:bb:cc:dd:ee:01",
            network_name=r"\Device\NPF_{1111}",
        ),
        "dev2": SimpleNamespace(
            index=2,
            name="Ethernet",
            description="Realtek PCIe GbE",
            ip="10.0.0.5",
            mac="aa:bb:cc:dd:ee:02",
            network_name=r"\Device\NPF_{2222}",
        ),
    }
    monkeypatch.setattr("capture.interface.scapy_conf.ifaces", fake_ifaces)

    listed = list_interfaces()
    assert [item.name for item in listed] == ["Wi-Fi", "Ethernet"]
    assert isinstance(listed[0], InterfaceInfo)

    assert select_interface("wi-fi").name == "Wi-Fi"
    assert select_interface(r"\Device\NPF_{2222}").name == "Ethernet"
    assert select_interface("1").name == "Ethernet"
    assert select_interface("Realtek").name == "Ethernet"
    assert select_interface(None, input_fn=lambda _: "0").name == "Wi-Fi"

    with pytest.raises(ValueError, match="Unknown interface"):
        select_interface("NonExistentNIC")


def test_select_interface_raises_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("capture.interface.scapy_conf.ifaces", {})
    with pytest.raises(RuntimeError, match="No capture interfaces found"):
        select_interface("Wi-Fi")


def test_sanitize_payload_modes() -> None:
    pkt = _sample_tcp_packet(b"0123456789ABCDEF")
    untouched = sanitize_payload(pkt)
    assert untouched is pkt

    stripped = sanitize_payload(pkt, no_payload=True)
    assert not stripped.haslayer(Raw)
    assert stripped.haslayer(TCP)
    assert pkt.haslayer(Raw)

    truncated = sanitize_payload(pkt, payload_bytes_limit=5)
    assert truncated[Raw].load == b"01234"
    assert pkt[Raw].load == b"0123456789ABCDEF"


def test_offline_reader_replays_pcap_and_respects_count(tmp_path: Path) -> None:
    pcap_file = tmp_path / "sample.pcap"
    pkts = [_sample_tcp_packet(f"pkt-{i}".encode()) for i in range(5)]
    wrpcap(str(pcap_file), pkts)

    q: queue.Queue = queue.Queue()
    reader = OfflineReader(q, count=3, payload_bytes_limit=4)
    stats = reader.read(pcap_file)

    assert stats.captured == 3
    assert stats.dropped == 0
    assert q.qsize() == 3
    first = q.get_nowait()
    assert first[Raw].load == b"pkt-"


def test_offline_reader_errors_and_cancellation(tmp_path: Path) -> None:
    q: queue.Queue = queue.Queue()
    reader = OfflineReader(q)
    with pytest.raises(FileNotFoundError):
        reader.read(tmp_path / "missing.pcap")

    bad_file = tmp_path / "bad.pcap"
    bad_file.write_bytes(b"definitely not a pcap header")
    with pytest.raises(ValueError, match="Failed to read PCAP"):
        reader.read(bad_file)

    pcap_file = tmp_path / "full.pcap"
    wrpcap(str(pcap_file), [_sample_tcp_packet() for _ in range(4)])
    stop_event = threading.Event()
    stop_event.set()
    stopped_reader = OfflineReader(q, stop_event=stop_event)
    stats = stopped_reader.read(pcap_file)
    assert stats.captured == 0


def test_capture_engine_with_injected_socket_and_drop_tracking() -> None:
    pkts = [_sample_tcp_packet(f"msg-{i}".encode()) for i in range(5)]
    q: queue.Queue = queue.Queue(maxsize=2)
    engine = CaptureEngine(
        iface="mock",
        packet_queue=q,
        no_payload=True,
        opened_socket=IterSocket(pkts),
    )
    engine.start()
    engine.join(timeout=3.0)
    stats = engine.stop()

    assert stats.captured == 2
    assert stats.dropped == 3
    assert stats.queue_depth == 2
    queued_pkt = q.get_nowait()
    assert not queued_pkt.haslayer(Raw)
    assert queued_pkt.haslayer(TCP)


def test_capture_engine_validates_arguments() -> None:
    q: queue.Queue = queue.Queue()
    with pytest.raises(ValueError):
        CaptureEngine("mock", q, count=-1)
    with pytest.raises(ValueError):
        CaptureEngine("mock", q, timeout=0)
    with pytest.raises(ValueError):
        CaptureEngine("mock", q, payload_bytes_limit=-5)
