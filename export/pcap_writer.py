"""Thread-safe PCAP file writer producing Wireshark/tshark-compatible captures."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from scapy.packet import Packet
from scapy.utils import PcapWriter as ScapyPcapWriter


class PcapWriter:
    """Thread-safe wrapper around Scapy's libpcap PcapWriter."""

    def __init__(self, path: str | Path, *, sync: bool = False) -> None:
        """Open a PCAP file for writing.

        Args:
            path: Output ``.pcap`` file path. Parent directories are created if needed.
            sync: Flush after every packet when True (safer, slightly slower).
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._writer = ScapyPcapWriter(str(self.path), append=False, sync=sync)
        self._closed = False
        self.written_count = 0

    def write(self, raw_pkt: Packet) -> None:
        """Write a single Scapy packet to the PCAP file thread-safely."""
        if raw_pkt is None:
            return
        with self._lock:
            if self._closed:
                return
            self._writer.write(raw_pkt)
            self.written_count += 1

    def close(self) -> None:
        """Flush buffered packets and close the underlying PCAP handle."""
        with self._lock:
            if self._closed:
                return
            try:
                self._writer.flush()
            finally:
                self._writer.close()
                self._closed = True

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
