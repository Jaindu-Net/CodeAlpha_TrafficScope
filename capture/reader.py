"""Offline PCAP reader for replaying saved captures without elevation."""

from __future__ import annotations

import queue
import threading
import time
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader

from capture.capturer import CaptureStats, sanitize_payload


class OfflineReader:
    """Reads packets from a PCAP file and enqueues them onto the worker pipeline."""

    def __init__(
        self,
        packet_queue: queue.Queue[Packet],
        *,
        count: int | None = None,
        no_payload: bool = False,
        payload_bytes_limit: int | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Initialize an offline PCAP reader.

        Args:
            packet_queue: Queue shared with downstream worker threads.
            count: Optional maximum number of packets to read.
            no_payload: Strip Raw payload bytes before enqueueing.
            payload_bytes_limit: Truncate Raw payload bytes to at most N bytes.
            stop_event: Optional event allowing early interruption during replay.
        """
        if count is not None and count < 0:
            raise ValueError("count must be >= 0")
        if payload_bytes_limit is not None and payload_bytes_limit < 0:
            raise ValueError("payload_bytes_limit must be >= 0")

        self._queue = packet_queue
        self.count = count
        self.no_payload = no_payload
        self.payload_bytes_limit = payload_bytes_limit
        self._stop_event = stop_event or threading.Event()
        self._stats_lock = threading.Lock()
        self._captured = 0
        self._dropped = 0
        self._start_time: float | None = None
        self._end_time: float | None = None

    def read(self, path: str | Path) -> CaptureStats:
        """Stream packets from disk into the queue until EOF, count, or stop_event."""
        pcap_path = Path(path)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self._start_time = time.monotonic()
        self._end_time = None

        try:
            with PcapReader(str(pcap_path)) as reader:
                for pkt in reader:
                    if self._stop_event.is_set():
                        break
                    if self.count is not None and self.count > 0 and self._captured >= self.count:
                        break

                    processed = sanitize_payload(
                        pkt,
                        no_payload=self.no_payload,
                        payload_bytes_limit=self.payload_bytes_limit,
                    )
                    if self._enqueue_blocking(processed):
                        with self._stats_lock:
                            self._captured += 1
                    else:
                        with self._stats_lock:
                            self._dropped += 1
                        break
        except (Scapy_Exception, OSError, EOFError) as exc:
            raise ValueError(f"Failed to read PCAP file '{pcap_path}': {exc}") from exc
        finally:
            self._end_time = time.monotonic()

        return self.get_stats()

    def _enqueue_blocking(self, pkt: Packet) -> bool:
        """Put a packet into the queue while remaining responsive to stop_event."""
        while not self._stop_event.is_set():
            try:
                self._queue.put(pkt, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def get_stats(self) -> CaptureStats:
        """Return current replay counters and throughput."""
        with self._stats_lock:
            captured = self._captured
            dropped = self._dropped

        if self._start_time is None:
            elapsed = 0.0
        else:
            end_ref = self._end_time if self._end_time is not None else time.monotonic()
            elapsed = max(0.0, end_ref - self._start_time)

        pps = captured / elapsed if elapsed > 0 else 0.0
        return CaptureStats(
            captured=captured,
            dropped=dropped,
            kernel_received=None,
            kernel_dropped=None,
            queue_depth=self._queue.qsize(),
            elapsed_seconds=elapsed,
            pps=pps,
        )
