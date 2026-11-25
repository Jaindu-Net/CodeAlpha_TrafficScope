"""Live packet capture engine acting as the thread-safe queue producer."""

from __future__ import annotations

import ctypes
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

from scapy.error import Scapy_Exception
from scapy.interfaces import resolve_iface
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer


@dataclass(frozen=True, slots=True)
class CaptureStats:
    """Snapshot of capture producer throughput and drop counters."""

    captured: int
    dropped: int
    kernel_received: int | None
    kernel_dropped: int | None
    queue_depth: int
    elapsed_seconds: float
    pps: float


def sanitize_payload(
    pkt: Packet,
    *,
    no_payload: bool = False,
    payload_bytes_limit: int | None = None,
) -> Packet:
    """Strip or truncate the Raw application payload of a packet when configured.

    Preserves all link, network, and transport headers so downstream rules and
    fingerprinting continue to function normally.
    """
    if not no_payload and payload_bytes_limit is None:
        return pkt

    if not pkt.haslayer(Raw):
        return pkt

    pkt_copy = pkt.copy()
    if no_payload:
        raw_layer = pkt_copy[Raw]
        if raw_layer.underlayer is not None:
            raw_layer.underlayer.remove_payload()
        else:
            raw_layer.load = b""
        return pkt_copy

    if payload_bytes_limit is not None:
        raw_layer = pkt_copy[Raw]
        raw_layer.load = bytes(raw_layer.load)[:payload_bytes_limit]
    return pkt_copy


class CaptureEngine:
    """Producer thread capturing packets from a NIC and pushing them into a queue."""

    def __init__(
        self,
        iface: str,
        packet_queue: queue.Queue[Packet],
        *,
        bpf_filter: str | None = None,
        count: int | None = None,
        timeout: float | None = None,
        no_payload: bool = False,
        payload_bytes_limit: int | None = None,
        opened_socket: Any | None = None,
    ) -> None:
        """Initialize the capture engine without starting capture yet.

        Args:
            iface: Interface name or NPF device identifier to sniff on.
            packet_queue: Thread-safe queue receiving captured Scapy packets.
            bpf_filter: Optional BPF capture filter string.
            count: Optional maximum packet count before stopping automatically.
            timeout: Optional maximum capture duration in seconds.
            no_payload: Strip Raw payload bytes before enqueueing.
            payload_bytes_limit: Truncate Raw payload bytes to at most N bytes.
            opened_socket: Optional pre-opened Scapy SuperSocket (used in tests).
        """
        if count is not None and count < 0:
            raise ValueError("count must be >= 0")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be > 0")
        if payload_bytes_limit is not None and payload_bytes_limit < 0:
            raise ValueError("payload_bytes_limit must be >= 0")

        self.iface = iface
        self._queue = packet_queue
        self.bpf_filter = bpf_filter.strip() if bpf_filter else None
        self.count = count or 0
        self.timeout = timeout
        self.no_payload = no_payload
        self.payload_bytes_limit = payload_bytes_limit
        self._injected_socket = opened_socket

        self._socket: Any | None = None
        self._socket_owned = False
        self._sniffer: AsyncSniffer | None = None
        self._timeout_timer: threading.Timer | None = None
        self._started_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._captured = 0
        self._dropped = 0
        self._start_time: float | None = None
        self._end_time: float | None = None
        self._last_kernel_stats: tuple[int | None, int | None] = (None, None)

    @property
    def is_running(self) -> bool:
        """Return True while the background sniffer thread is active."""
        return bool(self._sniffer is not None and self._sniffer.running)

    def start(self) -> None:
        """Open the capture socket and launch the background sniffer thread."""
        if self.is_running:
            raise RuntimeError("CaptureEngine is already running.")

        self._started_event.clear()
        self._end_time = None

        if self._injected_socket is not None:
            self._socket = self._injected_socket
            self._socket_owned = False
        else:
            try:
                l2listen_cls = resolve_iface(self.iface).l2listen()
                self._socket = l2listen_cls(
                    iface=self.iface,
                    filter=self.bpf_filter,
                )
                self._socket_owned = True
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to open capture interface '{self.iface}'"
                    f"{f' with filter {self.bpf_filter!r}' if self.bpf_filter else ''}: {exc}"
                ) from exc

        self._start_time = time.monotonic()
        # Scapy 2.8+ rejects `timeout` in AsyncSniffer; enforce timeout via Timer instead.
        self._sniffer = AsyncSniffer(
            opened_socket=self._socket,
            prn=self._on_packet,
            store=False,
            count=self.count,
            quiet=True,
            started_callback=self._started_event.set,
        )
        self._sniffer.start()
        self._started_event.wait(timeout=2.0)

        if self._sniffer.exception is not None:
            exc = self._sniffer.exception
            self._cleanup_socket()
            raise RuntimeError(f"Capture failed to start: {exc}") from exc

        if self.timeout is not None:
            self._timeout_timer = threading.Timer(self.timeout, self._handle_timeout)
            self._timeout_timer.daemon = True
            self._timeout_timer.start()

    def _handle_timeout(self) -> None:
        """Stop capture automatically when the configured timeout expires."""
        if self._sniffer is not None and self._sniffer.running:
            try:
                self._sniffer.stop(join=False)
            except Scapy_Exception:
                pass

    def _cancel_timer(self) -> None:
        """Cancel the timeout timer if active."""
        if self._timeout_timer is not None:
            self._timeout_timer.cancel()
            self._timeout_timer = None

    def _on_packet(self, pkt: Packet) -> None:
        """Normalize payload constraints and enqueue without blocking the capture thread."""
        processed = sanitize_payload(
            pkt,
            no_payload=self.no_payload,
            payload_bytes_limit=self.payload_bytes_limit,
        )
        try:
            self._queue.put_nowait(processed)
        except queue.Full:
            with self._stats_lock:
                self._dropped += 1
            return

        with self._stats_lock:
            self._captured += 1

    def join(self, timeout: float | None = None) -> None:
        """Wait for the sniffer thread to terminate naturally (count/timeout)."""
        if self._sniffer is not None:
            self._sniffer.join(timeout=timeout)
            if not self._sniffer.running:
                self._cancel_timer()
                if self._end_time is None:
                    self._end_time = time.monotonic()
                self._snapshot_and_close_socket()

    def stop(self) -> CaptureStats:
        """Signal the capture thread to stop, close owned sockets, and return stats."""
        self._cancel_timer()
        if self._sniffer is not None:
            if self._sniffer.running:
                try:
                    self._sniffer.stop(join=True)
                except Scapy_Exception:
                    # Handle race where sniffer finished right before stop() ran.
                    self._sniffer.join(timeout=2.0)
            else:
                self._sniffer.join(timeout=2.0)

        if self._end_time is None:
            self._end_time = time.monotonic()

        self._snapshot_and_close_socket()
        return self.get_stats()

    def _read_kernel_stats(self) -> tuple[int | None, int | None]:
        """Query Npcap/libpcap kernel receive and drop counters if supported."""
        if self._socket is None:
            return self._last_kernel_stats

        pcap_fd = getattr(self._socket, "pcap_fd", None)
        pcap_handle = getattr(pcap_fd, "pcap", None)
        if pcap_handle is None:
            return self._last_kernel_stats

        try:
            from scapy.libs import winpcapy

            stat = winpcapy.pcap_stat()
            rc = winpcapy.pcap_stats(pcap_handle, ctypes.byref(stat))
            if rc == 0:
                total_dropped = int(stat.ps_drop) + int(getattr(stat, "ps_ifdrop", 0))
                return int(stat.ps_recv), total_dropped
        except (ImportError, AttributeError, OSError):
            pass
        return self._last_kernel_stats

    def _snapshot_and_close_socket(self) -> None:
        """Record final kernel counters and close the owned L2 socket once."""
        if self._socket is not None:
            self._last_kernel_stats = self._read_kernel_stats()
            self._cleanup_socket()

    def _cleanup_socket(self) -> None:
        """Close the socket only if opened by this CaptureEngine instance."""
        if self._socket is not None and self._socket_owned:
            try:
                self._socket.close()
            except Exception:
                pass
        self._socket = None
        self._socket_owned = False

    def get_stats(self) -> CaptureStats:
        """Return a thread-safe snapshot of capture counters and throughput."""
        with self._stats_lock:
            captured = self._captured
            dropped = self._dropped

        kernel_received, kernel_dropped = self._read_kernel_stats()
        if self._start_time is None:
            elapsed = 0.0
        else:
            end_ref = self._end_time if self._end_time is not None else time.monotonic()
            elapsed = max(0.0, end_ref - self._start_time)

        pps = captured / elapsed if elapsed > 0 else 0.0
        return CaptureStats(
            captured=captured,
            dropped=dropped,
            kernel_received=kernel_received,
            kernel_dropped=kernel_dropped,
            queue_depth=self._queue.qsize(),
            elapsed_seconds=elapsed,
            pps=pps,
        )
