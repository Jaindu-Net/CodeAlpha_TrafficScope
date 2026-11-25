"""Thread-safe storage for active TCP stream reassembly state."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from parser.parsed_packet import FlowKey


@dataclass
class DirectionBuffer:
    """Per-direction sequence tracking and ordered payload assembly buffer."""

    base_seq: int | None = None
    next_seq: int | None = None
    isn_anchored: bool = False
    reassembled: bytearray = field(default_factory=bytearray)
    pending: list[tuple[int, bytes]] = field(default_factory=list)
    retransmissions: int = 0
    out_of_order_count: int = 0


@dataclass
class StreamState:
    """Bidirectional TCP stream state machine and payload buffers."""

    flow_key: FlowKey
    client_endpoint: tuple[str, int]
    server_endpoint: tuple[str, int]
    state: str = "NEW"
    client_isn: int | None = None
    server_isn: int | None = None
    client_fin_seen: bool = False
    server_fin_seen: bool = False
    created_at: float = 0.0
    last_seen: float = 0.0
    client_buffer: DirectionBuffer = field(default_factory=DirectionBuffer)
    server_buffer: DirectionBuffer = field(default_factory=DirectionBuffer)
    conversation: list[tuple[str, bytes]] = field(default_factory=list)


class StreamStore:
    """Thread-safe container managing active TCP streams and idle expiration."""

    def __init__(self, *, idle_timeout_seconds: float = 120.0) -> None:
        """Initialize the stream store with a configurable idle timeout."""
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be > 0")
        self.idle_timeout_seconds = idle_timeout_seconds
        self._lock = threading.RLock()
        self._streams: dict[FlowKey, StreamState] = {}
        self.expired_count = 0

    @property
    def lock(self) -> threading.RLock:
        """Expose reentrant lock for atomic stream updates in TCPReassembler."""
        return self._lock

    def get(self, flow_key: FlowKey) -> StreamState | None:
        """Return a tracked StreamState by canonical flow key, or None."""
        with self._lock:
            return self._streams.get(flow_key)

    def put(self, stream: StreamState) -> None:
        """Store or replace a StreamState entry."""
        with self._lock:
            self._streams[stream.flow_key] = stream

    def all_streams(self) -> list[StreamState]:
        """Return a snapshot list of all currently stored streams."""
        with self._lock:
            return list(self._streams.values())

    def count(self) -> int:
        """Return the number of currently tracked TCP streams."""
        with self._lock:
            return len(self._streams)

    def prune_expired(self, now: float) -> int:
        """Remove streams whose last_seen timestamp exceeds idle_timeout_seconds."""
        with self._lock:
            expired = [
                key
                for key, stream in self._streams.items()
                if (now - stream.last_seen) > self.idle_timeout_seconds
            ]
            for key in expired:
                del self._streams[key]
            self.expired_count += len(expired)
            return len(expired)
