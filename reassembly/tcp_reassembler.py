"""TCP stream reassembler handling out-of-order segments and retransmissions."""

from __future__ import annotations

import bisect
from typing import Any

from parser.parsed_packet import FlowKey, ParsedPacket
from parser.protocols.http_parser import parse_http_request, parse_http_response
from reassembly.stream_store import DirectionBuffer, StreamState, StreamStore

_FLAG_FIN = 0x01
_FLAG_SYN = 0x02
_FLAG_RST = 0x04
_FLAG_ACK = 0x10

_WELL_KNOWN_SERVER_PORTS = frozenset({21, 22, 25, 53, 80, 110, 143, 443, 3000, 8000, 8080, 8443})
_MAX_PENDING_BYTES_PER_DIRECTION = 4 * 1024 * 1024


def _seq_diff(a: int, b: int) -> int:
    """Compute signed 32-bit sequence number difference (a - b)."""
    diff = (a - b) & 0xFFFFFFFF
    return diff - 0x100000000 if diff >= 0x80000000 else diff


def _infer_endpoints(pkt: ParsedPacket) -> tuple[tuple[str, int], tuple[str, int]]:
    """Determine (client_endpoint, server_endpoint) for a TCP packet."""
    assert pkt.ip_src is not None and pkt.ip_dst is not None
    sport = pkt.src_port or 0
    dport = pkt.dst_port or 0
    src_ep = (pkt.ip_src, sport)
    dst_ep = (pkt.ip_dst, dport)

    flags = pkt.tcp_flags or 0
    if flags & _FLAG_SYN:
        return (dst_ep, src_ep) if (flags & _FLAG_ACK) else (src_ep, dst_ep)

    if sport in _WELL_KNOWN_SERVER_PORTS and dport not in _WELL_KNOWN_SERVER_PORTS:
        return dst_ep, src_ep
    return src_ep, dst_ep


def _anchor_isn(dir_buf: DirectionBuffer, seq: int) -> None:
    """Anchor a direction buffer's initial sequence numbers from a SYN flag."""
    if not dir_buf.isn_anchored:
        isn_next = (seq + 1) & 0xFFFFFFFF
        dir_buf.base_seq = isn_next
        dir_buf.next_seq = isn_next
        dir_buf.isn_anchored = True


class TCPReassembler:
    """Reconstructs contiguous bidirectional byte streams from raw TCP segments."""

    def __init__(
        self,
        store: StreamStore | None = None,
        *,
        idle_timeout_seconds: float = 120.0,
    ) -> None:
        """Initialize the TCP reassembler with a StreamStore instance."""
        self.store = store or StreamStore(idle_timeout_seconds=idle_timeout_seconds)

    def _get_or_create_stream_locked(self, pkt: ParsedPacket, flow_key: FlowKey) -> StreamState:
        """Look up or initialize a TCP StreamState while holding store.lock."""
        stream = self.store.get(flow_key)
        if stream is not None:
            return stream
        client_ep, server_ep = _infer_endpoints(pkt)
        stream = StreamState(
            flow_key=flow_key,
            client_endpoint=client_ep,
            server_endpoint=server_ep,
            created_at=pkt.timestamp,
            last_seen=pkt.timestamp,
        )
        self.store.put(stream)
        return stream

    def _apply_fin(self, stream: StreamState, dir_buf: DirectionBuffer, is_client: bool) -> None:
        """Record FIN arrival and transition connection state."""
        if is_client:
            stream.client_fin_seen = True
        else:
            stream.server_fin_seen = True
        if dir_buf.next_seq is not None:
            dir_buf.next_seq = (dir_buf.next_seq + 1) & 0xFFFFFFFF
        if stream.client_fin_seen and stream.server_fin_seen:
            stream.state = "CLOSED"
        elif stream.state != "CLOSED":
            stream.state = "FIN_WAIT"

    def _record_payload(
        self,
        stream: StreamState,
        dir_buf: DirectionBuffer,
        direction: str,
        pkt: ParsedPacket,
    ) -> None:
        """Assemble payload bytes for one TCP segment and append to stream conversation."""
        assert pkt.tcp_seq is not None
        if not pkt.payload_bytes:
            return
        if stream.state == "NEW":
            stream.state = "ESTABLISHED"
        assembled_chunk, prepended = self._insert_payload(
            dir_buf, pkt.tcp_seq, pkt.payload_bytes
        )
        if not assembled_chunk:
            return
        entry = (direction, assembled_chunk)
        if prepended:
            stream.conversation.insert(0, entry)
        else:
            stream.conversation.append(entry)

    def add_segment(self, pkt: ParsedPacket) -> StreamState | None:
        """Process a parsed TCP packet, updating stream state and ordered buffers."""
        if pkt.transport_proto != "TCP" or pkt.flow_key is None or pkt.tcp_seq is None:
            return None
        if pkt.ip_src is None or pkt.ip_dst is None:
            return None

        flow_key = pkt.flow_key
        with self.store.lock:
            self.store.prune_expired(pkt.timestamp)
            stream = self._get_or_create_stream_locked(pkt, flow_key)
            stream.last_seen = pkt.timestamp

            is_client = (pkt.ip_src, pkt.src_port or 0) == stream.client_endpoint
            direction = "CLIENT" if is_client else "SERVER"
            dir_buf = stream.client_buffer if is_client else stream.server_buffer

            flags = pkt.tcp_flags or 0
            self._update_state_machine(stream, dir_buf, is_client, flags, pkt.tcp_seq)
            self._record_payload(stream, dir_buf, direction, pkt)
            if flags & _FLAG_FIN:
                self._apply_fin(stream, dir_buf, is_client)
            return stream

    def _update_state_machine(
        self,
        stream: StreamState,
        dir_buf: DirectionBuffer,
        is_client: bool,
        flags: int,
        seq: int,
    ) -> None:
        """Advance TCP connection state based on SYN, ACK, and RST flags."""
        if flags & _FLAG_RST:
            stream.state = "CLOSED"
            return

        if flags & _FLAG_SYN:
            if not (flags & _FLAG_ACK):
                stream.state = "SYN_SEEN"
                if stream.client_isn is None:
                    stream.client_isn = seq
            elif stream.server_isn is None:
                stream.server_isn = seq
            _anchor_isn(dir_buf, seq)
            return

        if (flags & _FLAG_ACK) and stream.state == "SYN_SEEN":
            stream.state = "ESTABLISHED"

    def _buffer_pre_pending(self, dir_buf: DirectionBuffer, seq: int, payload: bytes) -> None:
        """Store detached earlier segments arriving mid-stream before base_seq."""
        assert dir_buf.base_seq is not None
        dir_buf.out_of_order_count += 1
        pending_total = sum(len(item[1]) for item in dir_buf.pre_pending)
        if pending_total + len(payload) > _MAX_PENDING_BYTES_PER_DIRECTION:
            return
        if any(ex_seq == seq and ex_data == payload for ex_seq, ex_data in dir_buf.pre_pending):
            dir_buf.retransmissions += 1
            return
        dir_buf.pre_pending.append((seq, payload))
        dir_buf.pre_pending.sort(
            key=lambda item: _seq_diff(
                (item[0] + len(item[1])) & 0xFFFFFFFF, dir_buf.base_seq or 0
            ),
            reverse=True,
        )

    def _drain_pre_pending(self, dir_buf: DirectionBuffer, prefix_parts: list[bytes]) -> None:
        """Prepend any buffered earlier mid-stream segments now contiguous with base_seq."""
        assert dir_buf.base_seq is not None
        while dir_buf.pre_pending:
            seg_seq, seg_data = dir_buf.pre_pending[0]
            seg_end = (seg_seq + len(seg_data)) & 0xFFFFFFFF
            end_diff = _seq_diff(seg_end, dir_buf.base_seq)
            if end_diff < 0:
                break
            dir_buf.pre_pending.pop(0)
            if _seq_diff(seg_seq, dir_buf.base_seq) >= 0:
                dir_buf.retransmissions += 1
                continue
            chunk_len = _seq_diff(dir_buf.base_seq, seg_seq)
            chunk = seg_data[:chunk_len]
            dir_buf.reassembled = bytearray(chunk) + dir_buf.reassembled
            dir_buf.base_seq = seg_seq
            prefix_parts.insert(0, chunk)

    def _handle_midstream_prefix(
        self,
        dir_buf: DirectionBuffer,
        seq: int,
        payload: bytes,
    ) -> tuple[bytes, bool] | None:
        """Handle segments arriving before base_seq when capture started mid-stream."""
        assert dir_buf.base_seq is not None and dir_buf.next_seq is not None
        if dir_buf.isn_anchored or _seq_diff(seq, dir_buf.base_seq) >= 0:
            return None

        end_offset = _seq_diff((seq + len(payload)) & 0xFFFFFFFF, dir_buf.base_seq)
        if end_offset < 0:
            self._buffer_pre_pending(dir_buf, seq, payload)
            return b"", False

        prefix_len = _seq_diff(dir_buf.base_seq, seq)
        prefix = payload[:prefix_len]
        dir_buf.reassembled = bytearray(prefix) + dir_buf.reassembled
        dir_buf.base_seq = seq
        dir_buf.out_of_order_count += 1

        tail_offset = _seq_diff((seq + len(payload)) & 0xFFFFFFFF, dir_buf.next_seq)
        if tail_offset > 0:
            tail = payload[len(payload) - tail_offset:]
            dir_buf.reassembled.extend(tail)
            dir_buf.next_seq = (dir_buf.next_seq + len(tail)) & 0xFFFFFFFF

        prefix_parts = [prefix]
        self._drain_pre_pending(dir_buf, prefix_parts)
        return b"".join(prefix_parts), True

    def _buffer_out_of_order(
        self,
        dir_buf: DirectionBuffer,
        seq: int,
        offset: int,
        payload: bytes,
    ) -> None:
        """Store an out-of-order segment in sequence-sorted pending list."""
        assert dir_buf.next_seq is not None
        dir_buf.out_of_order_count += 1
        pending_total = sum(len(item[1]) for item in dir_buf.pending)
        if pending_total + len(payload) > _MAX_PENDING_BYTES_PER_DIRECTION:
            return

        if any(ex_seq == seq and ex_data == payload for ex_seq, ex_data in dir_buf.pending):
            dir_buf.retransmissions += 1
            return

        keys = [_seq_diff(item[0], dir_buf.next_seq) for item in dir_buf.pending]
        pos = bisect.bisect_left(keys, offset)
        dir_buf.pending.insert(pos, (seq, payload))

    def _insert_payload(
        self,
        dir_buf: DirectionBuffer,
        seq: int,
        payload: bytes,
    ) -> tuple[bytes, bool]:
        """Insert payload bytes, returning (newly_contiguous_bytes, was_prepended)."""
        if dir_buf.next_seq is None:
            dir_buf.base_seq = seq
            dir_buf.next_seq = seq

        midstream_res = self._handle_midstream_prefix(dir_buf, seq, payload)
        if midstream_res is not None:
            return midstream_res

        assert dir_buf.next_seq is not None
        offset = _seq_diff(seq, dir_buf.next_seq)
        if offset + len(payload) <= 0:
            dir_buf.retransmissions += 1
            return b"", False

        if offset < 0:
            payload = payload[-offset:]
            seq = dir_buf.next_seq
            offset = 0

        if offset == 0:
            newly_contiguous = bytearray(payload)
            dir_buf.reassembled.extend(payload)
            dir_buf.next_seq = (dir_buf.next_seq + len(payload)) & 0xFFFFFFFF
            self._drain_pending(dir_buf, newly_contiguous)
            return bytes(newly_contiguous), False

        self._buffer_out_of_order(dir_buf, seq, offset, payload)
        return b"", False

    def _drain_pending(self, dir_buf: DirectionBuffer, out: bytearray) -> None:
        """Consume all pending out-of-order segments now contiguous with next_seq."""
        assert dir_buf.next_seq is not None
        while dir_buf.pending:
            seg_seq, seg_data = dir_buf.pending[0]
            offset = _seq_diff(seg_seq, dir_buf.next_seq)
            if offset > 0:
                break

            dir_buf.pending.pop(0)
            if offset + len(seg_data) <= 0:
                dir_buf.retransmissions += 1
                continue
            if offset < 0:
                seg_data = seg_data[-offset:]

            dir_buf.reassembled.extend(seg_data)
            out.extend(seg_data)
            dir_buf.next_seq = (dir_buf.next_seq + len(seg_data)) & 0xFFFFFFFF

    def get_stream_data(
        self,
        flow_key: FlowKey,
        *,
        direction: str = "both",
    ) -> bytes | None:
        """Return reassembled contiguous bytes for a stream (client, server, or both)."""
        with self.store.lock:
            stream = self.store.get(flow_key)
            if stream is None:
                return None
            if direction == "client":
                return bytes(stream.client_buffer.reassembled)
            if direction == "server":
                return bytes(stream.server_buffer.reassembled)
            return bytes(stream.client_buffer.reassembled + stream.server_buffer.reassembled)

    def follow_stream(self, flow_key: FlowKey) -> str:
        """Return a Wireshark-style annotated TCP conversation string."""
        with self.store.lock:
            stream = self.store.get(flow_key)
            if stream is None:
                return ""
            return _format_conversation(stream.conversation)

    def get_http_exchange(self, flow_key: FlowKey) -> dict[str, Any] | None:
        """Attempt HTTP request and response parsing on reassembled stream buffers."""
        with self.store.lock:
            stream = self.store.get(flow_key)
            if stream is None:
                return None
            client_bytes = bytes(stream.client_buffer.reassembled)
            server_bytes = bytes(stream.server_buffer.reassembled)

        req = parse_http_request(client_bytes) if client_bytes else None
        resp = parse_http_response(server_bytes) if server_bytes else None
        if req is None and resp is None:
            return None
        return {"request": req, "response": resp}

    def get_all_http_exchanges(self) -> list[dict[str, Any]]:
        """Return reconstructed HTTP exchanges across all tracked streams."""
        exchanges: list[dict[str, Any]] = []
        for stream in self.store.all_streams():
            exchange = self.get_http_exchange(stream.flow_key)
            if exchange is not None:
                exchanges.append(
                    {
                        "flow_key": stream.flow_key,
                        "client": stream.client_endpoint,
                        "server": stream.server_endpoint,
                        "request": exchange["request"],
                        "response": exchange["response"],
                    }
                )
        return exchanges

    def get_all_streams_text(self) -> list[tuple[FlowKey, str]]:
        """Return formatted conversation strings for all non-empty streams."""
        results: list[tuple[FlowKey, str]] = []
        for stream in self.store.all_streams():
            if stream.conversation:
                results.append((stream.flow_key, _format_conversation(stream.conversation)))
        return results


def _format_conversation(conversation: list[tuple[str, bytes]]) -> str:
    """Format directional byte chunks into a readable transcript."""
    lines: list[str] = []
    for direction, chunk in conversation:
        prefix = "→ CLIENT" if direction == "CLIENT" else "← SERVER"
        text = chunk.decode("utf-8", errors="replace")
        lines.append(f"[{prefix}]\n{text}")
    return "\n".join(lines)
