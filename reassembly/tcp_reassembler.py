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
    if (flags & _FLAG_SYN) and not (flags & _FLAG_ACK):
        return src_ep, dst_ep
    if (flags & _FLAG_SYN) and (flags & _FLAG_ACK):
        return dst_ep, src_ep

    if sport in _WELL_KNOWN_SERVER_PORTS and dport not in _WELL_KNOWN_SERVER_PORTS:
        return dst_ep, src_ep
    if dport in _WELL_KNOWN_SERVER_PORTS and sport not in _WELL_KNOWN_SERVER_PORTS:
        return src_ep, dst_ep

    return src_ep, dst_ep


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

    def add_segment(self, pkt: ParsedPacket) -> StreamState | None:
        """Process a parsed TCP packet, updating stream state and ordered buffers."""
        if pkt.transport_proto != "TCP" or pkt.flow_key is None or pkt.tcp_seq is None:
            return None
        if pkt.ip_src is None or pkt.ip_dst is None:
            return None

        flow_key = pkt.flow_key
        now = pkt.timestamp

        with self.store.lock:
            self.store.prune_expired(now)
            stream = self.store.get(flow_key)
            if stream is None:
                client_ep, server_ep = _infer_endpoints(pkt)
                stream = StreamState(
                    flow_key=flow_key,
                    client_endpoint=client_ep,
                    server_endpoint=server_ep,
                    created_at=now,
                    last_seen=now,
                )
                self.store.put(stream)

            stream.last_seen = now
            src_ep = (pkt.ip_src, pkt.src_port or 0)
            is_client = src_ep == stream.client_endpoint
            direction = "CLIENT" if is_client else "SERVER"
            dir_buf = stream.client_buffer if is_client else stream.server_buffer

            flags = pkt.tcp_flags or 0
            self._update_state_machine(stream, dir_buf, is_client, flags, pkt.tcp_seq)

            if pkt.payload_bytes:
                if stream.state == "NEW":
                    stream.state = "ESTABLISHED"
                assembled_chunk, prepended = self._insert_payload(
                    dir_buf, pkt.tcp_seq, pkt.payload_bytes
                )
                if assembled_chunk:
                    if prepended:
                        stream.conversation.insert(0, (direction, assembled_chunk))
                    else:
                        stream.conversation.append((direction, assembled_chunk))

            if flags & _FLAG_FIN:
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
                if not dir_buf.isn_anchored:
                    isn_next = (seq + 1) & 0xFFFFFFFF
                    dir_buf.base_seq = isn_next
                    dir_buf.next_seq = isn_next
                    dir_buf.isn_anchored = True
            else:
                if stream.server_isn is None:
                    stream.server_isn = seq
                if not dir_buf.isn_anchored:
                    isn_next = (seq + 1) & 0xFFFFFFFF
                    dir_buf.base_seq = isn_next
                    dir_buf.next_seq = isn_next
                    dir_buf.isn_anchored = True
            return

        if (flags & _FLAG_ACK) and stream.state == "SYN_SEEN":
            stream.state = "ESTABLISHED"

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

        assert dir_buf.base_seq is not None and dir_buf.next_seq is not None

        # Mid-stream capture (no SYN seen): handle earlier out-of-order prefix segments.
        if not dir_buf.isn_anchored and _seq_diff(seq, dir_buf.base_seq) < 0:
            end_offset = _seq_diff((seq + len(payload)) & 0xFFFFFFFF, dir_buf.base_seq)
            if end_offset >= 0:
                prefix_len = _seq_diff(dir_buf.base_seq, seq)
                prefix = payload[:prefix_len]
                dir_buf.reassembled = bytearray(prefix) + dir_buf.reassembled
                dir_buf.base_seq = seq
                dir_buf.out_of_order_count += 1
                # Also process any suffix beyond next_seq if this single segment spans across.
                tail_offset = _seq_diff((seq + len(payload)) & 0xFFFFFFFF, dir_buf.next_seq)
                if tail_offset > 0:
                    tail = payload[len(payload) - tail_offset:]
                    dir_buf.reassembled.extend(tail)
                    dir_buf.next_seq = (dir_buf.next_seq + len(tail)) & 0xFFFFFFFF
                return prefix, True

        offset = _seq_diff(seq, dir_buf.next_seq)

        # Pure retransmission of already-assembled bytes.
        if offset + len(payload) <= 0:
            dir_buf.retransmissions += 1
            return b"", False

        # Partial overlap with already-assembled prefix.
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

        # Out-of-order segment: deduplicate and store in sequence-sorted pending list.
        dir_buf.out_of_order_count += 1
        pending_total = sum(len(item[1]) for item in dir_buf.pending)
        if pending_total + len(payload) > _MAX_PENDING_BYTES_PER_DIRECTION:
            return b"", False

        for ex_seq, ex_data in dir_buf.pending:
            if ex_seq == seq and ex_data == payload:
                dir_buf.retransmissions += 1
                return b"", False

        # Sort keys by signed offset relative to current next_seq.
        keys = [_seq_diff(item[0], dir_buf.next_seq) for item in dir_buf.pending]
        pos = bisect.bisect_left(keys, offset)
        dir_buf.pending.insert(pos, (seq, payload))
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
            lines: list[str] = []
            for direction, chunk in stream.conversation:
                prefix = "→ CLIENT" if direction == "CLIENT" else "← SERVER"
                text = chunk.decode("utf-8", errors="replace")
                lines.append(f"[{prefix}]\n{text}")
            return "\n".join(lines)

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
