"""Thread-safe 5-tuple flow tracker with byte/packet counters and entropy sampling."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from parser.parsed_packet import FlowKey, ParsedPacket
from profiler.entropy import classify_entropy, shannon_entropy


@dataclass
class FlowRecord:
    """Aggregated statistics for a canonical bidirectional network flow."""

    flow_key: FlowKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    entropy_samples: list[float] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        """Return observed flow duration in seconds."""
        return max(0.0, self.last_seen - self.start_time)

    @property
    def mean_entropy(self) -> float:
        """Return mean sampled payload Shannon entropy for this flow."""
        if not self.entropy_samples:
            return 0.0
        return sum(self.entropy_samples) / len(self.entropy_samples)

    @property
    def entropy_label(self) -> str:
        """Return heuristic traffic classification derived from mean entropy."""
        return classify_entropy(self.mean_entropy)

    def to_netflow_dict(self) -> dict[str, Any]:
        """Serialize this flow into a NetFlow-style JSON-friendly dictionary."""
        start_iso = datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat()
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": start_iso,
            "duration_s": round(self.duration_s, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "mean_entropy": round(self.mean_entropy, 4),
        }


class FlowTracker:
    """Thread-safe flow table maintaining NetFlow-like summaries and entropy samples."""

    def __init__(self, *, entropy_sample_interval: int = 5) -> None:
        """Initialize the flow tracker.

        Args:
            entropy_sample_interval: Sample payload entropy every N packets per flow.
        """
        if entropy_sample_interval < 1:
            raise ValueError("entropy_sample_interval must be >= 1")
        self.entropy_sample_interval = entropy_sample_interval
        self._lock = threading.Lock()
        self._flows: dict[FlowKey, FlowRecord] = {}

    def update(self, pkt: ParsedPacket) -> FlowRecord | None:
        """Upsert a flow record from a ParsedPacket."""
        key = pkt.flow_key
        if key is None or pkt.ip_src is None or pkt.ip_dst is None:
            return None

        proto = pkt.effective_protocol
        with self._lock:
            record = self._flows.get(key)
            if record is None:
                record = FlowRecord(
                    flow_key=key,
                    src_ip=pkt.ip_src,
                    dst_ip=pkt.ip_dst,
                    src_port=pkt.src_port or 0,
                    dst_port=pkt.dst_port or 0,
                    protocol=proto,
                    start_time=pkt.timestamp,
                    last_seen=pkt.timestamp,
                )
                self._flows[key] = record

            record.packet_count += 1
            record.byte_count += pkt.packet_len
            if pkt.timestamp < record.start_time:
                record.start_time = pkt.timestamp
            if pkt.timestamp > record.last_seen:
                record.last_seen = pkt.timestamp
            if pkt.app_protocol is not None:
                record.protocol = pkt.app_protocol

            if pkt.payload_bytes and (
                not record.entropy_samples
                or record.packet_count % self.entropy_sample_interval == 0
            ):
                record.entropy_samples.append(shannon_entropy(pkt.payload_bytes))

            return record

    def get_top_talkers(self, n: int = 10) -> list[FlowRecord]:
        """Return top N flows ordered by total byte count descending."""
        with self._lock:
            return sorted(
                self._flows.values(),
                key=lambda rec: rec.byte_count,
                reverse=True,
            )[:n]

    def get_top_entropy_flows(self, n: int = 10) -> list[FlowRecord]:
        """Return top N flows with payload samples ordered by mean entropy descending."""
        with self._lock:
            sampled = [rec for rec in self._flows.values() if rec.entropy_samples]
            return sorted(
                sampled,
                key=lambda rec: (rec.mean_entropy, rec.byte_count),
                reverse=True,
            )[:n]

    def get_host_summary(self, n: int = 10) -> list[dict[str, Any]]:
        """Aggregate per-IP byte and packet totals for dashboard display."""
        host_stats: dict[str, dict[str, Any]] = {}
        with self._lock:
            for rec in self._flows.values():
                for ip in (rec.src_ip, rec.dst_ip):
                    entry = host_stats.get(ip)
                    if entry is None:
                        entry = {
                            "ip": ip,
                            "bytes": 0,
                            "packets": 0,
                            "protocol": rec.protocol,
                        }
                        host_stats[ip] = entry
                    entry["bytes"] += rec.byte_count
                    entry["packets"] += rec.packet_count
                    if rec.protocol in ("HTTP", "TLS", "DNS"):
                        entry["protocol"] = rec.protocol

        return sorted(host_stats.values(), key=lambda item: item["bytes"], reverse=True)[:n]

    def count(self) -> int:
        """Return total number of tracked flows."""
        with self._lock:
            return len(self._flows)

    def export_flows(self) -> list[dict[str, Any]]:
        """Serialize all tracked flows into NetFlow-style dictionaries."""
        with self._lock:
            records = sorted(self._flows.values(), key=lambda rec: rec.start_time)
            return [rec.to_netflow_dict() for rec in records]
