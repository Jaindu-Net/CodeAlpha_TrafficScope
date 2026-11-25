"""Rolling per-host statistical profiler and z-score deviation detector."""

from __future__ import annotations

import threading
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from parser.parsed_packet import ParsedPacket


@dataclass
class HostBaseline:
    """Sliding-window behavioral baseline for a single source IP address."""

    ip: str
    first_seen: float
    last_seen: float
    window_seconds: int = 60
    second_buckets: deque[list[int]] = field(default_factory=deque)
    payload_sizes: deque[int] = field(default_factory=lambda: deque(maxlen=1000))
    protocol_counts: Counter[str] = field(default_factory=Counter)
    total_packets: int = 0
    total_bytes: int = 0

    @property
    def mean_payload_size(self) -> float:
        """Return rolling mean payload size in bytes."""
        if not self.payload_sizes:
            return 0.0
        return float(np.mean(self.payload_sizes))

    @property
    def protocol_mix(self) -> dict[str, float]:
        """Return fractional protocol distribution observed for this host."""
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}
        return {proto: count / total for proto, count in self.protocol_counts.items()}


def _compute_payload_z_score(baseline: HostBaseline) -> float:
    """Compute z-score of the newest payload size vs prior rolling payload history."""
    if len(baseline.payload_sizes) < 11:
        return 0.0
    sizes = list(baseline.payload_sizes)
    prior = np.asarray(sizes[:-1], dtype=np.float64)
    current = float(sizes[-1])
    mean_sz = float(np.mean(prior))
    std_sz = float(np.std(prior))
    if std_sz > 1.0:
        return float((current - mean_sz) / std_sz)
    if abs(current - mean_sz) < max(256.0, mean_sz * 2.0):
        return 0.0
    effective_std = max(64.0, mean_sz * 0.5)
    return float((current - mean_sz) / effective_std)


def _detect_protocol_shift(
    baseline: HostBaseline,
    current_proto: str | None,
) -> bool:
    """Return True if a brand-new protocol appears after an established baseline."""
    if current_proto is None or baseline.total_packets < 25:
        return False
    return baseline.protocol_counts.get(current_proto, 0) == 1


class HostProfiler:
    """Maintains rolling per-host traffic baselines and flags statistical shifts."""

    def __init__(
        self,
        *,
        baseline_seconds: float = 60.0,
        window_seconds: int = 60,
        z_threshold: float = 2.5,
        min_history_seconds: int = 5,
    ) -> None:
        """Initialize the per-host statistical profiler.

        Args:
            baseline_seconds: Warmup period before flagging statistical deviations.
            window_seconds: Rolling baseline window length in seconds.
            z_threshold: Absolute z-score threshold triggering deviation flags.
            min_history_seconds: Minimum distinct 1-second buckets before flagging.
        """
        if baseline_seconds < 0:
            raise ValueError("baseline_seconds must be >= 0")
        if window_seconds < 2:
            raise ValueError("window_seconds must be >= 2")
        if z_threshold <= 0:
            raise ValueError("z_threshold must be > 0")

        self.baseline_seconds = baseline_seconds
        self.window_seconds = window_seconds
        self.z_threshold = z_threshold
        self.min_history_seconds = min_history_seconds
        self._lock = threading.Lock()
        self._hosts: dict[str, HostBaseline] = {}
        self._start_time: float | None = None
        self._flagged_events: set[tuple[str, int, str]] = set()

    def update(self, pkt: ParsedPacket) -> dict[str, Any] | None:
        """Record packet telemetry for pkt.ip_src and return deviation info if anomalous."""
        if pkt.ip_src is None:
            return None

        now = pkt.timestamp
        sec = int(now)
        proto = pkt.effective_protocol

        with self._lock:
            if self._start_time is None:
                self._start_time = now

            baseline = self._hosts.get(pkt.ip_src)
            if baseline is None:
                baseline = HostBaseline(
                    ip=pkt.ip_src,
                    first_seen=now,
                    last_seen=now,
                    window_seconds=self.window_seconds,
                )
                self._hosts[pkt.ip_src] = baseline

            baseline.last_seen = max(baseline.last_seen, now)
            baseline.total_packets += 1
            baseline.total_bytes += pkt.packet_len
            baseline.payload_sizes.append(len(pkt.payload_bytes))
            baseline.protocol_counts[proto] += 1

            if baseline.second_buckets and baseline.second_buckets[-1][0] == sec:
                baseline.second_buckets[-1][1] += 1
            else:
                baseline.second_buckets.append([sec, 1])

            cutoff_sec = sec - self.window_seconds
            while baseline.second_buckets and baseline.second_buckets[0][0] < cutoff_sec:
                baseline.second_buckets.popleft()

            deviation = self._compute_deviation_locked(baseline, now, sec, proto)
            if deviation is None or not deviation["flagged"]:
                return None

            reason_key = ",".join(deviation["reasons"])
            flag_key = (pkt.ip_src, sec, reason_key)
            if flag_key in self._flagged_events:
                return None
            self._flagged_events.add(flag_key)
            return deviation

    def get_deviation(self, ip: str, now: float | None = None) -> dict[str, Any] | None:
        """Return rolling mean, std, current pps, and z-score for a tracked host."""
        with self._lock:
            baseline = self._hosts.get(ip)
            if baseline is None or not baseline.second_buckets:
                return None
            ref_time = now if now is not None else baseline.last_seen
            return self._compute_deviation_locked(baseline, ref_time, int(ref_time), None)

    def _compute_pps_stats(
        self,
        baseline: HostBaseline,
        current_sec: int,
    ) -> tuple[int, float, float, float] | None:
        """Return (current_pps, mean_pps, std_pps, z_score) or None if insufficient history."""
        if len(baseline.second_buckets) < 2:
            return None

        prior = [count for sec_val, count in baseline.second_buckets if sec_val < current_sec]
        if len(prior) < self.min_history_seconds:
            return None

        current_pps = next(
            (
                count
                for sec_val, count in reversed(baseline.second_buckets)
                if sec_val == current_sec
            ),
            0,
        )
        arr = np.asarray(prior, dtype=np.float64)
        mean_pps = float(np.mean(arr))
        std_pps = float(np.std(arr))
        effective_std = std_pps if std_pps > 0.05 else max(0.5, mean_pps * 0.25)
        z_score = float((current_pps - mean_pps) / effective_std)
        return current_pps, mean_pps, std_pps, z_score

    def _compute_deviation_locked(
        self,
        baseline: HostBaseline,
        now: float,
        current_sec: int,
        current_proto: str | None,
    ) -> dict[str, Any] | None:
        """Evaluate PPS, payload-size, and protocol-mix deviations."""
        pps_stats = self._compute_pps_stats(baseline, current_sec)
        if pps_stats is None:
            return None

        current_pps, mean_pps, std_pps, z_score = pps_stats
        payload_z = _compute_payload_z_score(baseline)
        proto_shift = _detect_protocol_shift(baseline, current_proto)

        elapsed_learning = (now - self._start_time) if self._start_time is not None else 0.0
        warmup_done = elapsed_learning >= self.baseline_seconds

        reasons: list[str] = []
        if abs(z_score) > self.z_threshold:
            reasons.append("pps_spike")
        if abs(payload_z) > self.z_threshold:
            reasons.append("payload_size_shift")
        if proto_shift:
            reasons.append("protocol_shift")

        flagged = warmup_done and bool(reasons)
        return {
            "ip": baseline.ip,
            "current_pps": current_pps,
            "mean_pps": mean_pps,
            "std_pps": std_pps,
            "z_score": z_score,
            "payload_z_score": payload_z,
            "protocol_shift": proto_shift,
            "reasons": reasons,
            "mean_payload_size": baseline.mean_payload_size,
            "protocol_mix": baseline.protocol_mix,
            "warmup_complete": warmup_done,
            "flagged": flagged,
        }

    def get_host_baseline(self, ip: str) -> HostBaseline | None:
        """Return the HostBaseline object for an IP if tracked."""
        with self._lock:
            return self._hosts.get(ip)
