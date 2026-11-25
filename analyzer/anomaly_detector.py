"""Decoupled rule orchestrator for protocol anomaly and scan detection."""

from __future__ import annotations

import threading
from collections import Counter

from analyzer.alert import Alert, AlertType
from analyzer.rules.checksum_rule import ChecksumRule
from analyzer.rules.flag_rule import FlagRule
from analyzer.rules.scan_rule import ScanDetector
from analyzer.rules.ttl_rule import TTLRule
from parser.parsed_packet import ParsedPacket


class AnomalyDetector:
    """Applies protocol and scan-signature rules to ParsedPacket objects."""

    def __init__(
        self,
        *,
        cooldown_seconds: float = 60.0,
        window_seconds: float = 10.0,
        syn_threshold: int = 20,
        port_threshold: int = 15,
        check_reserved_bits: bool = True,
    ) -> None:
        """Initialize all rule instances and alert rate-limiting state."""
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")

        self.cooldown_seconds = cooldown_seconds
        self._rules = (
            ChecksumRule(),
            TTLRule(),
            FlagRule(check_reserved_bits=check_reserved_bits),
            ScanDetector(
                window_seconds=window_seconds,
                syn_threshold=syn_threshold,
                port_threshold=port_threshold,
            ),
        )
        self._lock = threading.Lock()
        self._last_alert_time: dict[tuple[AlertType, str | None], float] = {}
        self._counts: Counter[AlertType] = Counter()

    def inspect(self, pkt: ParsedPacket) -> list[Alert]:
        """Run all anomaly rules on a ParsedPacket and apply per-source cooldown."""
        raw_alerts: list[Alert] = []
        for rule in self._rules:
            raw_alerts.extend(rule.evaluate(pkt))

        if not raw_alerts:
            return []

        emitted: list[Alert] = []
        with self._lock:
            for alert in raw_alerts:
                key = (alert.type, alert.src_ip)
                last_ts = self._last_alert_time.get(key)
                if (
                    self.cooldown_seconds > 0
                    and last_ts is not None
                    and (alert.timestamp - last_ts) < self.cooldown_seconds
                ):
                    continue
                self._last_alert_time[key] = alert.timestamp
                self._counts[alert.type] += 1
                emitted.append(alert)
        return emitted

    def get_counts(self) -> dict[AlertType, int]:
        """Return thread-safe snapshot of emitted alert counts by AlertType."""
        with self._lock:
            return dict(self._counts)
