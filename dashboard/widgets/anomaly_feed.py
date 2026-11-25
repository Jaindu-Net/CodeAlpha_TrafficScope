"""Scrolling live anomaly alert feed widget."""

from __future__ import annotations

from datetime import datetime

from textual.widgets import RichLog

from analyzer.alert import Alert, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim white",
}


class AnomalyFeed(RichLog):
    """Scrollable RichLog displaying timestamped protocol and scan alerts."""

    def on_mount(self) -> None:
        """Configure markup rendering and auto-scroll."""
        self.markup = True
        self.auto_scroll = True

    def append_alerts(self, alerts: list[Alert]) -> None:
        """Append new Alert records with severity-based color styling."""
        for alert in alerts:
            ts_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
            style = _SEVERITY_STYLES.get(alert.severity, "white")
            src = alert.src_ip or "?"
            dst = alert.dst_ip or "?"
            line = (
                f"[{style}][{ts_str}] [{alert.severity.value}] {alert.type.value}[/{style}] "
                f"{src} -> {dst} | {alert.detail}"
            )
            self.write(line, scroll_end=True)
