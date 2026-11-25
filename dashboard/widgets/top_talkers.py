"""Live top-talkers table widget enriched with passive OS guesses."""

from __future__ import annotations

from typing import Any

from textual.widgets import DataTable


def format_bytes(num_bytes: int) -> str:
    """Format byte counts into human-readable units."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{num_bytes} B"


class TopTalkers(DataTable):
    """Displays top N source/destination IP addresses sorted by byte volume."""

    def on_mount(self) -> None:
        """Initialize columns on mount."""
        self.add_columns("IP", "Bytes", "Pkts", "Proto", "OS Guess")
        self.cursor_type = "none"

    def update_data(self, hosts: list[dict[str, Any]]) -> None:
        """Refresh rows from aggregated host statistics."""
        self.clear()
        for host in hosts[:10]:
            self.add_row(
                str(host["ip"]),
                format_bytes(int(host["bytes"])),
                f"{int(host['packets']):,}",
                str(host.get("protocol", "OTHER")),
                str(host.get("os_guess") or "—"),
            )
