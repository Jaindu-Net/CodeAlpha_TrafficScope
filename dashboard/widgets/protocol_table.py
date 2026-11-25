"""Live protocol breakdown table widget."""

from __future__ import annotations

from textual.widgets import DataTable


class ProtocolTable(DataTable):
    """Displays live protocol counts and percentage share."""

    def on_mount(self) -> None:
        """Initialize table columns on mount."""
        self.add_columns("Protocol", "Count", "%")
        self.cursor_type = "none"

    def update_data(self, protocol_counts: dict[str, int]) -> None:
        """Refresh rows from a snapshot mapping protocol -> packet count."""
        self.clear()
        total = sum(protocol_counts.values())
        if total == 0:
            return
        for proto, count in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True):
            pct = (count / total) * 100.0
            self.add_row(proto, f"{count:,}", f"{pct:5.1f}%")
