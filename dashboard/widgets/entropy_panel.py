"""Per-flow payload Shannon entropy heatmap panel widget."""

from __future__ import annotations

from typing import Any

from rich.table import Table
from textual.widgets import Static


def _entropy_heat_bar(entropy: float) -> str:
    """Render an 8-block visual heat bar and color tag for 0..8 bits/byte."""
    filled = max(0, min(8, round(entropy)))
    bar = "█" * filled + "░" * (8 - filled)
    if entropy < 3.5:
        color = "green"
    elif entropy <= 6.0:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{bar} {entropy:.2f}[/{color}]"


class EntropyPanel(Static):
    """Renders a Rich table showing top payload-carrying flows and entropy heat."""

    def on_mount(self) -> None:
        """Render initial empty panel."""
        self.update_data([])

    def update_data(self, entropy_flows: list[dict[str, Any]]) -> None:
        """Render a Rich table of flows with entropy scores and classifications."""
        table = Table(title="Payload Entropy Heatmap", expand=True)
        table.add_column("Flow", overflow="ellipsis", no_wrap=True)
        table.add_column("Proto", no_wrap=True)
        table.add_column("Heat (0-8)", no_wrap=True)
        table.add_column("Class", no_wrap=True)

        if not entropy_flows:
            table.add_row("Waiting for payload data...", "-", "-", "-")
        else:
            for item in entropy_flows[:8]:
                entropy_val = float(item["mean_entropy"])
                label = str(item["entropy_label"])
                color = (
                    "green"
                    if entropy_val < 3.5
                    else ("yellow" if entropy_val <= 6.0 else "red")
                )
                flow_str = (
                    f"{item['src_ip']}:{item['src_port']} -> "
                    f"{item['dst_ip']}:{item['dst_port']}"
                )
                table.add_row(
                    flow_str,
                    str(item["protocol"]),
                    _entropy_heat_bar(entropy_val),
                    f"[{color}]{label}[/{color}]",
                )

        self.update(table)
