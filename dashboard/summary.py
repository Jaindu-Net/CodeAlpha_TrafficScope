"""Rich-formatted exit statistics summary report."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dashboard.widgets.top_talkers import format_bytes


def _bar(fraction: float, width: int = 20) -> str:
    """Render an ASCII/Unicode horizontal proportion bar."""
    filled = max(0, min(width, round(fraction * width)))
    return "█" * filled + "░" * (width - filled)


def print_exit_report(stats: dict[str, Any], console: Console | None = None) -> None:
    """Print TrafficScope capture summary, top IPs/ports, anomalies, and throughput."""
    out = console or Console()

    elapsed = float(stats.get("elapsed_s", 0.0))
    total_pkts = int(stats.get("total_packets", 0))
    total_bytes = int(stats.get("total_bytes", 0))
    app_drops = int(stats.get("dropped_packets", 0))
    kernel_drops = stats.get("kernel_dropped")
    avg_pps = float(stats.get("avg_pps", 0.0))
    peak_pps = float(stats.get("peak_pps", 0.0))
    total_anomalies = int(stats.get("total_anomalies", 0))

    drop_str = f"{app_drops:,} (queue)"
    if kernel_drops is not None:
        drop_str += f" | {int(kernel_drops):,} (kernel)"

    overview = (
        f"[bold]Source:[/bold] {stats.get('source_label', 'N/A')}    "
        f"[bold]Duration:[/bold] {elapsed:.2f}s\n"
        f"[bold]Packets Captured:[/bold] {total_pkts:,}    "
        f"[bold]Total Volume:[/bold] {format_bytes(total_bytes)}\n"
        f"[bold]Throughput:[/bold] avg {avg_pps:,.1f} pps | peak {peak_pps:,.1f} pps\n"
        f"[bold]Dropped Packets:[/bold] {drop_str}    "
        f"[bold]Anomalies Flagged:[/bold] {total_anomalies:,}"
    )
    out.print()
    out.print(Panel(overview, title="TrafficScope Session Summary", border_style="cyan"))

    # Protocol breakdown
    proto_counts: dict[str, int] = stats.get("protocol_counts", {})
    if proto_counts:
        proto_table = Table(title="Protocol Breakdown")
        proto_table.add_column("Protocol", style="bold cyan")
        proto_table.add_column("Packets", justify="right")
        proto_table.add_column("Share", justify="right")
        proto_table.add_column("Distribution")
        proto_total = sum(proto_counts.values()) or 1
        for proto, cnt in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
            frac = cnt / proto_total
            proto_table.add_row(proto, f"{cnt:,}", f"{frac * 100:5.1f}%", _bar(frac))
        out.print(proto_table)

    # Top IPs
    top_hosts: list[dict[str, Any]] = stats.get("top_hosts", [])
    if top_hosts:
        host_table = Table(title="Top Talkers (IPs)")
        host_table.add_column("IP Address", style="bold green")
        host_table.add_column("Volume", justify="right")
        host_table.add_column("Packets", justify="right")
        host_table.add_column("Protocol")
        host_table.add_column("OS Guess")
        for host in top_hosts[:5]:
            host_table.add_row(
                str(host["ip"]),
                format_bytes(int(host["bytes"])),
                f"{int(host['packets']):,}",
                str(host.get("protocol", "OTHER")),
                str(host.get("os_guess") or "—"),
            )
        out.print(host_table)

    # Top Destination Ports
    top_ports: list[tuple[int, int]] = stats.get("top_ports", [])
    if top_ports:
        port_table = Table(title="Top Ports")
        port_table.add_column("Port", justify="right", style="yellow")
        port_table.add_column("Packets", justify="right")
        for port, cnt in top_ports[:5]:
            port_table.add_row(str(port), f"{cnt:,}")
        out.print(port_table)

    # Anomaly Breakdown
    anomaly_counts: dict[Any, int] = stats.get("anomaly_counts", {})
    if anomaly_counts:
        anom_table = Table(title="Anomalies by Type")
        anom_table.add_column("Alert Type", style="bold red")
        anom_table.add_column("Count", justify="right")
        for atype, cnt in sorted(anomaly_counts.items(), key=lambda x: x[1], reverse=True):
            label = atype.value if hasattr(atype, "value") else str(atype)
            anom_table.add_row(label, f"{cnt:,}")
        out.print(anom_table)

    # Entropy summary
    entropy_summary: dict[str, int] = stats.get("entropy_summary", {})
    if any(entropy_summary.values()):
        ent_table = Table(title="Flow Payload Entropy Summary")
        ent_table.add_column("Classification", style="bold magenta")
        ent_table.add_column("Flows", justify="right")
        for label, cnt in entropy_summary.items():
            ent_table.add_row(label, f"{cnt:,}")
        out.print(ent_table)
