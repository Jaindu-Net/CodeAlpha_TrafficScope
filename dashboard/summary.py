"""Rich-formatted exit statistics summary report."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dashboard.widgets.top_talkers import format_bytes


def _bar(fraction: float, width: int = 20) -> str:
    """Render a Unicode horizontal proportion bar."""
    filled = max(0, min(width, round(fraction * width)))
    return "█" * filled + "░" * (width - filled)


def _render_overview(stats: dict[str, Any], out: Console) -> None:
    """Render top-level session duration, volume, throughput, and drops panel."""
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


def _render_protocol_table(proto_counts: dict[str, int], out: Console) -> None:
    """Render protocol packet counts and visual share bars."""
    if not proto_counts:
        return
    table = Table(title="Protocol Breakdown")
    table.add_column("Protocol", style="bold cyan")
    table.add_column("Packets", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Distribution")
    total = sum(proto_counts.values()) or 1
    for proto, cnt in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
        frac = cnt / total
        table.add_row(proto, f"{cnt:,}", f"{frac * 100:5.1f}%", _bar(frac))
    out.print(table)


def _render_top_hosts(top_hosts: list[dict[str, Any]], out: Console) -> None:
    """Render top 5 host IPs by byte volume alongside passive OS guesses."""
    if not top_hosts:
        return
    table = Table(title="Top Talkers (IPs)")
    table.add_column("IP Address", style="bold green")
    table.add_column("Volume", justify="right")
    table.add_column("Packets", justify="right")
    table.add_column("Protocol")
    table.add_column("OS Guess")
    for host in top_hosts[:5]:
        table.add_row(
            str(host["ip"]),
            format_bytes(int(host["bytes"])),
            f"{int(host['packets']):,}",
            str(host.get("protocol", "OTHER")),
            str(host.get("os_guess") or "—"),
        )
    out.print(table)


def _render_top_ports(top_ports: list[tuple[int, int]], out: Console) -> None:
    """Render top 5 destination ports observed."""
    if not top_ports:
        return
    table = Table(title="Top Ports")
    table.add_column("Port", justify="right", style="yellow")
    table.add_column("Packets", justify="right")
    for port, cnt in top_ports[:5]:
        table.add_row(str(port), f"{cnt:,}")
    out.print(table)


def _render_anomalies(anomaly_counts: dict[Any, int], out: Console) -> None:
    """Render counts of detected anomalies grouped by AlertType."""
    if not anomaly_counts:
        return
    table = Table(title="Anomalies by Type")
    table.add_column("Alert Type", style="bold red")
    table.add_column("Count", justify="right")
    for atype, cnt in sorted(anomaly_counts.items(), key=lambda x: x[1], reverse=True):
        label = atype.value if hasattr(atype, "value") else str(atype)
        table.add_row(label, f"{cnt:,}")
    out.print(table)


def _render_entropy_summary(entropy_summary: dict[str, int], out: Console) -> None:
    """Render counts of flows across Shannon entropy classification buckets."""
    if not any(entropy_summary.values()):
        return
    table = Table(title="Flow Payload Entropy Summary")
    table.add_column("Classification", style="bold magenta")
    table.add_column("Flows", justify="right")
    for label, cnt in entropy_summary.items():
        table.add_row(label, f"{cnt:,}")
    out.print(table)


def print_exit_report(stats: dict[str, Any], console: Console | None = None) -> None:
    """Print TrafficScope capture summary, top IPs/ports, anomalies, and throughput."""
    out = console or Console()
    _render_overview(stats, out)
    _render_protocol_table(stats.get("protocol_counts", {}), out)
    _render_top_hosts(stats.get("top_hosts", []), out)
    _render_top_ports(stats.get("top_ports", []), out)
    _render_anomalies(stats.get("anomaly_counts", {}), out)
    _render_entropy_summary(stats.get("entropy_summary", {}), out)
