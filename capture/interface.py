"""Network interface discovery, selection, and Windows privilege verification."""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scapy.interfaces import conf as scapy_conf


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    """Metadata describing a local network capture interface."""

    index: int
    name: str
    description: str
    ip: str
    mac: str
    network_name: str


def is_elevated() -> bool:
    """Return True if the current process holds Administrator/root privileges."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid() == 0) if geteuid is not None else False


def warn_if_not_elevated(
    console: Console | None = None,
    *,
    exit_on_fail: bool = True,
) -> bool:
    """Verify elevation for live capture, warning clearly if unprivileged.

    Args:
        console: Optional Rich console to print the warning to.
        exit_on_fail: When True, exits with status code 1 if not elevated.

    Returns:
        True if elevated, False otherwise (when exit_on_fail is False).
    """
    if is_elevated():
        return True

    target_console = console or Console(stderr=True)
    message = (
        "[bold red]Administrator privileges are required for live packet capture.[/bold red]\n\n"
        "On Windows 10/11:\n"
        "  1. Ensure [bold]Npcap[/bold] is installed with "
        "[bold]WinPcap API-compatible Mode[/bold] enabled.\n"
        "  2. Open PowerShell or Windows Terminal via [bold]Run as administrator[/bold].\n"
        "  3. Or replay an existing capture without elevation using "
        "[cyan]--read <file.pcap>[/cyan]."
    )
    target_console.print(Panel(message, title="Elevation Required", border_style="red"))
    if exit_on_fail:
        sys.exit(1)
    return False


def list_interfaces() -> list[InterfaceInfo]:
    """Return available Scapy capture interfaces sorted by index and name."""
    raw_ifaces = list(scapy_conf.ifaces.values())
    interfaces: list[InterfaceInfo] = []
    for pos, iface in enumerate(raw_ifaces):
        raw_index = getattr(iface, "index", None)
        iface_index = raw_index if isinstance(raw_index, int) else pos
        interfaces.append(
            InterfaceInfo(
                index=iface_index,
                name=str(getattr(iface, "name", "") or f"iface-{pos}"),
                description=str(getattr(iface, "description", "") or ""),
                ip=str(getattr(iface, "ip", "") or "N/A"),
                mac=str(getattr(iface, "mac", "") or "N/A"),
                network_name=str(getattr(iface, "network_name", "") or ""),
            )
        )
    interfaces.sort(key=lambda item: (item.index, item.name.lower()))
    return interfaces


def format_interfaces_table(interfaces: list[InterfaceInfo]) -> Table:
    """Build a Rich table displaying available capture interfaces."""
    table = Table(title="Available Network Interfaces")
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold green")
    table.add_column("IP Address", style="yellow")
    table.add_column("MAC", style="dim")
    table.add_column("Description")

    for seq, iface in enumerate(interfaces):
        table.add_row(
            str(seq),
            iface.name,
            iface.ip,
            iface.mac,
            iface.description or iface.network_name,
        )
    return table


def _match_interface(query: str, interfaces: list[InterfaceInfo]) -> InterfaceInfo:
    """Resolve an interface query by index, exact name/GUID, or unique substring."""
    stripped = query.strip()
    if not stripped:
        raise ValueError("Interface selector cannot be empty.")

    if stripped.isdigit():
        seq_idx = int(stripped)
        if 0 <= seq_idx < len(interfaces):
            return interfaces[seq_idx]
        for iface in interfaces:
            if iface.index == seq_idx:
                return iface
        raise ValueError(f"Interface index {seq_idx} is out of range (0-{len(interfaces) - 1}).")

    lowered = stripped.lower()
    for iface in interfaces:
        if iface.name.lower() == lowered or iface.network_name.lower() == lowered:
            return iface

    partial_matches = [
        iface
        for iface in interfaces
        if lowered in iface.name.lower()
        or lowered in iface.description.lower()
        or lowered in iface.network_name.lower()
    ]
    if len(partial_matches) == 1:
        return partial_matches[0]
    if len(partial_matches) > 1:
        names = ", ".join(item.name for item in partial_matches)
        raise ValueError(f"Ambiguous interface '{query}'; matched: {names}")

    available = ", ".join(item.name for item in interfaces)
    raise ValueError(f"Unknown interface '{query}'. Available: {available}")


def select_interface(
    iface_name: str | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    console: Console | None = None,
) -> InterfaceInfo:
    """Resolve a user-specified interface or prompt interactively.

    Args:
        iface_name: Interface name, NPF device string, or list index. If None,
            displays available interfaces and prompts for selection.
        input_fn: Input callable used for interactive selection (injectable for tests).
        console: Optional Rich console for rendering the interface table.

    Returns:
        The resolved InterfaceInfo object.

    Raises:
        RuntimeError: If no capture interfaces are detected on the system.
        ValueError: If the requested or entered interface selector is invalid.
    """
    interfaces = list_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No capture interfaces found. Ensure Npcap is installed in WinPcap API-compatible mode."
        )

    if iface_name is not None:
        return _match_interface(iface_name, interfaces)

    target_console = console or Console()
    target_console.print(format_interfaces_table(interfaces))
    choice = input_fn("Select interface number [0]: ").strip()
    return _match_interface(choice or "0", interfaces)
