"""Dual-mode (CLI/TUI + Cyber SOC Web Dashboard) entry point for TrafficScope."""

from __future__ import annotations

import argparse
import sys
import threading
import time
from collections.abc import Sequence
from typing import Any

from rich.console import Console

from capture import format_interfaces_table, list_interfaces, select_interface, warn_if_not_elevated
from dashboard import (
    CaptureSessionError,
    CaptureSessionManager,
    TrafficScopeApp,
    print_exit_report,
    print_followed_streams,
    run_web_server,
)
from pipeline import (
    PipelineConfig,
    PipelineRuntime,
    default_thread_count,
    derive_flows_json_path,
    parse_ports_arg,
    resolve_pcap_read_path,
    resolve_pcap_save_path,
    shutdown_pipeline,
    start_pipeline,
    sync_drop_stats,
)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the TrafficScope CLI and Web Dashboard argument parser."""
    parser = argparse.ArgumentParser(
        prog="trafficscope",
        description="TrafficScope — Dual-Mode Windows Network Sniffer & Cyber SOC Analyzer",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the Cyber SOC Web Dashboard on localhost (no capture flags required).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Localhost TCP port for --web mode (default: 5000).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the browser when launching --web mode.",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface name, index, or '?' to list interfaces.",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        type=str,
        default=None,
        help="Optional BPF capture filter (e.g. 'tcp port 80').",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Stop after capturing/reading N packets.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Stop live capture after N seconds.",
    )
    parser.add_argument(
        "--save",
        type=str,
        default=None,
        help="Save raw captured packets to .pcap (also writes *_flows.json).",
    )
    parser.add_argument(
        "--read",
        type=str,
        default=None,
        help="Replay an existing .pcap file instead of live capture (no admin needed).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=default_thread_count(),
        help="Number of parallel parsing/analysis worker threads.",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Strip Raw payload bytes after header capture (privacy/memory mode).",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=None,
        help="Truncate Raw payload bytes per packet to at most N bytes.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the live Textual terminal dashboard.",
    )
    parser.add_argument(
        "--baseline-seconds",
        type=float,
        default=60.0,
        help="Warmup seconds before flagging per-host statistical rate deviations.",
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=20,
        help="SYN-without-ACK threshold per 10s window before flagging SYN_FLOOD.",
    )
    parser.add_argument(
        "--port-threshold",
        type=int,
        default=15,
        help="Distinct destination ports per 10s window before flagging PORT_SWEEP.",
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=2.5,
        help="Absolute z-score threshold for host rate/payload deviation alerts.",
    )
    parser.add_argument(
        "--http-ports",
        type=str,
        default=None,
        help="Comma-separated TCP ports dissected as HTTP (default: 80,8080,3000,8000,8008).",
    )
    parser.add_argument(
        "--follow-streams",
        action="store_true",
        help="Print reconstructed TCP stream conversations at exit.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-packet summaries and live alerts in non-dashboard mode.",
    )
    return parser


def _resolve_capture_source(args: argparse.Namespace, out: Console) -> tuple[bool, str, str]:
    """Validate privileges and select live interface or offline PCAP source."""
    if args.read is not None:
        return True, "", f"PCAP: {args.read}"

    warn_if_not_elevated(console=out, exit_on_fail=True)
    iface_info = select_interface(args.iface, console=out)
    target_iface = iface_info.network_name or iface_info.name
    return False, target_iface, iface_info.name


def _run_foreground_loop(rt: PipelineRuntime, args: argparse.Namespace, out: Console) -> None:
    """Run either the live Textual TUI or CLI wait loop until completion or Ctrl+C."""
    if args.dashboard:
        def _coordinator() -> None:
            while not rt.stop_event.is_set():
                sync_drop_stats(rt)
                if rt.producer_done.is_set() and rt.packet_queue.empty():
                    rt.dashboard_state.mark_complete()
                    break
                time.sleep(0.25)

        threading.Thread(target=_coordinator, daemon=True).start()
        TrafficScopeApp(rt.dashboard_state, stop_event=rt.stop_event).run()
        return

    if not args.verbose:
        out.print(
            f"[bold cyan]TrafficScope[/bold cyan] running on "
            f"[green]{rt.source_label}[/green] ({args.threads} workers). "
            "Press Ctrl+C to stop."
        )
    while not rt.producer_done.is_set() or not rt.packet_queue.empty():
        sync_drop_stats(rt)
        time.sleep(0.1)


def _run_web_mode(args: argparse.Namespace, out: Console) -> dict[str, Any]:
    """Launch the Cyber SOC Web Dashboard and optionally preload a PCAP replay."""
    manager = CaptureSessionManager()
    try:
        if args.read:
            manager.start_replay_path(
                args.read,
                options={
                    "bpf_filter": args.bpf_filter,
                    "count": args.count,
                    "threads": args.threads,
                    "no_payload": args.no_payload,
                    "payload_bytes": args.payload_bytes,
                    "baseline_seconds": args.baseline_seconds,
                    "http_ports": args.http_ports,
                },
            )
        run_web_server(
            port=args.port,
            open_browser=not args.no_browser,
            console=out,
            session_manager=manager,
        )
        return {"web_mode": True, "port": args.port}
    except CaptureSessionError as exc:
        raise ValueError(str(exc)) from exc
    finally:
        manager.close()


def run_session(args: argparse.Namespace, *, console: Console | None = None) -> dict[str, Any]:
    """Wire modules, run Web UI, Textual TUI, or CLI capture session cleanly."""
    out = console or Console()
    if args.threads < 1:
        raise ValueError("--threads must be >= 1")

    if getattr(args, "web", False):
        return _run_web_mode(args, out)

    if args.iface == "?":
        ifaces = list_interfaces()
        out.print(format_interfaces_table(ifaces))
        return {"listed_interfaces": len(ifaces)}

    http_ports = parse_ports_arg(args.http_ports)
    resolved_read = str(resolve_pcap_read_path(args.read)) if args.read else None
    resolved_save = str(resolve_pcap_save_path(args.save)) if args.save else None
    resolved_flows = str(derive_flows_json_path(resolved_save)) if resolved_save else None
    is_offline, target_iface, source_label = _resolve_capture_source(args, out)
    config = PipelineConfig(
        source_label=source_label,
        is_offline=is_offline,
        target_iface=target_iface,
        read_path=resolved_read,
        save_path=resolved_save,
        flows_save_path=resolved_flows,
        bpf_filter=args.bpf_filter,
        count=args.count,
        timeout=args.timeout,
        threads=args.threads,
        no_payload=args.no_payload,
        payload_bytes=args.payload_bytes,
        baseline_seconds=args.baseline_seconds,
        syn_threshold=args.syn_threshold,
        port_threshold=args.port_threshold,
        z_threshold=args.z_threshold,
        http_ports=http_ports,
        verbose=(args.verbose and not args.dashboard),
    )

    rt = start_pipeline(config, console=out)
    try:
        _run_foreground_loop(rt, args, out)
    except KeyboardInterrupt:
        out.print("\n[yellow]Stopping capture...[/yellow]")
    finally:
        shutdown_pipeline(rt)

    if rt.producer_error:
        raise rt.producer_error[0]

    summary_snap = rt.dashboard_state.snapshot()
    summary_snap["http_exchanges"] = rt.reassembler.get_all_http_exchanges()
    print_exit_report(summary_snap, console=out)
    if args.follow_streams:
        print_followed_streams(rt.reassembler.get_all_streams_text(), console=out)
    return summary_snap


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning process exit code."""
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args(argv)
    try:
        run_session(args)
        return 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        Console(stderr=True).print(f"[bold red]Error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
