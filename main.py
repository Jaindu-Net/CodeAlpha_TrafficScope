"""CLI entry point and multi-threaded pipeline orchestrator for TrafficScope."""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from scapy.packet import Packet

from analyzer import Alert, AlertType, AnomalyDetector, Severity
from capture import (
    CaptureEngine,
    OfflineReader,
    format_interfaces_table,
    list_interfaces,
    select_interface,
    warn_if_not_elevated,
)
from dashboard import DashboardState, TrafficScopeApp, print_exit_report
from export import FlowExporter, PcapWriter
from fingerprint import Fingerprinter
from parser import PacketParser, ParsedPacket
from profiler import FlowTracker, HostProfiler
from reassembly import IPDefragmenter, TCPReassembler


def default_thread_count() -> int:
    """Return bounded default worker thread count based on available CPU cores."""
    return min(4, max(1, (os.cpu_count() or 2) - 1))


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the TrafficScope CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="trafficscope",
        description="TrafficScope — Multi-threaded Windows Network Sniffer & Traffic Analyzer",
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
        help="Absolute z-score threshold for host rate deviation alerts.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-packet summaries and live alerts in non-dashboard mode.",
    )
    return parser


class PipelineWorker(threading.Thread):
    """Consumer thread running dissection, reassembly, anomaly, profile, and fingerprint."""

    def __init__(
        self,
        worker_id: int,
        packet_queue: queue.Queue[Packet],
        stop_event: threading.Event,
        *,
        parser: PacketParser,
        defragmenter: IPDefragmenter,
        reassembler: TCPReassembler,
        detector: AnomalyDetector,
        flow_tracker: FlowTracker,
        host_profiler: HostProfiler,
        fingerprinter: Fingerprinter,
        dashboard_state: DashboardState,
        pcap_writer: PcapWriter | None = None,
        verbose: bool = False,
        print_lock: threading.Lock | None = None,
        console: Console | None = None,
    ) -> None:
        super().__init__(name=f"worker-{worker_id}", daemon=True)
        self._queue = packet_queue
        self._stop_event = stop_event
        self._parser = parser
        self._defragmenter = defragmenter
        self._reassembler = reassembler
        self._detector = detector
        self._flow_tracker = flow_tracker
        self._host_profiler = host_profiler
        self._fingerprinter = fingerprinter
        self._state = dashboard_state
        self._pcap_writer = pcap_writer
        self._verbose = verbose
        self._print_lock = print_lock or threading.Lock()
        self._console = console

    def run(self) -> None:
        """Drain packets from the queue until stop_event is set and queue is empty."""
        while not (self._stop_event.is_set() and self._queue.empty()):
            try:
                raw_pkt = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                self._process_packet(raw_pkt)
            finally:
                self._queue.task_done()

    def _process_packet(self, raw_pkt: Packet) -> None:
        """Run one packet through all analysis stages safely."""
        if self._pcap_writer is not None:
            self._pcap_writer.write(raw_pkt)

        parsed = self._parser.parse(raw_pkt)
        defragged = self._defragmenter.add_fragment(parsed)
        if defragged is None:
            return

        self._reassembler.add_segment(defragged)
        alerts = list(self._detector.inspect(defragged))
        self._flow_tracker.update(defragged)

        deviation = self._host_profiler.update(defragged)
        if deviation is not None and deviation.get("flagged"):
            alerts.append(_build_statistical_alert(defragged, deviation))

        self._fingerprinter.fingerprint(defragged)
        self._state.record_packet(defragged)
        self._state.record_alerts(alerts)

        if self._verbose and self._console is not None:
            self._log_verbose(defragged, alerts)

    def _log_verbose(self, pkt: ParsedPacket, alerts: list[Alert]) -> None:
        """Print concise packet and alert lines thread-safely."""
        assert self._console is not None
        with self._print_lock:
            self._console.print(f"[dim]{pkt!r}[/dim]", highlight=False)
            for alert in alerts:
                self._console.print(
                    f"[bold red][ALERT {alert.type.value}][/bold red] "
                    f"{alert.src_ip} -> {alert.dst_ip}: {alert.detail}",
                    highlight=False,
                )


def _build_statistical_alert(pkt: ParsedPacket, deviation: dict[str, Any]) -> Alert:
    """Create a STATISTICAL_ANOMALY alert from a HostProfiler deviation dict."""
    return Alert(
        timestamp=pkt.timestamp,
        type=AlertType.STATISTICAL_ANOMALY,
        severity=Severity.MEDIUM,
        src_ip=pkt.ip_src,
        dst_ip=pkt.ip_dst,
        detail=(
            f"Traffic rate deviation for {pkt.ip_src}: "
            f"z={deviation['z_score']:.2f} "
            f"({deviation['current_pps']} pps vs mean {deviation['mean_pps']:.1f})"
        ),
        raw_context=deviation,
    )


def _derive_flows_json_path(pcap_path: str) -> Path:
    """Compute `<stem>_flows.json` path adjacent to a `--save` PCAP file."""
    target = Path(pcap_path)
    return target.with_name(f"{target.stem}_flows.json")


@dataclass
class _PipelineRuntime:
    """Holds instantiated session components for clean startup and teardown."""

    source_label: str
    packet_queue: queue.Queue[Packet]
    stop_event: threading.Event
    producer_done: threading.Event
    flow_tracker: FlowTracker
    pcap_writer: PcapWriter | None
    dashboard_state: DashboardState
    workers: list[PipelineWorker]
    engine: CaptureEngine | None
    reader: OfflineReader | None
    producer_thread: threading.Thread
    producer_error: list[BaseException]


def _resolve_capture_source(args: argparse.Namespace, out: Console) -> tuple[bool, str, str]:
    """Validate privileges and select live interface or offline PCAP path."""
    if args.read is not None:
        return True, "", f"PCAP: {args.read}"

    warn_if_not_elevated(console=out, exit_on_fail=True)
    iface_info = select_interface(args.iface, console=out)
    target_iface = iface_info.network_name or iface_info.name
    return False, target_iface, iface_info.name


def _start_pipeline(args: argparse.Namespace, out: Console) -> _PipelineRuntime:
    """Instantiate all pipeline modules, workers, and capture/replay producer."""
    is_offline, target_iface, source_label = _resolve_capture_source(args, out)
    packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=4096)
    stop_event = threading.Event()
    producer_done = threading.Event()

    parser = PacketParser()
    defragmenter = IPDefragmenter(parser=parser)
    reassembler = TCPReassembler()
    detector = AnomalyDetector(
        syn_threshold=args.syn_threshold,
        port_threshold=args.port_threshold,
    )
    flow_tracker = FlowTracker()
    host_profiler = HostProfiler(
        baseline_seconds=args.baseline_seconds,
        z_threshold=args.z_threshold,
    )
    fingerprinter = Fingerprinter()
    pcap_writer = PcapWriter(args.save) if args.save else None
    dashboard_state = DashboardState(
        source_label,
        flow_tracker=flow_tracker,
        fingerprinter=fingerprinter,
    )

    print_lock = threading.Lock()
    workers = [
        PipelineWorker(
            idx + 1,
            packet_queue,
            stop_event,
            parser=parser,
            defragmenter=defragmenter,
            reassembler=reassembler,
            detector=detector,
            flow_tracker=flow_tracker,
            host_profiler=host_profiler,
            fingerprinter=fingerprinter,
            dashboard_state=dashboard_state,
            pcap_writer=pcap_writer,
            verbose=(args.verbose and not args.dashboard),
            print_lock=print_lock,
            console=out,
        )
        for idx in range(args.threads)
    ]
    for worker in workers:
        worker.start()

    producer_error: list[BaseException] = []
    engine: CaptureEngine | None = None
    reader: OfflineReader | None = None

    if is_offline:
        reader = OfflineReader(
            packet_queue,
            count=args.count,
            no_payload=args.no_payload,
            payload_bytes_limit=args.payload_bytes,
            stop_event=stop_event,
        )
        producer_thread = threading.Thread(
            target=_run_offline_reader,
            args=(reader, args.read, producer_done, producer_error),
            name="offline-reader",
            daemon=True,
        )
        producer_thread.start()
    else:
        engine = CaptureEngine(
            target_iface,
            packet_queue,
            bpf_filter=args.bpf_filter,
            count=args.count,
            timeout=args.timeout,
            no_payload=args.no_payload,
            payload_bytes_limit=args.payload_bytes,
        )
        engine.start()
        producer_thread = threading.Thread(
            target=_watch_live_engine,
            args=(engine, producer_done),
            name="capture-watcher",
            daemon=True,
        )
        producer_thread.start()

    return _PipelineRuntime(
        source_label=source_label,
        packet_queue=packet_queue,
        stop_event=stop_event,
        producer_done=producer_done,
        flow_tracker=flow_tracker,
        pcap_writer=pcap_writer,
        dashboard_state=dashboard_state,
        workers=workers,
        engine=engine,
        reader=reader,
        producer_thread=producer_thread,
        producer_error=producer_error,
    )


def _run_offline_reader(
    reader: OfflineReader,
    pcap_path: str,
    producer_done: threading.Event,
    producer_error: list[BaseException],
) -> None:
    """Execute OfflineReader in a background thread and record errors."""
    try:
        reader.read(pcap_path)
    except BaseException as exc:
        producer_error.append(exc)
    finally:
        producer_done.set()


def _watch_live_engine(engine: CaptureEngine, producer_done: threading.Event) -> None:
    """Wait for CaptureEngine termination and signal completion."""
    engine.join()
    producer_done.set()


def _sync_drop_stats(rt: _PipelineRuntime) -> None:
    """Propagate producer drop stats into DashboardState."""
    stats_src = rt.engine if rt.engine is not None else rt.reader
    if stats_src is not None:
        st = stats_src.get_stats()
        rt.dashboard_state.update_drop_stats(st.dropped, st.kernel_dropped)


def _run_foreground_loop(rt: _PipelineRuntime, args: argparse.Namespace, out: Console) -> None:
    """Run either the live Textual TUI or CLI wait loop until completion or Ctrl+C."""
    if args.dashboard:
        def _coordinator() -> None:
            while not rt.stop_event.is_set():
                _sync_drop_stats(rt)
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
        _sync_drop_stats(rt)
        time.sleep(0.1)


def _shutdown_pipeline(rt: _PipelineRuntime, save_path: str | None) -> None:
    """Stop capture, drain worker threads, flush exports, and finalize timestamps."""
    rt.stop_event.set()
    if rt.engine is not None:
        final_cap = rt.engine.stop()
        rt.dashboard_state.update_drop_stats(final_cap.dropped, final_cap.kernel_dropped)
    elif rt.reader is not None:
        final_cap = rt.reader.get_stats()
        rt.dashboard_state.update_drop_stats(final_cap.dropped, final_cap.kernel_dropped)

    rt.producer_thread.join(timeout=2.0)
    for worker in rt.workers:
        worker.join(timeout=3.0)

    if rt.pcap_writer is not None:
        rt.pcap_writer.close()
        if save_path:
            flows_path = _derive_flows_json_path(save_path)
            FlowExporter(rt.flow_tracker.export_flows()).export_json(flows_path)

    rt.dashboard_state.mark_complete()


def run_session(args: argparse.Namespace, *, console: Console | None = None) -> dict[str, Any]:
    """Wire modules, run capture or offline replay, export results, and report stats."""
    out = console or Console()
    if args.threads < 1:
        raise ValueError("--threads must be >= 1")

    if args.iface == "?":
        ifaces = list_interfaces()
        out.print(format_interfaces_table(ifaces))
        return {"listed_interfaces": len(ifaces)}

    rt = _start_pipeline(args, out)
    try:
        _run_foreground_loop(rt, args, out)
    except KeyboardInterrupt:
        out.print("\n[yellow]Stopping capture...[/yellow]")
    finally:
        _shutdown_pipeline(rt, args.save)

    if rt.producer_error:
        raise rt.producer_error[0]

    summary_snap = rt.dashboard_state.snapshot()
    print_exit_report(summary_snap, console=out)
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
