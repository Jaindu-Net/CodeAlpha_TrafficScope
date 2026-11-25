"""Shared multi-threaded packet processing pipeline for CLI and Web modes."""

from __future__ import annotations

import os
import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from scapy.packet import Packet

from analyzer import Alert, AlertType, AnomalyDetector, Severity
from capture import CaptureEngine, OfflineReader
from dashboard.tui import DashboardState
from export import FlowExporter, PcapWriter
from fingerprint import Fingerprinter
from parser import PacketParser, ParsedPacket
from parser.layers.application import DEFAULT_HTTP_PORTS
from profiler import FlowTracker, HostProfiler
from reassembly import IPDefragmenter, TCPReassembler

DEFAULT_OUTPUT_DIR = Path("output")
DEFAULT_PCAP_DIR = DEFAULT_OUTPUT_DIR / "pcap"
DEFAULT_JSON_DIR = DEFAULT_OUTPUT_DIR / "json"


def default_thread_count() -> int:
    """Return bounded default worker thread count based on available CPU cores."""
    return min(4, max(1, (os.cpu_count() or 2) - 1))


def parse_ports_arg(raw: str | None) -> frozenset[int]:
    """Parse a comma-separated port list string into validated port numbers."""
    if raw is None or not raw.strip():
        return DEFAULT_HTTP_PORTS
    ports: set[int] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if not token.isdigit():
            raise ValueError(f"Invalid port number in --http-ports: {token!r}")
        port = int(token)
        if not (1 <= port <= 65535):
            raise ValueError(f"Port out of range (1-65535): {port}")
        ports.add(port)
    if not ports:
        raise ValueError("--http-ports cannot be empty.")
    return frozenset(ports)


def build_statistical_alert(pkt: ParsedPacket, deviation: dict[str, Any]) -> Alert:
    """Create a STATISTICAL_ANOMALY alert from a HostProfiler deviation dict."""
    reasons = ", ".join(deviation.get("reasons", ())) or "rate_shift"
    return Alert(
        timestamp=pkt.timestamp,
        type=AlertType.STATISTICAL_ANOMALY,
        severity=Severity.MEDIUM,
        src_ip=pkt.ip_src,
        dst_ip=pkt.ip_dst,
        detail=(
            f"Behavioral deviation ({reasons}) for {pkt.ip_src}: "
            f"pps_z={deviation['z_score']:.2f}, "
            f"payload_z={deviation.get('payload_z_score', 0.0):.2f} "
            f"({deviation['current_pps']} pps vs mean {deviation['mean_pps']:.1f})"
        ),
        raw_context=deviation,
    )


def resolve_pcap_save_path(
    raw_path: str | Path,
    *,
    pcap_dir: Path = DEFAULT_PCAP_DIR,
) -> Path:
    """Place bare capture filenames inside output/pcap/ while keeping explicit paths."""
    target = Path(raw_path)
    if target.parent == Path("."):
        return pcap_dir / target.name
    return target


def resolve_pcap_read_path(
    raw_path: str | Path,
    *,
    pcap_dir: Path = DEFAULT_PCAP_DIR,
) -> Path:
    """Resolve PCAP read path, falling back to output/pcap/ for bare filenames."""
    target = Path(raw_path).expanduser()
    if target.exists() or target.parent != Path("."):
        return target
    fallback = pcap_dir / target.name
    return fallback if fallback.is_file() else target


def derive_flows_json_path(
    pcap_path: str | Path,
    *,
    json_dir: Path = DEFAULT_JSON_DIR,
    pcap_dir: Path = DEFAULT_PCAP_DIR,
) -> Path:
    """Compute `<stem>_flows.json` in output/json/ for managed PCAPs, else adjacent."""
    target = Path(pcap_path)
    if target.resolve().parent == pcap_dir.resolve():
        return json_dir / f"{target.stem}_flows.json"
    return target.with_name(f"{target.stem}_flows.json")


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
            alerts.append(build_statistical_alert(defragged, deviation))

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


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Configuration parameters for launching a live or offline TrafficScope pipeline."""

    source_label: str
    is_offline: bool
    target_iface: str = ""
    read_path: str | None = None
    save_path: str | None = None
    flows_save_path: str | None = None
    bpf_filter: str | None = None
    count: int | None = None
    timeout: float | None = None
    threads: int = 2
    no_payload: bool = False
    payload_bytes: int | None = None
    baseline_seconds: float = 60.0
    syn_threshold: int = 20
    port_threshold: int = 15
    z_threshold: float = 2.5
    http_ports: frozenset[int] = DEFAULT_HTTP_PORTS
    verbose: bool = False


@dataclass
class PipelineRuntime:
    """Holds instantiated session components for clean startup and teardown."""

    source_label: str
    save_path: str | None
    flows_save_path: str | None
    packet_queue: queue.Queue[Packet]
    stop_event: threading.Event
    producer_done: threading.Event
    reassembler: TCPReassembler
    flow_tracker: FlowTracker
    pcap_writer: PcapWriter | None
    dashboard_state: DashboardState
    workers: list[PipelineWorker]
    engine: CaptureEngine | None
    reader: OfflineReader | None
    producer_thread: threading.Thread
    producer_error: list[BaseException]


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


def start_pipeline(
    config: PipelineConfig,
    *,
    console: Console | None = None,
    opened_socket: Any | None = None,
) -> PipelineRuntime:
    """Instantiate modules, launch worker threads, and start live or offline producer."""
    if config.threads < 1:
        raise ValueError("--threads must be >= 1")

    packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=4096)
    stop_event = threading.Event()
    producer_done = threading.Event()

    parser = PacketParser(http_ports=config.http_ports)
    defragmenter = IPDefragmenter(parser=parser)
    reassembler = TCPReassembler()
    detector = AnomalyDetector(
        syn_threshold=config.syn_threshold,
        port_threshold=config.port_threshold,
    )
    flow_tracker = FlowTracker()
    host_profiler = HostProfiler(
        baseline_seconds=config.baseline_seconds,
        z_threshold=config.z_threshold,
    )
    fingerprinter = Fingerprinter()
    pcap_writer = PcapWriter(config.save_path) if config.save_path else None
    dashboard_state = DashboardState(
        config.source_label,
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
            verbose=config.verbose,
            print_lock=print_lock,
            console=console,
        )
        for idx in range(config.threads)
    ]
    for worker in workers:
        worker.start()

    producer_error: list[BaseException] = []
    engine: CaptureEngine | None = None
    reader: OfflineReader | None = None

    try:
        if config.is_offline:
            if not config.read_path:
                raise ValueError("read_path is required for offline pipeline mode.")
            reader = OfflineReader(
                packet_queue,
                count=config.count,
                no_payload=config.no_payload,
                payload_bytes_limit=config.payload_bytes,
                stop_event=stop_event,
            )
            producer_thread = threading.Thread(
                target=_run_offline_reader,
                args=(reader, config.read_path, producer_done, producer_error),
                name="offline-reader",
                daemon=True,
            )
            producer_thread.start()
        else:
            engine = CaptureEngine(
                config.target_iface,
                packet_queue,
                bpf_filter=config.bpf_filter,
                count=config.count,
                timeout=config.timeout,
                no_payload=config.no_payload,
                payload_bytes_limit=config.payload_bytes,
                opened_socket=opened_socket,
            )
            engine.start()
            producer_thread = threading.Thread(
                target=_watch_live_engine,
                args=(engine, producer_done),
                name="capture-watcher",
                daemon=True,
            )
            producer_thread.start()
    except Exception:
        stop_event.set()
        for worker in workers:
            worker.join(timeout=1.5)
        if pcap_writer is not None:
            pcap_writer.close()
        raise

    return PipelineRuntime(
        source_label=config.source_label,
        save_path=config.save_path,
        flows_save_path=config.flows_save_path,
        packet_queue=packet_queue,
        stop_event=stop_event,
        producer_done=producer_done,
        reassembler=reassembler,
        flow_tracker=flow_tracker,
        pcap_writer=pcap_writer,
        dashboard_state=dashboard_state,
        workers=workers,
        engine=engine,
        reader=reader,
        producer_thread=producer_thread,
        producer_error=producer_error,
    )


def sync_drop_stats(rt: PipelineRuntime) -> None:
    """Propagate producer drop stats into DashboardState."""
    stats_src = rt.engine if rt.engine is not None else rt.reader
    if stats_src is not None:
        st = stats_src.get_stats()
        rt.dashboard_state.update_drop_stats(st.dropped, st.kernel_dropped)


def shutdown_pipeline(rt: PipelineRuntime) -> None:
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
        if rt.flows_save_path or rt.save_path:
            flows_path = (
                Path(rt.flows_save_path)
                if rt.flows_save_path
                else derive_flows_json_path(rt.save_path or "")
            )
            FlowExporter(rt.flow_tracker.export_flows()).export_json(flows_path)

    rt.dashboard_state.mark_complete()
