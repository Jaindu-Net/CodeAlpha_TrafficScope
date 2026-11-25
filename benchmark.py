"""Replay benchmark measuring TrafficScope parser and pipeline throughput."""

from __future__ import annotations

import argparse
import os
import platform
import queue
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import rdpcap, wrpcap

from analyzer import AnomalyDetector
from capture import OfflineReader
from fingerprint import Fingerprinter
from parser import PacketParser
from profiler import FlowTracker, HostProfiler
from reassembly import IPDefragmenter, TCPReassembler


def generate_benchmark_pcap(path: Path, count: int) -> None:
    """Create a realistic mixed-protocol synthetic PCAP for repeatable benchmarks."""
    pkts: list[Packet] = []
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    for idx in range(count):
        mod = idx % 3
        if mod == 0:
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.168.1.10", dst="93.184.216.34", ttl=128)
                / TCP(sport=40000 + (idx % 1000), dport=80, flags="PA", seq=100 + idx)
                / Raw(http_payload)
            )
        elif mod == 1:
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.168.1.10", dst="8.8.8.8", ttl=64)
                / UDP(sport=50000 + (idx % 500), dport=53)
                / DNS(id=idx & 0xFFFF, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
            )
        else:
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.168.1.20", dst="10.0.0.5", ttl=64)
                / TCP(sport=55000 + (idx % 100), dport=443, flags="S", window=29200, seq=idx)
            )
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def benchmark_parser_loop(packets: list[Packet]) -> dict[str, float]:
    """Measure pure PacketParser throughput in a tight single-thread loop."""
    parser = PacketParser()
    total_bytes = sum(len(bytes(p)) for p in packets)
    start = time.perf_counter()
    for pkt in packets:
        parser.parse(pkt)
    elapsed = max(1e-9, time.perf_counter() - start)
    return {
        "packets": float(len(packets)),
        "duration_s": elapsed,
        "pps": len(packets) / elapsed,
        "mb_per_s": (total_bytes / (1024 * 1024)) / elapsed,
    }


def benchmark_pipeline(pcap_path: Path, num_threads: int) -> dict[str, float]:
    """Measure OfflineReader -> Queue -> N workers full analysis throughput."""
    packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=4096)
    stop_event = threading.Event()
    parser = PacketParser()
    defrag = IPDefragmenter(parser=parser)
    reassembler = TCPReassembler()
    detector = AnomalyDetector()
    tracker = FlowTracker()
    profiler = HostProfiler()
    fp = Fingerprinter()

    total_bytes = 0
    bytes_lock = threading.Lock()

    def _worker() -> None:
        nonlocal total_bytes
        local_bytes = 0
        while not (stop_event.is_set() and packet_queue.empty()):
            try:
                raw = packet_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                parsed = parser.parse(raw)
                local_bytes += parsed.packet_len
                ready = defrag.add_fragment(parsed)
                if ready is not None:
                    reassembler.add_segment(ready)
                    detector.inspect(ready)
                    tracker.update(ready)
                    profiler.update(ready)
                    fp.fingerprint(ready)
            finally:
                packet_queue.task_done()
        with bytes_lock:
            total_bytes += local_bytes

    workers = [threading.Thread(target=_worker, daemon=True) for _ in range(num_threads)]
    for w in workers:
        w.start()

    reader = OfflineReader(packet_queue, stop_event=stop_event)
    start = time.perf_counter()
    cap_stats = reader.read(pcap_path)
    packet_queue.join()
    stop_event.set()
    for w in workers:
        w.join()
    elapsed = max(1e-9, time.perf_counter() - start)

    return {
        "threads": float(num_threads),
        "packets": float(cap_stats.captured),
        "duration_s": elapsed,
        "pps": cap_stats.captured / elapsed,
        "mb_per_s": (total_bytes / (1024 * 1024)) / elapsed,
    }


def write_results_markdown(
    output_path: Path,
    pcap_label: str,
    parser_res: dict[str, float],
    pipeline_results: list[dict[str, float]],
) -> None:
    """Write benchmark results and environment metadata to docs/benchmark_results.md."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# TrafficScope Benchmark Results",
        "",
        f"- **Run Date:** {now_iso}",
        f"- **OS:** {platform.platform()}",
        f"- **Python:** {platform.python_version()}",
        f"- **Logical CPUs:** {os.cpu_count()}",
        f"- **Test Dataset:** {pcap_label} ({int(parser_res['packets']):,} packets)",
        "",
        "## Methodology",
        "",
        "1. **Raw Parser Tight Loop:** Pre-loads packets in memory and times "
        "`PacketParser.parse()` in a single thread to establish the CPU dissection ceiling.",
        "2. **Full Producer-Consumer Pipeline:** Streams the PCAP via `OfflineReader` into a "
        "bounded `queue.Queue(4096)` consumed by `N` worker threads executing dissection, IP "
        "defragmentation, TCP reassembly, anomaly rules, statistical profiling, and passive "
        "OS fingerprinting.",
        "",
        "## Results",
        "",
        "| Mode | Workers | Packets | Duration (s) | Sustained Throughput (pps) | MB/s |",
        "|---|---:|---:|---:|---:|---:|",
        (
            f"| Raw `PacketParser` Loop | 1 | {int(parser_res['packets']):,} | "
            f"{parser_res['duration_s']:.3f} | {parser_res['pps']:,.1f} | "
            f"{parser_res['mb_per_s']:.2f} |"
        ),
    ]
    for res in pipeline_results:
        lines.append(
            f"| Full Analysis Pipeline | {int(res['threads'])} | {int(res['packets']):,} | "
            f"{res['duration_s']:.3f} | {res['pps']:,.1f} | {res['mb_per_s']:.2f} |"
        )
    lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    """Run replay benchmark and save results to docs/benchmark_results.md."""
    argp = argparse.ArgumentParser(description="Benchmark TrafficScope parsing & pipeline speed.")
    argp.add_argument("--pcap", type=str, default=None, help="Existing PCAP path to replay.")
    argp.add_argument(
        "--generate",
        type=int,
        default=5000,
        help="Number of synthetic packets to generate if --pcap is omitted.",
    )
    argp.add_argument(
        "--output",
        type=str,
        default="docs/benchmark_results.md",
        help="Markdown file to save benchmark report.",
    )
    args = argp.parse_args()

    console = Console()
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.pcap:
        pcap_path = Path(args.pcap)
        pcap_label = pcap_path.name
    else:
        temp_dir = tempfile.TemporaryDirectory()
        pcap_path = Path(temp_dir.name) / "synthetic_benchmark.pcap"
        console.print(f"[cyan]Generating {args.generate:,} synthetic packets...[/cyan]")
        generate_benchmark_pcap(pcap_path, args.generate)
        pcap_label = "Synthetic Mixed PCAP"

    try:
        packets = list(rdpcap(str(pcap_path)))
        parser_res = benchmark_parser_loop(packets)
        pipeline_results = [benchmark_pipeline(pcap_path, n) for n in (1, 2, 4)]

        table = Table(title="TrafficScope Throughput Benchmark")
        table.add_column("Mode", style="bold cyan")
        table.add_column("Workers", justify="right")
        table.add_column("Packets", justify="right")
        table.add_column("Duration (s)", justify="right")
        table.add_column("Packets / sec", justify="right", style="bold green")
        table.add_column("MB / sec", justify="right")

        table.add_row(
            "Raw PacketParser",
            "1",
            f"{int(parser_res['packets']):,}",
            f"{parser_res['duration_s']:.3f}",
            f"{parser_res['pps']:,.1f}",
            f"{parser_res['mb_per_s']:.2f}",
        )
        for res in pipeline_results:
            table.add_row(
                "Full Pipeline",
                str(int(res["threads"])),
                f"{int(res['packets']):,}",
                f"{res['duration_s']:.3f}",
                f"{res['pps']:,.1f}",
                f"{res['mb_per_s']:.2f}",
            )
        console.print(table)

        out_path = Path(args.output)
        write_results_markdown(out_path, pcap_label, parser_res, pipeline_results)
        console.print(f"[green]Saved benchmark results to {out_path}[/green]")
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    main()
