# TrafficScope Benchmark Results

- **Run Date:** 2026-11-25 14:48 UTC
- **OS:** Windows-11-10.0.26200-SP0
- **Python:** 3.13.13
- **Logical CPUs:** 16
- **Test Dataset:** Synthetic Mixed PCAP (5,000 packets)

## Methodology

1. **Raw Parser Tight Loop:** Pre-loads packets in memory and times `PacketParser.parse()` in a single thread to establish the CPU dissection ceiling.
2. **Full Producer-Consumer Pipeline:** Streams the PCAP via `OfflineReader` into a bounded `queue.Queue(4096)` consumed by `N` worker threads executing dissection, IP defragmentation, TCP reassembly, anomaly rules, statistical profiling, and passive OS fingerprinting.

## Results

| Mode | Workers | Packets | Duration (s) | Sustained Throughput (pps) | MB/s |
|---|---:|---:|---:|---:|---:|
| Raw `PacketParser` Loop | 1 | 5,000 | 0.407 | 12,274.0 | 0.88 |
| Full Analysis Pipeline | 1 | 5,000 | 1.480 | 3,378.4 | 0.24 |
| Full Analysis Pipeline | 2 | 5,000 | 1.391 | 3,594.9 | 0.26 |
| Full Analysis Pipeline | 4 | 5,000 | 1.471 | 3,399.4 | 0.24 |
