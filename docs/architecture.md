# TrafficScope Architecture

TrafficScope enforces strict module boundaries around a thread-safe producer-consumer pipeline so packet capture never blocks downstream dissection or analysis under load.

## Data Flow

```mermaid
flowchart LR
    NIC["NIC (Npcap) / PCAP File"]
    CE["CaptureEngine / OfflineReader (capture/)"]
    Q["Bounded queue.Queue(4096)"]
    W["N x PipelineWorker Threads (main.py)"]
    PW["PcapWriter (export/pcap_writer.py)"]
    PP["PacketParser (parser/)"]
    DEFRAG["IPDefragmenter (reassembly/ip_defrag.py)"]
    TCP["TCPReassembler (reassembly/tcp_reassembler.py)"]
    AD["AnomalyDetector (analyzer/)"]
    PF["FlowTracker and HostProfiler (profiler/)"]
    FP["Fingerprinter (fingerprint/)"]
    SS["DashboardState Lock (dashboard/tui.py)"]
    TUI["TrafficScopeApp Textual (dashboard/)"]
    EXIT["Exit Report and Flow JSON (dashboard/summary.py, export/)"]

    NIC --> CE
    CE --> Q
    Q --> W
    W --> PW
    W --> PP
    PP --> DEFRAG
    DEFRAG --> TCP
    DEFRAG --> AD
    DEFRAG --> PF
    DEFRAG --> FP
    AD --> SS
    PF --> SS
    FP --> SS
    SS --> TUI
    SS --> EXIT
    PF --> EXIT
```

## Key Design Boundaries

1. **Non-blocking Producer (`capture/`):** `CaptureEngine` uses `queue.put_nowait()` so slow analysis never stalls Npcap ring reads. Dropped packets are counted explicitly alongside Npcap `pcap_stats()` kernel drop counters.
2. **Immutable Canonical Contract (`parser/parsed_packet.py`):** `ParsedPacket` is a frozen dataclass (`slots=True`), guaranteeing thread-safe sharing across downstream stages.
3. **Decoupled Anomaly Detection (`analyzer/`):** Imports only `ParsedPacket` and stdlib types; contains zero imports from `capture/`, `reassembly/`, `export/`, or `dashboard/`.
4. **Polling UI Bridge (`dashboard/`):** Worker threads update `DashboardState` under a short lock; the Textual event loop reads immutable snapshots on a 1-second timer without cross-thread widget mutations.
