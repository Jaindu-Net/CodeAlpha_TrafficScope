"""Thread-safe capture and telemetry session controller for TrafficScope Web UI."""

from __future__ import annotations

import csv
import io
import os
import re
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from capture import is_elevated, list_interfaces, select_interface
from export import FlowExporter
from parser.layers.application import DEFAULT_HTTP_PORTS
from parser.parsed_packet import FlowKey
from pipeline import (
    DEFAULT_JSON_DIR,
    DEFAULT_PCAP_DIR,
    PipelineConfig,
    PipelineRuntime,
    default_thread_count,
    derive_flows_json_path,
    parse_ports_arg,
    resolve_pcap_read_path,
    shutdown_pipeline,
    start_pipeline,
    sync_drop_stats,
)
from profiler.flow_tracker import FlowRecord

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
_ALLOWED_PCAP_EXTENSIONS = frozenset({".pcap", ".pcapng", ".cap"})
_MAX_HTTP_BODY_PREVIEW = 32 * 1024
_ANSI_CTRL_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_UNSAFE_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class CaptureSessionError(RuntimeError):
    """Domain error with an HTTP status code for web controller operations."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def sanitize_text_output(
    raw: bytes | str | None,
    *,
    max_chars: int = _MAX_HTTP_BODY_PREVIEW,
) -> str:
    """Decode and strip terminal control / ANSI sequences from untrusted text."""
    if raw is None:
        return ""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    cleaned = _ANSI_CTRL_RE.sub("", text)
    cleaned = _UNSAFE_CTRL_RE.sub(".", cleaned)
    if len(cleaned) > max_chars:
        return f"{cleaned[:max_chars]}\n... [truncated {len(cleaned) - max_chars} chars]"
    return cleaned


def encode_flow_key(flow_key: FlowKey) -> str:
    """Encode a canonical 5-tuple FlowKey into a URL-safe delimiter string."""
    return f"{flow_key[0]}|{flow_key[1]}|{flow_key[2]}|{flow_key[3]}|{flow_key[4]}"


def parse_flow_id(flow_id: str) -> FlowKey:
    """Parse an encoded flow identifier back into a canonical 5-tuple FlowKey."""
    parts = flow_id.strip().split("|")
    if len(parts) != 5 or not parts[0] or not parts[2] or not parts[4]:
        raise CaptureSessionError("Malformed flow identifier.", status_code=400)

    try:
        port_a = int(parts[1])
        port_b = int(parts[3])
    except ValueError as exc:
        raise CaptureSessionError("Invalid port inside flow identifier.", status_code=400) from exc

    if not (0 <= port_a <= 65535 and 0 <= port_b <= 65535):
        raise CaptureSessionError("Port out of valid 0-65535 range.", status_code=400)

    proto = parts[4].upper()
    ep_a = (parts[0], port_a)
    ep_b = (parts[2], port_b)
    if ep_a <= ep_b:
        return (ep_a[0], ep_a[1], ep_b[0], ep_b[1], proto)
    return (ep_b[0], ep_b[1], ep_a[0], ep_a[1], proto)


def _serialize_http_message(msg: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a JSON-safe shallow copy of a parsed HTTP request or response dict."""
    if msg is None:
        return None
    copy = dict(msg)
    raw_body = copy.pop("body", b"")
    body_bytes = bytes(raw_body) if isinstance(raw_body, (bytes, bytearray)) else b""
    copy["body_bytes"] = len(body_bytes)
    copy["body_preview"] = sanitize_text_output(body_bytes)
    return copy


def serialize_http_exchange(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert TCPReassembler HTTP exchange entry into JSON-safe fields."""
    flow_key = entry["flow_key"]
    client_ep = entry["client"]
    server_ep = entry["server"]
    return {
        "flow_id": encode_flow_key(flow_key),
        "client": f"{client_ep[0]}:{client_ep[1]}",
        "server": f"{server_ep[0]}:{server_ep[1]}",
        "request": _serialize_http_message(entry.get("request")),
        "response": _serialize_http_message(entry.get("response")),
    }


def _safe_int(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
    default: int | None,
) -> int | None:
    """Parse an optional bounded integer option from JSON/form payloads."""
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CaptureSessionError(f"Invalid integer for '{name}'.", status_code=400) from exc
    if parsed < minimum or parsed > maximum:
        raise CaptureSessionError(
            f"'{name}' must be between {minimum} and {maximum}.",
            status_code=400,
        )
    return parsed


def _safe_float(
    value: Any,
    name: str,
    *,
    minimum: float,
    maximum: float,
    default: float | None,
) -> float | None:
    """Parse an optional bounded float option from JSON/form payloads."""
    if value is None or value == "":
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise CaptureSessionError(f"Invalid number for '{name}'.", status_code=400) from exc
    if parsed < minimum or parsed > maximum:
        raise CaptureSessionError(
            f"'{name}' must be between {minimum} and {maximum}.",
            status_code=400,
        )
    return parsed


def _parse_bool(value: Any) -> bool:
    """Interpret boolean or string form toggle fields safely."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _validate_pcap_path(raw_path: str, *, pcap_dir: Path = DEFAULT_PCAP_DIR) -> Path:
    """Validate a local PCAP file path provided for offline replay."""
    cleaned = raw_path.strip()
    if not cleaned:
        raise CaptureSessionError("PCAP file path is required.", status_code=400)
    candidate = resolve_pcap_read_path(cleaned, pcap_dir=pcap_dir).resolve()
    if candidate.suffix.lower() not in _ALLOWED_PCAP_EXTENSIONS:
        raise CaptureSessionError(
            "Unsupported file extension. Allowed: .pcap, .pcapng, .cap.",
            status_code=400,
        )
    if not candidate.is_file():
        raise CaptureSessionError(f"PCAP file not found: {candidate.name}", status_code=404)
    return candidate


def _empty_telemetry(elevated: bool, last_error: str | None) -> dict[str, Any]:
    """Return consistent baseline telemetry schema before any capture starts."""
    return {
        "mode": "idle",
        "running": False,
        "elevated": elevated,
        "has_pcap_export": False,
        "has_flows_export": False,
        "last_error": last_error,
        "source_label": "Idle — Select interface or PCAP file",
        "elapsed_s": 0.0,
        "total_packets": 0,
        "total_bytes": 0,
        "dropped_packets": 0,
        "kernel_dropped": None,
        "current_pps": 0.0,
        "avg_pps": 0.0,
        "peak_pps": 0.0,
        "protocol_counts": {},
        "top_ports": [],
        "anomaly_counts": {},
        "total_anomalies": 0,
        "alert_seq": 0,
        "alerts_serialized": [],
        "recent_packets": [],
        "dns_records": [],
        "tls_sessions": [],
        "timeline": [],
        "capture_complete": False,
        "top_hosts": [],
        "entropy_flows": [],
        "entropy_summary": {"low": 0, "medium": 0, "high": 0},
        "http_exchanges": [],
        "http_exchange_count": 0,
        "stream_count": 0,
    }


def _collect_os_map(rt: PipelineRuntime) -> dict[str, tuple[str, int]]:
    """Extract {ip: (os_guess, confidence)} from runtime workers' fingerprinter."""
    os_map: dict[str, tuple[str, int]] = {}
    fingerprinter = getattr(rt.dashboard_state, "fingerprinter", None)
    if fingerprinter is None:
        return os_map
    for ip, result in fingerprinter.get_all_results().items():
        os_map[ip] = (result.os_guess, result.confidence)
    return os_map


def _safe_csv_cell(value: Any) -> str:
    """Flatten newlines and guard against spreadsheet CSV formula injection."""
    if value is None:
        return ""
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def _build_csv_bytes(headers: list[str], rows: list[list[Any]]) -> bytes:
    """Serialize headers and sanitized rows into UTF-8 BOM CSV bytes for Excel."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow([_safe_csv_cell(cell) for cell in row])
    return buf.getvalue().encode("utf-8-sig")


def _serialize_flow_record(
    rec: FlowRecord,
    os_map: dict[str, tuple[str, int]],
    has_stream: bool,
) -> dict[str, Any]:
    """Serialize one FlowRecord with stream handle and passive OS context."""
    data = rec.to_netflow_dict()
    src_os = os_map.get(rec.src_ip)
    dst_os = os_map.get(rec.dst_ip)
    data["flow_id"] = encode_flow_key(rec.flow_key)
    data["entropy_label"] = rec.entropy_label
    data["has_stream"] = has_stream
    data["src_os"] = src_os[0] if src_os else None
    data["dst_os"] = dst_os[0] if dst_os else None
    data["os_confidence"] = src_os[1] if src_os else (dst_os[1] if dst_os else None)
    return data


class CaptureSessionManager:
    """Thread-safe controller bridging Flask endpoints with TrafficScope's pipeline."""

    def __init__(
        self,
        *,
        pcap_dir: Path = DEFAULT_PCAP_DIR,
        json_dir: Path = DEFAULT_JSON_DIR,
        pipeline_starter: Callable[..., PipelineRuntime] = start_pipeline,
        elevation_checker: Callable[[], bool] = is_elevated,
        interface_lister: Callable[[], list[Any]] = list_interfaces,
        interface_selector: Callable[..., Any] = select_interface,
    ) -> None:
        """Initialize the capture session manager with dedicated output directories."""
        self._lock = threading.RLock()
        self._pcap_dir = Path(pcap_dir)
        self._json_dir = Path(json_dir)
        self._pipeline_starter = pipeline_starter
        self._elevation_checker = elevation_checker
        self._interface_lister = interface_lister
        self._interface_selector = interface_selector
        self._quiet_console = Console(file=open(os.devnull, "w", encoding="utf-8"), quiet=True)
        self._temp_dir = tempfile.TemporaryDirectory(
            prefix="trafficscope_web_",
            ignore_cleanup_errors=True,
        )

        self._runtime: PipelineRuntime | None = None
        self._mode = "idle"
        self._finalized = False
        self._session_pcap: Path | None = None
        self._last_error: str | None = None

    def _next_live_paths(self) -> tuple[Path, Path]:
        """Allocate dedicated local output/pcap and output/json paths for live captures."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        name = f"live_{stamp}"
        return self._pcap_dir / f"{name}.pcap", self._json_dir / f"{name}_flows.json"

    def _next_replay_paths(self, stem: str) -> tuple[Path, Path]:
        """Allocate temp PCAP export path and dedicated output/json path for replays."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        safe_stem = re.sub(r"[^a-zA-Z0-9_-]+", "_", stem).strip("_") or "replay"
        pcap_tmp = Path(self._temp_dir.name) / f"replay_{safe_stem}_{stamp}.pcap"
        json_out = self._json_dir / f"{safe_stem}_{stamp}_flows.json"
        return pcap_tmp, json_out

    def _build_config(
        self,
        *,
        source_label: str,
        is_offline: bool,
        target_iface: str = "",
        read_path: str | None = None,
        save_path: str | None = None,
        flows_save_path: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> PipelineConfig:
        """Validate web request parameters into an immutable PipelineConfig."""
        opts = options or {}
        try:
            http_ports_raw = opts.get("http_ports")
            http_ports = (
                parse_ports_arg(str(http_ports_raw))
                if http_ports_raw is not None and str(http_ports_raw).strip()
                else DEFAULT_HTTP_PORTS
            )
        except ValueError as exc:
            raise CaptureSessionError(str(exc), status_code=400) from exc

        threads = _safe_int(
            opts.get("threads"),
            "threads",
            minimum=1,
            maximum=16,
            default=default_thread_count(),
        )
        assert threads is not None
        baseline = _safe_float(
            opts.get("baseline_seconds"),
            "baseline_seconds",
            minimum=1.0,
            maximum=3600.0,
            default=60.0,
        )
        assert baseline is not None
        count = _safe_int(opts.get("count"), "count", minimum=1, maximum=5_000_000, default=None)
        timeout = _safe_float(
            opts.get("timeout"),
            "timeout",
            minimum=0.5,
            maximum=86400.0,
            default=None,
        )
        payload_bytes = _safe_int(
            opts.get("payload_bytes"),
            "payload_bytes",
            minimum=1,
            maximum=65535,
            default=None,
        )
        bpf_raw = opts.get("bpf_filter")
        bpf_filter = str(bpf_raw).strip() if bpf_raw and str(bpf_raw).strip() else None

        if flows_save_path is not None:
            resolved_flows_path: str | None = flows_save_path
        elif save_path is not None:
            resolved_flows_path = str(
                derive_flows_json_path(save_path, json_dir=self._json_dir, pcap_dir=self._pcap_dir)
            )
        else:
            resolved_flows_path = None

        return PipelineConfig(
            source_label=source_label,
            is_offline=is_offline,
            target_iface=target_iface,
            read_path=read_path,
            save_path=save_path,
            flows_save_path=resolved_flows_path,
            bpf_filter=bpf_filter,
            count=count,
            timeout=timeout,
            threads=threads,
            no_payload=_parse_bool(opts.get("no_payload")),
            payload_bytes=payload_bytes,
            baseline_seconds=baseline,
            http_ports=http_ports,
            verbose=False,
        )

    def _is_running_locked(self) -> bool:
        """Return True if an active pipeline session has not finished yet."""
        return self._runtime is not None and not self._finalized

    def _finalize_runtime_locked(self, rt: PipelineRuntime) -> None:
        """Cleanly shut down pipeline threads and flush capture exports once."""
        if self._finalized:
            return
        shutdown_pipeline(rt)
        self._finalized = True
        if rt.producer_error and self._last_error is None:
            self._last_error = str(rt.producer_error[0])

    def _refresh_runtime_locked(self) -> None:
        """Sync drop counters and finalize completed captures automatically."""
        rt = self._runtime
        if rt is None:
            return
        sync_drop_stats(rt)
        if rt.producer_error and self._last_error is None:
            self._last_error = str(rt.producer_error[0])
        if not self._finalized and rt.producer_done.is_set() and rt.packet_queue.empty():
            self._finalize_runtime_locked(rt)

    def _reset_session_locked(self) -> None:
        """Finalize any previous runtime before replacing it with a new session."""
        if self._runtime is not None and not self._finalized:
            self._finalize_runtime_locked(self._runtime)
        self._runtime = None
        self._finalized = False
        self._last_error = None
        self._session_pcap = None

    def _wait_briefly_for_replay(self, rt: PipelineRuntime, timeout_s: float = 0.4) -> None:
        """Give short PCAP replays a brief moment to complete before first response."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if rt.producer_done.is_set() and rt.packet_queue.empty():
                with self._lock:
                    self._refresh_runtime_locked()
                return
            time.sleep(0.02)

    def get_interfaces(self) -> dict[str, Any]:
        """Return discovered interfaces and current elevation privilege status."""
        elevated = bool(self._elevation_checker())
        try:
            interfaces = self._interface_lister()
        except Exception as exc:  # noqa: BLE001
            raise CaptureSessionError(
                f"Failed to list network interfaces: {exc}",
                status_code=500,
            ) from exc

        items = [
            {
                "index": info.index,
                "name": info.name,
                "description": info.description,
                "ip": info.ip,
                "mac": info.mac,
                "network_name": info.network_name,
            }
            for info in interfaces
        ]
        return {"elevated": elevated, "interfaces": items}

    def get_status(self) -> dict[str, Any]:
        """Return lightweight current session status without heavy payload arrays."""
        with self._lock:
            self._refresh_runtime_locked()
            rt = self._runtime
            running = self._is_running_locked()
            has_pcap = bool(self._session_pcap and self._session_pcap.is_file() and not running)
            return {
                "mode": self._mode,
                "running": running,
                "elevated": bool(self._elevation_checker()),
                "source_label": rt.source_label if rt is not None else "Idle",
                "total_packets": rt.dashboard_state.snapshot()["total_packets"] if rt else 0,
                "has_pcap_export": has_pcap,
                "has_flows_export": rt is not None,
                "last_error": self._last_error,
            }

    def _prepare_live_config(
        self,
        options: dict[str, Any],
        *,
        has_injected_socket: bool,
    ) -> tuple[PipelineConfig, Path]:
        """Validate live capture permissions, NIC selection, and config parameters."""
        if self._is_running_locked():
            raise CaptureSessionError(
                "A capture session is already running. Stop it before starting another.",
                status_code=409,
            )
        if not has_injected_socket and not self._elevation_checker():
            raise CaptureSessionError(
                "Live capture requires Administrator privileges on Windows. "
                "Re-launch TrafficScope as Administrator, or use PCAP Replay without elevation.",
                status_code=403,
            )

        iface_arg = options.get("iface")
        iface_str = str(iface_arg).strip() if iface_arg is not None else ""
        try:
            selected = self._interface_selector(iface_str or None, console=self._quiet_console)
        except (ValueError, RuntimeError) as exc:
            raise CaptureSessionError(str(exc), status_code=400) from exc

        pcap_out, flows_out = self._next_live_paths()
        config = self._build_config(
            source_label=selected.name or selected.description,
            is_offline=False,
            target_iface=selected.network_name or selected.name,
            save_path=str(pcap_out),
            flows_save_path=str(flows_out),
            options=options,
        )
        return config, pcap_out

    def start_live(
        self,
        options: dict[str, Any] | None = None,
        *,
        opened_socket: Any | None = None,
    ) -> dict[str, Any]:
        """Start a live packet capture session on the requested network interface."""
        opts = options or {}
        with self._lock:
            self._refresh_runtime_locked()
            config, pcap_out = self._prepare_live_config(
                opts,
                has_injected_socket=(opened_socket is not None),
            )
            self._reset_session_locked()
            try:
                rt = self._pipeline_starter(
                    config,
                    console=self._quiet_console,
                    opened_socket=opened_socket,
                )
            except PermissionError as exc:
                raise CaptureSessionError(str(exc), status_code=403) from exc
            except (ValueError, RuntimeError, OSError) as exc:
                raise CaptureSessionError(str(exc), status_code=400) from exc

            self._runtime = rt
            self._mode = "live"
            self._finalized = False
            self._session_pcap = pcap_out
            return self.get_status()

    def start_replay_path(
        self,
        raw_path: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Start an offline replay session from a validated local PCAP file path."""
        pcap_path = _validate_pcap_path(raw_path, pcap_dir=self._pcap_dir)
        return self._launch_replay(pcap_path, options=options)

    def start_replay_upload(
        self,
        upload: FileStorage | None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate and store an uploaded PCAP file, then launch offline replay."""
        if upload is None or not upload.filename:
            raise CaptureSessionError("No PCAP file was uploaded.", status_code=400)

        safe_name = secure_filename(upload.filename)
        suffix = Path(safe_name).suffix.lower()
        if suffix not in _ALLOWED_PCAP_EXTENSIONS:
            raise CaptureSessionError(
                "Unsupported uploaded file type. Allowed: .pcap, .pcapng, .cap.",
                status_code=400,
            )

        upload_dir = Path(self._temp_dir.name) / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        dest = upload_dir / f"{int(time.time() * 1000)}_{safe_name}"
        upload.save(dest)

        size = dest.stat().st_size
        if size == 0:
            dest.unlink(missing_ok=True)
            raise CaptureSessionError("Uploaded PCAP file is empty.", status_code=400)
        if size > MAX_UPLOAD_BYTES:
            dest.unlink(missing_ok=True)
            raise CaptureSessionError(
                f"Uploaded PCAP exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                status_code=413,
            )

        return self._launch_replay(dest, options=options)

    def _launch_replay(
        self,
        pcap_path: Path,
        *,
        options: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Configure and start an offline PCAP replay pipeline cleanly."""
        with self._lock:
            self._refresh_runtime_locked()
            if self._is_running_locked():
                raise CaptureSessionError(
                    "Stop the active capture before replaying a PCAP file.",
                    status_code=409,
                )

            pcap_out, flows_out = self._next_replay_paths(pcap_path.stem)
            config = self._build_config(
                source_label=f"PCAP: {pcap_path.name}",
                is_offline=True,
                read_path=str(pcap_path),
                save_path=str(pcap_out),
                flows_save_path=str(flows_out),
                options=options,
            )

            self._reset_session_locked()
            try:
                rt = self._pipeline_starter(config, console=self._quiet_console)
            except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
                raise CaptureSessionError(str(exc), status_code=400) from exc

            self._runtime = rt
            self._mode = "replay"
            self._finalized = False
            self._session_pcap = pcap_out

        self._wait_briefly_for_replay(rt)
        return self.get_status()

    def stop_capture(self) -> dict[str, Any]:
        """Stop the active capture/replay session if running and finalize exports."""
        with self._lock:
            if self._runtime is not None:
                self._finalize_runtime_locked(self._runtime)
            return self.get_status()

    def get_telemetry(self) -> dict[str, Any]:
        """Return a JSON-safe real-time telemetry snapshot for the Web Dashboard."""
        with self._lock:
            self._refresh_runtime_locked()
            rt = self._runtime
            elevated = bool(self._elevation_checker())
            if rt is None:
                return _empty_telemetry(elevated, self._last_error)

            snap = rt.dashboard_state.snapshot()
            snap.pop("new_alerts", None)
            exchanges = [
                serialize_http_exchange(entry)
                for entry in rt.reassembler.get_all_http_exchanges()[:50]
            ]
            running = self._is_running_locked()
            snap["mode"] = self._mode
            snap["running"] = running
            snap["elevated"] = elevated
            snap["has_pcap_export"] = bool(
                self._session_pcap and self._session_pcap.is_file() and not running
            )
            snap["has_flows_export"] = True
            snap["last_error"] = self._last_error
            snap["http_exchanges"] = exchanges
            snap["http_exchange_count"] = len(exchanges)
            snap["stream_count"] = len(rt.reassembler.store.all_streams())
            return snap

    def get_flows(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """Return tracked NetFlow summaries enriched with flow_id and OS fingerprints."""
        with self._lock:
            self._refresh_runtime_locked()
            rt = self._runtime
            if rt is None:
                return []

            bounded = max(1, min(limit, 500))
            os_map = _collect_os_map(rt)
            records = rt.flow_tracker.get_top_talkers(n=bounded)
            return [
                _serialize_flow_record(
                    rec,
                    os_map,
                    rt.reassembler.follow_stream(rec.flow_key) != "",
                )
                for rec in records
            ]

    def get_stream_detail(self, flow_id: str) -> dict[str, Any]:
        """Return sanitized Follow-TCP-Stream transcript and HTTP breakdown for a flow."""
        flow_key = parse_flow_id(flow_id)
        with self._lock:
            self._refresh_runtime_locked()
            rt = self._runtime
            if rt is None:
                raise CaptureSessionError("No capture session data is loaded.", status_code=404)

            transcript = rt.reassembler.follow_stream(flow_key)
            raw_exchange = rt.reassembler.get_http_exchange(flow_key)
            if not transcript and raw_exchange is None:
                raise CaptureSessionError(
                    "No reassembled TCP stream found for this flow.",
                    status_code=404,
                )

            http_payload = (
                {
                    "request": _serialize_http_message(raw_exchange.get("request")),
                    "response": _serialize_http_message(raw_exchange.get("response")),
                }
                if raw_exchange is not None
                else None
            )
            return {
                "flow_id": encode_flow_key(flow_key),
                "flow_key": list(flow_key),
                "transcript": sanitize_text_output(transcript, max_chars=128 * 1024),
                "http_exchange": http_payload,
            }

    def get_export_pcap_path(self) -> Path:
        """Return the finalized session PCAP path for HTTP download."""
        with self._lock:
            self._refresh_runtime_locked()
            if self._runtime is None or self._session_pcap is None:
                raise CaptureSessionError("No PCAP session has been recorded yet.", status_code=404)
            if self._is_running_locked():
                raise CaptureSessionError(
                    "Stop the active capture before downloading the complete PCAP file.",
                    status_code=409,
                )
            if not self._session_pcap.is_file():
                raise CaptureSessionError("Recorded PCAP file is missing.", status_code=404)
            return self._session_pcap

    def get_export_flows_data(self) -> dict[str, Any]:
        """Return a FlowExporter-compatible JSON payload of all tracked flows."""
        with self._lock:
            self._refresh_runtime_locked()
            rt = self._runtime
            if rt is None:
                raise CaptureSessionError("No session flows available to export.", status_code=404)
            flows = rt.flow_tracker.export_flows()
            return {
                "_schema_version": FlowExporter.SCHEMA_VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "flow_count": len(flows),
                "flows": flows,
            }

    def get_export_report_data(self) -> dict[str, Any]:
        """Return a complete SOC session report JSON payload (KPIs, alerts, DNS, TLS, flows)."""
        snap = self.get_telemetry()
        if snap.get("mode") == "idle" and self._runtime is None:
            raise CaptureSessionError("No session data available to export.", status_code=404)
        flows = self.get_flows(limit=500)
        return {
            "_schema_version": FlowExporter.SCHEMA_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "session": {
                "source_label": snap["source_label"],
                "mode": snap["mode"],
                "running": snap["running"],
                "elapsed_s": snap["elapsed_s"],
                "capture_complete": snap["capture_complete"],
            },
            "kpis": {
                "total_packets": snap["total_packets"],
                "total_bytes": snap["total_bytes"],
                "dropped_packets": snap["dropped_packets"],
                "kernel_dropped": snap["kernel_dropped"],
                "current_pps": snap["current_pps"],
                "avg_pps": snap["avg_pps"],
                "peak_pps": snap["peak_pps"],
                "total_anomalies": snap["total_anomalies"],
                "stream_count": snap["stream_count"],
                "http_exchange_count": snap["http_exchange_count"],
            },
            "protocol_counts": snap["protocol_counts"],
            "anomaly_counts": snap["anomaly_counts"],
            "entropy_summary": snap["entropy_summary"],
            "top_hosts": snap["top_hosts"],
            "alerts": snap["alerts_serialized"],
            "dns_records": snap["dns_records"],
            "tls_sessions": snap["tls_sessions"],
            "http_exchanges": snap["http_exchanges"],
            "flows": flows,
        }

    def get_export_csv_data(self, kind: str) -> tuple[str, bytes]:
        """Return `(filename, utf8_csv_bytes)` for alerts, flows, or recent packets."""
        normalized = kind.strip().lower()
        snap = self.get_telemetry()
        if snap.get("mode") == "idle" and self._runtime is None:
            raise CaptureSessionError("No session data available to export.", status_code=404)

        if normalized == "alerts":
            headers = ["time", "severity", "type", "src_ip", "dst_ip", "detail"]
            rows = [
                [
                    item.get("time_str"),
                    item.get("severity"),
                    item.get("type"),
                    item.get("src_ip"),
                    item.get("dst_ip"),
                    item.get("detail"),
                ]
                for item in snap["alerts_serialized"]
            ]
            return "trafficscope_alerts.csv", _build_csv_bytes(headers, rows)

        if normalized == "flows":
            headers = [
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "os_guess",
                "os_confidence",
                "packet_count",
                "byte_count",
                "duration_s",
                "mean_entropy",
                "entropy_label",
            ]
            rows = [
                [
                    flow.get("src_ip"),
                    flow.get("src_port"),
                    flow.get("dst_ip"),
                    flow.get("dst_port"),
                    flow.get("protocol"),
                    flow.get("src_os") or flow.get("dst_os") or "",
                    flow.get("os_confidence") or "",
                    flow.get("packet_count"),
                    flow.get("byte_count"),
                    flow.get("duration_s"),
                    flow.get("mean_entropy"),
                    flow.get("entropy_label"),
                ]
                for flow in self.get_flows(limit=500)
            ]
            return "trafficscope_flows.csv", _build_csv_bytes(headers, rows)

        if normalized == "packets":
            headers = [
                "id",
                "time",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "length",
                "info",
            ]
            rows = [
                [
                    pkt.get("id"),
                    pkt.get("time"),
                    pkt.get("src_ip"),
                    pkt.get("src_port"),
                    pkt.get("dst_ip"),
                    pkt.get("dst_port"),
                    pkt.get("protocol"),
                    pkt.get("length"),
                    pkt.get("info"),
                ]
                for pkt in snap["recent_packets"]
            ]
            return "trafficscope_packets.csv", _build_csv_bytes(headers, rows)

        raise CaptureSessionError(
            "Unsupported CSV export type. Use 'alerts', 'flows', or 'packets'.",
            status_code=400,
        )

    def close(self) -> None:
        """Stop active pipelines and remove temporary session artifacts."""
        with self._lock:
            self._reset_session_locked()
        try:
            self._quiet_console.file.close()
        except OSError:
            pass
        self._temp_dir.cleanup()
