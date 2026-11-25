"""Flask API and UI routes for the TrafficScope Web Dashboard."""

from __future__ import annotations

import json
from typing import Any

from flask import Blueprint, Response, jsonify, render_template, request, send_file

from dashboard.web.controller import CaptureSessionError, CaptureSessionManager


def _extract_replay_form_options() -> dict[str, Any]:
    """Extract optional pipeline tuning flags submitted with a multipart PCAP upload."""
    form = request.form
    return {
        "bpf_filter": form.get("bpf_filter"),
        "no_payload": form.get("no_payload"),
        "payload_bytes": form.get("payload_bytes"),
        "threads": form.get("threads"),
        "baseline_seconds": form.get("baseline_seconds"),
        "http_ports": form.get("http_ports"),
        "count": form.get("count"),
    }


def _parse_limit_param(raw: str | None, *, default: int = 200) -> int:
    """Validate optional pagination limit query parameter."""
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise CaptureSessionError(
            "Query parameter 'limit' must be an integer.",
            status_code=400,
        ) from exc
    if value < 1 or value > 500:
        raise CaptureSessionError("'limit' must be between 1 and 500.", status_code=400)
    return value


def create_api_blueprint(manager: CaptureSessionManager) -> Blueprint:
    """Create the Flask Blueprint bound to a specific CaptureSessionManager."""
    bp = Blueprint("trafficscope_web", __name__)

    @bp.errorhandler(CaptureSessionError)
    def handle_session_error(exc: CaptureSessionError) -> tuple[Response, int]:
        """Translate controller domain exceptions into structured JSON responses."""
        return jsonify({"error": str(exc)}), exc.status_code

    @bp.get("/")
    def index() -> str:
        """Serve the main SOC dark-mode TrafficScope web dashboard."""
        return render_template("index.html")

    @bp.get("/api/interfaces")
    def api_interfaces() -> Response:
        """Return available network interfaces and elevation privilege status."""
        return jsonify(manager.get_interfaces())

    @bp.get("/api/status")
    def api_status() -> Response:
        """Return current session mode, activity flag, and export readiness."""
        return jsonify(manager.get_status())

    @bp.post("/api/capture/start")
    def api_start_capture() -> Response:
        """Start a live capture session using UI-selected interface and options."""
        payload = request.get_json(silent=True)
        if payload is not None and not isinstance(payload, dict):
            raise CaptureSessionError("JSON request body must be an object.", status_code=400)
        return jsonify(manager.start_live(payload or {}))

    @bp.post("/api/capture/stop")
    def api_stop_capture() -> Response:
        """Stop the active live capture or replay session gracefully."""
        return jsonify(manager.stop_capture())

    @bp.post("/api/replay")
    def api_replay() -> Response:
        """Replay a PCAP file via multipart upload or local path JSON payload."""
        if "file" in request.files:
            upload = request.files.get("file")
            options = _extract_replay_form_options()
            return jsonify(manager.start_replay_upload(upload, options=options))

        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise CaptureSessionError("JSON request body must be an object.", status_code=400)
        raw_path = str(payload.get("path", ""))
        return jsonify(manager.start_replay_path(raw_path, options=payload))

    @bp.get("/api/telemetry")
    def api_telemetry() -> Response:
        """Return live telemetry snapshot (KPIs, protocols, packets, alerts, DNS, TLS)."""
        return jsonify(manager.get_telemetry())

    @bp.get("/api/flows")
    def api_flows() -> Response:
        """Return aggregated NetFlow summaries enriched with stream IDs and OS guesses."""
        limit = _parse_limit_param(request.args.get("limit"))
        return jsonify({"flows": manager.get_flows(limit=limit)})

    @bp.get("/api/streams/<flow_id>")
    def api_stream_detail(flow_id: str) -> Response:
        """Return sanitized Follow-TCP-Stream transcript and parsed HTTP exchange."""
        return jsonify(manager.get_stream_detail(flow_id))

    @bp.get("/api/export/pcap")
    def api_export_pcap() -> Response:
        """Download the recorded session PCAP capture file."""
        pcap_path = manager.get_export_pcap_path()
        return send_file(
            pcap_path,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name="trafficscope_capture.pcap",
        )

    @bp.get("/api/export/flows")
    def api_export_flows() -> Response:
        """Download tracked flows as NetFlow-style versioned JSON."""
        payload = manager.get_export_flows_data()
        return Response(
            json.dumps(payload, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": 'attachment; filename="trafficscope_flows.json"'},
        )

    @bp.get("/api/export/report")
    def api_export_report() -> Response:
        """Download full SOC report JSON (KPIs, alerts, DNS, TLS, HTTP, OS, flows)."""
        payload = manager.get_export_report_data()
        return Response(
            json.dumps(payload, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": 'attachment; filename="trafficscope_report.json"'},
        )

    @bp.get("/api/export/csv")
    def api_export_csv() -> Response:
        """Download alerts, flows, or recent packets as Excel-safe UTF-8 CSV."""
        kind = request.args.get("kind", "alerts")
        filename, csv_bytes = manager.get_export_csv_data(kind)
        return Response(
            csv_bytes,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return bp
