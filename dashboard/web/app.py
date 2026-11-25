"""Flask application factory and threaded localhost HTTP runner."""

from __future__ import annotations

import threading
import webbrowser
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request
from rich.console import Console
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.serving import make_server

from dashboard.web.controller import MAX_UPLOAD_BYTES, CaptureSessionManager
from dashboard.web.routes import create_api_blueprint

DEFAULT_WEB_HOST = "127.0.0.1"
_WEB_ROOT = Path(__file__).resolve().parent
_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def _apply_security_headers(response: Response) -> Response:
    """Attach hardened HTTP security headers to every Flask response."""
    response.headers["Content-Security-Policy"] = _CSP_HEADER
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def create_app(session_manager: CaptureSessionManager | None = None) -> Flask:
    """Construct a configured Flask application instance for TrafficScope."""
    manager = session_manager or CaptureSessionManager()
    app = Flask(
        __name__,
        template_folder=str(_WEB_ROOT / "templates"),
        static_folder=str(_WEB_ROOT / "static"),
        static_url_path="/static",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (1024 * 1024)
    app.config["JSON_SORT_KEYS"] = False
    app.extensions["trafficscope_manager"] = manager

    app.after_request(_apply_security_headers)
    app.register_blueprint(create_api_blueprint(manager))

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_exc: RequestEntityTooLarge) -> tuple[Response, int]:
        """Return HTTP 413 JSON error when PCAP upload exceeds size limit."""
        limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        return jsonify({"error": f"Uploaded file exceeds {limit_mb} MB limit."}), 413

    @app.errorhandler(404)
    def handle_not_found(exc: Any) -> tuple[Response, int] | Any:
        """Return JSON 404 responses for unknown /api/* endpoints."""
        if request.path.startswith("/api/"):
            return jsonify({"error": "Requested API endpoint was not found."}), 404
        return exc

    return app


def run_web_server(
    *,
    host: str = DEFAULT_WEB_HOST,
    port: int = 5000,
    open_browser: bool = True,
    console: Console | None = None,
    session_manager: CaptureSessionManager | None = None,
) -> None:
    """Start the local threaded TrafficScope web server until Ctrl+C."""
    if not (1 <= port <= 65535):
        raise ValueError("--port must be between 1 and 65535.")

    out = console or Console()
    owns_manager = session_manager is None
    manager = session_manager or CaptureSessionManager()
    app = create_app(manager)

    try:
        server = make_server(host, port, app, threaded=True)
    except OSError as exc:
        if owns_manager:
            manager.close()
        raise RuntimeError(f"Could not start web server on {host}:{port}: {exc}") from exc

    bound_port = int(server.server_port)
    url = f"http://{host}:{bound_port}"
    out.print(
        f"[bold cyan]TrafficScope Web Dashboard[/bold cyan] running at [green]{url}[/green]\n"
        "Open this URL in your browser to start live capture or replay .pcap files.\n"
        "Press Ctrl+C to stop the server."
    )

    timer: threading.Timer | None = None
    if open_browser:
        timer = threading.Timer(0.6, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out.print("\n[yellow]Shutting down TrafficScope Web Dashboard...[/yellow]")
    finally:
        if timer is not None:
            timer.cancel()
        server.shutdown()
        server.server_close()
        if owns_manager:
            manager.close()
