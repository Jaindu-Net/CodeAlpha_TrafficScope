"""TrafficScope Web Dashboard package (Flask API + SOC dark UI)."""

from dashboard.web.app import create_app, run_web_server
from dashboard.web.controller import CaptureSessionError, CaptureSessionManager

__all__ = [
    "CaptureSessionError",
    "CaptureSessionManager",
    "create_app",
    "run_web_server",
]
