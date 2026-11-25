"""Stateless HTTP/1.x request and response metadata parser."""

from __future__ import annotations

from typing import Any

_HTTP_METHODS = frozenset({
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
})


def _split_headers_and_body(payload: bytes) -> tuple[bytes, bytes, bool]:
    """Split HTTP headers from body, returning (header_bytes, body_bytes, has_end_of_headers)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = payload.find(sep)
        if idx != -1:
            return payload[:idx], payload[idx + len(sep):], True
    return payload, b"", False


def _parse_headers(lines: list[str]) -> dict[str, str]:
    """Parse HTTP header lines into a lowercase-keyed dict preserving values."""
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        headers[key.strip().lower()] = val.strip()
    return headers


def _parse_content_length(headers: dict[str, str]) -> int | None:
    """Safely parse Content-Length header when present and numeric."""
    raw = headers.get("content-length")
    if raw is None or not raw.isdigit():
        return None
    return int(raw)


def _is_complete(
    has_eoh: bool,
    headers: dict[str, str],
    body: bytes,
) -> bool:
    """Estimate whether the full HTTP message is contained in the given bytes."""
    if not has_eoh:
        return False
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return b"0\r\n\r\n" in body or body.startswith(b"0\r\n")
    content_length = _parse_content_length(headers)
    if content_length is not None:
        return len(body) >= content_length
    return True


def parse_http_request(payload: bytes) -> dict[str, Any] | None:
    """Parse an HTTP/1.x request from raw bytes, or return None if invalid."""
    if not payload:
        return None

    header_bytes, body, has_eoh = _split_headers_and_body(payload)
    try:
        header_text = header_bytes.decode("latin-1")
    except UnicodeDecodeError:
        return None

    lines = header_text.splitlines()
    if not lines:
        return None

    parts = lines[0].split(" ", 2)
    if len(parts) != 3:
        return None
    method, path, version = parts
    if method not in _HTTP_METHODS or not version.startswith("HTTP/"):
        return None

    headers = _parse_headers(lines[1:])
    return {
        "message_type": "request",
        "method": method,
        "path": path,
        "version": version,
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "content_type": headers.get("content-type"),
        "content_length": _parse_content_length(headers),
        "chunked": "chunked" in headers.get("transfer-encoding", "").lower(),
        "headers": headers,
        "body": body,
        "complete": _is_complete(has_eoh, headers, body),
    }


def parse_http_response(payload: bytes) -> dict[str, Any] | None:
    """Parse an HTTP/1.x response from raw bytes, or return None if invalid."""
    if not payload or not payload.startswith(b"HTTP/"):
        return None

    header_bytes, body, has_eoh = _split_headers_and_body(payload)
    try:
        header_text = header_bytes.decode("latin-1")
    except UnicodeDecodeError:
        return None

    lines = header_text.splitlines()
    if not lines:
        return None

    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        return None

    version = parts[0]
    status_code = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    headers = _parse_headers(lines[1:])

    return {
        "message_type": "response",
        "version": version,
        "status_code": status_code,
        "reason": reason,
        "content_type": headers.get("content-type"),
        "content_length": _parse_content_length(headers),
        "chunked": "chunked" in headers.get("transfer-encoding", "").lower(),
        "headers": headers,
        "body": body,
        "complete": _is_complete(has_eoh, headers, body),
    }


def parse_http(payload: bytes) -> dict[str, Any] | None:
    """Dissect either an HTTP request or response from raw bytes."""
    if payload.startswith(b"HTTP/"):
        return parse_http_response(payload)
    return parse_http_request(payload)
