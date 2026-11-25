"""Alert data structures emitted by the TrafficScope anomaly detector."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AlertType(str, Enum):
    """Supported protocol anomaly and passive scan signature categories."""

    INVALID_CHECKSUM = "INVALID_CHECKSUM"
    TTL_ANOMALY = "TTL_ANOMALY"
    SCAN_NULL = "SCAN_NULL"
    SCAN_FIN = "SCAN_FIN"
    SCAN_XMAS = "SCAN_XMAS"
    RESERVED_FLAG = "RESERVED_FLAG"
    SYN_FIN_ILLEGAL = "SYN_FIN_ILLEGAL"
    SYN_FLOOD = "SYN_FLOOD"
    PORT_SWEEP = "PORT_SWEEP"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"


class Severity(str, Enum):
    """Alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class Alert:
    """Immutable anomaly alert emitted during passive packet inspection."""

    timestamp: float
    type: AlertType
    severity: Severity
    src_ip: str | None
    dst_ip: str | None
    detail: str
    raw_context: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
