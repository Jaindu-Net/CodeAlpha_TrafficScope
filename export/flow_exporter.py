"""NetFlow-style JSON flow summary exporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FlowExporter:
    """Serializes tracked 5-tuple flow records into versioned JSON output."""

    SCHEMA_VERSION = "1.0"

    def __init__(self, flows: list[dict[str, Any]] | None = None) -> None:
        """Initialize the exporter with an optional list of flow dictionaries."""
        self._flows = list(flows) if flows is not None else []

    def export_json(
        self,
        path: str | Path,
        *,
        flows: list[dict[str, Any]] | None = None,
    ) -> Path:
        """Write flow records to a pretty-printed JSON file."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        flow_list = list(flows) if flows is not None else self._flows

        payload = {
            "_schema_version": self.SCHEMA_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "flow_count": len(flow_list),
            "flows": flow_list,
        }
        target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target_path
