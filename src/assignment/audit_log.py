"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"req-{len(self.logs)+1}"
        self._open[req_id] = time.time()
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"req-{len(self.logs)+1}"
        start_t = self._open.pop(req_id, time.time())
        latency_ms = round((time.time() - start_t) * 1000, 2)
        log_entry = {
            "request_id": req_id,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "response_text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(log_entry)
        return log_entry

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
