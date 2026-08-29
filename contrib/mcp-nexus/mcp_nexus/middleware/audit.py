"""Audit logging — tracks all tool calls with timestamps."""

from __future__ import annotations

import json
import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    timestamp: float
    tool: str
    client_id: str
    args: dict
    success: bool
    duration_ms: float
    error: str | None = None
    metadata: dict | None = None
    request_id: str | None = None
    trace_id: str | None = None
    session_id: str | None = None
    backend_kind: str | None = None
    backend_instance: str | None = None
    registry_version: str | None = None
    server_instance_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "tool": self.tool,
            "client": self.client_id,
            "args": {k: v[:100] if isinstance(v, str) and len(v) > 100 else v for k, v in self.args.items()},
            "ok": self.success,
            "ms": round(self.duration_ms, 1),
            "error": self.error,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "session_id": self.session_id,
            "backend_kind": self.backend_kind,
            "backend_instance": self.backend_instance,
            "registry_version": self.registry_version,
            "server_instance_id": self.server_instance_id,
            "metadata": self.metadata or {},
        }


class AuditLog:
    """In-memory audit log with optional file persistence."""

    def __init__(self, max_entries: int = 5000, log_file: str | None = None):
        self._entries: deque[AuditEntry] = deque(maxlen=max_entries)
        self._log_file = Path(log_file) if log_file else None
        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def record(self, entry: AuditEntry):
        self._entries.append(entry)
        if self._log_file:
            try:
                with self._log_file.open("a") as f:
                    f.write(json.dumps(entry.to_dict()) + "\n")
            except Exception as e:
                logger.warning("Failed to write audit log: %s", e)

    def recent(self, count: int = 50, tool: str = "") -> list[dict]:
        entries = list(self._entries)
        if tool:
            entries = [e for e in entries if e.tool == tool]
        return [e.to_dict() for e in entries[-count:]]

    def failures(self, count: int = 50, tool: str = "") -> list[dict]:
        entries = [e for e in self._entries if not e.success]
        if tool:
            entries = [e for e in entries if e.tool == tool]
        return [e.to_dict() for e in entries[-count:]]

    def slowest(self, count: int = 10) -> list[dict]:
        entries = sorted(self._entries, key=lambda entry: entry.duration_ms, reverse=True)
        return [e.to_dict() for e in entries[:count]]

    def stats(self) -> dict:
        if not self._entries:
            return {"total": 0}

        total = len(self._entries)
        errors = sum(1 for e in self._entries if not e.success)
        tools: dict[str, int] = {}
        tool_durations: dict[str, list[float]] = {}
        tool_errors: dict[str, int] = {}
        for e in self._entries:
            tools[e.tool] = tools.get(e.tool, 0) + 1
            tool_durations.setdefault(e.tool, []).append(e.duration_ms)
            if not e.success:
                tool_errors[e.tool] = tool_errors.get(e.tool, 0) + 1

        avg_ms = sum(e.duration_ms for e in self._entries) / total
        durations = sorted(e.duration_ms for e in self._entries)
        p95_index = min(total - 1, max(0, int(total * 0.95) - 1))
        p95_ms = durations[p95_index]
        slow_tools = {
            tool: round(mean(values), 1)
            for tool, values in sorted(tool_durations.items(), key=lambda item: mean(item[1]), reverse=True)[:10]
        }

        return {
            "total": total,
            "errors": errors,
            "error_rate": round(errors / total * 100, 1),
            "avg_duration_ms": round(avg_ms, 1),
            "p95_duration_ms": round(p95_ms, 1),
            "top_tools": dict(sorted(tools.items(), key=lambda x: -x[1])[:10]),
            "failure_hotspots": dict(sorted(tool_errors.items(), key=lambda item: -item[1])[:10]),
            "slow_tools": slow_tools,
        }
