"""Request tracing and session-scoped state for Nexus."""

from __future__ import annotations

import contextvars
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RequestTrace:
    request_id: str
    trace_id: str
    session_id: str | None = None
    transport: str = "unknown"
    auth_mode: str = "none"
    forwarded_headers: dict[str, str] = field(default_factory=dict)


_current_trace: contextvars.ContextVar[RequestTrace | None] = contextvars.ContextVar(
    "_current_trace",
    default=None,
)


def get_request_trace() -> RequestTrace | None:
    return _current_trace.get()


def set_request_trace(trace: RequestTrace):
    return _current_trace.set(trace)


def reset_request_trace(token):
    _current_trace.reset(token)


class SessionStateStore:
    """Tracks session-scoped state outside the MCP registry lifecycle."""

    def __init__(self):
        self._sessions: dict[str, dict[str, Any]] = {}

    def touch(
        self,
        session_id: str,
        *,
        request_id: str,
        trace_id: str,
        transport: str,
        registry_version: str,
        server_instance_id: str,
    ):
        now = time.time()
        state = self._sessions.setdefault(
            session_id,
            {
                "session_id": session_id,
                "request_count": 0,
                "created_at": now,
                "active_db_profile": None,
                "last_tool_name": None,
                "last_error": None,
            },
        )
        state["request_count"] += 1
        state["last_seen_at"] = now
        state["last_request_id"] = request_id
        state["last_trace_id"] = trace_id
        state["transport"] = transport
        state["registry_version"] = registry_version
        state["server_instance_id"] = server_instance_id
        state["status"] = "active"
        state.setdefault("created_with_registry_version", registry_version)
        state.pop("closed_at", None)

    def set_active_db_profile(self, session_id: str, profile_name: str):
        state = self._sessions.setdefault(session_id, {"session_id": session_id, "request_count": 0})
        state["active_db_profile"] = profile_name
        state["last_seen_at"] = time.time()

    def get_active_db_profile(self, session_id: str) -> str | None:
        state = self._sessions.get(session_id)
        return state.get("active_db_profile") if state else None

    def note_tool_result(self, session_id: str | None, tool_name: str, ok: bool, error_message: str | None = None):
        if not session_id:
            return
        state = self._sessions.setdefault(session_id, {"session_id": session_id, "request_count": 0})
        state["last_tool_name"] = tool_name
        state["last_tool_ok"] = ok
        state["last_error"] = error_message
        state["last_seen_at"] = time.time()

    def sync_active(
        self,
        active_session_ids: set[str],
        *,
        registry_version: str,
        server_instance_id: str,
    ):
        now = time.time()
        for session_id, state in self._sessions.items():
            if session_id in active_session_ids:
                state["status"] = "active"
                state["registry_version"] = registry_version
                state["server_instance_id"] = server_instance_id
                continue
            if state.get("status") == "active":
                state["status"] = "closed"
                state["closed_at"] = now

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        state = self._sessions.get(session_id)
        return dict(state) if state else None

    def list_sessions(self) -> list[dict[str, Any]]:
        return [
            dict(value)
            for value in sorted(self._sessions.values(), key=lambda item: item.get("last_seen_at", 0), reverse=True)
        ]
