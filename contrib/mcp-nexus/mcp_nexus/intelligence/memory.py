"""SQLite-backed intelligence engine with short-term memory and online learning."""

from __future__ import annotations

import asyncio
import json
import math
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any

from mcp_nexus.catalog import category_for_tool
from mcp_nexus.intelligence.learning import ContextualSoftmaxRanker

_SCHEMA = """
CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    args_summary TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    duration_ms REAL,
    session_id INTEGER,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS interaction_states (
    interaction_id INTEGER PRIMARY KEY,
    before_state TEXT NOT NULL,
    after_state TEXT NOT NULL,
    features TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(interaction_id) REFERENCES interactions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS preferences (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    times_seen INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS preference_values (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (key, value)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    last_activity REAL NOT NULL,
    tool_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS tool_sequences (
    prev_tool TEXT NOT NULL,
    next_tool TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (prev_tool, next_tool)
);

CREATE TABLE IF NOT EXISTS transition_outcomes (
    prev_tool TEXT NOT NULL,
    next_tool TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    total_duration_ms REAL NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL,
    PRIMARY KEY (prev_tool, next_tool)
);

CREATE TABLE IF NOT EXISTS tool_stats (
    tool TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    total_duration_ms REAL NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS model_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_interactions_ts ON interactions(ts);
CREATE INDEX IF NOT EXISTS idx_interactions_tool ON interactions(tool);
CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
CREATE INDEX IF NOT EXISTS idx_transition_prev_tool ON transition_outcomes(prev_tool);
CREATE INDEX IF NOT EXISTS idx_preference_values_key ON preference_values(key);
"""

_SESSION_GAP = 1800
_MODEL_STATE_KEY = "contextual_softmax_ranker_v1"


class MemoryEngine:
    """Learns reusable context from tool transitions and outcomes."""

    def __init__(self, data_dir: str = "~/.mcp-nexus"):
        self._data_dir = Path(data_dir).expanduser()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / "memory.db"
        self._conn: sqlite3.Connection | None = None
        self._current_session: int | None = None
        self._last_tool: str | None = None
        self._last_success: bool | None = None
        self._last_session_id: int | None = None
        self._last_features: dict[str, float] | None = None
        self._last_activity: float = 0
        self._ranker = ContextualSoftmaxRanker()

    def open(self):
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._load_or_rebuild_learning_state()
        self._hydrate_runtime_state()

    def close(self):
        if self._conn:
            self._finalize_session()
            self._conn.close()
            self._conn = None

    async def record(
        self,
        tool: str,
        args: dict[str, Any],
        success: bool,
        duration_ms: float,
        *,
        result_payload: dict[str, Any] | None = None,
        error_message: str | None = None,
        client_session_id: str | None = None,
    ):
        """Record a tool invocation with its context and outcome."""
        await asyncio.to_thread(
            self._record_sync,
            tool,
            args,
            success,
            duration_ms,
            result_payload,
            error_message,
            client_session_id,
        )

    def _record_sync(
        self,
        tool: str,
        args: dict[str, Any],
        success: bool,
        duration_ms: float,
        result_payload: dict[str, Any] | None,
        error_message: str | None,
        client_session_id: str | None,
    ):
        if not self._conn:
            return
        now = time.time()
        session_id = self._ensure_session(now)
        session_tool_count_before = self._session_tool_count(session_id)
        args_summary = self._summarize_args(args)
        before_state = self._build_before_state(
            session_id=session_id,
            session_tool_count_before=session_tool_count_before,
            client_session_id=client_session_id,
        )
        after_state = self._build_after_state(
            tool=tool,
            success=success,
            duration_ms=duration_ms,
            result_payload=result_payload or {},
            error_message=error_message,
            session_id=session_id,
            session_tool_count_after=session_tool_count_before + 1,
            client_session_id=client_session_id,
        )
        features = self._event_features(
            tool=tool,
            args=args,
            success=success,
            duration_ms=duration_ms,
            before_state=before_state,
            after_state=after_state,
        )

        cursor = self._conn.execute(
            "INSERT INTO interactions (tool, args_summary, success, duration_ms, session_id, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tool, args_summary, int(success), duration_ms, session_id, now),
        )
        interaction_id = int(cursor.lastrowid)
        self._conn.execute(
            "INSERT INTO interaction_states (interaction_id, before_state, after_state, features, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                interaction_id,
                self._json_dumps(before_state),
                self._json_dumps(after_state),
                self._json_dumps(features),
                now,
            ),
        )
        self._conn.execute(
            "UPDATE sessions SET last_activity=?, tool_count=tool_count+1 WHERE id=?",
            (now, session_id),
        )

        self._record_tool_stats(tool, success, duration_ms, now)

        if self._last_tool:
            self._record_transition(self._last_tool, tool, success, duration_ms, now)
            if self._last_features and self._last_session_id == session_id:
                self._ranker.observe(self._last_features, tool)
                self._persist_ranker(now)

        self._last_tool = tool
        self._last_success = success
        self._last_session_id = session_id
        self._last_features = features
        self._last_activity = now

        self._learn_preferences(args, now)
        self._conn.commit()

    async def get_context(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_context_sync)

    def _get_context_sync(self) -> dict[str, Any]:
        if not self._conn:
            return {"status": "memory not initialized"}

        context: dict[str, Any] = {}
        short_term: dict[str, Any] = {}

        row = self._conn.execute(
            "SELECT id, started_at, last_activity, tool_count FROM sessions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            elapsed = time.time() - row["last_activity"]
            session_payload = {
                "tools_used": row["tool_count"],
                "duration_min": round((row["last_activity"] - row["started_at"]) / 60, 1),
            }
            if elapsed < _SESSION_GAP:
                context["current_session"] = {"active": True, **session_payload}
                short_term["session"] = {"active": True, **session_payload}
            else:
                context["last_session"] = {
                    "ended_ago_min": round(elapsed / 60, 1),
                    "tools_used": row["tool_count"],
                }
                short_term["session"] = {
                    "active": False,
                    "ended_ago_min": round(elapsed / 60, 1),
                    "tools_used": row["tool_count"],
                }

            recent_rows = self._conn.execute(
                "SELECT i.tool, i.args_summary, i.success, i.duration_ms, i.ts, s.before_state, s.after_state "
                "FROM interactions i "
                "LEFT JOIN interaction_states s ON s.interaction_id=i.id "
                "WHERE i.session_id=? ORDER BY i.ts DESC LIMIT 10",
                (row["id"],),
            ).fetchall()
            recent_actions = [self._recent_action_payload(record) for record in recent_rows]
            if recent_actions:
                context["recent_actions"] = recent_actions
                short_term["recent_actions"] = recent_actions

        error_rows = self._conn.execute(
            "SELECT i.tool, i.args_summary, i.ts, s.after_state "
            "FROM interactions i "
            "LEFT JOIN interaction_states s ON s.interaction_id=i.id "
            "WHERE i.success=0 ORDER BY i.ts DESC LIMIT 5"
        ).fetchall()
        if error_rows:
            context["recent_errors"] = [
                {
                    "tool": row["tool"],
                    "args": self._parse_args_summary(row["args_summary"]),
                    "ago_min": round((time.time() - row["ts"]) / 60, 1),
                    "error_code": self._load_json_dict(row["after_state"]).get("error_code"),
                }
                for row in error_rows
            ]

        predicted_next = self._suggest_next_sync(self._last_tool or "")
        if predicted_next:
            context["predicted_next"] = predicted_next
            short_term["predicted_next"] = predicted_next

        long_term = {
            "preferences": self._get_preferences_sync(),
            "workflows": self._get_workflows_sync()[:5],
            "learning": self._learning_summary(),
        }
        context["short_term_memory"] = short_term
        context["long_term_memory"] = long_term
        return context

    async def get_preferences(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_preferences_sync)

    def _get_preferences_sync(self) -> dict[str, Any]:
        if not self._conn:
            return {}
        rows = self._conn.execute(
            "SELECT key, value, confidence, times_seen FROM preferences "
            "ORDER BY confidence DESC, times_seen DESC, key ASC"
        ).fetchall()
        return {
            row["key"]: {
                "value": row["value"],
                "confidence": round(row["confidence"], 2),
                "seen": row["times_seen"],
            }
            for row in rows
        }

    async def get_insights(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_insights_sync)

    def _get_insights_sync(self) -> dict[str, Any]:
        if not self._conn:
            return {}

        insights: dict[str, Any] = {}
        totals = self._conn.execute(
            "SELECT COUNT(*) as total, SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) as errors, "
            "AVG(duration_ms) as avg_ms FROM interactions"
        ).fetchone()
        if totals and totals["total"]:
            insights["totals"] = {
                "interactions": totals["total"],
                "errors": totals["errors"],
                "error_rate_pct": round((totals["errors"] / totals["total"]) * 100, 1),
                "avg_duration_ms": round(totals["avg_ms"], 1) if totals["avg_ms"] else 0,
            }

        all_tools = self._conn.execute(
            "SELECT tool, COUNT(*) as cnt FROM interactions GROUP BY tool ORDER BY cnt DESC"
        ).fetchall()
        insights["top_tools"] = {row["tool"]: row["cnt"] for row in all_tools[:10]}

        categories: Counter[str] = Counter()
        for row in all_tools:
            category = category_for_tool(row["tool"])
            if category:
                categories[category] += row["cnt"]
        if categories:
            insights["focus_areas"] = dict(categories.most_common())

        slow_tools = self._conn.execute(
            "SELECT tool, AVG(duration_ms) as avg_ms FROM interactions "
            "GROUP BY tool HAVING COUNT(*) >= 1 ORDER BY avg_ms DESC LIMIT 10"
        ).fetchall()
        insights["slow_tools"] = {
            row["tool"]: round(row["avg_ms"], 1) for row in slow_tools if row["avg_ms"] is not None
        }

        failure_hotspots = self._conn.execute(
            "SELECT tool, COUNT(*) as cnt FROM interactions WHERE success=0 GROUP BY tool ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        insights["failure_hotspots"] = {row["tool"]: row["cnt"] for row in failure_hotspots}

        session_row = self._conn.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()
        insights["total_sessions"] = session_row["cnt"] if session_row else 0
        insights["learning"] = self._learning_summary()
        return insights

    async def suggest_next(self, current_tool: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._suggest_next_sync, current_tool)

    def _suggest_next_sync(self, current_tool: str) -> list[dict[str, Any]]:
        if not self._conn or not current_tool:
            return []

        features = self._suggestion_features(current_tool)
        transition_rows = self._conn.execute(
            "SELECT next_tool, count, success_count, failure_count, total_duration_ms "
            "FROM transition_outcomes WHERE prev_tool=? ORDER BY count DESC",
            (current_tool,),
        ).fetchall()
        transition_stats = {row["next_tool"]: row for row in transition_rows}
        candidate_labels = set(transition_stats)
        if not candidate_labels and self._ranker.has_signal(features):
            candidate_labels.update(self._ranker.labels)
        if not candidate_labels:
            return []

        model_probabilities = self._ranker.probabilities(features, allowed_labels=candidate_labels)
        if not model_probabilities and not transition_stats:
            return []

        total_transition_count = sum(row["count"] for row in transition_rows) or 0
        suggestions: list[dict[str, Any]] = []
        for tool_name in sorted(candidate_labels):
            row = transition_stats.get(tool_name)
            transition_share = (row["count"] / total_transition_count) if row and total_transition_count else 0.0
            model_probability = model_probabilities.get(tool_name, transition_share)
            expected_success_rate = (
                self._success_rate(row["success_count"], row["failure_count"])
                if row
                else None
            )
            score = model_probability * (expected_success_rate if expected_success_rate is not None else 1.0)
            suggestions.append(
                {
                    "tool": tool_name,
                    "score": round(score, 4),
                    "probability": round(model_probability, 4),
                    "transition_share": round(transition_share, 4),
                    "expected_success_rate": (
                        round(expected_success_rate, 4) if expected_success_rate is not None else None
                    ),
                    "times": row["count"] if row else 0,
                    "avg_duration_ms": (
                        round(row["total_duration_ms"] / row["count"], 1) if row and row["count"] else None
                    ),
                }
            )

        suggestions.sort(key=lambda item: (item["score"], item["times"], item["probability"]), reverse=True)
        return suggestions[:5]

    async def get_workflows(self) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._get_workflows_sync)

    def _get_workflows_sync(self) -> list[dict[str, Any]]:
        if not self._conn:
            return []

        rows = self._conn.execute(
            "SELECT prev_tool, next_tool, count, success_count, failure_count "
            "FROM transition_outcomes WHERE count >= 3 ORDER BY count DESC LIMIT 20"
        ).fetchall()

        workflows = []
        seen: set[str] = set()
        for row in rows:
            chain = [row["prev_tool"], row["next_tool"]]
            extension = self._conn.execute(
                "SELECT next_tool, count FROM transition_outcomes "
                "WHERE prev_tool=? AND count >= 2 ORDER BY count DESC LIMIT 1",
                (row["next_tool"],),
            ).fetchone()
            if extension:
                chain.append(extension["next_tool"])

            chain_key = "->".join(chain)
            if chain_key in seen:
                continue
            seen.add(chain_key)
            workflows.append(
                {
                    "chain": chain,
                    "frequency": row["count"],
                    "expected_success_rate": round(
                        self._success_rate(row["success_count"], row["failure_count"]),
                        4,
                    ),
                }
            )
        return workflows[:10]

    async def set_preference(self, key: str, value: str):
        await asyncio.to_thread(self._set_preference_sync, key, value)

    def _set_preference_sync(self, key: str, value: str):
        if not self._conn:
            return
        now = time.time()
        self._conn.execute(
            "INSERT INTO preference_values (key, value, count, first_seen, last_seen) "
            "VALUES (?, ?, 100, ?, ?) "
            "ON CONFLICT(key, value) DO UPDATE SET count=MAX(count, 100), last_seen=excluded.last_seen",
            (key, value, now, now),
        )
        self._conn.execute(
            "INSERT INTO preferences (key, value, confidence, times_seen, first_seen, last_seen) "
            "VALUES (?, ?, 1.0, 100, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET "
            "value=excluded.value, confidence=1.0, times_seen=100, last_seen=excluded.last_seen",
            (key, value, now, now),
        )
        self._conn.commit()

    async def clear(self):
        await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self):
        if not self._conn:
            return
        self._conn.executescript(
            """
            DELETE FROM interaction_states;
            DELETE FROM interactions;
            DELETE FROM preferences;
            DELETE FROM preference_values;
            DELETE FROM sessions;
            DELETE FROM tool_sequences;
            DELETE FROM transition_outcomes;
            DELETE FROM tool_stats;
            DELETE FROM model_state;
            """
        )
        self._conn.commit()
        self._current_session = None
        self._last_tool = None
        self._last_success = None
        self._last_session_id = None
        self._last_features = None
        self._last_activity = 0
        self._ranker = ContextualSoftmaxRanker()

    def _load_or_rebuild_learning_state(self) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT value FROM model_state WHERE key=?",
            (_MODEL_STATE_KEY,),
        ).fetchone()
        if row:
            self._ranker = ContextualSoftmaxRanker.from_dict(self._load_json_dict(row["value"]))
            return
        self._ranker = ContextualSoftmaxRanker()
        self._rebuild_learning_state()

    def _rebuild_learning_state(self) -> None:
        assert self._conn is not None
        self._conn.execute("DELETE FROM transition_outcomes")
        self._conn.execute("DELETE FROM tool_stats")
        last_by_session: dict[int, tuple[str, bool, dict[str, float]]] = {}
        rows = self._conn.execute(
            "SELECT i.tool, i.success, i.duration_ms, i.session_id, i.args_summary, s.features, s.after_state "
            "FROM interactions i "
            "LEFT JOIN interaction_states s ON s.interaction_id=i.id "
            "ORDER BY i.ts ASC, i.id ASC"
        ).fetchall()
        now = time.time()
        for row in rows:
            tool = row["tool"]
            success = bool(row["success"])
            duration_ms = float(row["duration_ms"] or 0.0)
            session_id = int(row["session_id"])
            features = self._load_json_dict(row["features"])
            if not features:
                features = self._event_features(
                    tool=tool,
                    args=self._parse_args_summary(row["args_summary"]) if row["args_summary"] else {},
                    success=success,
                    duration_ms=duration_ms,
                    before_state={},
                    after_state=self._load_json_dict(row["after_state"]),
                )

            self._record_tool_stats(tool, success, duration_ms, now, commit=False)

            previous = last_by_session.get(session_id)
            if previous:
                prev_tool, _, prev_features = previous
                self._record_transition(prev_tool, tool, success, duration_ms, now, commit=False)
                self._ranker.observe(prev_features, tool)

            last_by_session[session_id] = (tool, success, features)
        self._persist_ranker(now)
        self._conn.commit()

    def _hydrate_runtime_state(self) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT i.tool, i.success, i.session_id, i.ts, s.features "
            "FROM interactions i "
            "LEFT JOIN interaction_states s ON s.interaction_id=i.id "
            "ORDER BY i.ts DESC, i.id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return
        self._last_tool = row["tool"]
        self._last_success = bool(row["success"])
        self._last_session_id = int(row["session_id"])
        self._last_activity = float(row["ts"])
        loaded_features = self._load_json_dict(row["features"])
        self._last_features = (
            {str(name): float(value) for name, value in loaded_features.items()}
            if loaded_features
            else None
        )
        if (time.time() - self._last_activity) < _SESSION_GAP:
            self._current_session = self._last_session_id

    def _persist_ranker(self, now: float) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO model_state (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (_MODEL_STATE_KEY, self._json_dumps(self._ranker.to_dict()), now),
        )

    def _record_tool_stats(
        self,
        tool: str,
        success: bool,
        duration_ms: float,
        now: float,
        *,
        commit: bool = False,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO tool_stats (tool, count, success_count, failure_count, total_duration_ms, last_seen) "
            "VALUES (?, 1, ?, ?, ?, ?) "
            "ON CONFLICT(tool) DO UPDATE SET "
            "count=count+1, "
            "success_count=success_count+excluded.success_count, "
            "failure_count=failure_count+excluded.failure_count, "
            "total_duration_ms=total_duration_ms+excluded.total_duration_ms, "
            "last_seen=excluded.last_seen",
            (tool, int(success), int(not success), duration_ms, now),
        )
        if commit:
            self._conn.commit()

    def _record_transition(
        self,
        prev_tool: str,
        next_tool: str,
        success: bool,
        duration_ms: float,
        now: float,
        *,
        commit: bool = False,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO tool_sequences (prev_tool, next_tool, count) VALUES (?, ?, 1) "
            "ON CONFLICT(prev_tool, next_tool) DO UPDATE SET count=count+1",
            (prev_tool, next_tool),
        )
        self._conn.execute(
            "INSERT INTO transition_outcomes "
            "(prev_tool, next_tool, count, success_count, failure_count, total_duration_ms, last_seen) "
            "VALUES (?, ?, 1, ?, ?, ?, ?) "
            "ON CONFLICT(prev_tool, next_tool) DO UPDATE SET "
            "count=count+1, "
            "success_count=success_count+excluded.success_count, "
            "failure_count=failure_count+excluded.failure_count, "
            "total_duration_ms=total_duration_ms+excluded.total_duration_ms, "
            "last_seen=excluded.last_seen",
            (prev_tool, next_tool, int(success), int(not success), duration_ms, now),
        )
        if commit:
            self._conn.commit()

    def _learn_preferences(self, args: dict[str, Any], now: float) -> None:
        if not self._conn:
            return
        for key, value in self._preference_candidates(args):
            self._observe_preference(key, value, now)

    def _observe_preference(self, key: str, value: str, now: float) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO preference_values (key, value, count, first_seen, last_seen) VALUES (?, ?, 1, ?, ?) "
            "ON CONFLICT(key, value) DO UPDATE SET count=count+1, last_seen=excluded.last_seen",
            (key, value, now, now),
        )
        top = self._conn.execute(
            "SELECT value, count FROM preference_values WHERE key=? ORDER BY count DESC, last_seen DESC LIMIT 1",
            (key,),
        ).fetchone()
        totals = self._conn.execute(
            "SELECT SUM(count) as total, MIN(first_seen) as first_seen, MAX(last_seen) as last_seen "
            "FROM preference_values WHERE key=?",
            (key,),
        ).fetchone()
        if not top or not totals or not totals["total"]:
            return
        confidence = float(top["count"]) / float(totals["total"])
        self._conn.execute(
            "INSERT INTO preferences (key, value, confidence, times_seen, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET "
            "value=excluded.value, "
            "confidence=excluded.confidence, "
            "times_seen=excluded.times_seen, "
            "last_seen=excluded.last_seen",
            (key, top["value"], confidence, top["count"], totals["first_seen"], totals["last_seen"]),
        )

    def _preference_candidates(self, args: dict[str, Any]) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        for arg_name, raw_value in sorted(args.items()):
            normalized = self._normalize_preference_value(raw_value)
            if normalized is None:
                continue
            candidates.append((f"arg:{arg_name}", normalized))
        return candidates

    def _normalize_preference_value(self, value: Any) -> str | None:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if not candidate or "\n" in candidate or len(candidate) > 240:
            return None
        if candidate in {".", "/", "/tmp"}:
            return None
        return candidate

    def _build_before_state(
        self,
        *,
        session_id: int,
        session_tool_count_before: int,
        client_session_id: str | None,
    ) -> dict[str, Any]:
        return {
            "internal_session_id": session_id,
            "client_session_id": client_session_id,
            "session_tool_count_before": session_tool_count_before,
            "previous_tool": self._last_tool,
            "previous_tool_category": category_for_tool(self._last_tool) if self._last_tool else None,
            "previous_tool_ok": self._last_success,
        }

    def _build_after_state(
        self,
        *,
        tool: str,
        success: bool,
        duration_ms: float,
        result_payload: dict[str, Any],
        error_message: str | None,
        session_id: int,
        session_tool_count_after: int,
        client_session_id: str | None,
    ) -> dict[str, Any]:
        data_payload = result_payload.get("data")
        usage_payload = result_payload.get("usage")
        resource_usage = result_payload.get("resource_usage")
        return {
            "tool": tool,
            "category": category_for_tool(tool),
            "ok": success,
            "duration_ms": round(duration_ms, 2),
            "error_code": result_payload.get("error_code"),
            "error_stage": result_payload.get("error_stage"),
            "message": result_payload.get("message") or error_message,
            "profile": result_payload.get("profile"),
            "artifact_count": len(result_payload.get("artifact_paths") or []),
            "data_keys": sorted(data_payload) if isinstance(data_payload, dict) else [],
            "usage_keys": sorted(usage_payload) if isinstance(usage_payload, dict) else [],
            "resource_usage_keys": sorted(resource_usage) if isinstance(resource_usage, dict) else [],
            "internal_session_id": session_id,
            "client_session_id": client_session_id,
            "session_tool_count_after": session_tool_count_after,
        }

    def _event_features(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        success: bool,
        duration_ms: float,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
    ) -> dict[str, float]:
        features: dict[str, float] = {
            f"tool:{tool}": 1.0,
            f"ok:{int(success)}": 1.0,
            "duration_log": round(math.log1p(max(duration_ms, 0.0)), 4),
            "session_depth_log": round(math.log1p(max(int(before_state.get("session_tool_count_before", 0)), 0)), 4),
        }
        category = category_for_tool(tool)
        if category:
            features[f"category:{category}"] = 1.0

        previous_tool = before_state.get("previous_tool")
        if isinstance(previous_tool, str) and previous_tool:
            features[f"previous_tool:{previous_tool}"] = 1.0

        previous_ok = before_state.get("previous_tool_ok")
        if isinstance(previous_ok, bool):
            features[f"previous_ok:{int(previous_ok)}"] = 1.0

        for arg_name, arg_value in sorted(args.items()):
            features[f"arg:{arg_name}"] = 1.0
            value_type = type(arg_value).__name__
            features[f"arg_type:{arg_name}:{value_type}"] = 1.0

        for key in after_state.get("data_keys", []):
            features[f"data_key:{key}"] = 1.0
        for key in after_state.get("usage_keys", []):
            features[f"usage_key:{key}"] = 1.0
        for key in after_state.get("resource_usage_keys", []):
            features[f"resource_key:{key}"] = 1.0

        if after_state.get("profile"):
            features[f"profile:{after_state['profile']}"] = 1.0
        if after_state.get("error_code"):
            features[f"error_code:{after_state['error_code']}"] = 1.0
        if after_state.get("artifact_count"):
            features["has_artifacts"] = 1.0
        if after_state.get("message"):
            features["has_message"] = 1.0
        return features

    def _suggestion_features(self, current_tool: str) -> dict[str, float]:
        if current_tool == self._last_tool and self._last_features:
            return dict(self._last_features)
        features: dict[str, float] = {f"tool:{current_tool}": 1.0}
        category = category_for_tool(current_tool)
        if category:
            features[f"category:{category}"] = 1.0
        return features

    def _recent_action_payload(self, record: sqlite3.Row) -> dict[str, Any]:
        before_state = self._load_json_dict(record["before_state"])
        after_state = self._load_json_dict(record["after_state"])
        payload: dict[str, Any] = {
            "tool": record["tool"],
            "args": self._parse_args_summary(record["args_summary"]),
            "ok": bool(record["success"]),
            "duration_ms": round(float(record["duration_ms"] or 0.0), 2),
        }
        if before_state:
            payload["before"] = before_state
        if after_state:
            payload["after"] = after_state
        return payload

    def _learning_summary(self) -> dict[str, Any]:
        if not self._conn:
            return {}
        transition_count = self._conn.execute("SELECT COUNT(*) as cnt FROM transition_outcomes").fetchone()
        reliable_rows = self._conn.execute(
            "SELECT prev_tool, next_tool, count, success_count, failure_count FROM transition_outcomes "
            "WHERE count >= 2 ORDER BY count DESC, success_count DESC LIMIT 5"
        ).fetchall()
        return {
            "model": {
                "type": "online_softmax_ranker",
                "updates": self._ranker.updates,
                "labels": len(self._ranker.labels),
                "features": self._ranker.feature_count(),
            },
            "transition_coverage": transition_count["cnt"] if transition_count else 0,
            "top_reliable_transitions": [
                {
                    "from": row["prev_tool"],
                    "to": row["next_tool"],
                    "count": row["count"],
                    "expected_success_rate": round(
                        self._success_rate(row["success_count"], row["failure_count"]),
                        4,
                    ),
                }
                for row in reliable_rows
            ],
        }

    def _session_tool_count(self, session_id: int) -> int:
        assert self._conn is not None
        row = self._conn.execute("SELECT tool_count FROM sessions WHERE id=?", (session_id,)).fetchone()
        return int(row["tool_count"]) if row else 0

    def _ensure_session(self, now: float) -> int:
        if self._current_session and (now - self._last_activity) < _SESSION_GAP:
            return self._current_session

        self._finalize_session()
        assert self._conn is not None
        cursor = self._conn.execute(
            "INSERT INTO sessions (started_at, last_activity, tool_count) VALUES (?, ?, 0)",
            (now, now),
        )
        self._current_session = int(cursor.lastrowid)
        return self._current_session

    def _finalize_session(self):
        if not self._current_session or not self._conn:
            return

        tools = self._conn.execute(
            "SELECT tool, COUNT(*) as cnt FROM interactions WHERE session_id=? GROUP BY tool ORDER BY cnt DESC LIMIT 5",
            (self._current_session,),
        ).fetchall()
        if tools:
            parts = [f"{row['tool']}({row['cnt']})" for row in tools]
            self._conn.execute(
                "UPDATE sessions SET summary=? WHERE id=?",
                (", ".join(parts), self._current_session),
            )
            self._conn.commit()
        self._current_session = None

    @staticmethod
    def _success_rate(success_count: int, failure_count: int) -> float:
        return (success_count + 1.0) / (success_count + failure_count + 2.0)

    @staticmethod
    def _summarize_args(args: dict[str, Any]) -> str:
        interesting = {}
        for key, value in args.items():
            if value is None or value == "" or value is False or value == 0:
                continue
            if isinstance(value, str) and len(value) > 120:
                value = value[:120] + "..."
            interesting[key] = value
        return json.dumps(interesting, default=str) if interesting else "{}"

    @staticmethod
    def _parse_args_summary(summary: str) -> dict[str, Any] | str:
        try:
            parsed = json.loads(summary)
            return parsed if isinstance(parsed, dict) else summary
        except Exception:
            return summary

    @staticmethod
    def _json_dumps(payload: Any) -> str:
        return json.dumps(payload, default=str, sort_keys=True)

    @staticmethod
    def _load_json_dict(payload: Any) -> dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        if not payload:
            return {}
        try:
            parsed = json.loads(str(payload))
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
