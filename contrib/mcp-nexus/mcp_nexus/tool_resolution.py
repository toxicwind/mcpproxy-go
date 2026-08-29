"""Canonical tool-name resolution for MCP tool lookup."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from mcp.server.fastmcp import FastMCP

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MULTI_UNDERSCORE = re.compile(r"_+")


def normalize_tool_lookup_key(name: str) -> str:
    """Normalize external tool identifiers to a canonical lookup key."""
    lowered = str(name or "").casefold()
    collapsed = _NON_ALNUM.sub("_", lowered)
    return _MULTI_UNDERSCORE.sub("_", collapsed).strip("_")


def _tool_alias_candidates(tool_name: str, tool_title: str | None) -> set[str]:
    candidates: set[str] = {
        tool_name,
        tool_name.replace("_", " "),
        tool_name.replace("_", "-"),
        tool_name.replace("-", " "),
        tool_name.replace("-", "_"),
    }
    if tool_title:
        candidates.update(
            {
                tool_title,
                tool_title.replace(" ", "_"),
                tool_title.replace(" ", "-"),
            }
        )
    return {normalize_tool_lookup_key(item) for item in candidates if normalize_tool_lookup_key(item)}


def build_tool_lookup_index(tools: Iterable[Any]) -> dict[str, str]:
    """Build normalized alias index for tool-name lookup."""
    candidate_to_tools: dict[str, set[str]] = {}
    for tool in tools:
        name = str(getattr(tool, "name", "") or "").strip()
        if not name:
            continue
        title = getattr(tool, "title", None)
        normalized_title = str(title).strip() if isinstance(title, str) else None
        for candidate in _tool_alias_candidates(name, normalized_title):
            candidate_to_tools.setdefault(candidate, set()).add(name)

    index: dict[str, str] = {}
    for candidate, names in candidate_to_tools.items():
        if len(names) == 1:
            index[candidate] = next(iter(names))
    return index


def enable_tool_name_resolution(mcp: FastMCP) -> None:
    """Enable normalized, alias-aware tool lookup for a FastMCP server."""
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return
    if getattr(manager, "_nexus_tool_resolution_enabled", False):
        return

    original_get_tool = manager.get_tool
    original_add_tool = manager.add_tool
    original_remove_tool = manager.remove_tool

    def refresh_index() -> None:
        manager._nexus_tool_lookup_index = build_tool_lookup_index(getattr(manager, "_tools", {}).values())

    def resolved_get_tool(name: str):
        tool = original_get_tool(name)
        if tool is not None:
            return tool
        candidate = normalize_tool_lookup_key(name)
        if not candidate:
            return None
        canonical_name = getattr(manager, "_nexus_tool_lookup_index", {}).get(candidate)
        if not canonical_name:
            return None
        return original_get_tool(canonical_name)

    def resolved_add_tool(*args, **kwargs):
        tool = original_add_tool(*args, **kwargs)
        refresh_index()
        return tool

    def resolved_remove_tool(*args, **kwargs):
        result = original_remove_tool(*args, **kwargs)
        refresh_index()
        return result

    manager.get_tool = resolved_get_tool  # type: ignore[method-assign]
    manager.add_tool = resolved_add_tool  # type: ignore[method-assign]
    manager.remove_tool = resolved_remove_tool  # type: ignore[method-assign]
    manager._nexus_tool_resolution_enabled = True
    refresh_index()
