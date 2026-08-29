"""Intelligence tools — recall context, view insights, manage preferences."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_nexus.catalog import (
    TASK_FAMILY_POLICIES,
    TOOL_CATEGORIES,
    catalog_summary,
    task_family_for_tool,
    task_family_handoff,
)
from mcp_nexus.server import control_plane_reference, get_memory, get_registry


def register(mcp: FastMCP):

    @mcp.tool()
    async def nexus_recall() -> str:
        """Recall what you were working on — short-term context, long-term memory, and recent errors.

        Use this at the start of a conversation to pick up where you left off.
        """
        memory = get_memory()
        if not memory:
            return json.dumps({"status": "intelligence disabled"})

        ctx = await memory.get_context()
        prefs = await memory.get_preferences()
        if prefs:
            ctx["preferences"] = prefs
            if "long_term_memory" in ctx and isinstance(ctx["long_term_memory"], dict):
                ctx["long_term_memory"]["preferences"] = prefs
        return json.dumps(ctx, indent=2)

    @mcp.tool()
    async def nexus_insights() -> str:
        """View usage analytics — top tools, focus areas, error rates, and detected workflows.

        Helps understand how you use the server and identify automation opportunities.
        """
        memory = get_memory()
        if not memory:
            return json.dumps({"status": "intelligence disabled"})

        insights = await memory.get_insights()
        workflows = await memory.get_workflows()
        if workflows:
            insights["detected_workflows"] = workflows
        return json.dumps(insights, indent=2)

    @mcp.tool()
    async def nexus_suggest(current_tool: str = "") -> str:
        """Get next-step suggestions from learned transition patterns and observed outcomes.

        Args:
            current_tool: The tool you just used (auto-filled if omitted).
        """
        memory = get_memory()
        if not memory:
            return json.dumps({"status": "intelligence disabled"})

        ctx = await memory.get_context()
        if not current_tool:
            recent = ctx.get("recent_actions", [])
            if recent:
                current_tool = recent[0]["tool"]
        suggestions = await memory.suggest_next(current_tool) if current_tool else []
        return json.dumps(
            {
                "based_on": current_tool or None,
                "next_tools": suggestions,
                "recent_context": ctx.get("recent_actions", [])[:3],
            },
            indent=2,
        )

    @mcp.tool()
    async def nexus_preferences(action: str = "list", key: str = "", value: str = "") -> str:
        """View or set user preferences that the system has learned.

        Args:
            action: "list" to view all, "set" to manually set a preference, "clear" to reset all memory.
            key: Preference key (for set action). Learned keys are generic slots such as arg:repo_path or arg:profile.
            value: Preference value (for set action).
        """
        memory = get_memory()
        if not memory:
            return json.dumps({"status": "intelligence disabled"})

        if action == "set" and key and value:
            await memory.set_preference(key, value)
            return json.dumps({"status": "ok", "key": key, "value": value})

        if action == "clear":
            await memory.clear()
            return json.dumps({"status": "memory cleared"})

        prefs = await memory.get_preferences()
        return json.dumps(prefs, indent=2)

    @mcp.tool()
    async def nexus_workflows() -> str:
        """Return the strongest detected multi-step workflows from historical usage."""
        memory = get_memory()
        if not memory:
            return json.dumps({"status": "intelligence disabled"})
        return json.dumps({"workflows": await memory.get_workflows()}, indent=2)

    @mcp.tool()
    async def nexus_tool_catalog() -> str:
        """Return the explicit Nexus server catalog by category.

        This catalog describes tools compiled into the active server build. It
        does not prove that the current caller-exported surface can invoke every
        listed tool.
        """
        registry = get_registry()
        surface_reference = control_plane_reference()
        summary = catalog_summary()
        return json.dumps(
            {
                "server_instance_id": registry.server_instance_id,
                "registry_version": registry.registry_version,
                "surface_scope": "server_catalog",
                "callable_surface_confirmed": False,
                "availability_note": (
                    "This catalog describes tools compiled into the active server build. The current "
                    "caller-exported callable surface may be narrower."
                ),
                "control_plane": surface_reference,
                "total_tools": summary.total_tools,
                "categories": {category: list(tools) for category, tools in TOOL_CATEGORIES.items()},
                "category_counts": summary.category_counts,
                "task_families": {
                    family: {
                        "description": str(policy["description"]),
                        "preferred_tools": list(policy["preferred_tools"]),
                        "disallowed_tools": list(policy["disallowed_tools"]),
                        "workflow": policy.get("workflow", {}),
                    }
                    for family, policy in TASK_FAMILY_POLICIES.items()
                },
            },
            indent=2,
        )

    @mcp.tool()
    async def nexus_tool_handoff(task_family: str = "", current_tool: str = "", outcome: str = "") -> str:
        """Return the next specialized tool sequence for an explicit task-family handoff.

        Use this when a preferred tool fails, is unavailable, or you need a registry-aware
        fallback order instead of improvising the next tool.
        """
        registry = get_registry()
        available_tools = [binding.name for binding in registry.tools]
        handoff = task_family_handoff(
            task_family=task_family,
            current_tool=current_tool,
            outcome=outcome,
            available_tools=available_tools,
            availability_scope="server_registry_snapshot",
        )
        return json.dumps(
            {
                "task_family": task_family or task_family_for_tool(current_tool),
                "current_tool": current_tool or None,
                "outcome": outcome or None,
                "resolved": handoff is not None,
                "registry_version": registry.registry_version,
                "server_instance_id": registry.server_instance_id,
                "surface_scope": "server_registry_snapshot",
                "callable_surface_confirmed": False,
                "availability_note": (
                    "The handoff uses the active server registry snapshot. The current caller-exported "
                    "callable surface may still be narrower."
                ),
                "control_plane": control_plane_reference(),
                "handoff": handoff,
            },
            indent=2,
        )

    @mcp.tool()
    async def nexus_tool_registry(tool_name: str = "", include_all: bool = False) -> str:
        """Return the active server registry snapshot or a specific runtime tool binding.

        Use this when a tool call appears missing, stale, or bound to the wrong
        runtime. It reflects the active server instance, but it does not prove
        that the current caller-exported tool surface can invoke every binding.
        """
        registry = get_registry()
        binding = registry.tool(tool_name) if tool_name else None
        payload: dict[str, object] = {
            "server_instance_id": registry.server_instance_id,
            "registry_version": registry.registry_version,
            "alias_base": registry.alias_base,
            "tool_count": len(registry.tools),
            "surface_scope": "server_registry_snapshot",
            "callable_surface_confirmed": False,
            "availability_note": (
                "This is the active server registry snapshot. The current caller-exported callable surface "
                "may still be narrower."
            ),
            "control_plane": control_plane_reference(),
        }
        if tool_name:
            payload["tool_name"] = tool_name
            payload["available"] = binding is not None
            payload["tool"] = binding.to_dict() if binding is not None else None
            payload["available_tools"] = sorted(item.name for item in registry.tools)
            return json.dumps(payload, indent=2)
        if include_all:
            payload["tools"] = [binding.to_dict() for binding in registry.tools]
        else:
            payload["tools"] = [binding.name for binding in registry.tools]
        return json.dumps(payload, indent=2)
