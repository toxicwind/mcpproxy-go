"""Observability tools for Nexus audit and failure analysis."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_nexus.server import get_audit


def register(mcp: FastMCP):

    @mcp.tool()
    async def nexus_audit_recent(count: int = 50, tool: str = "") -> str:
        """Return recent audit entries across tools or for one tool."""
        audit = get_audit()
        if not audit:
            return json.dumps({"status": "audit disabled"})
        return json.dumps({"entries": audit.recent(count=count, tool=tool)}, indent=2)

    @mcp.tool()
    async def nexus_audit_summary() -> str:
        """Return aggregate audit metrics including slow and failure hotspots."""
        audit = get_audit()
        if not audit:
            return json.dumps({"status": "audit disabled"})
        return json.dumps(audit.stats(), indent=2)

    @mcp.tool()
    async def nexus_audit_failures(count: int = 25, tool: str = "") -> str:
        """Return recent failed tool calls to support debugging and ops review."""
        audit = get_audit()
        if not audit:
            return json.dumps({"status": "audit disabled"})
        return json.dumps({"entries": audit.failures(count=count, tool=tool)}, indent=2)

    @mcp.tool()
    async def nexus_slowest_tools(count: int = 10) -> str:
        """Return the slowest recent tool calls by duration."""
        audit = get_audit()
        if not audit:
            return json.dumps({"status": "audit disabled"})
        return json.dumps({"entries": audit.slowest(count=count)}, indent=2)
