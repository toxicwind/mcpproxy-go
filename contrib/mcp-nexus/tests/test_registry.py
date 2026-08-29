"""Tests for stable tool registry metadata."""

import json

import pytest
from mcp.server.fastmcp import FastMCP

from mcp_nexus.config import Settings
from mcp_nexus.registry import apply_registry_metadata, build_tool_registry, tool_implementation_fingerprint
from mcp_nexus.server import create_server
from mcp_nexus.tool_resolution import enable_tool_name_resolution
from mcp_nexus.tools import intelligence


def test_registry_builds_stable_bindings():
    mcp = FastMCP("test")

    @mcp.tool()
    async def db_query(query: str) -> str:
        return query

    registry = build_tool_registry(mcp, server_instance_id="instance-1", alias_base="/mcp-nexus")
    binding = registry.tool("db_query")

    assert binding is not None
    assert binding.stable_path == "/mcp-nexus/db_query"
    assert binding.runtime_path == "/mcp-nexus/runtime/instance-1/db_query"
    assert binding.category == "database"
    assert binding.implementation_fingerprint


def test_registry_metadata_is_attached_to_tools():
    mcp = FastMCP("test")

    @mcp.tool()
    async def execute_command(command: str) -> str:
        return command

    registry = build_tool_registry(mcp, server_instance_id="instance-2", alias_base="/mcp-nexus")
    apply_registry_metadata(mcp, registry)

    tool = mcp._tool_manager._tools["execute_command"]
    binding = registry.tool("execute_command")
    assert tool.meta is not None
    assert binding is not None
    assert tool.meta["nexus"]["registry_version"] == registry.registry_version
    assert tool.meta["nexus"]["stable_path"] == "/mcp-nexus/execute_command"
    assert tool.meta["nexus"]["implementation_fingerprint"] == binding.implementation_fingerprint


def test_registry_version_changes_when_tool_implementation_changes():
    mcp_one = FastMCP("test-one")
    mcp_two = FastMCP("test-two")

    @mcp_one.tool(name="db_query")
    async def db_query_one(query: str) -> str:
        return query

    @mcp_two.tool(name="db_query")
    async def db_query_two(query: str) -> str:
        value = query.strip()
        return value

    registry_one = build_tool_registry(mcp_one, server_instance_id="instance-1", alias_base="/mcp-nexus")
    registry_two = build_tool_registry(mcp_two, server_instance_id="instance-1", alias_base="/mcp-nexus")
    binding_one = registry_one.tool("db_query")
    binding_two = registry_two.tool("db_query")

    assert binding_one is not None
    assert binding_two is not None
    assert binding_one.implementation_fingerprint != binding_two.implementation_fingerprint
    assert registry_one.registry_version != registry_two.registry_version


def test_tool_implementation_fingerprint_falls_back_without_source() -> None:
    namespace: dict[str, object] = {}
    exec(
        "def dynamic_tool(value):\n"
        "    return value.strip()\n",
        namespace,
    )
    fingerprint = tool_implementation_fingerprint(namespace["dynamic_tool"])

    assert fingerprint
    assert isinstance(fingerprint, str)


def test_create_server_uses_configured_streamable_http_path():
    settings = Settings()
    settings.mcp_path = "/mcp/nexus"
    server = create_server(settings)
    assert server.settings.streamable_http_path == "/mcp/nexus"


@pytest.mark.asyncio
async def test_nexus_tool_registry_reports_live_binding(monkeypatch):
    mcp = FastMCP("test-intelligence")

    @mcp.tool()
    async def http_fetch(url: str) -> str:
        return url

    registry = build_tool_registry(mcp, server_instance_id="instance-3", alias_base="/mcp-nexus")
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_registry", lambda: registry)
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_memory", lambda: None)

    intelligence.register(mcp)

    tool = mcp._tool_manager._tools["nexus_tool_registry"]
    payload = json.loads(await tool.fn(tool_name="http_fetch"))

    assert payload["available"] is True
    assert payload["surface_scope"] == "server_registry_snapshot"
    assert payload["callable_surface_confirmed"] is False
    assert payload["tool"]["name"] == "http_fetch"
    assert payload["tool"]["stable_path"] == "/mcp-nexus/http_fetch"


@pytest.mark.asyncio
async def test_nexus_tool_catalog_marks_server_catalog_scope(monkeypatch):
    mcp = FastMCP("test-intelligence-catalog")

    @mcp.tool()
    async def http_fetch(url: str) -> str:
        return url

    registry = build_tool_registry(mcp, server_instance_id="instance-5", alias_base="/mcp-nexus")
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_registry", lambda: registry)
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_memory", lambda: None)

    intelligence.register(mcp)

    tool = mcp._tool_manager._tools["nexus_tool_catalog"]
    payload = json.loads(await tool.fn())

    assert payload["surface_scope"] == "server_catalog"
    assert payload["callable_surface_confirmed"] is False
    assert payload["server_instance_id"] == "instance-5"
    assert "availability_note" in payload
    assert payload["control_plane"]["tool_registry_http_fetch_call_template"]["url"]


@pytest.mark.asyncio
async def test_nexus_tool_handoff_reports_registry_aware_next_tools(monkeypatch):
    mcp = FastMCP("test-intelligence-handoff")

    @mcp.tool()
    async def web_retrieve(url: str) -> str:
        return url

    @mcp.tool()
    async def browser_fetch(url: str) -> str:
        return url

    @mcp.tool()
    async def browser_bootstrap(target: str = "chromium") -> str:
        return target

    registry = build_tool_registry(mcp, server_instance_id="instance-4", alias_base="/mcp-nexus")
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_registry", lambda: registry)
    monkeypatch.setattr("mcp_nexus.tools.intelligence.get_memory", lambda: None)

    intelligence.register(mcp)

    tool = mcp._tool_manager._tools["nexus_tool_handoff"]
    payload = json.loads(await tool.fn(current_tool="http_fetch", outcome="blocked_access"))

    assert payload["resolved"] is True
    assert payload["surface_scope"] == "server_registry_snapshot"
    assert payload["handoff"]["recommended_tool"] == "browser_fetch"
    assert payload["handoff"]["next_tools"][0]["tool"] == "browser_fetch"
    assert payload["handoff"]["next_tools"][0]["available"] is True
    assert payload["handoff"]["next_tools"][0]["availability_scope"] == "server_registry_snapshot"
    assert payload["handoff"]["next_tools"][0]["callable_surface_confirmed"] is False


@pytest.mark.asyncio
async def test_tool_lookup_resolves_humanized_tool_names():
    mcp = FastMCP("test-tool-resolution")

    @mcp.tool()
    async def browser_screenshot(url: str) -> str:
        return url

    enable_tool_name_resolution(mcp)

    assert await mcp._tool_manager.call_tool("Browser screenshot", {"url": "https://example.com"}) == "https://example.com"
    assert await mcp._tool_manager.call_tool("browser-screenshot", {"url": "https://example.com"}) == "https://example.com"


@pytest.mark.asyncio
async def test_tool_lookup_keeps_ambiguous_aliases_unresolved():
    mcp = FastMCP("test-tool-resolution-ambiguity")

    @mcp.tool(name="browser_screenshot")
    async def browser_screenshot_one(url: str) -> str:
        return f"one:{url}"

    @mcp.tool(name="browser-screenshot")
    async def browser_screenshot_two(url: str) -> str:
        return f"two:{url}"

    enable_tool_name_resolution(mcp)

    assert mcp._tool_manager.get_tool("browser screenshot") is None
