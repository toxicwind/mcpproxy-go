"""Tests for task-family routing and specialized tool redirects."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP

from mcp_nexus.catalog import task_family_policy
from mcp_nexus.results import ArtifactManager, ToolExecutionContext
from mcp_nexus.task_routing import terminal_specialized_redirect
from mcp_nexus.tools import terminal


def test_task_family_policy_exposes_web_retrieval_preferences() -> None:
    policy = task_family_policy("web_retrieval")

    assert policy is not None
    assert policy["preferred_tools"][0] == "web_retrieve"
    assert "execute_python" in policy["disallowed_tools"]


def test_terminal_redirect_detects_shell_web_fetch() -> None:
    redirect = terminal_specialized_redirect(
        "execute_command",
        command=(
            "curl -L -H 'Accept: text/html,application/xhtml+xml' "
            "-H 'User-Agent: Mozilla/5.0' https://www.example.com/article"
        ),
    )

    assert redirect is not None
    assert redirect.task_family == "web_retrieval"
    assert redirect.recommended_tool == "web_retrieve"
    assert redirect.url_candidates == ("https://www.example.com/article",)


def test_terminal_redirect_ignores_non_retrieval_https_commands() -> None:
    redirect = terminal_specialized_redirect(
        "execute_command",
        command="git clone https://github.com/example/project.git",
    )

    assert redirect is None


def test_terminal_redirect_does_not_block_generic_api_curl() -> None:
    redirect = terminal_specialized_redirect(
        "execute_command",
        command="curl -X POST https://api.example.com/v1/items -H 'Authorization: Bearer token'",
    )

    assert redirect is None


@pytest.mark.asyncio
async def test_execute_python_returns_structured_redirect_for_web_fetch(monkeypatch, tmp_path: Path) -> None:
    class StubSettings:
        output_limit_bytes = 20000
        error_limit_bytes = 20000
        output_preview_bytes = 4000
        error_preview_bytes = 4000
        default_cwd = "/tmp"

        @staticmethod
        def expanded_path(value: str) -> str:
            return value or "/tmp"

    monkeypatch.setattr("mcp_nexus.tools.terminal.get_settings", lambda: StubSettings())
    monkeypatch.setattr(
        "mcp_nexus.tools.terminal.tool_context",
        lambda tool_name: ToolExecutionContext(
            tool_name=tool_name,
            stable_name=tool_name,
            resolved_runtime_id="runtime-1",
            server_instance_id="server-1",
            registry_version="registry-1",
            request_id="request-1",
            trace_id="trace-1",
            session_id=None,
            backend_kind="local",
            backend_instance="unit-test",
        ),
    )
    monkeypatch.setattr(
        "mcp_nexus.tools.terminal.get_artifacts",
        lambda: ArtifactManager(str(tmp_path / "artifacts")),
    )

    mcp = FastMCP("test-terminal-routing")
    terminal.register(mcp)

    result = await mcp._tool_manager._tools["execute_python"].fn(
        code=(
            "import requests\n"
            "headers = {'Accept': 'text/html,application/xhtml+xml', 'User-Agent': 'Mozilla/5.0'}\n"
            "requests.get('https://www.example.com/article', headers=headers)\n"
        ),
    )

    assert result.ok is False
    assert result.error_code == "SPECIALIZED_TOOL_REQUIRED"
    assert result.error_stage == "validation"
    assert result.data["redirect"]["recommended_tool"] == "web_retrieve"
    assert result.data["redirect"]["task_family"] == "web_retrieval"


@pytest.mark.asyncio
async def test_execute_batch_returns_redirect_before_running_commands(monkeypatch, tmp_path: Path) -> None:
    class StubSettings:
        output_limit_bytes = 20000
        error_limit_bytes = 20000
        output_preview_bytes = 4000
        error_preview_bytes = 4000
        default_cwd = "/tmp"
        default_command_timeout = 60

        @staticmethod
        def expanded_path(value: str) -> str:
            return value or "/tmp"

    monkeypatch.setattr("mcp_nexus.tools.terminal.get_settings", lambda: StubSettings())
    monkeypatch.setattr(
        "mcp_nexus.tools.terminal.tool_context",
        lambda tool_name: ToolExecutionContext(
            tool_name=tool_name,
            stable_name=tool_name,
            resolved_runtime_id="runtime-1",
            server_instance_id="server-1",
            registry_version="registry-1",
            request_id="request-1",
            trace_id="trace-1",
            session_id=None,
            backend_kind="local",
            backend_instance="unit-test",
        ),
    )
    monkeypatch.setattr(
        "mcp_nexus.tools.terminal.get_artifacts",
        lambda: ArtifactManager(str(tmp_path / "artifacts")),
    )

    mcp = FastMCP("test-terminal-routing")
    terminal.register(mcp)

    result = await mcp._tool_manager._tools["execute_batch"].fn(
        commands=[
            "echo hello",
            "curl -L -H 'Accept: text/html,application/xhtml+xml' https://www.example.com/article",
        ],
    )

    assert result.ok is False
    assert result.error_code == "SPECIALIZED_TOOL_REQUIRED"
    assert result.data["redirect"]["recommended_tool"] == "web_retrieve"
    assert "batch_command:2" in result.data["redirect"]["evidence"]
