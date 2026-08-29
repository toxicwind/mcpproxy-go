"""Tests for structured tool results and artifact fallback."""

from mcp_nexus.results import ArtifactManager, ToolExecutionContext, build_tool_result


def test_build_tool_result_spills_large_stdout_to_artifact(tmp_path):
    artifacts = ArtifactManager(str(tmp_path))
    context = ToolExecutionContext(
        tool_name="execute_command",
        stable_name="execute_command",
        resolved_runtime_id="runtime-1",
        server_instance_id="instance-1",
        registry_version="registry-1",
        request_id="request-1",
        trace_id="trace-1",
        session_id="session-1",
        backend_kind="local",
        backend_instance="root@127.0.0.1:22",
    )

    result = build_tool_result(
        context=context,
        artifacts=artifacts,
        ok=True,
        duration_ms=12.3,
        stdout_text="x" * 128,
        stderr_text="",
        output_limit=16,
        error_limit=16,
        output_preview_limit=32,
        error_preview_limit=16,
    )

    assert result.stdout is None
    assert result.stdout_preview is not None
    assert len(result.artifact_paths) == 1
