"""Tests for capability parsing and managed execution helpers."""

from mcp_nexus.runtime import (
    ExecutionLimits,
    ExecutionRequest,
    ServerCapabilities,
    build_managed_command,
    extract_execution_metadata,
    parse_capability_output,
)


def test_parse_capability_output():
    raw = "\n".join(
        [
            "system=linux",
            "distro_id=ubuntu",
            "python_command=python3",
            "package_manager=apt-get",
            "package_manager=brew",
            "service_manager=systemd",
            "supports_resource_limits=1",
            "cmd_rg=1",
            "cmd_git=1",
            "cmd_chromium=1",
        ]
    )

    capabilities = parse_capability_output(raw)
    assert capabilities.system == "linux"
    assert capabilities.distro_id == "ubuntu"
    assert capabilities.package_manager == "apt-get"
    assert capabilities.package_managers == ("apt-get", "brew")
    assert capabilities.supports_resource_limits is True
    assert capabilities.has("rg") is True
    assert capabilities.has("git") is True
    assert capabilities.has("chromium") is True


def test_extract_execution_metadata():
    stderr = 'line 1\n__NEXUS_EXEC_META__{"wall_ms": 12.3}\n'
    cleaned, usage = extract_execution_metadata(stderr)
    assert cleaned == "line 1"
    assert usage == {"wall_ms": 12.3}


def test_build_managed_command_prefers_python_wrapper():
    capabilities = ServerCapabilities(system="linux", python_command="python3", supports_resource_limits=True)
    request = ExecutionRequest(command="echo hi", capture_usage=True, limits=ExecutionLimits(memory_mb=32))
    command = build_managed_command(capabilities, request)
    assert command.startswith("python3 -c ")
    assert "echo hi" in command
