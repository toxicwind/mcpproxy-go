"""Tests for detached background job helpers."""

from mcp_nexus.jobs import (
    build_job_probe_command,
    build_job_start_command,
    job_paths,
    make_job_id,
    parse_job_probe,
)


def test_make_job_id_uses_slug_prefix():
    job_id = make_job_id("Predictive Maintenance")
    assert job_id.startswith("predictive-maintenance-")


def test_build_job_start_command_sets_unbuffered_python_and_logs():
    paths = job_paths("/var/tmp/mcp-nexus/jobs", "job-1")
    command = build_job_start_command(
        paths=paths,
        command="python3 /tmp/pdm.py",
        cwd="/srv/app",
        env={"FOO": "bar"},
        line_buffered=True,
        python_unbuffered=True,
    )
    assert "PYTHONUNBUFFERED=1" in command
    assert "stdbuf -oL -eL" in command
    assert paths.stdout_path in command
    assert paths.stderr_path in command


def test_parse_job_probe_splits_meta_and_log_sections():
    payload = "\n".join(
        [
            "job_id=job-1",
            "status=running",
            "stdout_bytes=10",
            "__STDOUT__",
            "line one",
            "__STDERR__",
            "line two",
        ]
    )
    parsed = parse_job_probe(payload)
    assert parsed["job_id"] == "job-1"
    assert parsed["status"] == "running"
    assert parsed["stdout_preview"] == "line one"
    assert parsed["stderr_preview"] == "line two"


def test_build_job_probe_command_requests_preview_sections():
    command = build_job_probe_command(job_paths("/var/tmp/mcp-nexus/jobs", "job-1"), preview_lines=25)
    assert "__STDOUT__" in command
    assert "tail -n 25" in command
