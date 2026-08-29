"""Reusable helpers for detached background jobs on the target host."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class BackgroundJobPaths:
    job_id: str
    job_dir: str
    payload_path: str
    runner_path: str
    stdout_path: str
    stderr_path: str
    pid_path: str
    launcher_pid_path: str
    created_at_path: str
    started_at_path: str
    ended_at_path: str
    exit_code_path: str


def normalize_job_name(name: str) -> str:
    """Convert a human label into a filesystem-friendly slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    return slug[:48] or "job"


def make_job_id(name: str = "") -> str:
    """Return a sortable, collision-resistant job id."""
    prefix = normalize_job_name(name) if name else "job"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")  # noqa: UP017 - Python 3.10 compatibility
    return f"{prefix}-{timestamp}-{uuid4().hex[:8]}"


def job_paths(root: str, job_id: str) -> BackgroundJobPaths:
    """Return canonical paths for a background job."""
    job_dir = str(PurePosixPath(root) / job_id)
    return BackgroundJobPaths(
        job_id=job_id,
        job_dir=job_dir,
        payload_path=str(PurePosixPath(job_dir) / "payload.sh"),
        runner_path=str(PurePosixPath(job_dir) / "runner.sh"),
        stdout_path=str(PurePosixPath(job_dir) / "stdout.log"),
        stderr_path=str(PurePosixPath(job_dir) / "stderr.log"),
        pid_path=str(PurePosixPath(job_dir) / "pid"),
        launcher_pid_path=str(PurePosixPath(job_dir) / "launcher_pid"),
        created_at_path=str(PurePosixPath(job_dir) / "created_at"),
        started_at_path=str(PurePosixPath(job_dir) / "started_at"),
        ended_at_path=str(PurePosixPath(job_dir) / "ended_at"),
        exit_code_path=str(PurePosixPath(job_dir) / "exit_code"),
    )


def _export_lines(env: dict[str, str], *, python_unbuffered: bool) -> list[str]:
    exports = dict(env)
    if python_unbuffered:
        exports.setdefault("PYTHONUNBUFFERED", "1")
    lines = []
    for key, value in sorted(exports.items()):
        lines.append(f"export {key}={shlex.quote(value)}")
    return lines


def build_job_start_command(
    *,
    paths: BackgroundJobPaths,
    command: str,
    cwd: str = "",
    env: dict[str, str] | None = None,
    line_buffered: bool = True,
    python_unbuffered: bool = True,
) -> str:
    """Build a remote shell command that launches and registers a detached job."""
    payload_script = "#!/bin/sh\nset -eu\n" + command.rstrip() + "\n"
    run_lines = [
        "#!/bin/sh",
        "set +e",
        "umask 077",
        f"printf '%s' \"$$\" > {shlex.quote(paths.pid_path)}",
        f"date +%s > {shlex.quote(paths.started_at_path)}",
    ]
    if cwd:
        run_lines.append(f"cd {shlex.quote(cwd)}")
    run_lines.extend(_export_lines(env or {}, python_unbuffered=python_unbuffered))
    command_prefix = "stdbuf -oL -eL " if line_buffered else ""
    run_lines.extend(
        [
            f"if {'command -v stdbuf >/dev/null 2>&1' if line_buffered else 'false'}; then",
            (
                f"  {command_prefix}/bin/sh {shlex.quote(paths.payload_path)} "
                f">> {shlex.quote(paths.stdout_path)} 2>> {shlex.quote(paths.stderr_path)}"
            ),
            "else",
            (
                f"  /bin/sh {shlex.quote(paths.payload_path)} "
                f">> {shlex.quote(paths.stdout_path)} 2>> {shlex.quote(paths.stderr_path)}"
            ),
            "fi",
            "rc=$?",
            f"printf '%s' \"$rc\" > {shlex.quote(paths.exit_code_path)}",
            f"date +%s > {shlex.quote(paths.ended_at_path)}",
            f"rm -f {shlex.quote(paths.pid_path)}",
            "exit 0",
        ]
    )
    runner_script = "\n".join(run_lines) + "\n"

    return "\n".join(
        [
            f"job_dir={shlex.quote(paths.job_dir)}",
            'mkdir -p "$job_dir"',
            f"cat > {shlex.quote(paths.payload_path)} <<'NEXUS_JOB_PAYLOAD'",
            payload_script.rstrip("\n"),
            "NEXUS_JOB_PAYLOAD",
            f"chmod 700 {shlex.quote(paths.payload_path)}",
            f"cat > {shlex.quote(paths.runner_path)} <<'NEXUS_JOB_RUNNER'",
            runner_script.rstrip("\n"),
            "NEXUS_JOB_RUNNER",
            f"chmod 700 {shlex.quote(paths.runner_path)}",
            f"date +%s > {shlex.quote(paths.created_at_path)}",
            f"nohup {shlex.quote(paths.runner_path)} >/dev/null 2>&1 </dev/null &",
            "launcher_pid=$!",
            f"printf '%s' \"$launcher_pid\" > {shlex.quote(paths.launcher_pid_path)}",
            f"printf 'job_id=%s\\njob_dir=%s\\nstdout_path=%s\\nstderr_path=%s\\nlauncher_pid=%s\\n' "
            f'{shlex.quote(paths.job_id)} "$job_dir" {shlex.quote(paths.stdout_path)} '
            f'{shlex.quote(paths.stderr_path)} "$launcher_pid"',
        ]
    )


def build_job_probe_command(paths: BackgroundJobPaths, *, preview_lines: int = 0) -> str:
    """Build a remote shell command that reports status for a detached job."""
    preview_lines = max(0, preview_lines)
    return "\n".join(
        [
            f"job_dir={shlex.quote(paths.job_dir)}",
            'if [ ! -d "$job_dir" ]; then',
            "  echo 'status=missing'",
            f"  echo 'job_id={paths.job_id}'",
            "  exit 0",
            "fi",
            f"stdout_path={shlex.quote(paths.stdout_path)}",
            f"stderr_path={shlex.quote(paths.stderr_path)}",
            f"pid=$(cat {shlex.quote(paths.pid_path)} 2>/dev/null || true)",
            f"launcher_pid=$(cat {shlex.quote(paths.launcher_pid_path)} 2>/dev/null || true)",
            f"exit_code=$(cat {shlex.quote(paths.exit_code_path)} 2>/dev/null || true)",
            f"created_at=$(cat {shlex.quote(paths.created_at_path)} 2>/dev/null || true)",
            f"started_at=$(cat {shlex.quote(paths.started_at_path)} 2>/dev/null || true)",
            f"ended_at=$(cat {shlex.quote(paths.ended_at_path)} 2>/dev/null || true)",
            'stdout_bytes=$(wc -c < "$stdout_path" 2>/dev/null || echo 0)',
            'stderr_bytes=$(wc -c < "$stderr_path" 2>/dev/null || echo 0)',
            "status=unknown",
            'if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then',
            "  status=running",
            'elif [ -n "$exit_code" ]; then',
            "  if [ \"$exit_code\" = '0' ]; then status=completed; else status=failed; fi",
            "fi",
            f"printf 'job_id=%s\\njob_dir=%s\\nstatus=%s\\npid=%s\\nlauncher_pid=%s\\nexit_code=%s\\n' "
            f'{shlex.quote(paths.job_id)} "$job_dir" "$status" "$pid" "$launcher_pid" "$exit_code"',
            (
                "printf 'created_at=%s\\nstarted_at=%s\\nended_at=%s\\nstdout_path=%s\\nstderr_path=%s"
                "\\nstdout_bytes=%s\\nstderr_bytes=%s\\n' "
                '"$created_at" "$started_at" "$ended_at" "$stdout_path" "$stderr_path" '
                '"$stdout_bytes" "$stderr_bytes"'
            ),
            "if [ \"$status\" = 'running' ]; then",
            (
                '  ps_line=$(ps -p "$pid" -o pid=,ppid=,etime=,%cpu=,%mem=,stat=,args= 2>/dev/null '
                "| tr -s ' ' | sed 's/^ //')"
            ),
            "  printf 'ps=%s\\n' \"$ps_line\"",
            "else",
            "  printf 'ps=\\n'",
            "fi",
            f"if [ {preview_lines} -gt 0 ]; then",
            "  echo '__STDOUT__'",
            f'  tail -n {preview_lines} "$stdout_path" 2>/dev/null || true',
            "  echo '__STDERR__'",
            f'  tail -n {preview_lines} "$stderr_path" 2>/dev/null || true',
            "fi",
        ]
    )


def build_job_list_command(root: str, *, limit: int = 20) -> str:
    """Build a remote shell command that lists job directories."""
    return "\n".join(
        [
            f"root={shlex.quote(root)}",
            'if [ ! -d "$root" ]; then exit 0; fi',
            f'find "$root" -mindepth 1 -maxdepth 1 -type d | sort | tail -n {max(1, limit)}',
        ]
    )


def build_job_stop_command(paths: BackgroundJobPaths, *, signal_name: str) -> str:
    """Build a remote shell command that stops a detached job."""
    return "\n".join(
        [
            f"pid=$(cat {shlex.quote(paths.pid_path)} 2>/dev/null || true)",
            'if [ -z "$pid" ]; then',
            "  echo 'status=not_running'",
            "  exit 0",
            "fi",
            f'kill -{shlex.quote(signal_name)} "$pid" 2>/dev/null',
            "rc=$?",
            'if [ "$rc" -eq 0 ]; then status=signaled; else status=error; fi',
            'printf \'status=%s\\npid=%s\\n\' "$status" "$pid"',
            "exit 0",
        ]
    )


def build_job_logs_command(paths: BackgroundJobPaths, *, lines: int, stream: str) -> str:
    """Build a remote shell command that reads job logs."""
    normalized_stream = stream if stream in {"stdout", "stderr", "combined"} else "combined"
    line_count = max(1, lines)
    if normalized_stream == "stdout":
        return f"tail -n {line_count} {shlex.quote(paths.stdout_path)} 2>/dev/null || true"
    if normalized_stream == "stderr":
        return f"tail -n {line_count} {shlex.quote(paths.stderr_path)} 2>/dev/null || true"
    return "\n".join(
        [
            "echo '__STDOUT__'",
            f"tail -n {line_count} {shlex.quote(paths.stdout_path)} 2>/dev/null || true",
            "echo '__STDERR__'",
            f"tail -n {line_count} {shlex.quote(paths.stderr_path)} 2>/dev/null || true",
        ]
    )


def parse_job_probe(output: str) -> dict[str, Any]:
    """Parse the key/value status probe output."""
    meta: dict[str, Any] = {}
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    section = "meta"
    for raw_line in output.splitlines():
        if raw_line == "__STDOUT__":
            section = "stdout"
            continue
        if raw_line == "__STDERR__":
            section = "stderr"
            continue
        if section == "meta" and "=" in raw_line:
            key, value = raw_line.split("=", 1)
            meta[key] = value
        elif section == "stdout":
            stdout_lines.append(raw_line)
        elif section == "stderr":
            stderr_lines.append(raw_line)
    meta["stdout_preview"] = "\n".join(stdout_lines).strip()
    meta["stderr_preview"] = "\n".join(stderr_lines).strip()
    return meta
