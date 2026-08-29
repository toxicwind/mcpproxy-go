"""Process, service, and detached job management tools."""

from __future__ import annotations

import asyncio
import json
import shlex
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_nexus.jobs import (
    build_job_list_command,
    build_job_logs_command,
    build_job_probe_command,
    build_job_start_command,
    build_job_stop_command,
    job_paths,
    make_job_id,
    parse_job_probe,
)
from mcp_nexus.results import ToolResult, build_tool_result
from mcp_nexus.server import get_artifacts, get_pool, get_settings, tool_context


def _service_manager(capabilities) -> str:
    return capabilities.service_manager


def _compose_command(capabilities) -> str:
    return capabilities.compose_command


def _service_action_command(manager: str, action: str, service_name: str) -> str:
    if manager == "systemd":
        return f"systemctl {action} {shlex.quote(service_name)}"
    if manager == "service":
        return f"service {shlex.quote(service_name)} {shlex.quote(action)}"
    if manager == "launchctl":
        launch_action = {"start": "kickstart -k", "stop": "stop", "restart": "kickstart -k"}.get(action, action)
        return f"launchctl {launch_action} {shlex.quote(service_name)}"
    raise RuntimeError("No supported service manager detected on this host")


def _job_root() -> str:
    return get_settings().job_root


def _result(
    tool_name: str,
    *,
    ok: bool,
    duration_ms: float,
    stdout_text: str = "",
    stderr_text: str = "",
    error_code: str | None = None,
    error_stage: str | None = None,
    message: str | None = None,
    data: Any = None,
) -> ToolResult:
    settings = get_settings()
    return build_tool_result(
        context=tool_context(tool_name),
        artifacts=get_artifacts(),
        ok=ok,
        duration_ms=duration_ms,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        output_limit=settings.output_limit_bytes,
        error_limit=settings.error_limit_bytes,
        output_preview_limit=settings.output_preview_bytes,
        error_preview_limit=settings.error_preview_bytes,
        error_code=error_code,
        error_stage=error_stage,
        message=message,
        data=data,
    )


async def _run_remote(command: str, *, timeout: int = 30) -> tuple[Any, float]:
    pool = get_pool()
    conn = await pool.acquire()
    try:
        started = time.monotonic()
        result = await conn.run_full(command, timeout=timeout)
        return result, (time.monotonic() - started) * 1000
    finally:
        pool.release(conn)


async def _probe_job(job_id: str, *, preview_lines: int = 20) -> dict[str, Any]:
    result, _ = await _run_remote(build_job_probe_command(job_paths(_job_root(), job_id), preview_lines=preview_lines))
    if not result.ok and not result.stdout:
        raise RuntimeError(result.stderr.strip() or "failed to inspect background job")
    return parse_job_probe(result.stdout)


def _parse_ps_line(line: str) -> dict[str, Any] | None:
    normalized = line.strip()
    if not normalized:
        return None
    parts = normalized.split(" ", 6)
    if len(parts) < 7:
        return {"raw": normalized}
    pid, ppid, elapsed, cpu, mem, state, command = parts
    return {
        "pid": int(pid),
        "ppid": int(ppid),
        "elapsed": elapsed,
        "cpu_percent": float(cpu),
        "memory_percent": float(mem),
        "state": state,
        "command": command,
    }


async def _list_job_ids(limit: int) -> list[str]:
    result, _ = await _run_remote(build_job_list_command(_job_root(), limit=limit), timeout=15)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "failed to list background jobs")
    return [line.rsplit("/", 1)[-1] for line in result.stdout.splitlines() if line.strip()]


def register(mcp: FastMCP):

    @mcp.tool()
    async def list_services(filter_pattern: str = "") -> str:
        """List services using the active service manager on the host."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            if manager == "systemd":
                cmd = "systemctl list-units --type=service --all --no-pager"
            elif manager == "service":
                cmd = "service --status-all 2>&1"
            elif manager == "launchctl":
                cmd = "launchctl list"
            else:
                return json.dumps({"error": "No supported service manager detected"})
            if filter_pattern:
                cmd += f" | grep -i {shlex.quote(filter_pattern)}"
            result = await conn.run_full(cmd, timeout=20)
            return json.dumps({"manager": manager, "services": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def service_status(service_name: str) -> str:
        """Get detailed service status using the active service manager."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            if manager == "systemd":
                details = await conn.run_full(f"systemctl status {shlex.quote(service_name)} --no-pager -l", timeout=10)
                active = await conn.run_full(f"systemctl is-active {shlex.quote(service_name)}")
                enabled = await conn.run_full(f"systemctl is-enabled {shlex.quote(service_name)}")
                payload = {
                    "manager": manager,
                    "service": service_name,
                    "active": active.stdout.strip(),
                    "enabled": enabled.stdout.strip(),
                    "details": details.stdout.strip(),
                }
            elif manager == "service":
                details = await conn.run_full(f"service {shlex.quote(service_name)} status", timeout=10)
                payload = {
                    "manager": manager,
                    "service": service_name,
                    "active": "active" if details.ok else "unknown",
                    "details": (details.stdout + details.stderr).strip(),
                }
            elif manager == "launchctl":
                details = await conn.run_full(f"launchctl print system/{shlex.quote(service_name)}", timeout=10)
                payload = {
                    "manager": manager,
                    "service": service_name,
                    "active": "loaded" if details.ok else "unknown",
                    "details": (details.stdout + details.stderr).strip(),
                }
            else:
                return json.dumps({"error": "No supported service manager detected"})
            return json.dumps(payload)
        finally:
            pool.release(conn)

    @mcp.tool()
    async def restart_service(service_name: str) -> str:
        """Restart a service."""
        return await _service_action(service_name, "restart")

    @mcp.tool()
    async def start_service(service_name: str) -> str:
        """Start a service."""
        return await _service_action(service_name, "start")

    @mcp.tool()
    async def stop_service(service_name: str) -> str:
        """Stop a service."""
        return await _service_action(service_name, "stop")

    @mcp.tool()
    async def view_logs(service_name: str, lines: int = 100, since: str = "", follow: bool = False) -> str:
        """View recent service logs using journalctl or platform fallback."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            if manager == "systemd":
                cmd = f"journalctl -u {shlex.quote(service_name)} --no-pager -n {lines}"
                if since:
                    cmd += f" --since {shlex.quote(since)}"
            elif manager == "launchctl":
                time_window = shlex.quote(since or "1h")
                cmd = (
                    "log show --style compact "
                    f"--last {time_window} --predicate 'process == \"{service_name}\"' | tail -n {lines}"
                )
            else:
                cmd = f"tail -n {lines} /var/log/{shlex.quote(service_name)}.log 2>/dev/null"
            result = await conn.run_full(cmd, timeout=20)
            return json.dumps(
                {
                    "manager": manager,
                    "service": service_name,
                    "follow_supported": False and follow,
                    "logs": (result.stdout + result.stderr).strip()[-30000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def list_processes(filter_pattern: str = "", sort_by: str = "cpu") -> str:
        """List running processes sorted by CPU or memory."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            sort_key = "-%cpu" if sort_by == "cpu" else "-%mem"
            cmd = f"ps aux --sort={sort_key} | head -30"
            if filter_pattern:
                cmd = f"ps aux | grep -i {shlex.quote(filter_pattern)} | grep -v grep"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps({"processes": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def kill_process(pid: int, signal: str = "TERM") -> str:
        """Send a signal to a process."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"kill -{shlex.quote(signal)} {pid}")
            return json.dumps(
                {
                    "pid": pid,
                    "signal": signal,
                    "ok": result.ok,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def cron_list() -> str:
        """List all crontab entries."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full("crontab -l 2>/dev/null")
            return json.dumps({"crontab": result.stdout.strip() if result.ok else "(no crontab)"})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def cron_add(schedule: str, command: str) -> str:
        """Add a crontab entry."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            entry = f"{schedule} {command}"
            cmd = f"(crontab -l 2>/dev/null; echo {shlex.quote(entry)}) | sort -u | crontab -"
            result = await conn.run_full(cmd)
            return json.dumps({"added": entry, "ok": result.ok})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def enable_service(service_name: str) -> str:
        """Enable a service at boot when the host supports it."""
        return await _service_toggle(service_name, "enable")

    @mcp.tool()
    async def disable_service(service_name: str) -> str:
        """Disable a service at boot when the host supports it."""
        return await _service_toggle(service_name, "disable")

    @mcp.tool()
    async def service_dependencies(service_name: str) -> str:
        """Inspect service dependency tree when supported."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            if manager != "systemd":
                return json.dumps({"error": "service dependency inspection currently requires systemd"})
            result = await conn.run_full(f"systemctl list-dependencies {shlex.quote(service_name)}", timeout=15)
            return json.dumps({"service": service_name, "dependencies": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def process_tree(filter_pattern: str = "") -> str:
        """Return a process tree view, falling back to ps output when pstree is unavailable."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            has_pstree = await conn.run_full("which pstree 2>/dev/null")
            cmd = "pstree -a" if has_pstree.ok else "ps -eo pid,ppid,%cpu,%mem,command | sort -n"
            if filter_pattern:
                cmd += f" | grep -i {shlex.quote(filter_pattern)}"
            result = await conn.run_full(cmd, timeout=20)
            return json.dumps({"tree": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def process_open_files(pid: int) -> str:
        """List files and sockets opened by a process."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            cmd = f"lsof -p {pid}" if capabilities.has("lsof") else f"ls -lah /proc/{pid}/fd 2>/dev/null"
            result = await conn.run_full(cmd, timeout=20)
            return json.dumps({"pid": pid, "open_files": (result.stdout + result.stderr).strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def docker_compose_ps(path: str = ".", all_containers: bool = True) -> str:
        """List docker compose services for a project path."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            compose = _compose_command(capabilities)
            if not compose:
                return json.dumps({"error": "docker compose is not available on this host"})
            flag = "-a" if all_containers else ""
            result = await conn.run_full(f"cd {shlex.quote(path)} && {compose} ps {flag}", timeout=30)
            return json.dumps({"path": path, "services": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def docker_compose_logs(path: str = ".", service_name: str = "", lines: int = 100) -> str:
        """Show docker compose logs for a project or specific service."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            compose = _compose_command(capabilities)
            if not compose:
                return json.dumps({"error": "docker compose is not available on this host"})
            service_part = f" {shlex.quote(service_name)}" if service_name else ""
            result = await conn.run_full(
                f"cd {shlex.quote(path)} && {compose} logs --tail={lines}{service_part}",
                timeout=30,
            )
            return json.dumps({"path": path, "service": service_name or None, "logs": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool(structured_output=True)
    async def run_background_command(
        command: str,
        name: str = "",
        cwd: str = "",
        env: dict[str, str] | None = None,
        line_buffered: bool = True,
        python_unbuffered: bool = True,
    ) -> ToolResult:
        """Launch a detached command with managed stdout/stderr capture and a reusable job id."""
        started = time.monotonic()
        job_id = make_job_id(name)
        paths = job_paths(_job_root(), job_id)
        try:
            result, duration_ms = await _run_remote(
                build_job_start_command(
                    paths=paths,
                    command=command,
                    cwd=cwd or get_settings().default_cwd,
                    env=env,
                    line_buffered=line_buffered,
                    python_unbuffered=python_unbuffered,
                ),
                timeout=20,
            )
        except Exception as exc:
            return _result(
                "run_background_command",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_START_FAILED",
                error_stage="launch",
                message="Failed to launch detached background job.",
            )

        if not result.ok:
            return _result(
                "run_background_command",
                ok=False,
                duration_ms=duration_ms,
                stdout_text=result.stdout,
                stderr_text=result.stderr,
                error_code="JOB_START_FAILED",
                error_stage="launch",
                message="Failed to launch detached background job.",
                data={"job_id": job_id, "job_root": _job_root()},
            )

        meta = parse_job_probe(result.stdout)
        return _result(
            "run_background_command",
            ok=True,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            data={
                "job_id": job_id,
                "name": name or None,
                "cwd": cwd or get_settings().default_cwd or None,
                "job_root": _job_root(),
                "job_dir": meta.get("job_dir"),
                "stdout_path": meta.get("stdout_path", paths.stdout_path),
                "stderr_path": meta.get("stderr_path", paths.stderr_path),
                "launcher_pid": meta.get("launcher_pid"),
                "line_buffered": line_buffered,
                "python_unbuffered": python_unbuffered,
            },
        )

    @mcp.tool(structured_output=True)
    async def background_job_status(job_id: str, preview_lines: int = 20) -> ToolResult:
        """Inspect a detached background job without hand-written ps/wc/tail polling."""
        started = time.monotonic()
        try:
            meta = await _probe_job(job_id, preview_lines=preview_lines)
        except Exception as exc:
            return _result(
                "background_job_status",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_STATUS_FAILED",
                error_stage="inspection",
                message="Failed to inspect detached job.",
                data={"job_id": job_id},
            )

        status = str(meta.get("status", "unknown"))
        ps_info = _parse_ps_line(str(meta.get("ps", "")))
        return _result(
            "background_job_status",
            ok=status != "missing",
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=str(meta.get("stdout_preview", "")),
            stderr_text=str(meta.get("stderr_preview", "")),
            error_code="JOB_NOT_FOUND" if status == "missing" else None,
            error_stage="lookup" if status == "missing" else None,
            message="Detached job not found." if status == "missing" else None,
            data={
                "job_id": job_id,
                "status": status,
                "pid": meta.get("pid") or None,
                "launcher_pid": meta.get("launcher_pid") or None,
                "exit_code": meta.get("exit_code") or None,
                "created_at": meta.get("created_at") or None,
                "started_at": meta.get("started_at") or None,
                "ended_at": meta.get("ended_at") or None,
                "stdout_path": meta.get("stdout_path") or None,
                "stderr_path": meta.get("stderr_path") or None,
                "stdout_bytes": int(meta.get("stdout_bytes", "0") or 0),
                "stderr_bytes": int(meta.get("stderr_bytes", "0") or 0),
                "process": ps_info,
            },
        )

    @mcp.tool(structured_output=True)
    async def background_job_logs(job_id: str, lines: int = 100, stream: str = "combined") -> ToolResult:
        """Read captured stdout/stderr for a detached background job."""
        started = time.monotonic()
        paths = job_paths(_job_root(), job_id)
        try:
            status = await _probe_job(job_id, preview_lines=0)
            result, duration_ms = await _run_remote(
                build_job_logs_command(paths, lines=lines, stream=stream),
                timeout=20,
            )
        except Exception as exc:
            return _result(
                "background_job_logs",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_LOGS_FAILED",
                error_stage="inspection",
                message="Failed to read detached job logs.",
                data={"job_id": job_id},
            )

        if not result.ok:
            return _result(
                "background_job_logs",
                ok=False,
                duration_ms=duration_ms,
                stdout_text=result.stdout,
                stderr_text=result.stderr,
                error_code="JOB_LOGS_FAILED",
                error_stage="inspection",
                message="Failed to read detached job logs.",
                data={"job_id": job_id, "status": status.get("status")},
            )

        if stream == "combined":
            parsed = parse_job_probe("status=ok\n" + result.stdout)
            stdout_text = parsed.get("stdout_preview", "")
            stderr_text = parsed.get("stderr_preview", "")
        elif stream == "stdout":
            stdout_text = result.stdout
            stderr_text = ""
        else:
            stdout_text = ""
            stderr_text = result.stdout

        return _result(
            "background_job_logs",
            ok=True,
            duration_ms=duration_ms,
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            data={
                "job_id": job_id,
                "status": status.get("status"),
                "stream": stream,
                "lines": lines,
                "stdout_path": status.get("stdout_path"),
                "stderr_path": status.get("stderr_path"),
            },
        )

    @mcp.tool(structured_output=True)
    async def background_job_wait(
        job_id: str,
        timeout: int = 300,
        poll_interval_sec: int = 5,
        preview_lines: int = 40,
    ) -> ToolResult:
        """Wait server-side for a detached job to finish instead of polling with repeated sleep commands."""
        started = time.monotonic()
        deadline = time.monotonic() + max(1, timeout)
        interval = max(1, poll_interval_sec)
        last_meta: dict[str, Any] | None = None

        try:
            while True:
                last_meta = await _probe_job(job_id, preview_lines=preview_lines)
                status = str(last_meta.get("status", "unknown"))
                if status in {"completed", "failed", "missing"}:
                    break
                if time.monotonic() >= deadline:
                    return _result(
                        "background_job_wait",
                        ok=False,
                        duration_ms=(time.monotonic() - started) * 1000,
                        stdout_text=str(last_meta.get("stdout_preview", "")),
                        stderr_text=str(last_meta.get("stderr_preview", "")),
                        error_code="JOB_WAIT_TIMEOUT",
                        error_stage="wait",
                        message="Timed out while waiting for detached job to finish.",
                        data={
                            "job_id": job_id,
                            "status": status,
                            "pid": last_meta.get("pid") or None,
                            "stdout_bytes": int(last_meta.get("stdout_bytes", "0") or 0),
                            "stderr_bytes": int(last_meta.get("stderr_bytes", "0") or 0),
                        },
                    )
                await asyncio.sleep(interval)
        except Exception as exc:
            return _result(
                "background_job_wait",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_WAIT_FAILED",
                error_stage="wait",
                message="Failed while waiting for detached job.",
                data={"job_id": job_id},
            )

        assert last_meta is not None
        final_status = str(last_meta.get("status", "unknown"))
        return _result(
            "background_job_wait",
            ok=final_status == "completed",
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=str(last_meta.get("stdout_preview", "")),
            stderr_text=str(last_meta.get("stderr_preview", "")),
            error_code=(
                "JOB_FAILED" if final_status == "failed" else ("JOB_NOT_FOUND" if final_status == "missing" else None)
            ),
            error_stage="wait" if final_status in {"failed", "missing"} else None,
            message="Detached job finished with a non-zero exit code." if final_status == "failed" else None,
            data={
                "job_id": job_id,
                "status": final_status,
                "exit_code": last_meta.get("exit_code") or None,
                "pid": last_meta.get("pid") or None,
                "stdout_path": last_meta.get("stdout_path") or None,
                "stderr_path": last_meta.get("stderr_path") or None,
                "stdout_bytes": int(last_meta.get("stdout_bytes", "0") or 0),
                "stderr_bytes": int(last_meta.get("stderr_bytes", "0") or 0),
            },
        )

    @mcp.tool(structured_output=True)
    async def background_job_stop(job_id: str, signal: str = "TERM") -> ToolResult:
        """Stop a detached background job by job id."""
        started = time.monotonic()
        try:
            result, duration_ms = await _run_remote(
                build_job_stop_command(job_paths(_job_root(), job_id), signal_name=signal),
                timeout=10,
            )
        except Exception as exc:
            return _result(
                "background_job_stop",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_STOP_FAILED",
                error_stage="signal",
                message="Failed to stop detached job.",
                data={"job_id": job_id, "signal": signal},
            )

        meta = parse_job_probe(result.stdout)
        status = meta.get("status", "error")
        return _result(
            "background_job_stop",
            ok=status == "signaled",
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=None if status == "signaled" else "JOB_NOT_RUNNING",
            error_stage=None if status == "signaled" else "signal",
            message=None if status == "signaled" else "Detached job is not currently running.",
            data={"job_id": job_id, "signal": signal, "status": status, "pid": meta.get("pid") or None},
        )

    @mcp.tool(structured_output=True)
    async def list_background_jobs(limit: int = 20, active_only: bool = False) -> ToolResult:
        """List detached jobs known to the target host, optionally filtering to active ones."""
        started = time.monotonic()
        try:
            job_ids = await _list_job_ids(limit=max(1, min(limit, 100)))
            jobs = []
            for job_id in reversed(job_ids):
                meta = await _probe_job(job_id, preview_lines=5)
                status = str(meta.get("status", "unknown"))
                if active_only and status != "running":
                    continue
                jobs.append(
                    {
                        "job_id": job_id,
                        "status": status,
                        "pid": meta.get("pid") or None,
                        "exit_code": meta.get("exit_code") or None,
                        "stdout_bytes": int(meta.get("stdout_bytes", "0") or 0),
                        "stderr_bytes": int(meta.get("stderr_bytes", "0") or 0),
                        "created_at": meta.get("created_at") or None,
                        "started_at": meta.get("started_at") or None,
                        "ended_at": meta.get("ended_at") or None,
                        "stdout_path": meta.get("stdout_path") or None,
                        "stderr_path": meta.get("stderr_path") or None,
                    }
                )
            return _result(
                "list_background_jobs",
                ok=True,
                duration_ms=(time.monotonic() - started) * 1000,
                data={"jobs": jobs, "job_root": _job_root(), "active_only": active_only},
            )
        except Exception as exc:
            return _result(
                "list_background_jobs",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="JOB_LIST_FAILED",
                error_stage="inspection",
                message="Failed to list detached jobs.",
            )

    @mcp.tool(structured_output=True)
    async def process_status(pid: int, include_io: bool = True) -> ToolResult:
        """Inspect one process without composing ps, wc, and /proc commands manually."""
        started = time.monotonic()
        io_command = f"cat /proc/{pid}/io 2>/dev/null" if include_io else "true"
        command = "\n".join(
            [
                f"if ! ps -p {pid} >/dev/null 2>&1; then echo 'status=missing'; exit 0; fi",
                f"ps -p {pid} -o pid=,ppid=,etime=,%cpu=,%mem=,stat=,args= | tr -s ' ' | sed 's/^ //'",
                "echo '__IO__'",
                io_command,
            ]
        )
        try:
            result, duration_ms = await _run_remote(command, timeout=10)
        except Exception as exc:
            return _result(
                "process_status",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="PROCESS_STATUS_FAILED",
                error_stage="inspection",
                message="Failed to inspect process.",
                data={"pid": pid},
            )

        if not result.ok and not result.stdout:
            return _result(
                "process_status",
                ok=False,
                duration_ms=duration_ms,
                stdout_text=result.stdout,
                stderr_text=result.stderr,
                error_code="PROCESS_STATUS_FAILED",
                error_stage="inspection",
                message="Failed to inspect process.",
                data={"pid": pid},
            )

        head, _, io_part = result.stdout.partition("__IO__\n")
        ps_info = _parse_ps_line(head.strip())
        if head.strip() == "status=missing":
            return _result(
                "process_status",
                ok=False,
                duration_ms=duration_ms,
                error_code="PROCESS_NOT_FOUND",
                error_stage="lookup",
                message="Process was not found.",
                data={"pid": pid},
            )
        return _result(
            "process_status",
            ok=True,
            duration_ms=duration_ms,
            stdout_text=head.strip(),
            stderr_text=io_part.strip(),
            data={"pid": pid, "process": ps_info, "io": io_part.strip() if include_io else None},
        )

    async def _service_action(service_name: str, action: str) -> str:
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            cmd = _service_action_command(manager, action, service_name)
            result = await conn.run_full(cmd, timeout=30)
            status_payload = await service_status(service_name)
            try:
                status = json.loads(status_payload)
            except json.JSONDecodeError:
                status = {"details": status_payload}
            return json.dumps(
                {
                    "manager": manager,
                    "service": service_name,
                    "action": action,
                    "ok": result.ok,
                    "status": status,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    async def _service_toggle(service_name: str, action: str) -> str:
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            manager = _service_manager(capabilities)
            if manager == "systemd":
                cmd = f"systemctl {action} {shlex.quote(service_name)}"
            elif manager == "launchctl":
                return json.dumps({"error": f"{action} is not managed through launchctl in a portable way"})
            elif manager == "service":
                return json.dumps({"error": "service enable/disable requires systemd on this host"})
            else:
                return json.dumps({"error": "No supported service manager detected"})
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps(
                {
                    "manager": manager,
                    "service": service_name,
                    "action": action,
                    "ok": result.ok,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)
