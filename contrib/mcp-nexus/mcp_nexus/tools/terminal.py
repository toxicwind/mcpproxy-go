"""Terminal and runtime inspection tools."""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_nexus.python_execution import (
    python_inline_wrapper,
    python_run_path_wrapper,
    secret_file_env_var,
    write_secret_file,
)
from mcp_nexus.python_sandbox import (
    ensure_python_sandbox,
    sandbox_root,
)
from mcp_nexus.python_sandbox import (
    sandbox_path as build_sandbox_path,
)
from mcp_nexus.results import ToolResult, build_tool_result, preview_text
from mcp_nexus.runtime import ExecutionLimits, ExecutionRequest, build_managed_command, extract_execution_metadata
from mcp_nexus.server import get_artifacts, get_pool, get_settings, tool_context
from mcp_nexus.task_routing import ToolRedirect, terminal_specialized_redirect
from mcp_nexus.transport.ssh import CommandResult


def _safe_cwd(cwd: str) -> str:
    settings = get_settings()
    return settings.expanded_path(cwd or settings.default_cwd)


def _unique_heredoc_marker(script: str, *, prefix: str) -> str:
    marker = prefix
    counter = 0
    while marker in script:
        counter += 1
        marker = f"{prefix}_{counter}"
    return marker


def _stdin_script_command(interpreter: str, script: str, *, stdin_flag: str = "") -> str:
    marker = _unique_heredoc_marker(script, prefix="NEXUS_SCRIPT_EOF")
    stdin_suffix = f" {stdin_flag}" if stdin_flag else ""
    return f"{shlex.quote(interpreter)}{stdin_suffix} <<'{marker}'\n{script}\n{marker}"


def _stdin_script_argv_command(
    interpreter: str,
    script: str,
    *,
    args: list[str] | None = None,
    stdin_flag: str = "",
) -> str:
    marker = _unique_heredoc_marker(script, prefix="NEXUS_SCRIPT_EOF")
    argv = " ".join(shlex.quote(arg) for arg in (args or []))
    stdin_suffix = f" {stdin_flag}" if stdin_flag else ""
    argv_suffix = f" {argv}" if argv else ""
    return f"{shlex.quote(interpreter)}{stdin_suffix}{argv_suffix} <<'{marker}'\n{script}\n{marker}"


def _argv_command(program: str, args: list[str] | None = None) -> str:
    return " ".join([shlex.quote(program), *(shlex.quote(arg) for arg in (args or []))])


def _error_code_for_result(result: CommandResult) -> tuple[str | None, str | None]:
    if result.ok:
        return None, None
    stderr = result.stderr.lower()
    if result.exit_code == 124 or "timed out" in stderr:
        return "TIMEOUT", "execution"
    return "COMMAND_FAILED", "execution"


@dataclass(frozen=True)
class BatchCommandResult:
    index: int
    command: str
    ok: bool
    exit_code: int | None
    duration_ms: float
    error_code: str | None
    error_stage: str | None
    stdout_preview: str
    stderr_preview: str
    usage: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "command": self.command,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "error_code": self.error_code,
            "error_stage": self.error_stage,
            "stdout_preview": self.stdout_preview,
            "stderr_preview": self.stderr_preview,
            "usage": self.usage,
        }


async def _run_execution_on_connection(
    conn,
    *,
    capabilities,
    command: str,
    cwd: str = "",
    timeout: int = 60,
    env: dict[str, str] | None = None,
    capture_usage: bool = True,
    cpu_limit_sec: int = 0,
    memory_limit_mb: int = 0,
    file_size_limit_mb: int = 0,
    process_limit: int = 0,
) -> tuple[CommandResult, dict[str, Any] | None, dict[str, Any], float]:
    request = ExecutionRequest(
        command=command,
        cwd=_safe_cwd(cwd),
        timeout=timeout,
        env=env or {},
        capture_usage=capture_usage,
        limits=ExecutionLimits(
            cpu_seconds=max(0, cpu_limit_sec),
            memory_mb=max(0, memory_limit_mb),
            file_size_mb=max(0, file_size_limit_mb),
            process_count=max(0, process_limit),
        ),
    )
    start = time.monotonic()
    result = await conn.run_full(build_managed_command(capabilities, request), timeout=timeout)
    duration_ms = (time.monotonic() - start) * 1000
    stderr, usage = extract_execution_metadata(result.stderr)
    normalized = CommandResult(stdout=result.stdout, stderr=stderr, exit_code=result.exit_code)
    capability_data = {
        "system": capabilities.system,
        "python_command": capabilities.python_command,
        "package_manager": capabilities.package_manager,
        "service_manager": capabilities.service_manager,
    }
    return normalized, usage, capability_data, duration_ms


async def _run_execution(
    *,
    command: str,
    cwd: str = "",
    timeout: int = 60,
    env: dict[str, str] | None = None,
    capture_usage: bool = True,
    cpu_limit_sec: int = 0,
    memory_limit_mb: int = 0,
    file_size_limit_mb: int = 0,
    process_limit: int = 0,
) -> tuple[CommandResult, dict[str, Any] | None, dict[str, Any], float]:
    settings = get_settings()
    timeout = min(timeout or settings.default_command_timeout, 600)
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities()
        return await _run_execution_on_connection(
            conn,
            capabilities=capabilities,
            command=command,
            cwd=cwd,
            timeout=timeout,
            env=env,
            capture_usage=capture_usage,
            cpu_limit_sec=cpu_limit_sec,
            memory_limit_mb=memory_limit_mb,
            file_size_limit_mb=file_size_limit_mb,
            process_limit=process_limit,
        )
    finally:
        pool.release(conn)


def _aggregate_batch_usage(results: list[BatchCommandResult]) -> dict[str, Any] | None:
    usages = [result.usage for result in results if result.usage]
    if not usages:
        return None

    aggregate: dict[str, Any] = {
        "command_count": len(results),
        "usage_count": len(usages),
        "wall_ms_total": round(sum(float(item.get("wall_ms", 0.0)) for item in usages), 2),
        "user_cpu_s_total": round(sum(float(item.get("user_cpu_s", 0.0)) for item in usages), 4),
        "system_cpu_s_total": round(sum(float(item.get("system_cpu_s", 0.0)) for item in usages), 4),
        "max_rss_kb_peak": max(int(item.get("max_rss_kb", 0) or 0) for item in usages),
    }
    return aggregate


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
    exit_code: int | None = None,
    data: Any = None,
    usage: dict[str, Any] | None = None,
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
        exit_code=exit_code,
        resource_usage=usage,
    )


def _redirect_result(tool_name: str, redirect: ToolRedirect, *, duration_ms: float) -> ToolResult:
    return _result(
        tool_name,
        ok=False,
        duration_ms=duration_ms,
        error_code="SPECIALIZED_TOOL_REQUIRED",
        error_stage="validation",
        message=(
            f"This request matches {redirect.task_family} and should use "
            f"{redirect.recommended_tool} instead of {tool_name}."
        ),
        data={"redirect": redirect.to_dict()},
    )


async def _resolve_database_binding(
    tool_name: str,
    *,
    started: float,
    database_profile: str = "",
    database: str = "",
    db_env_var: str = "",
) -> tuple[tuple[str, str] | None, ToolResult | None]:
    wants_db_env = bool(database_profile.strip() or database.strip() or db_env_var.strip())
    if not wants_db_env:
        return None, None

    settings = get_settings()
    profile_name = database_profile.strip()
    try:
        resolved = settings.resolve_requested_db_profile(
            profile_name=profile_name,
            database=database,
            execution_backend=str(get_pool().backend_metadata()["backend_kind"]),
        )
    except ValueError as exc:
        return None, _result(
            tool_name,
            ok=False,
            duration_ms=(time.monotonic() - started) * 1000,
            error_code="INVALID_DATABASE_URI",
            error_stage="validation",
            message=str(exc),
        )

    if resolved is None:
        return None, _result(
            tool_name,
            ok=False,
            duration_ms=(time.monotonic() - started) * 1000,
            error_code="DB_PROFILE_NOT_FOUND" if profile_name else "DB_PROFILE_NOT_CONFIGURED",
            error_stage="configuration",
            message=(
                f"Database profile {profile_name!r} was not found."
                if profile_name
                else "No database profile is configured. Set NEXUS_DB_PROFILES_JSON or pass a database URI."
            ),
        )

    return (db_env_var.strip() or "NEXUS_DB_URI", resolved.dsn), None


async def _resolve_database_env(
    tool_name: str,
    *,
    started: float,
    database_profile: str = "",
    database: str = "",
    db_env_var: str = "",
) -> tuple[dict[str, str] | None, ToolResult | None]:
    binding, error = await _resolve_database_binding(
        tool_name,
        started=started,
        database_profile=database_profile,
        database=database,
        db_env_var=db_env_var,
    )
    if error:
        return None, error
    if binding is None:
        return {}, None
    env_var, dsn = binding
    return {env_var: dsn}, None


def register(mcp: FastMCP):

    @mcp.tool(structured_output=True)
    async def execute_command(
        command: str,
        cwd: str = "",
        timeout: int = 60,
        env: dict[str, str] | None = None,
        database_profile: str = "",
        database: str = "",
        db_env_var: str = "",
        capture_usage: bool = True,
        cpu_limit_sec: int = 0,
        memory_limit_mb: int = 0,
        file_size_limit_mb: int = 0,
        process_limit: int = 0,
    ) -> ToolResult:
        """Execute a shell command with structured stdout/stderr and artifact fallbacks."""
        started = time.monotonic()
        redirect = terminal_specialized_redirect("execute_command", command=command)
        if redirect is not None:
            return _redirect_result("execute_command", redirect, duration_ms=(time.monotonic() - started) * 1000)
        database_env, env_error = await _resolve_database_env(
            "execute_command",
            started=started,
            database_profile=database_profile,
            database=database,
            db_env_var=db_env_var,
        )
        if env_error:
            return env_error
        try:
            result, usage, capabilities, duration_ms = await _run_execution(
                command=command,
                cwd=cwd,
                timeout=timeout,
                env={**(env or {}), **(database_env or {})},
                capture_usage=capture_usage,
                cpu_limit_sec=cpu_limit_sec,
                memory_limit_mb=memory_limit_mb,
                file_size_limit_mb=file_size_limit_mb,
                process_limit=process_limit,
            )
        except Exception as exc:
            return _result(
                "execute_command",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="EXECUTION_SETUP_FAILED",
                error_stage="setup",
                message="Failed to prepare command execution.",
            )

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "execute_command",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Command execution failed.",
            exit_code=result.exit_code,
            data={"capabilities": capabilities, "cwd": _safe_cwd(cwd) or None},
            usage=usage,
        )

    @mcp.tool(structured_output=True)
    async def execute_batch(
        commands: list[str],
        cwd: str = "",
        timeout: int = 60,
        env: dict[str, str] | None = None,
        database_profile: str = "",
        database: str = "",
        db_env_var: str = "",
        capture_usage: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
        cpu_limit_sec: int = 0,
        memory_limit_mb: int = 0,
        file_size_limit_mb: int = 0,
        process_limit: int = 0,
        max_commands: int = 20,
    ) -> ToolResult:
        """Execute a sequence of shell commands with structured per-step results."""
        started = time.monotonic()
        redirect = terminal_specialized_redirect("execute_batch", commands=commands)
        if redirect is not None:
            return _redirect_result("execute_batch", redirect, duration_ms=(time.monotonic() - started) * 1000)
        settings = get_settings()
        if not commands:
            return _result(
                "execute_batch",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="COMMANDS_REQUIRED",
                error_stage="validation",
                message="commands is required",
            )
        if len(commands) > max_commands:
            return _result(
                "execute_batch",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="COMMAND_LIMIT_EXCEEDED",
                error_stage="validation",
                message=f"commands must contain at most {max_commands} items",
                data={"command_count": len(commands), "max_commands": max_commands},
            )

        timeout = min(timeout or settings.default_command_timeout, 600)
        database_env, env_error = await _resolve_database_env(
            "execute_batch",
            started=started,
            database_profile=database_profile,
            database=database,
            db_env_var=db_env_var,
        )
        if env_error:
            return env_error
        env = {**(env or {}), **(database_env or {})}
        planned_commands = [
            {
                "index": index,
                "command": command,
                "cwd": _safe_cwd(cwd) or None,
                "timeout": timeout,
                "env_keys": sorted(env.keys()),
                "capture_usage": capture_usage,
                "limits": {
                    "cpu_seconds": max(0, cpu_limit_sec),
                    "memory_mb": max(0, memory_limit_mb),
                    "file_size_mb": max(0, file_size_limit_mb),
                    "process_count": max(0, process_limit),
                },
            }
            for index, command in enumerate(commands, start=1)
        ]

        if dry_run:
            return _result(
                "execute_batch",
                ok=True,
                duration_ms=(time.monotonic() - started) * 1000,
                message="Dry run completed without executing commands.",
                data={
                    "dry_run": True,
                    "cwd": _safe_cwd(cwd) or None,
                    "command_count": len(commands),
                    "timeout": timeout,
                    "capture_usage": capture_usage,
                    "stop_on_error": stop_on_error,
                    "max_commands": max_commands,
                    "limits": {
                        "cpu_seconds": max(0, cpu_limit_sec),
                        "memory_mb": max(0, memory_limit_mb),
                        "file_size_mb": max(0, file_size_limit_mb),
                        "process_count": max(0, process_limit),
                    },
                    "planned_commands": planned_commands,
                },
            )

        pool = get_pool()
        try:
            conn = await pool.acquire()
        except Exception as exc:
            return _result(
                "execute_batch",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="BATCH_EXECUTION_SETUP_FAILED",
                error_stage="setup",
                message="Failed to prepare batch execution.",
                data={"command_count": len(commands), "dry_run": False},
            )

        command_results: list[BatchCommandResult] = []
        stdout_sections: list[str] = []
        stderr_sections: list[str] = []
        capability_data: dict[str, Any] = {}
        try:
            try:
                capabilities = await conn.probe_capabilities()
            except Exception as exc:
                return _result(
                    "execute_batch",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    stderr_text=str(exc),
                    error_code="BATCH_EXECUTION_SETUP_FAILED",
                    error_stage="setup",
                    message="Failed to probe execution capabilities.",
                    data={"command_count": len(commands), "dry_run": False},
                )
            for index, command in enumerate(commands, start=1):
                command_start = time.monotonic()
                try:
                    result, usage, capability_data, duration_ms = await _run_execution_on_connection(
                        conn,
                        capabilities=capabilities,
                        command=command,
                        cwd=cwd,
                        timeout=timeout,
                        env=env,
                        capture_usage=capture_usage,
                        cpu_limit_sec=cpu_limit_sec,
                        memory_limit_mb=memory_limit_mb,
                        file_size_limit_mb=file_size_limit_mb,
                        process_limit=process_limit,
                    )
                except Exception as exc:
                    command_results.append(
                        BatchCommandResult(
                            index=index,
                            command=command,
                            ok=False,
                            exit_code=None,
                            duration_ms=(time.monotonic() - command_start) * 1000,
                            error_code="BATCH_EXECUTION_FAILED",
                            error_stage="execution",
                            stdout_preview="",
                            stderr_preview=str(exc),
                            usage=None,
                        )
                    )
                    stderr_sections.append(f"[{index}] $ {command}\n{str(exc)}")
                    if stop_on_error:
                        break
                    continue

                error_code, error_stage = _error_code_for_result(result)
                stdout_preview = preview_text(result.stdout, settings.output_preview_bytes) or ""
                stderr_preview = preview_text(result.stderr, settings.error_preview_bytes) or ""
                command_results.append(
                    BatchCommandResult(
                        index=index,
                        command=command,
                        ok=result.ok,
                        exit_code=result.exit_code,
                        duration_ms=duration_ms,
                        error_code=error_code,
                        error_stage=error_stage,
                        stdout_preview=stdout_preview,
                        stderr_preview=stderr_preview,
                        usage=usage,
                    )
                )
                if result.stdout.strip():
                    stdout_sections.append(f"[{index}] $ {command}\n{result.stdout.rstrip()}")
                if result.stderr.strip():
                    stderr_sections.append(f"[{index}] $ {command}\n{result.stderr.rstrip()}")
                if not result.ok and stop_on_error:
                    break
        finally:
            pool.release(conn)

        batch_usage = _aggregate_batch_usage(command_results)
        total_duration_ms = (time.monotonic() - started) * 1000
        succeeded = sum(1 for item in command_results if item.ok)
        failed = len(command_results) - succeeded
        all_ok = failed == 0 and len(command_results) == len(commands)
        aborted = len(command_results) < len(commands)
        if aborted and failed:
            error_code = "BATCH_ABORTED_ON_ERROR" if stop_on_error else "BATCH_PARTIAL_FAILURE"
            error_stage = "execution"
            message = (
                "Batch execution stopped after a command failed."
                if stop_on_error
                else "Batch completed with failures."
            )
        elif failed:
            error_code = "BATCH_PARTIAL_FAILURE"
            error_stage = "execution"
            message = "Batch completed with failures."
        else:
            error_code = None
            error_stage = None
            message = None

        return _result(
            "execute_batch",
            ok=all_ok,
            duration_ms=total_duration_ms,
            stdout_text="\n\n".join(stdout_sections),
            stderr_text="\n\n".join(stderr_sections),
            error_code=error_code,
            error_stage=error_stage,
            message=message,
            data={
                "dry_run": False,
                "cwd": _safe_cwd(cwd) or None,
                "command_count": len(commands),
                "executed_count": len(command_results),
                "success_count": succeeded,
                "failure_count": failed,
                "aborted": aborted,
                "stop_on_error": stop_on_error,
                "timeout": timeout,
                "capture_usage": capture_usage,
                "max_commands": max_commands,
                "limits": {
                    "cpu_seconds": max(0, cpu_limit_sec),
                    "memory_mb": max(0, memory_limit_mb),
                    "file_size_mb": max(0, file_size_limit_mb),
                    "process_count": max(0, process_limit),
                },
                "results": [item.to_dict() for item in command_results],
                "planned_commands": planned_commands,
                "capabilities": capability_data if command_results else {},
            },
            usage=batch_usage,
        )

    @mcp.tool(structured_output=True)
    async def execute_script(
        script: str,
        interpreter: str = "bash",
        cwd: str = "",
        timeout: int = 120,
        env: dict[str, str] | None = None,
        database_profile: str = "",
        database: str = "",
        db_env_var: str = "",
        capture_usage: bool = True,
        cpu_limit_sec: int = 0,
        memory_limit_mb: int = 0,
    ) -> ToolResult:
        """Execute a multi-line script through the chosen interpreter."""
        started = time.monotonic()
        redirect = terminal_specialized_redirect(
            "execute_script",
            script=script,
            interpreter=interpreter,
        )
        if redirect is not None:
            return _redirect_result("execute_script", redirect, duration_ms=(time.monotonic() - started) * 1000)
        command = _stdin_script_command(interpreter, script)
        database_env, env_error = await _resolve_database_env(
            "execute_script",
            started=started,
            database_profile=database_profile,
            database=database,
            db_env_var=db_env_var,
        )
        if env_error:
            return env_error
        try:
            result, usage, capabilities, duration_ms = await _run_execution(
                command=command,
                cwd=cwd,
                timeout=timeout,
                env={**(env or {}), **(database_env or {})},
                capture_usage=capture_usage,
                cpu_limit_sec=cpu_limit_sec,
                memory_limit_mb=memory_limit_mb,
            )
        except Exception as exc:
            return _result(
                "execute_script",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="EXECUTION_SETUP_FAILED",
                error_stage="setup",
                message="Failed to prepare script execution.",
                data={"interpreter": interpreter},
            )

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "execute_script",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Script execution failed.",
            exit_code=result.exit_code,
            data={"interpreter": interpreter, "capabilities": capabilities, "cwd": _safe_cwd(cwd) or None},
            usage=usage,
        )

    @mcp.tool(structured_output=True)
    async def execute_python(
        code: str,
        cwd: str = "",
        timeout: int = 120,
        sandbox_path: str = "",
        requirements: list[str] | None = None,
        env: dict[str, str] | None = None,
        database_profile: str = "",
        database: str = "",
        db_env_var: str = "",
        capture_usage: bool = True,
        cpu_limit_sec: int = 60,
        memory_limit_mb: int = 512,
    ) -> ToolResult:
        """Execute Python code on the connected target without embedding raw credentials in the code."""
        runtime_env = dict(env or {})
        sandbox_info: dict[str, Any] | None = None
        started = time.monotonic()
        redirect = terminal_specialized_redirect("execute_python", code=code)
        if redirect is not None:
            return _redirect_result("execute_python", redirect, duration_ms=(time.monotonic() - started) * 1000)
        database_binding, env_error = await _resolve_database_binding(
            "execute_python",
            started=started,
            database_profile=database_profile,
            database=database,
            db_env_var=db_env_var,
        )
        if env_error:
            return env_error

        pool = get_pool()
        conn = await pool.acquire()
        db_secret_path = ""
        try:
            capabilities = await conn.probe_capabilities()
            if not capabilities.python_command:
                return _result(
                    "execute_python",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="PYTHON_UNAVAILABLE",
                    error_stage="capability_probe",
                    message="Python is not available on the target host.",
                    data={"capabilities": capabilities.to_dict()},
                )
            python_bin = capabilities.python_command

            if sandbox_path or requirements:
                sandbox_info, _ = await ensure_python_sandbox(
                    sandbox_path_value=sandbox_path or build_sandbox_path(name="python"),
                    requirements=requirements,
                )
                python_bin = str(sandbox_info["python"])
                sandbox_root = str(sandbox_info["path"])
                runtime_env["VIRTUAL_ENV"] = sandbox_root
                runtime_env["PATH"] = f"{sandbox_root}/bin:$PATH"

            command = _stdin_script_command(python_bin, code, stdin_flag="-")
            if database_binding is not None:
                db_env_name, dsn = database_binding
                db_secret_path = await write_secret_file(conn, prefix="execute-python-db", content=dsn)
                runtime_env[secret_file_env_var(db_env_name)] = db_secret_path
                command = _stdin_script_command(
                    python_bin,
                    python_inline_wrapper(code, db_env_var=db_env_name),
                    stdin_flag="-",
                )

            result, usage, capability_data, duration_ms = await _run_execution_on_connection(
                conn,
                capabilities=capabilities,
                command=command,
                cwd=cwd,
                timeout=timeout,
                env=runtime_env,
                capture_usage=capture_usage,
                cpu_limit_sec=cpu_limit_sec,
                memory_limit_mb=memory_limit_mb,
            )
        except Exception as exc:
            return _result(
                "execute_python",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="PYTHON_EXECUTION_SETUP_FAILED",
                error_stage="setup",
                message="Failed to prepare Python execution.",
                data={"sandbox": sandbox_info},
            )
        finally:
            if db_secret_path:
                await conn.run_full(f"rm -f {shlex.quote(db_secret_path)}", timeout=20)
            pool.release(conn)

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "execute_python",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Python execution failed.",
            exit_code=result.exit_code,
            data={
                "capabilities": capability_data,
                "sandbox": sandbox_info,
                "cwd": _safe_cwd(cwd) or None,
                "database_delivery": "secret_file" if database_binding is not None else None,
            },
            usage=usage,
        )

    @mcp.tool(structured_output=True)
    async def execute_python_file(
        path: str,
        args: list[str] | None = None,
        cwd: str = "",
        timeout: int = 120,
        sandbox_path: str = "",
        requirements: list[str] | None = None,
        env: dict[str, str] | None = None,
        database_profile: str = "",
        database: str = "",
        db_env_var: str = "",
        capture_usage: bool = True,
        cpu_limit_sec: int = 60,
        memory_limit_mb: int = 512,
    ) -> ToolResult:
        """Execute an existing Python file on the target host with optional sandboxed dependencies."""
        started = time.monotonic()
        if not path.strip():
            return _result(
                "execute_python_file",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="PATH_REQUIRED",
                error_stage="validation",
                message="path is required",
            )

        runtime_env = dict(env or {})
        sandbox_info: dict[str, Any] | None = None
        database_binding, env_error = await _resolve_database_binding(
            "execute_python_file",
            started=started,
            database_profile=database_profile,
            database=database,
            db_env_var=db_env_var,
        )
        if env_error:
            return env_error

        pool = get_pool()
        conn = await pool.acquire()
        db_secret_path = ""
        try:
            capabilities = await conn.probe_capabilities()
            if not capabilities.python_command:
                return _result(
                    "execute_python_file",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="PYTHON_UNAVAILABLE",
                    error_stage="capability_probe",
                    message="Python is not available on the target host.",
                    data={"capabilities": capabilities.to_dict()},
                )

            python_bin = capabilities.python_command
            if sandbox_path or requirements:
                sandbox_info, _ = await ensure_python_sandbox(
                    sandbox_path_value=sandbox_path or build_sandbox_path(name="python"),
                    requirements=requirements,
                )
                python_bin = str(sandbox_info["python"])
                sandbox_root = str(sandbox_info["path"])
                runtime_env["VIRTUAL_ENV"] = sandbox_root
                runtime_env["PATH"] = f"{sandbox_root}/bin:$PATH"

            command = _argv_command(python_bin, [path, *(args or [])])
            if database_binding is not None:
                db_env_name, dsn = database_binding
                db_secret_path = await write_secret_file(conn, prefix="execute-python-file-db", content=dsn)
                runtime_env[secret_file_env_var(db_env_name)] = db_secret_path
                command = _stdin_script_argv_command(
                    python_bin,
                    python_run_path_wrapper(db_env_var=db_env_name),
                    args=[path, *(args or [])],
                    stdin_flag="-",
                )

            result, usage, capability_data, duration_ms = await _run_execution_on_connection(
                conn,
                capabilities=capabilities,
                command=command,
                cwd=cwd,
                timeout=timeout,
                env=runtime_env,
                capture_usage=capture_usage,
                cpu_limit_sec=cpu_limit_sec,
                memory_limit_mb=memory_limit_mb,
            )
        except Exception as exc:
            return _result(
                "execute_python_file",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="PYTHON_EXECUTION_SETUP_FAILED",
                error_stage="setup",
                message="Failed to prepare Python file execution.",
                data={"sandbox": sandbox_info, "path": path},
            )
        finally:
            if db_secret_path:
                await conn.run_full(f"rm -f {shlex.quote(db_secret_path)}", timeout=20)
            pool.release(conn)

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "execute_python_file",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Python file execution failed.",
            exit_code=result.exit_code,
            data={
                "capabilities": capability_data,
                "sandbox": sandbox_info,
                "cwd": _safe_cwd(cwd) or None,
                "path": path,
                "args": args or [],
                "database_delivery": "secret_file" if database_binding is not None else None,
            },
            usage=usage,
        )

    @mcp.tool(structured_output=True)
    async def environment_info() -> ToolResult:
        """Get environment and runtime defaults for the connected target host."""
        settings = get_settings()
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            command = (
                "echo '---HOSTNAME---' && hostname && "
                "echo '---UPTIME---' && uptime && "
                "echo '---WHOAMI---' && whoami && "
                "echo '---SHELL---' && echo ${SHELL:-/bin/sh} && "
                "echo '---KERNEL---' && uname -a"
            )
            result = await conn.run_full(command, timeout=15)
        except Exception as exc:
            return _result(
                "environment_info",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="ENVIRONMENT_INFO_FAILED",
                error_stage="inspection",
                message="Failed to inspect target environment.",
            )
        finally:
            pool.release(conn)

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "environment_info",
            ok=result.ok,
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Environment inspection failed.",
            exit_code=result.exit_code,
            data={
                "defaults": {
                    "cwd": settings.default_cwd or None,
                    "timeout_sec": settings.default_command_timeout,
                    "output_limit_bytes": settings.output_limit_bytes,
                    "sandbox_root": sandbox_root(),
                },
                "capabilities": capabilities.to_dict(),
            },
        )

    @mcp.tool(structured_output=True)
    async def which_command(name: str) -> ToolResult:
        """Check if a command exists and show its resolved path."""
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        try:
            command = (
                f"command -v {shlex.quote(name)} 2>/dev/null && {shlex.quote(name)} --version 2>/dev/null | head -1"
            )
            result = await conn.run_full(command)
        except Exception as exc:
            return _result(
                "which_command",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="WHICH_FAILED",
                error_stage="inspection",
                message="Failed to resolve command path.",
                data={"command": name},
            )
        finally:
            pool.release(conn)

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "which_command",
            ok=result.ok,
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Command was not found.",
            exit_code=result.exit_code,
            data={"command": name, "found": result.ok},
        )

    @mcp.tool(structured_output=True)
    async def server_capabilities(refresh: bool = False) -> ToolResult:
        """Return the target host capabilities used for package, service, and sandbox defaults."""
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities(refresh=refresh)
        except Exception as exc:
            return _result(
                "server_capabilities",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="CAPABILITY_PROBE_FAILED",
                error_stage="inspection",
                message="Failed to probe server capabilities.",
            )
        finally:
            pool.release(conn)

        return _result(
            "server_capabilities",
            ok=True,
            duration_ms=(time.monotonic() - started) * 1000,
            data=capabilities.to_dict(),
        )

    @mcp.tool(structured_output=True)
    async def create_python_sandbox(
        name: str = "",
        path: str = "",
        requirements: list[str] | None = None,
        recreate: bool = False,
    ) -> ToolResult:
        """Create a reusable virtualenv sandbox on the target host."""
        started = time.monotonic()
        try:
            sandbox_info, capabilities = await ensure_python_sandbox(
                sandbox_path_value=build_sandbox_path(name=name, path=path),
                requirements=requirements,
                recreate=recreate,
            )
        except Exception as exc:
            return _result(
                "create_python_sandbox",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="SANDBOX_CREATE_FAILED",
                error_stage="setup",
                message="Failed to create Python sandbox.",
            )

        return _result(
            "create_python_sandbox",
            ok=True,
            duration_ms=(time.monotonic() - started) * 1000,
            data={"sandbox": sandbox_info, "capabilities": capabilities},
        )

    @mcp.tool(structured_output=True)
    async def list_python_sandboxes(base_path: str = "") -> ToolResult:
        """List discovered Python virtualenv sandboxes under the configured sandbox root."""
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        try:
            search_root = base_path or sandbox_root()
            command = (
                f"test -d {shlex.quote(search_root)} || exit 0; "
                f"find {shlex.quote(search_root)} -maxdepth 3 -name pyvenv.cfg -print"
            )
            result = await conn.run_full(command, timeout=20)
        except Exception as exc:
            return _result(
                "list_python_sandboxes",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="SANDBOX_LIST_FAILED",
                error_stage="inspection",
                message="Failed to list Python sandboxes.",
                data={"base_path": base_path or sandbox_root()},
            )
        finally:
            pool.release(conn)

        sandboxes = []
        for cfg in filter(None, result.stdout.splitlines()):
            sandbox = str(PurePosixPath(cfg).parent)
            sandboxes.append({"path": sandbox, "python": f"{sandbox}/bin/python", "pip": f"{sandbox}/bin/pip"})

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "list_python_sandboxes",
            ok=result.ok,
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Failed to enumerate sandboxes.",
            exit_code=result.exit_code,
            data={"base_path": base_path or sandbox_root(), "sandboxes": sandboxes},
        )

    @mcp.tool(structured_output=True)
    async def remove_python_sandbox(path: str) -> ToolResult:
        """Remove a Python sandbox created under the configured sandbox root."""
        started = time.monotonic()
        if not path:
            return _result(
                "remove_python_sandbox",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="PATH_REQUIRED",
                error_stage="validation",
                message="path is required",
            )

        root = PurePosixPath(sandbox_root())
        target = PurePosixPath(path)
        if root not in target.parents and target != root:
            return _result(
                "remove_python_sandbox",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="SANDBOX_SCOPE_VIOLATION",
                error_stage="validation",
                message="sandbox removal is restricted to the configured sandbox root",
                data={"sandbox_root": str(root)},
            )

        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"rm -rf {shlex.quote(path)}", timeout=60)
        except Exception as exc:
            return _result(
                "remove_python_sandbox",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="SANDBOX_REMOVE_FAILED",
                error_stage="execution",
                message="Failed to remove Python sandbox.",
                data={"path": path},
            )
        finally:
            pool.release(conn)

        error_code, error_stage = _error_code_for_result(result)
        return _result(
            "remove_python_sandbox",
            ok=result.ok,
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Sandbox removal failed.",
            exit_code=result.exit_code,
            data={"path": path, "removed": result.ok},
        )
