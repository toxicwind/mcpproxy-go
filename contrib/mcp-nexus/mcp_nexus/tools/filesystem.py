"""File system operations — read, write, edit, search, list."""

from __future__ import annotations

import json
import shlex
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_nexus.results import ToolResult, build_tool_result
from mcp_nexus.server import get_artifacts, get_pool, get_settings, tool_context


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
        exit_code=exit_code,
        data=data,
    )


def _diff_status_label(code: str) -> str:
    return {
        "A": "added",
        "D": "deleted",
        "M": "modified",
        "R": "renamed",
        "C": "copied",
        "T": "type_changed",
        "U": "conflicted",
        "X": "unknown",
        "B": "broken",
    }.get(code, "unknown")


def _parse_compare_status_output(output: str, *, max_entries: int = 200) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []
    counts = {
        "added": 0,
        "deleted": 0,
        "modified": 0,
        "renamed": 0,
        "copied": 0,
        "type_changed": 0,
        "conflicted": 0,
        "unknown": 0,
    }
    entry_count = 0

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        entry_count += 1
        parts = line.split("\t")
        status_code = parts[0].strip()
        code = status_code[0] if status_code else "?"
        label = _diff_status_label(code)
        counts[label] = counts.get(label, 0) + 1
        entry: dict[str, Any] = {
            "status_code": status_code,
            "status": label,
        }
        if code in {"R", "C"} and len(parts) >= 3:
            entry["old_path"] = parts[1]
            entry["new_path"] = parts[2]
        elif len(parts) >= 2:
            entry["path"] = parts[1]
        else:
            entry["raw"] = line
        if len(changes) < max_entries:
            changes.append(entry)

    return {
        "changes": changes,
        "counts": counts,
        "truncated": entry_count > len(changes),
        "total": entry_count,
    }


def _path_kind_command(label: str, path: str) -> str:
    quoted = shlex.quote(path)
    return (
        f"if [ -L {quoted} ]; then printf '{label}=symlink\\n'; "
        f"elif [ -d {quoted} ]; then printf '{label}=directory\\n'; "
        f"elif [ -f {quoted} ]; then printf '{label}=file\\n'; "
        f"elif [ -e {quoted} ]; then printf '{label}=other\\n'; "
        f"else printf '{label}=missing\\n'; fi"
    )


def register(mcp: FastMCP):

    @mcp.tool()
    async def read_file(path: str, offset: int = 0, limit: int = 2000) -> str:
        """Read file contents with optional line range.

        Args:
            path: Absolute path on the remote server.
            offset: Start from this line number (0-based).
            limit: Maximum number of lines to return.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"sed -n '{offset + 1},{offset + limit}p' {shlex.quote(path)}"
            result = await conn.run_full(cmd, timeout=30)
            if not result.ok:
                return json.dumps({"error": result.stderr.strip(), "path": path})
            total = await conn.run(f"wc -l < {shlex.quote(path)}", timeout=10)
            return json.dumps(
                {
                    "path": path,
                    "content": result.stdout,
                    "offset": offset,
                    "limit": limit,
                    "total_lines": int(total.strip()) if total.strip().isdigit() else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def write_file(path: str, content: str) -> str:
        """Write content to a file (creates parent directories if needed).

        Args:
            path: Absolute path on the remote server.
            content: File content to write.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            dir_path = "/".join(path.rsplit("/", 1)[:-1])
            if dir_path:
                await conn.run_full(f"mkdir -p {shlex.quote(dir_path)}")
            await conn.write_file(path, content)
            return json.dumps({"status": "ok", "path": path, "bytes": len(content.encode("utf-8"))})
        except Exception as e:
            return json.dumps({"error": str(e), "path": path})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def edit_file(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
        """Edit a file by replacing exact string matches.

        Args:
            path: Absolute path on the remote server.
            old_string: The exact text to find and replace.
            new_string: The replacement text.
            replace_all: If True, replace all occurrences. Otherwise only the first.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            current = await conn.read_file(path)
            count = current.count(old_string)
            if count == 0:
                return json.dumps({"error": "old_string not found in file", "path": path})
            if count > 1 and not replace_all:
                return json.dumps(
                    {
                        "error": f"old_string found {count} times — set replace_all=true or provide more context",
                        "path": path,
                        "occurrences": count,
                    }
                )
            if replace_all:
                updated = current.replace(old_string, new_string)
            else:
                updated = current.replace(old_string, new_string, 1)
            await conn.write_file(path, updated)
            return json.dumps({"status": "ok", "path": path, "replacements": count if replace_all else 1})
        except Exception as e:
            return json.dumps({"error": str(e), "path": path})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def list_directory(path: str = "/", show_hidden: bool = False, long_format: bool = False) -> str:
        """List directory contents.

        Args:
            path: Directory path on the remote server.
            show_hidden: Include hidden files (dotfiles).
            long_format: Show detailed info (permissions, size, date).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            flags = "-1"
            if show_hidden:
                flags += "a"
            if long_format:
                flags = "-lh" + ("a" if show_hidden else "")
            result = await conn.run(f"ls {flags} {shlex.quote(path)}", timeout=15)
            return json.dumps({"path": path, "entries": result.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def search_files(pattern: str, path: str = "/", max_results: int = 50) -> str:
        """Search for files by glob pattern.

        Args:
            pattern: Glob pattern (e.g., "*.py", "**/*.json").
            path: Base directory to search from.
            max_results: Maximum number of results.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"find {shlex.quote(path)} -name {shlex.quote(pattern)} -type f 2>/dev/null | head -n {max_results}"
            result = await conn.run_full(cmd, timeout=30)
            files = [f for f in result.stdout.strip().split("\n") if f]
            return json.dumps({"pattern": pattern, "base": path, "count": len(files), "files": files})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def search_content(
        pattern: str, path: str = "/", glob_filter: str = "", max_results: int = 50, context_lines: int = 0
    ) -> str:
        """Search file contents using regex (ripgrep or grep).

        Args:
            pattern: Regex pattern to search for.
            path: Base directory to search in.
            glob_filter: Optional file glob filter (e.g., "*.py").
            max_results: Maximum number of matching lines.
            context_lines: Number of context lines before/after each match.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            # Try ripgrep first, fall back to grep
            rg_check = await conn.run_full("which rg 2>/dev/null")
            if rg_check.ok:
                cmd = f"rg -n --max-count {max_results}"
                if context_lines:
                    cmd += f" -C {context_lines}"
                if glob_filter:
                    cmd += f" --glob {shlex.quote(glob_filter)}"
                cmd += f" {shlex.quote(pattern)} {shlex.quote(path)}"
            else:
                cmd = "grep -rn"
                if context_lines:
                    cmd += f" -C {context_lines}"
                if glob_filter:
                    cmd += f" --include={shlex.quote(glob_filter)}"
                cmd += f" {shlex.quote(pattern)} {shlex.quote(path)} | head -n {max_results}"

            result = await conn.run_full(cmd, timeout=60)
            return json.dumps(
                {
                    "pattern": pattern,
                    "base": path,
                    "matches": result.stdout.strip() if result.stdout.strip() else "(no matches)",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool(structured_output=True)
    async def compare_paths(
        left_path: str,
        right_path: str,
        include_patch: bool = False,
        context_lines: int = 3,
        max_entries: int = 200,
        ignore_whitespace: bool = False,
    ) -> ToolResult:
        """Compare two files or directory trees with structured diff summaries."""
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        try:
            kind_probe = await conn.run_full(
                "\n".join(
                    [
                        _path_kind_command("left_kind", left_path),
                        _path_kind_command("right_kind", right_path),
                    ]
                ),
                timeout=10,
            )
            if not kind_probe.ok:
                return _result(
                    "compare_paths",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    stdout_text=kind_probe.stdout,
                    stderr_text=kind_probe.stderr,
                    error_code="PATH_KIND_PROBE_FAILED",
                    error_stage="inspection",
                    message="Failed to inspect comparison targets.",
                    data={"left_path": left_path, "right_path": right_path},
                )

            kinds: dict[str, str] = {}
            for raw_line in kind_probe.stdout.splitlines():
                if "=" not in raw_line:
                    continue
                key, value = raw_line.split("=", 1)
                kinds[key.strip()] = value.strip()

            left_kind = kinds.get("left_kind", "unknown")
            right_kind = kinds.get("right_kind", "unknown")
            if "missing" in {left_kind, right_kind}:
                return _result(
                    "compare_paths",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="PATH_NOT_FOUND",
                    error_stage="inspection",
                    message="One or both comparison targets were not found.",
                    data={
                        "left_path": left_path,
                        "right_path": right_path,
                        "left_kind": left_kind,
                        "right_kind": right_kind,
                    },
                )

            git_check = await conn.run_full("which git 2>/dev/null", timeout=5)
            if not git_check.ok:
                return _result(
                    "compare_paths",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="GIT_UNAVAILABLE",
                    error_stage="capability_probe",
                    message="git is not installed on the target host.",
                    data={
                        "left_path": left_path,
                        "right_path": right_path,
                        "left_kind": left_kind,
                        "right_kind": right_kind,
                    },
                )

            ignore_flag = " --ignore-all-space" if ignore_whitespace else ""
            compare_root = f"-- {shlex.quote(left_path)} {shlex.quote(right_path)}"
            name_status_cmd = (
                "git diff --no-index --no-ext-diff"
                f"{ignore_flag} --name-status {compare_root}"
            )
            summary_cmd = f"git diff --no-index --no-ext-diff{ignore_flag} --summary {compare_root}"
            patch_cmd = f"git diff --no-index --no-ext-diff{ignore_flag} -U{max(0, context_lines)} {compare_root}"

            name_status_result = await conn.run_full(name_status_cmd, timeout=60)
            if name_status_result.exit_code not in {0, 1}:
                return _result(
                    "compare_paths",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    stdout_text=name_status_result.stdout,
                    stderr_text=name_status_result.stderr,
                    error_code="DIFF_ENGINE_FAILED",
                    error_stage="inspection",
                    message="Failed to compute the comparison.",
                    data={
                        "left_path": left_path,
                        "right_path": right_path,
                        "left_kind": left_kind,
                        "right_kind": right_kind,
                    },
                    exit_code=name_status_result.exit_code,
                )

            summary_result = await conn.run_full(summary_cmd, timeout=60)
            patch_result = None
            if include_patch:
                patch_result = await conn.run_full(patch_cmd, timeout=120)

            parsed = _parse_compare_status_output(name_status_result.stdout, max_entries=max_entries)
            identical = name_status_result.exit_code == 0
            diff_detected = name_status_result.exit_code == 1
            summary_text = summary_result.stdout.strip() or summary_result.stderr.strip()
            report_parts = [
                f"left: {left_path} ({left_kind})",
                f"right: {right_path} ({right_kind})",
                "engine: git --no-index",
                f"status: {'identical' if identical else 'different'}",
                (
                    "changes: "
                    f"added {parsed['counts']['added']}, deleted {parsed['counts']['deleted']}, "
                    f"modified {parsed['counts']['modified']}, renamed {parsed['counts']['renamed']}, "
                    f"copied {parsed['counts']['copied']}, type_changed {parsed['counts']['type_changed']}"
                ),
            ]
            if summary_text:
                report_parts.extend(["summary:", summary_text])
            if parsed["changes"]:
                report_parts.extend(["name-status preview:", json.dumps(parsed["changes"], indent=2)])
            if include_patch and patch_result is not None:
                if patch_result.exit_code not in {0, 1}:
                    return _result(
                        "compare_paths",
                        ok=False,
                        duration_ms=(time.monotonic() - started) * 1000,
                        stdout_text=patch_result.stdout,
                        stderr_text=patch_result.stderr,
                        error_code="DIFF_ENGINE_FAILED",
                        error_stage="inspection",
                        message="Failed to compute the patch preview.",
                        data={
                            "left_path": left_path,
                            "right_path": right_path,
                            "left_kind": left_kind,
                            "right_kind": right_kind,
                        },
                        exit_code=patch_result.exit_code,
                    )
                report_parts.extend(["patch preview:", patch_result.stdout.strip()])

            message = "Paths are identical." if identical else "Paths differ."
            return _result(
                "compare_paths",
                ok=True,
                duration_ms=(time.monotonic() - started) * 1000,
                stdout_text="\n\n".join(part for part in report_parts if part),
                message=message,
                exit_code=name_status_result.exit_code,
                data={
                    "left_path": left_path,
                    "right_path": right_path,
                    "left_kind": left_kind,
                    "right_kind": right_kind,
                    "engine": "git --no-index",
                    "identical": identical,
                    "diff_detected": diff_detected,
                    "ignore_whitespace": ignore_whitespace,
                    "context_lines": max(0, context_lines),
                    "max_entries": max_entries,
                    "counts": parsed["counts"],
                    "changes_preview": parsed["changes"],
                    "changes_truncated": parsed["truncated"],
                    "total_changes": parsed["total"],
                    "summary": summary_text or None,
                    "patch_included": include_patch,
                },
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def file_info(path: str) -> str:
        """Get detailed file information (size, permissions, timestamps).

        Args:
            path: Absolute path on the remote server.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = (
                f"stat -c '%s|%a|%U|%G|%y|%x|%F' {shlex.quote(path)} 2>/dev/null || "
                f"stat -f '%z|%Lp|%Su|%Sg|%Sm|%Sa|%HT' {shlex.quote(path)}"
            )
            result = await conn.run_full(cmd, timeout=10)
            if not result.ok:
                return json.dumps({"error": f"File not found: {path}"})
            parts = result.stdout.strip().split("|")
            return json.dumps(
                {
                    "path": path,
                    "size_bytes": parts[0] if len(parts) > 0 else "?",
                    "permissions": parts[1] if len(parts) > 1 else "?",
                    "owner": parts[2] if len(parts) > 2 else "?",
                    "group": parts[3] if len(parts) > 3 else "?",
                    "modified": parts[4] if len(parts) > 4 else "?",
                    "accessed": parts[5] if len(parts) > 5 else "?",
                    "type": parts[6] if len(parts) > 6 else "?",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def move_file(source: str, destination: str) -> str:
        """Move or rename a file/directory.

        Args:
            source: Current path.
            destination: New path.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"mv {shlex.quote(source)} {shlex.quote(destination)}")
            if result.ok:
                return json.dumps({"status": "ok", "from": source, "to": destination})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def delete_file(path: str, recursive: bool = False) -> str:
        """Delete a file or directory.

        Args:
            path: Absolute path to delete.
            recursive: If True, delete directories recursively (use with caution).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            flag = "-rf" if recursive else "-f"
            # Safety: block dangerous paths
            dangerous = ["/", "/root", "/etc", "/usr", "/var", "/bin", "/sbin", "/boot"]
            if path.rstrip("/") in dangerous:
                return json.dumps({"error": f"Refusing to delete protected path: {path}"})
            result = await conn.run_full(f"rm {flag} {shlex.quote(path)}")
            if result.ok:
                return json.dumps({"status": "ok", "operation": "delete", "path": path})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def create_directory(path: str) -> str:
        """Create a directory (and parents if needed).

        Args:
            path: Directory path to create.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"mkdir -p {shlex.quote(path)}")
            if result.ok:
                return json.dumps({"status": "ok", "path": path})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def tail_file(path: str, lines: int = 50, follow: bool = False) -> str:
        """Read the last N lines of a file (like tail).

        Args:
            path: File path on the remote server.
            lines: Number of lines from the end.
            follow: If True, capture a 3-second snapshot of new output (for live logs).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if follow:
                cmd = f"timeout 3 tail -f -n {lines} {shlex.quote(path)} 2>&1 || true"
            else:
                cmd = f"tail -n {lines} {shlex.quote(path)}"
            result = await conn.run_full(cmd, timeout=10)
            if not result.ok and not follow:
                return json.dumps({"error": result.stderr.strip(), "path": path})
            return json.dumps({"path": path, "lines": lines, "content": result.stdout})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def head_file(path: str, lines: int = 50) -> str:
        """Read the first N lines of a file.

        Args:
            path: File path on the remote server.
            lines: Number of lines from the beginning.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"head -n {lines} {shlex.quote(path)}", timeout=10)
            if not result.ok:
                return json.dumps({"error": result.stderr.strip(), "path": path})
            return json.dumps({"path": path, "lines": lines, "content": result.stdout})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def chmod_file(path: str, mode: str) -> str:
        """Change file permissions.

        Args:
            path: File or directory path.
            mode: Permission mode (e.g., "755", "644", "+x", "u+rw").
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"chmod {shlex.quote(mode)} {shlex.quote(path)} 2>&1")
            if result.ok:
                return json.dumps({"status": "ok", "path": path, "mode": mode})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def chown_file(path: str, owner: str, recursive: bool = False) -> str:
        """Change file ownership.

        Args:
            path: File or directory path.
            owner: New owner in "user:group" or "user" format.
            recursive: Apply recursively to directories.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            flag = "-R" if recursive else ""
            result = await conn.run_full(f"chown {flag} {shlex.quote(owner)} {shlex.quote(path)} 2>&1")
            if result.ok:
                return json.dumps({"status": "ok", "path": path, "owner": owner})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def file_exists(path: str) -> str:
        """Check if a file or directory exists and what type it is.

        Args:
            path: Path to check.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = (
                f"if [ -f {shlex.quote(path)} ]; then echo FILE; "
                f"elif [ -d {shlex.quote(path)} ]; then echo DIR; "
                f"elif [ -L {shlex.quote(path)} ]; then echo LINK; "
                f"else echo NONE; fi"
            )
            result = await conn.run(cmd, timeout=5)
            kind = result.strip()
            return json.dumps({"path": path, "exists": kind != "NONE", "type": kind.lower()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def batch_read(paths: list[str], max_lines_per_file: int = 200) -> str:
        """Read multiple files at once (first N lines each).

        Args:
            paths: List of file paths to read.
            max_lines_per_file: Max lines per file.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            results = {}
            for p in paths[:20]:  # cap at 20 files
                cmd = f"head -n {max_lines_per_file} {shlex.quote(p)} 2>&1"
                r = await conn.run_full(cmd, timeout=10)
                results[p] = r.stdout if r.ok else f"(error: {r.stderr.strip()})"
            return json.dumps({"files": results, "count": len(results)})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def replace_in_file(path: str, pattern: str, replacement: str, regex: bool = True) -> str:
        """Find and replace in a file using sed.

        Args:
            path: File path.
            pattern: Search pattern (regex by default).
            replacement: Replacement string.
            regex: If False, treat pattern as literal text.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if not regex:
                pattern = pattern.replace("/", "\\/").replace(".", "\\.").replace("*", "\\*")
            safe_pat = pattern.replace("'", "'\\''")
            safe_rep = replacement.replace("'", "'\\''")
            count_cmd = f"grep -c '{safe_pat}' {shlex.quote(path)} 2>/dev/null || echo 0"
            count_r = await conn.run(count_cmd, timeout=10)
            count = int(count_r.strip()) if count_r.strip().isdigit() else 0
            if count == 0:
                return json.dumps({"error": "Pattern not found", "path": path})
            cmd = f"sed -i 's/{safe_pat}/{safe_rep}/g' {shlex.quote(path)} 2>&1"
            result = await conn.run_full(cmd, timeout=15)
            return json.dumps(
                {
                    "status": "ok" if result.ok else "error",
                    "path": path,
                    "matches_replaced": count,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def count_lines(path: str) -> str:
        """Count lines, words, and characters in a file.

        Args:
            path: File path.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"wc {shlex.quote(path)} 2>&1")
            if not result.ok:
                return json.dumps({"error": result.stderr.strip()})
            parts = result.stdout.strip().split()
            return json.dumps(
                {
                    "path": path,
                    "lines": int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else None,
                    "words": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                    "chars": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def tree(path: str = ".", max_depth: int = 3) -> str:
        """Show directory tree structure.

        Args:
            path: Root directory.
            max_depth: Maximum depth to traverse.
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            # Try tree command, fall back to find
            check = await conn.run_full("which tree 2>/dev/null")
            if check.ok:
                cmd = f"tree -L {max_depth} --charset=utf-8 {shlex.quote(path)}"
            else:
                cmd = f"find {shlex.quote(path)} -maxdepth {max_depth} | head -200 | sort"
            result = await conn.run(cmd, timeout=15)
            return json.dumps({"path": path, "tree": result.strip()})
        finally:
            pool.release(conn)
