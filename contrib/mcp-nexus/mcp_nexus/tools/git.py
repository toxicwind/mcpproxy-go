"""Git operations for repository inspection and delivery flows."""

from __future__ import annotations

import json
import re
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
        exit_code=exit_code,
        data=data,
        resource_usage=usage,
    )


def _parse_tracking_counts(summary: str) -> tuple[int, int]:
    ahead = 0
    behind = 0
    for match in re.finditer(r"(ahead|behind) (\d+)", summary):
        kind, count = match.groups()
        if kind == "ahead":
            ahead = int(count)
        else:
            behind = int(count)
    return ahead, behind


def _parse_status_header(header: str) -> dict[str, Any]:
    text = header.strip()
    if text.startswith("HEAD"):
        return {
            "branch": None,
            "upstream": None,
            "ahead": 0,
            "behind": 0,
            "detached_head": True,
            "raw": text,
        }

    summary = ""
    if text.endswith("]") and " [" in text:
        text, summary = text[:-1].split(" [", 1)

    branch = text
    upstream = None
    if "..." in text:
        branch, upstream = text.split("...", 1)
    ahead, behind = _parse_tracking_counts(summary)
    return {
        "branch": branch or None,
        "upstream": upstream or None,
        "ahead": ahead,
        "behind": behind,
        "detached_head": False,
        "raw": header,
    }


def _status_label(code: str) -> str:
    if code == "??":
        return "untracked"
    if code == "!!":
        return "ignored"
    if "U" in code:
        return "conflicted"
    if code[0] == "R":
        return "renamed"
    if code[0] == "C":
        return "copied"
    if code[0] != " " and code[1] != " ":
        return "staged_and_unstaged"
    if code[0] != " ":
        return "staged"
    if code[1] != " ":
        return "unstaged"
    return "clean"


def _parse_status_output(output: str, *, max_entries: int = 50) -> dict[str, Any]:
    header: dict[str, Any] = {
        "branch": None,
        "upstream": None,
        "ahead": 0,
        "behind": 0,
        "detached_head": False,
        "raw": "",
    }
    entries: list[dict[str, Any]] = []
    staged_count = 0
    unstaged_count = 0
    untracked_count = 0
    ignored_count = 0
    conflicted_count = 0
    entry_count = 0

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("## "):
            header = _parse_status_header(line[3:])
            continue
        if line.startswith("?? "):
            untracked_count += 1
            entry_count += 1
            if len(entries) < max_entries:
                entries.append({"status_code": "??", "status": "untracked", "path": line[3:]})
            continue
        if line.startswith("!! "):
            ignored_count += 1
            entry_count += 1
            if len(entries) < max_entries:
                entries.append({"status_code": "!!", "status": "ignored", "path": line[3:]})
            continue
        if len(line) < 3:
            continue

        status_code = line[:2]
        path = line[3:]
        entry_count += 1
        label = _status_label(status_code)
        staged = status_code[0] != " "
        unstaged = status_code[1] != " "
        conflicted = "U" in status_code
        if staged:
            staged_count += 1
        if unstaged:
            unstaged_count += 1
        if conflicted:
            conflicted_count += 1
        entry: dict[str, Any] = {
            "status_code": status_code,
            "status": label,
            "path": path,
            "staged": staged,
            "unstaged": unstaged,
            "conflicted": conflicted,
        }
        if " -> " in path and status_code[0] in {"R", "C"}:
            old_path, new_path = path.split(" -> ", 1)
            entry["old_path"] = old_path
            entry["new_path"] = new_path
        if len(entries) < max_entries:
            entries.append(entry)

    total_count = entry_count
    tracked_count = total_count - untracked_count - ignored_count
    dirty = bool(staged_count or unstaged_count or untracked_count or conflicted_count)
    return {
        "header": header,
        "entries": entries,
        "counts": {
            "staged": staged_count,
            "unstaged": unstaged_count,
            "untracked": untracked_count,
            "ignored": ignored_count,
            "conflicted": conflicted_count,
            "tracked": tracked_count,
            "total": total_count,
        },
        "dirty": dirty,
        "truncated": entry_count > len(entries),
    }


def _parse_worktree_output(output: str, *, max_entries: int = 20) -> list[dict[str, Any]]:
    worktrees: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                worktrees.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value.strip()
        elif key == "HEAD":
            current["head"] = value.strip()
        elif key == "branch":
            current["branch"] = value.strip()
        elif key == "bare":
            current["bare"] = True
    if current:
        worktrees.append(current)
    return worktrees[:max_entries]


def _parse_stash_output(output: str, *, max_entries: int = 20) -> list[dict[str, Any]]:
    stashes: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t", 2)
        entry = {"ref": parts[0]}
        if len(parts) > 1:
            entry["age"] = parts[1]
        if len(parts) > 2:
            entry["message"] = parts[2]
        stashes.append(entry)
    return stashes[:max_entries]


def _git(sub: str, cwd: str) -> str:
    return f"cd {shlex.quote(cwd)} && git {sub}"


def register(mcp: FastMCP):

    @mcp.tool()
    async def git_status(repo_path: str = ".") -> str:
        """Show git status of a repository."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run(_git("status --porcelain -b", repo_path), timeout=15)
            branch = await conn.run_full(_git("branch --show-current", repo_path), timeout=5)
            return json.dumps(
                {
                    "repo": repo_path,
                    "branch": branch.stdout.strip() if branch.ok else "unknown",
                    "status": result.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool(structured_output=True)
    async def git_diagnose(repo_path: str = ".", include_diff: bool = False, max_entries: int = 50) -> ToolResult:
        """Summarize repository health, branch state, worktrees, stashes, and conflicts."""
        started = time.monotonic()
        pool = get_pool()
        conn = await pool.acquire()
        warnings: list[str] = []
        try:
            git_check = await conn.run_full("which git 2>/dev/null", timeout=5)
            if not git_check.ok:
                return _result(
                    "git_diagnose",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="GIT_UNAVAILABLE",
                    error_stage="capability_probe",
                    message="git is not installed on the target host.",
                    data={"repo_path": repo_path},
                )

            root_result = await conn.run_full(_git("rev-parse --show-toplevel", repo_path), timeout=10)
            if not root_result.ok:
                return _result(
                    "git_diagnose",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    stdout_text=root_result.stdout,
                    stderr_text=root_result.stderr,
                    error_code="NOT_A_GIT_REPOSITORY",
                    error_stage="inspection",
                    message="Path is not inside a git repository.",
                    data={"repo_path": repo_path},
                )

            head_result = await conn.run_full(_git("rev-parse --short HEAD", repo_path), timeout=10)
            status_result = await conn.run_full(
                _git("status --porcelain=v1 -b --untracked-files=all", repo_path),
                timeout=20,
            )
            if not status_result.ok:
                return _result(
                    "git_diagnose",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    stdout_text=status_result.stdout,
                    stderr_text=status_result.stderr,
                    error_code="GIT_STATUS_FAILED",
                    error_stage="inspection",
                    message="Failed to inspect repository status.",
                    data={"repo_path": repo_path, "root": root_result.stdout.strip()},
                )

            status = _parse_status_output(status_result.stdout, max_entries=max_entries)

            worktree_result = await conn.run_full(_git("worktree list --porcelain", repo_path), timeout=20)
            if worktree_result.ok:
                worktrees = _parse_worktree_output(worktree_result.stdout, max_entries=max_entries)
            else:
                worktrees = []
                warnings.append(worktree_result.stderr.strip() or "worktree inspection unavailable")

            stash_result = await conn.run_full(_git("stash list --format=%gd\t%cr\t%s", repo_path), timeout=15)
            if stash_result.ok:
                stashes = _parse_stash_output(stash_result.stdout, max_entries=max_entries)
            else:
                stashes = []
                warnings.append(stash_result.stderr.strip() or "stash inspection unavailable")

            markers_cmd = "\n".join(
                [
                    "for marker in MERGE_HEAD REBASE_HEAD CHERRY_PICK_HEAD REVERT_HEAD BISECT_LOG; do",
                    '  path=$(git rev-parse --git-path "$marker")',
                    '  if [ -e "$path" ]; then',
                    '    printf "%s=1\\n" "$marker"',
                    "  else",
                    '    printf "%s=0\\n" "$marker"',
                    "  fi",
                    "done",
                ]
            )
            markers_result = await conn.run_full(f"cd {shlex.quote(repo_path)} && {markers_cmd}", timeout=20)
            markers: dict[str, bool] = {}
            if markers_result.ok:
                for raw_line in markers_result.stdout.splitlines():
                    if "=" not in raw_line:
                        continue
                    key, value = raw_line.split("=", 1)
                    markers[key] = value.strip() == "1"
            else:
                warnings.append(markers_result.stderr.strip() or "state marker inspection unavailable")

            staged_diff = ""
            unstaged_diff = ""
            if include_diff:
                staged_result = await conn.run_full(
                    _git("diff --cached --stat --summary --no-ext-diff", repo_path),
                    timeout=30,
                )
                if staged_result.exit_code in {0, 1}:
                    staged_diff = staged_result.stdout.strip()
                else:
                    warnings.append(staged_result.stderr.strip() or "staged diff stat unavailable")

                unstaged_result = await conn.run_full(
                    _git("diff --stat --summary --no-ext-diff", repo_path),
                    timeout=30,
                )
                if unstaged_result.exit_code in {0, 1}:
                    unstaged_diff = unstaged_result.stdout.strip()
                else:
                    warnings.append(unstaged_result.stderr.strip() or "unstaged diff stat unavailable")

            header = status["header"]
            branch = header.get("branch")
            upstream = header.get("upstream")
            ahead = header.get("ahead", 0)
            behind = header.get("behind", 0)
            detached_head = bool(header.get("detached_head"))
            counts = status["counts"]
            dirty = bool(status["dirty"])
            conflicted = counts["conflicted"] > 0
            if conflicted:
                overall_state = "conflicted"
            elif dirty:
                overall_state = "dirty"
            else:
                overall_state = "clean"
            if detached_head:
                overall_state = f"detached-{overall_state}"

            summary_lines = [
                f"repo: {root_result.stdout.strip()}",
                f"head: {head_result.stdout.strip() if head_result.ok else 'unknown'}",
                f"branch: {branch or '(detached)'}",
            ]
            if upstream:
                summary_lines.append(f"upstream: {upstream} (+{ahead} / -{behind})")
            summary_lines.extend(
                [
                    (
                        "state: "
                        f"{overall_state} "
                        f"(tracked {counts['tracked']}, staged flags {counts['staged']}, "
                        f"unstaged flags {counts['unstaged']}, untracked {counts['untracked']}, "
                        f"conflicted {counts['conflicted']})"
                    ),
                    f"worktrees: {len(worktrees)}",
                    f"stashes: {len(stashes)}",
                ]
            )
            if warnings:
                summary_lines.append("warnings:")
                summary_lines.extend(f"- {warning}" for warning in warnings)
            if include_diff:
                if staged_diff:
                    summary_lines.extend(["staged diff stat:", staged_diff])
                if unstaged_diff:
                    summary_lines.extend(["unstaged diff stat:", unstaged_diff])

            if conflicted:
                message = "Repository has unresolved conflicts."
            elif detached_head and dirty:
                message = "Repository is detached and has pending changes."
            elif detached_head and not dirty:
                message = "Repository is detached but clean."
            elif dirty:
                message = "Repository has pending changes."
            else:
                message = "Repository is clean."
            if warnings:
                message = f"{message} Partial diagnostic data was unavailable."

            return _result(
                "git_diagnose",
                ok=True,
                duration_ms=(time.monotonic() - started) * 1000,
                stdout_text="\n".join(summary_lines),
                message=message,
                data={
                    "repo_path": repo_path,
                    "root": root_result.stdout.strip(),
                    "head": head_result.stdout.strip() if head_result.ok else None,
                    "max_entries": max_entries,
                    "branch": branch,
                    "upstream": upstream,
                    "ahead": ahead,
                    "behind": behind,
                    "detached_head": detached_head,
                    "overall_state": overall_state,
                    "dirty": dirty,
                    "conflicted": conflicted,
                    "counts": counts,
                    "status_preview": status["entries"],
                    "status_truncated": status["truncated"],
                    "worktrees": worktrees,
                    "stashes": stashes,
                    "markers": markers,
                    "include_diff": include_diff,
                    "diff_stat": {
                        "staged": staged_diff or None,
                        "unstaged": unstaged_diff or None,
                    }
                    if include_diff
                    else None,
                    "warnings": warnings,
                },
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_diff(repo_path: str = ".", staged: bool = False, file_path: str = "") -> str:
        """Show git diff."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = "diff --stat"
            if staged:
                cmd += " --cached"
            if file_path:
                cmd += f" -- {shlex.quote(file_path)}"
            stat = await conn.run(_git(cmd, repo_path), timeout=15)

            detail_cmd = cmd.replace("--stat", "")
            detail = await conn.run(_git(detail_cmd, repo_path), timeout=30)
            return json.dumps(
                {
                    "repo": repo_path,
                    "staged": staged,
                    "stat": stat.strip(),
                    "diff": detail.strip()[-30000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_log(repo_path: str = ".", count: int = 20, oneline: bool = True) -> str:
        """Show git log."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            fmt = "--oneline" if oneline else "--format=%H|%an|%ar|%s"
            result = await conn.run(_git(f"log -{count} {fmt}", repo_path), timeout=15)
            return json.dumps({"repo": repo_path, "log": result.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_commit(repo_path: str, message: str, add_all: bool = False, files: list[str] | None = None) -> str:
        """Create a git commit."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if add_all:
                await conn.run(_git("add -A", repo_path), timeout=15)
            elif files:
                for file_path in files:
                    await conn.run(_git(f"add {shlex.quote(file_path)}", repo_path), timeout=10)

            escaped_msg = message.replace("'", "'\\''")
            result = await conn.run_full(_git(f"commit -m '{escaped_msg}'", repo_path), timeout=30)
            if result.ok:
                sha = await conn.run(_git("rev-parse --short HEAD", repo_path), timeout=5)
                return json.dumps({"status": "ok", "sha": sha.strip(), "message": message})
            return json.dumps({"error": result.stderr.strip() or result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_branch(repo_path: str = ".", action: str = "list", name: str = "") -> str:
        """Manage git branches."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if action == "list":
                result = await conn.run(_git("branch -a", repo_path), timeout=10)
            elif action == "create" and name:
                result = await conn.run(_git(f"checkout -b {shlex.quote(name)}", repo_path), timeout=10)
            elif action == "switch" and name:
                result = await conn.run(_git(f"checkout {shlex.quote(name)}", repo_path), timeout=10)
            elif action == "delete" and name:
                result = await conn.run(_git(f"branch -d {shlex.quote(name)}", repo_path), timeout=10)
            else:
                return json.dumps({"error": f"Invalid action '{action}' or missing branch name"})
            return json.dumps({"repo": repo_path, "action": action, "output": result.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_pull(repo_path: str = ".", remote: str = "origin", branch: str = "") -> str:
        """Pull latest changes from remote."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"pull {shlex.quote(remote)}"
            if branch:
                cmd += f" {shlex.quote(branch)}"
            result = await conn.run_full(_git(cmd, repo_path), timeout=120)
            return json.dumps(
                {
                    "status": "ok" if result.ok else "error",
                    "output": result.stdout.strip(),
                    "errors": result.stderr.strip() if result.stderr else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_push(
        repo_path: str = ".",
        remote: str = "origin",
        branch: str = "",
        set_upstream: bool = False,
    ) -> str:
        """Push commits to remote."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"push {shlex.quote(remote)}"
            if set_upstream:
                cmd = f"push -u {shlex.quote(remote)}"
            if branch:
                cmd += f" {shlex.quote(branch)}"
            result = await conn.run_full(_git(cmd, repo_path), timeout=120)
            return json.dumps(
                {"status": "ok" if result.ok else "error", "output": (result.stdout + result.stderr).strip()}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_stash(repo_path: str = ".", action: str = "push", message: str = "") -> str:
        """Manage git stash."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if action == "push":
                cmd = "stash push"
                if message:
                    cmd += f" -m {shlex.quote(message)}"
            elif action == "pop":
                cmd = "stash pop"
            elif action == "list":
                cmd = "stash list"
            elif action == "drop":
                cmd = "stash drop"
            else:
                return json.dumps({"error": f"Invalid stash action: {action}"})
            result = await conn.run_full(_git(cmd, repo_path), timeout=15)
            return json.dumps({"action": action, "output": result.stdout.strip(), "ok": result.ok})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_stage(repo_path: str = ".", files: list[str] | None = None, add_all: bool = False) -> str:
        """Stage files explicitly or stage the entire worktree when requested."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if add_all:
                result = await conn.run_full(_git("add -A", repo_path), timeout=20)
                staged = ["<all>"]
            elif files:
                staged = files
                for file_path in files:
                    result = await conn.run_full(_git(f"add {shlex.quote(file_path)}", repo_path), timeout=20)
                    if not result.ok:
                        return json.dumps({"error": result.stderr.strip() or result.stdout.strip(), "file": file_path})
            else:
                return json.dumps({"error": "Either files or add_all must be provided"})
            return json.dumps({"repo": repo_path, "staged": staged, "ok": result.ok})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_show(repo_path: str = ".", ref: str = "HEAD", file_path: str = "", stat: bool = True) -> str:
        """Show a commit, object, or file revision."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            target = f"{ref}:{file_path}" if file_path else ref
            flags = "--stat " if stat and not file_path else ""
            result = await conn.run_full(_git(f"show {flags}{shlex.quote(target)}", repo_path), timeout=30)
            return json.dumps(
                {"repo": repo_path, "ref": ref, "target": target, "output": result.stdout.strip()[-40000:]}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_fetch(repo_path: str = ".", remote: str = "origin", prune: bool = False, tags: bool = False) -> str:
        """Fetch remote refs without changing the working tree."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            flags = []
            if prune:
                flags.append("--prune")
            if tags:
                flags.append("--tags")
            result = await conn.run_full(
                _git(f"fetch {' '.join(flags)} {shlex.quote(remote)}".strip(), repo_path),
                timeout=120,
            )
            return json.dumps(
                {
                    "repo": repo_path,
                    "remote": remote,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_remotes(repo_path: str = ".") -> str:
        """Inspect configured git remotes and tracking branches."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            remotes = await conn.run_full(_git("remote -v", repo_path), timeout=15)
            branches = await conn.run_full(_git("branch -vv", repo_path), timeout=15)
            return json.dumps(
                {"repo": repo_path, "remotes": remotes.stdout.strip(), "branches": branches.stdout.strip()}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_blame(repo_path: str, file_path: str, line_number: int = 0) -> str:
        """Blame a file or a specific line for authorship context."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if line_number > 0:
                cmd = _git(f"blame -L {line_number},{line_number} -- {shlex.quote(file_path)}", repo_path)
            else:
                cmd = _git(f"blame -- {shlex.quote(file_path)}", repo_path)
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps(
                {
                    "repo": repo_path,
                    "file": file_path,
                    "line": line_number or None,
                    "output": result.stdout.strip()[-20000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def git_tags(repo_path: str = ".", pattern: str = "") -> str:
        """List git tags with optional pattern filtering."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = "tag --list"
            if pattern:
                cmd += f" {shlex.quote(pattern)}"
            result = await conn.run_full(_git(cmd, repo_path), timeout=15)
            return json.dumps({"repo": repo_path, "pattern": pattern or None, "tags": result.stdout.strip()})
        finally:
            pool.release(conn)
