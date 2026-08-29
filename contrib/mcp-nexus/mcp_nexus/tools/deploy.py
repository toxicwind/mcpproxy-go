"""Deployment tools for sync, release activation, rollback, and compose flows."""

from __future__ import annotations

import json
import shlex

from mcp.server.fastmcp import FastMCP

from mcp_nexus.server import get_pool, get_settings


def _release_defaults(releases_dir: str, current_link: str) -> tuple[str, str]:
    settings = get_settings()
    return releases_dir or settings.release_root, current_link or settings.current_release_link


def register(mcp: FastMCP):

    @mcp.tool()
    async def deploy_sync(
        local_path: str,
        remote_path: str,
        exclude: list[str] | None = None,
        dry_run: bool = False,
    ) -> str:
        """Sync files from one path to another on the target host using rsync when available."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            excludes = exclude or ["__pycache__", "*.pyc", ".DS_Store", ".git", "node_modules"]
            if capabilities.has("rsync"):
                exclude_flags = " ".join(f"--exclude={shlex.quote(item)}" for item in excludes)
                dry = "--dry-run" if dry_run else ""
                cmd = (
                    f"rsync -avz --delete {dry} {exclude_flags} {shlex.quote(local_path)}/ {shlex.quote(remote_path)}/"
                )
            else:
                if excludes:
                    return json.dumps({"error": "rsync is required when exclude filters are used"})
                copy_flag = "-an" if dry_run else "-a"
                cmd = (
                    f"mkdir -p {shlex.quote(remote_path)} && "
                    f"cp {copy_flag} {shlex.quote(local_path)}/. {shlex.quote(remote_path)}/"
                )
            result = await conn.run_full(cmd, timeout=300)
            return json.dumps(
                {
                    "status": "ok" if result.ok else "error",
                    "dry_run": dry_run,
                    "output": result.stdout.strip()[-5000:],
                    "errors": result.stderr.strip() if result.stderr else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_service(service_name: str, pre_command: str = "", post_command: str = "") -> str:
        """Deploy by restarting a service with optional pre/post commands."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            results: dict[str, object] = {"service": service_name}
            if pre_command:
                pre = await conn.run_full(pre_command, timeout=120)
                results["pre_command"] = {"ok": pre.ok, "output": pre.stdout.strip()[-2000:]}
                if not pre.ok:
                    results["error"] = "Pre-command failed, aborting deploy"
                    return json.dumps(results)

            restart = await conn.run_full(f"systemctl restart {shlex.quote(service_name)}", timeout=30)
            results["restart"] = {"ok": restart.ok}
            status = await conn.run_full(f"systemctl is-active {shlex.quote(service_name)}")
            results["status"] = status.stdout.strip()

            if post_command:
                post = await conn.run_full(post_command, timeout=60)
                results["post_command"] = {"ok": post.ok, "output": post.stdout.strip()[-2000:]}
            return json.dumps(results)
        finally:
            pool.release(conn)

    @mcp.tool()
    async def create_backup(path: str, backup_dir: str = "/root/backups") -> str:
        """Create a timestamped backup of a file or directory."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            await conn.run_full(f"mkdir -p {shlex.quote(backup_dir)}")
            name = path.rstrip("/").rsplit("/", 1)[-1]
            timestamp = (await conn.run("date +%Y%m%d_%H%M%S")).strip()
            backup_path = f"{backup_dir}/{name}_{timestamp}.tar.gz"
            cmd = f"tar czf {shlex.quote(backup_path)} -C {shlex.quote(path.rsplit('/', 1)[0])} {shlex.quote(name)}"
            result = await conn.run_full(cmd, timeout=120)
            if result.ok:
                size = await conn.run(f"du -h {shlex.quote(backup_path)}")
                return json.dumps({"status": "ok", "backup": backup_path, "size": size.strip()})
            return json.dumps({"error": result.stderr.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def list_backups(backup_dir: str = "/root/backups") -> str:
        """List available backups."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"ls -lhtr {shlex.quote(backup_dir)}/*.tar.gz 2>/dev/null")
            return json.dumps(
                {"backup_dir": backup_dir, "backups": result.stdout.strip() if result.ok else "(no backups found)"}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def restore_backup(backup_path: str, restore_to: str) -> str:
        """Restore from a backup archive."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            exists = await conn.file_exists(backup_path)
            if not exists:
                return json.dumps({"error": f"Backup not found: {backup_path}"})
            cmd = (
                f"mkdir -p {shlex.quote(restore_to)} && tar xzf {shlex.quote(backup_path)} -C {shlex.quote(restore_to)}"
            )
            result = await conn.run_full(cmd, timeout=120)
            return json.dumps(
                {
                    "status": "ok" if result.ok else "error",
                    "backup": backup_path,
                    "restored_to": restore_to,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def pip_install(packages: str, venv_path: str = "") -> str:
        """Install Python packages (in a virtualenv if specified)."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if venv_path:
                cmd = f"{shlex.quote(venv_path)}/bin/pip install {packages}"
            else:
                cmd = f"pip install {packages}"
            result = await conn.run_full(cmd, timeout=120)
            return json.dumps(
                {
                    "ok": result.ok,
                    "output": result.stdout.strip()[-3000:],
                    "errors": result.stderr.strip() if result.stderr else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_release(
        source_path: str,
        releases_dir: str = "",
        current_link: str = "",
        exclude: list[str] | None = None,
        activate: bool = True,
        keep: int = 5,
        dry_run: bool = False,
    ) -> str:
        """Create a timestamped release directory and optionally point a stable symlink at it."""
        releases_dir, current_link = _release_defaults(releases_dir, current_link)
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            release_name = (await conn.run("date +%Y%m%d_%H%M%S")).strip()
            release_path = f"{releases_dir.rstrip('/')}/{release_name}"
            await conn.run_full(f"mkdir -p {shlex.quote(releases_dir)}")
            excludes = exclude or [".git", "__pycache__", "*.pyc", ".DS_Store", "node_modules"]
            if capabilities.has("rsync"):
                exclude_flags = " ".join(f"--exclude={shlex.quote(item)}" for item in excludes)
                dry_flag = "--dry-run" if dry_run else ""
                sync = (
                    f"mkdir -p {shlex.quote(release_path)} && "
                    f"rsync -a --delete {dry_flag} {exclude_flags} "
                    f"{shlex.quote(source_path)}/ {shlex.quote(release_path)}/"
                )
            else:
                if excludes:
                    return json.dumps({"error": "release deployment with exclude filters requires rsync"})
                copy_flag = "-an" if dry_run else "-a"
                sync = (
                    f"mkdir -p {shlex.quote(release_path)} && "
                    f"cp {copy_flag} {shlex.quote(source_path)}/. {shlex.quote(release_path)}/"
                )
            sync_result = await conn.run_full(sync, timeout=600)
            if not sync_result.ok:
                return json.dumps({"error": sync_result.stderr.strip() or sync_result.stdout.strip()})
            activated = False
            if activate and not dry_run:
                link_result = await conn.run_full(
                    f"ln -sfn {shlex.quote(release_path)} {shlex.quote(current_link)}", timeout=20
                )
                activated = link_result.ok
            if keep > 0 and not dry_run:
                prune = f"ls -1dt {shlex.quote(releases_dir)}/* 2>/dev/null | tail -n +{keep + 1} | xargs -r rm -rf"
                await conn.run_full(prune, timeout=60)
            return json.dumps(
                {
                    "source_path": source_path,
                    "release_path": release_path,
                    "current_link": current_link,
                    "activated": activated,
                    "dry_run": dry_run,
                    "output": sync_result.stdout.strip()[-5000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_activate_release(release_path: str, current_link: str = "") -> str:
        """Point the stable symlink at an existing release directory."""
        _, current_link = _release_defaults("", current_link)
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"ln -sfn {shlex.quote(release_path)} {shlex.quote(current_link)}", timeout=20)
            return json.dumps(
                {
                    "release_path": release_path,
                    "current_link": current_link,
                    "activated": result.ok,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_rollback_release(releases_dir: str = "", current_link: str = "", steps: int = 1) -> str:
        """Rollback the stable symlink to a previous release."""
        releases_dir, current_link = _release_defaults(releases_dir, current_link)
        pool = get_pool()
        conn = await pool.acquire()
        try:
            index = max(steps + 1, 2)
            target = await conn.run_full(
                f"ls -1dt {shlex.quote(releases_dir)}/* 2>/dev/null | sed -n '{index}p'", timeout=20
            )
            release_path = target.stdout.strip()
            if not release_path:
                return json.dumps({"error": "No rollback target found"})
            result = await conn.run_full(f"ln -sfn {shlex.quote(release_path)} {shlex.quote(current_link)}", timeout=20)
            return json.dumps(
                {
                    "rollback_to": release_path,
                    "current_link": current_link,
                    "ok": result.ok,
                    "error": result.stderr.strip() if not result.ok else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_compose(
        path: str = ".", service_name: str = "", pull: bool = False, build: bool = False, detach: bool = True
    ) -> str:
        """Deploy a docker compose application using the host's compose command."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            compose = capabilities.compose_command
            if not compose:
                return json.dumps({"error": "docker compose is not available on this host"})
            steps = []
            if pull:
                steps.append(f"{compose} pull")
            up = f"{compose} up {'-d' if detach else ''}"
            if build:
                up += " --build"
            if service_name:
                up += f" {shlex.quote(service_name)}"
            steps.append(up.strip())
            cmd = f"cd {shlex.quote(path)} && " + " && ".join(steps)
            result = await conn.run_full(cmd, timeout=900)
            return json.dumps(
                {
                    "path": path,
                    "service": service_name or None,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip()[-20000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def deploy_health_check(url: str = "", command: str = "", cwd: str = "", timeout: int = 30) -> str:
        """Run an HTTP or command-based health check after deployment."""
        if not url and not command:
            return json.dumps({"error": "Either url or command must be provided"})
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if url:
                check_command = f"curl -fsS --max-time {timeout} {shlex.quote(url)}"
            else:
                check_command = command
            if cwd:
                check_command = f"cd {shlex.quote(cwd)} && {check_command}"
            result = await conn.run_full(check_command, timeout=timeout + 5)
            return json.dumps(
                {
                    "url": url or None,
                    "command": command or None,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip()[-10000:],
                }
            )
        finally:
            pool.release(conn)
