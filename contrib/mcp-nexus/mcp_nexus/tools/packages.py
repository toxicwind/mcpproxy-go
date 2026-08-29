"""Package management tools with capability-aware backends."""

from __future__ import annotations

import json
import shlex
from pathlib import PurePosixPath

from mcp.server.fastmcp import FastMCP

from mcp_nexus.runtime import primary_package_manager
from mcp_nexus.server import get_pool


def _backend_name(capabilities, manager: str = "auto") -> str:
    if manager and manager != "auto":
        return manager
    return primary_package_manager(capabilities)


def _backend_commands(
    manager: str, package: str = "", packages: list[str] | None = None, limit: int = 20
) -> dict[str, str]:
    quoted_package = shlex.quote(package) if package else ""
    quoted_packages = " ".join(shlex.quote(item) for item in (packages or []))
    return {
        "apt-get": {
            "list": "dpkg-query -W -f='${Package}\t${Version}\n' | head -200",
            "search": f"apt-cache search {quoted_package} | head -{limit}",
            "info": (
                f"apt-cache policy {quoted_package} && echo '---' && apt show {quoted_package} 2>/dev/null | head -80"
            ),
            "outdated": "apt list --upgradable 2>/dev/null | tail -n +2",
            "install_dry": f"DEBIAN_FRONTEND=noninteractive apt-get install --dry-run {quoted_packages}",
            "install": f"DEBIAN_FRONTEND=noninteractive apt-get install -y {quoted_packages}",
        },
        "dnf": {
            "list": "rpm -qa | sort | head -200",
            "search": f"dnf search {quoted_package} | head -{limit}",
            "info": f"dnf info {quoted_package}",
            "outdated": "dnf check-update || true",
            "install_dry": f"dnf install --assumeno {quoted_packages}",
            "install": f"dnf install -y {quoted_packages}",
        },
        "yum": {
            "list": "rpm -qa | sort | head -200",
            "search": f"yum search {quoted_package} | head -{limit}",
            "info": f"yum info {quoted_package}",
            "outdated": "yum check-update || true",
            "install_dry": f"yum install --assumeno {quoted_packages}",
            "install": f"yum install -y {quoted_packages}",
        },
        "apk": {
            "list": "apk list -I | head -200",
            "search": f"apk search {quoted_package} | head -{limit}",
            "info": f"apk info -a {quoted_package}",
            "outdated": "apk version -l '<'",
            "install_dry": f"apk add --simulate {quoted_packages}",
            "install": f"apk add {quoted_packages}",
        },
        "pacman": {
            "list": "pacman -Q | head -200",
            "search": f"pacman -Ss {quoted_package} | head -{limit}",
            "info": f"pacman -Si {quoted_package}",
            "outdated": "pacman -Qu",
            "install_dry": f"pacman -S --print {quoted_packages}",
            "install": f"pacman -S --noconfirm {quoted_packages}",
        },
        "zypper": {
            "list": "zypper search --installed-only | tail -n +5 | head -200",
            "search": f"zypper search {quoted_package} | head -{limit}",
            "info": f"zypper info {quoted_package}",
            "outdated": "zypper list-updates",
            "install_dry": f"zypper install --dry-run {quoted_packages}",
            "install": f"zypper install -y {quoted_packages}",
        },
        "brew": {
            "list": "brew list --versions | head -200",
            "search": f"brew search {quoted_package} | head -{limit}",
            "info": f"brew info {quoted_package}",
            "outdated": "brew outdated --verbose",
            "install_dry": f"brew install --dry-run {quoted_packages}",
            "install": f"brew install {quoted_packages}",
        },
    }.get(manager, {})


async def _capabilities():
    pool = get_pool()
    conn = await pool.acquire()
    try:
        return await conn.probe_capabilities()
    finally:
        pool.release(conn)


def register(mcp: FastMCP):

    @mcp.tool()
    async def pip_list(venv: str = "", pattern: str = "") -> str:
        """List installed Python packages."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            pip = f"{venv}/bin/pip" if venv else "pip3"
            cmd = f"{pip} list --format=columns 2>&1"
            if pattern:
                cmd += f" | grep -i {shlex.quote(pattern)}"
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps({"packages": result.stdout.strip(), "venv": venv or "(system)"})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def pip_show(package: str, venv: str = "") -> str:
        """Show details for a Python package."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            pip = f"{venv}/bin/pip" if venv else "pip3"
            result = await conn.run_full(f"{pip} show {shlex.quote(package)} 2>&1", timeout=15)
            return json.dumps(
                {
                    "package": package,
                    "found": result.exit_code == 0,
                    "info": result.stdout.strip() if result.ok else result.stderr.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def apt_list(pattern: str = "", upgradable: bool = False) -> str:
        """List Debian packages on apt-based hosts."""
        capabilities = await _capabilities()
        if primary_package_manager(capabilities) != "apt-get":
            return json.dumps({"error": "apt is not the active package manager on this host"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            if upgradable:
                cmd = _backend_commands("apt-get")["outdated"]
            elif pattern:
                cmd = f"dpkg -l | grep -i {shlex.quote(pattern)} | head -50"
            else:
                cmd = _backend_commands("apt-get")["list"]
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps({"packages": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def apt_install(packages: str, dry_run: bool = True) -> str:
        """Install Debian packages on apt-based hosts."""
        capabilities = await _capabilities()
        if primary_package_manager(capabilities) != "apt-get":
            return json.dumps({"error": "apt is not the active package manager on this host"})

        package_items = [item for item in packages.split() if item]
        cmd_key = "install_dry" if dry_run else "install"
        cmd = _backend_commands("apt-get", packages=package_items)[cmd_key]
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(cmd, timeout=180)
            return json.dumps(
                {
                    "packages": package_items,
                    "dry_run": dry_run,
                    "output": result.stdout[-10000:],
                    "exit_code": result.exit_code,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def npm_list(path: str = "", global_packages: bool = False) -> str:
        """List installed npm packages."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            check = await conn.run_full("which npm 2>/dev/null")
            if not check.ok:
                return json.dumps({"error": "npm not installed"})

            if global_packages:
                cmd = "npm list -g --depth=0 2>&1"
            elif path:
                cmd = f"cd {shlex.quote(path)} && npm list --depth=0 2>&1"
            else:
                cmd = "npm list --depth=0 2>&1"
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps(
                {"packages": result.stdout.strip(), "scope": "global" if global_packages else path or "."}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def package_managers(refresh: bool = False) -> str:
        """Inspect detected system package managers and host defaults."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities(refresh=refresh)
            return json.dumps(
                {
                    "primary": primary_package_manager(capabilities),
                    "available": list(capabilities.package_managers),
                    "system": capabilities.system,
                    "distro": capabilities.distro_id or None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def package_search(query: str, manager: str = "auto", limit: int = 20) -> str:
        """Search packages using the host's primary package manager by default."""
        capabilities = await _capabilities()
        backend = _backend_name(capabilities, manager)
        commands = _backend_commands(backend, package=query, limit=limit)
        if not commands:
            return json.dumps({"error": f"unsupported package manager: {backend}"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(commands["search"], timeout=60)
            return json.dumps({"manager": backend, "query": query, "results": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def package_info(package: str, manager: str = "auto") -> str:
        """Show package metadata through the selected or detected backend."""
        capabilities = await _capabilities()
        backend = _backend_name(capabilities, manager)
        commands = _backend_commands(backend, package=package)
        if not commands:
            return json.dumps({"error": f"unsupported package manager: {backend}"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(commands["info"], timeout=60)
            return json.dumps({"manager": backend, "package": package, "info": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def package_install(packages: list[str], manager: str = "auto", dry_run: bool = True) -> str:
        """Install packages through the selected or detected system backend."""
        if not packages:
            return json.dumps({"error": "packages is required"})

        capabilities = await _capabilities()
        backend = _backend_name(capabilities, manager)
        commands = _backend_commands(backend, packages=packages)
        if not commands:
            return json.dumps({"error": f"unsupported package manager: {backend}"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = commands["install_dry" if dry_run else "install"]
            result = await conn.run_full(cmd, timeout=240)
            return json.dumps(
                {
                    "manager": backend,
                    "packages": packages,
                    "dry_run": dry_run,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip()[-12000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def package_outdated(manager: str = "auto", limit: int = 100) -> str:
        """Show outdated packages using the selected or detected backend."""
        capabilities = await _capabilities()
        backend = _backend_name(capabilities, manager)
        commands = _backend_commands(backend)
        if not commands:
            return json.dumps({"error": f"unsupported package manager: {backend}"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run_full(f"{commands['outdated']} | head -{limit}", timeout=120)
            return json.dumps({"manager": backend, "packages": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def npm_install(
        packages: list[str],
        path: str = "",
        global_packages: bool = False,
        save_dev: bool = False,
    ) -> str:
        """Install npm packages locally or globally."""
        if not packages:
            return json.dumps({"error": "packages is required"})

        pool = get_pool()
        conn = await pool.acquire()
        try:
            check = await conn.run_full("which npm 2>/dev/null")
            if not check.ok:
                return json.dumps({"error": "npm not installed"})
            scope = "-g" if global_packages else ""
            dev_flag = "--save-dev" if save_dev and not global_packages else ""
            package_args = " ".join(shlex.quote(item) for item in packages)
            prefix = f"cd {shlex.quote(path)} && " if path and not global_packages else ""
            cmd = f"{prefix}npm install {scope} {dev_flag} {package_args}"
            result = await conn.run_full(cmd, timeout=240)
            return json.dumps({"ok": result.ok, "output": (result.stdout + result.stderr).strip()[-12000:]})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def python_virtualenvs(base_path: str = "") -> str:
        """Discover Python virtualenvs by scanning for pyvenv.cfg."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            root = base_path or "."
            command = f"find {shlex.quote(root)} -maxdepth 4 -name pyvenv.cfg -print 2>/dev/null | head -100"
            result = await conn.run_full(command, timeout=30)
            envs = []
            for cfg in filter(None, result.stdout.splitlines()):
                env_path = str(PurePosixPath(cfg).parent)
                envs.append({"path": env_path, "python": f"{env_path}/bin/python"})
            return json.dumps({"base_path": root, "virtualenvs": envs})
        finally:
            pool.release(conn)
