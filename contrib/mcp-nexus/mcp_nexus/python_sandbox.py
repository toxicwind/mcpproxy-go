"""Reusable Python sandbox helpers shared by multiple tool surfaces."""

from __future__ import annotations

import shlex
import time
from pathlib import PurePosixPath
from typing import Any

from mcp_nexus.server import get_pool, get_settings


def sandbox_root() -> str:
    settings = get_settings()
    return settings.expanded_path(settings.sandbox_root)


def sandbox_path(name: str = "", path: str = "") -> str:
    settings = get_settings()
    if path:
        return settings.expanded_path(path)
    suffix = name or f"python-{int(time.time())}"
    return str(PurePosixPath(sandbox_root()) / suffix)


async def ensure_python_sandbox(
    *,
    sandbox_path_value: str,
    requirements: list[str] | None = None,
    recreate: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities()
        if not capabilities.python_command:
            raise RuntimeError("Python is not available on the target host")

        sandbox = sandbox_path(path=sandbox_path_value)
        base_dir = str(PurePosixPath(sandbox).parent)
        if recreate:
            await conn.run_full(f"rm -rf {shlex.quote(sandbox)}")

        exists = await conn.file_exists(f"{sandbox}/pyvenv.cfg")
        if not exists:
            cmd = (
                f"mkdir -p {shlex.quote(base_dir)} && "
                f"{shlex.quote(capabilities.python_command)} -m venv {shlex.quote(sandbox)} && "
                f"{shlex.quote(sandbox)}/bin/python -m pip install --upgrade pip"
            )
            result = await conn.run_full(cmd, timeout=180)
            if not result.ok:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "sandbox creation failed")

        if requirements:
            packages = " ".join(shlex.quote(req) for req in requirements)
            install = await conn.run_full(f"{shlex.quote(sandbox)}/bin/pip install {packages}", timeout=240)
            if not install.ok:
                raise RuntimeError(install.stderr.strip() or install.stdout.strip() or "sandbox install failed")

        return (
            {
                "path": sandbox,
                "python": f"{sandbox}/bin/python",
                "pip": f"{sandbox}/bin/pip",
                "requirements": requirements or [],
            },
            capabilities.to_dict(),
        )
    finally:
        pool.release(conn)
