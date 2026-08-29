"""Reusable helpers for remote Python execution policies and secret delivery."""

from __future__ import annotations

import json
import shlex
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

STANDARD_NUMERIC_THREAD_ENV_VARS = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "BLIS_NUM_THREADS",
)


def numeric_thread_env(limit: int) -> dict[str, str]:
    """Return a standard numeric-library thread policy for Python jobs."""
    normalized = max(1, int(limit or 1))
    return {name: str(normalized) for name in STANDARD_NUMERIC_THREAD_ENV_VARS}


def secret_file_env_var(variable_name: str) -> str:
    """Return the non-secret env var name that points at a secret file."""
    base = variable_name.strip() or "NEXUS_DB_URI"
    return base if base.endswith("_FILE") else f"{base}_FILE"


def python_database_bootstrap(db_env_var: str) -> str:
    """Load a database URI from a file path env var into the expected runtime env var."""
    file_env_var = secret_file_env_var(db_env_var)
    return f"""
import os
from pathlib import Path

_nexus_db_secret_path = os.environ.pop({file_env_var!r}, "")
if _nexus_db_secret_path:
    os.environ[{db_env_var!r}] = Path(_nexus_db_secret_path).read_text(encoding="utf-8").strip()
    try:
        Path(_nexus_db_secret_path).unlink()
    except FileNotFoundError:
        pass
""".strip()


def python_inline_wrapper(code: str, *, db_env_var: str) -> str:
    """Wrap inline Python so database bootstrap runs before user code without changing user syntax."""
    return "\n\n".join(
        [
            python_database_bootstrap(db_env_var),
            f"_NEXUS_USER_CODE = {json.dumps(code)}",
            'exec(compile(_NEXUS_USER_CODE, "<stdin>", "exec"), {"__name__": "__main__", "__file__": "<stdin>"})',
        ]
    )


def python_run_path_wrapper(*, db_env_var: str) -> str:
    """Wrap Python file execution so database bootstrap runs before the target script."""
    return "\n\n".join(
        [
            python_database_bootstrap(db_env_var),
            "import runpy",
            "import sys",
            "_nexus_script_path = sys.argv[1]",
            "sys.argv = sys.argv[1:]",
            'runpy.run_path(_nexus_script_path, run_name="__main__")',
        ]
    )


def remote_secret_file_path(prefix: str) -> str:
    safe_prefix = prefix.strip().replace("/", "-") or "nexus-secret"
    return str(PurePosixPath("/tmp") / f"{safe_prefix}-{uuid4().hex}.secret")


async def write_secret_file(conn: Any, *, prefix: str, content: str) -> str:
    """Write secret content to a temporary remote file with restrictive permissions."""
    path = remote_secret_file_path(prefix)
    await conn.write_file(path, content)
    result = await conn.run_full(f"chmod 600 {shlex.quote(path)}", timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "failed to protect secret file")
    return path
