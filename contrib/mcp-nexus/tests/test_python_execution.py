"""Tests for reusable Python execution helpers."""

from __future__ import annotations

import os
import subprocess
import sys

from mcp_nexus.python_execution import (
    STANDARD_NUMERIC_THREAD_ENV_VARS,
    numeric_thread_env,
    python_inline_wrapper,
    python_run_path_wrapper,
    secret_file_env_var,
)


def test_numeric_thread_env_sets_standard_thread_limits() -> None:
    env = numeric_thread_env(1)

    assert tuple(env.keys()) == STANDARD_NUMERIC_THREAD_ENV_VARS
    assert set(env.values()) == {"1"}


def test_secret_file_env_var_uses_explicit_file_suffix() -> None:
    assert secret_file_env_var("NEXUS_DB_URI") == "NEXUS_DB_URI_FILE"
    assert secret_file_env_var("CUSTOM_DB_URI_FILE") == "CUSTOM_DB_URI_FILE"


def test_python_inline_wrapper_bootstraps_db_env_from_file(tmp_path) -> None:
    secret_path = tmp_path / "db.secret"
    secret_path.write_text("postgresql://robot:secret@localhost:5433/db", encoding="utf-8")
    env = os.environ.copy()
    env["NEXUS_DB_URI_FILE"] = str(secret_path)
    wrapper = python_inline_wrapper(
        "import os; print(os.environ['NEXUS_DB_URI'])",
        db_env_var="NEXUS_DB_URI",
    )

    result = subprocess.run(
        [sys.executable, "-c", wrapper],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "postgresql://robot:secret@localhost:5433/db"
    assert not secret_path.exists()


def test_python_run_path_wrapper_bootstraps_db_env_and_preserves_args(tmp_path) -> None:
    secret_path = tmp_path / "db.secret"
    secret_path.write_text("postgresql://robot:secret@localhost:5433/db", encoding="utf-8")
    script_path = tmp_path / "script.py"
    script_path.write_text(
        "import os, sys\n"
        "print(os.environ['NEXUS_DB_URI'])\n"
        "print(','.join(sys.argv))\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["NEXUS_DB_URI_FILE"] = str(secret_path)

    result = subprocess.run(
        [sys.executable, "-c", python_run_path_wrapper(db_env_var="NEXUS_DB_URI"), str(script_path), "alpha", "beta"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    stdout_lines = result.stdout.strip().splitlines()
    assert stdout_lines[0] == "postgresql://robot:secret@localhost:5433/db"
    assert stdout_lines[1] == f"{script_path},alpha,beta"
    assert not secret_path.exists()
