"""Tests for product scaffolding."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_nexus.config import Settings
from mcp_nexus.scaffold import default_exec_command, render_env_file, render_systemd_unit, write_scaffold


def test_render_env_file_uses_current_settings() -> None:
    settings = Settings()
    settings.ssh_host = "infra.example.com"
    settings.ssh_port = 2222
    settings.ssh_user = "deploy"
    settings.public_base_url = "https://nexus.example.com"
    settings.oauth_enabled = True

    rendered = render_env_file(settings)

    assert "NEXUS_SSH_HOST=infra.example.com" in rendered
    assert "NEXUS_SSH_PORT=2222" in rendered
    assert "NEXUS_SSH_USER=deploy" in rendered
    assert "NEXUS_PUBLIC_BASE_URL=https://nexus.example.com" in rendered
    assert "NEXUS_OAUTH_ENABLED=true" in rendered


def test_render_systemd_unit_is_installable_example() -> None:
    rendered = render_systemd_unit(
        service_name="mcp-nexus",
        working_directory="/srv/mcp-nexus",
        env_file="/srv/mcp-nexus/.env",
        exec_command="/opt/mcp-nexus/bin/python -m mcp_nexus serve --host 127.0.0.1 --port 8766",
        service_user="deploy",
    )

    assert "WorkingDirectory=/srv/mcp-nexus" in rendered
    assert "EnvironmentFile=/srv/mcp-nexus/.env" in rendered
    assert "User=deploy" in rendered
    assert "ExecStart=/opt/mcp-nexus/bin/python -m mcp_nexus serve --host 127.0.0.1 --port 8766" in rendered


def test_write_scaffold_writes_env_and_optional_systemd(tmp_path: Path) -> None:
    settings = Settings()
    settings.port = 9100

    written = write_scaffold(
        tmp_path,
        settings=settings,
        include_systemd=True,
        service_user="deploy",
        exec_command=default_exec_command(port=settings.port, python_executable="/venv/bin/python"),
    )

    assert tmp_path / ".env" in written
    assert tmp_path / "mcp-nexus.service" in written
    assert "NEXUS_PORT=9100" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "ExecStart=/venv/bin/python -m mcp_nexus serve --host 127.0.0.1 --port 9100" in (
        tmp_path / "mcp-nexus.service"
    ).read_text(encoding="utf-8")


def test_write_scaffold_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    settings = Settings()
    (tmp_path / ".env").write_text("existing\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_scaffold(tmp_path, settings=settings)
