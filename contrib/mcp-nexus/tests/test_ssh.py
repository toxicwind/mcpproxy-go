"""Tests for SSH connection pool (localhost mode only — no real SSH needed)."""

import pytest

from mcp_nexus.config import Settings
from mcp_nexus.transport.ssh import CommandResult, SSHConnection, SSHPool


@pytest.fixture
def local_settings():
    s = Settings()
    s.ssh_host = "127.0.0.1"
    return s


def test_command_result():
    r = CommandResult(stdout="hello\n", stderr="", exit_code=0)
    assert r.ok is True
    assert r.stdout == "hello\n"

    r2 = CommandResult(stdout="", stderr="error", exit_code=1)
    assert r2.ok is False
    with pytest.raises(RuntimeError):
        r2.raise_on_error("test")


@pytest.mark.asyncio
async def test_local_connection():
    conn = SSHConnection(conn=None, is_local=True)
    assert conn.is_alive is True
    result = await conn.run("echo nexus-test")
    assert "nexus-test" in result


@pytest.mark.asyncio
async def test_local_pool(local_settings):
    pool = SSHPool(local_settings)
    conn = await pool.acquire()
    try:
        result = await conn.run("echo ok")
        assert "ok" in result
    finally:
        pool.release(conn)
    await pool.close()


@pytest.mark.asyncio
async def test_pool_health(local_settings):
    pool = SSHPool(local_settings)
    health = await pool.health_check()
    assert health["status"] == "healthy"
    assert health["mode"] == "local"
    await pool.close()


def test_containerized_loopback_target_does_not_use_local_exec():
    settings = Settings()
    settings.runtime_container = True
    settings.allow_container_localhost_exec = False
    settings.host_bridge_address = "host.docker.internal"
    settings.ssh_host = "127.0.0.1"

    pool = SSHPool(settings)
    assert pool._is_local is False
