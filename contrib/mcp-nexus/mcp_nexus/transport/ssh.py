"""SSH connection pool with auto-reconnect and localhost fallback."""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
from dataclasses import dataclass

import asyncssh

from mcp_nexus.config import Settings
from mcp_nexus.runtime import ServerCapabilities, capability_probe_command, parse_capability_output

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def raise_on_error(self, context: str = ""):
        if not self.ok:
            msg = self.stderr.strip() or self.stdout.strip() or "Unknown error"
            raise RuntimeError(f"{context}: {msg}" if context else msg)


class SSHConnection:
    """Wraps a single SSH connection or localhost execution."""

    def __init__(self, conn: asyncssh.SSHClientConnection | None, is_local: bool = False):
        self._conn = conn
        self._is_local = is_local
        self._last_used = time.monotonic()
        self._capabilities: ServerCapabilities | None = None
        self._capabilities_at: float = 0.0

    @property
    def is_alive(self) -> bool:
        if self._is_local:
            return True
        if self._conn is None:
            return False
        try:
            return not self._conn.is_closed
        except Exception:
            return False

    async def run(self, command: str, timeout: int = 60, cwd: str = "") -> str:
        """Execute command and return stdout. Raises on non-zero exit."""
        result = await self.run_full(command, timeout=timeout, cwd=cwd)
        result.raise_on_error(command[:80])
        return result.stdout

    async def run_full(self, command: str, timeout: int = 60, cwd: str = "") -> CommandResult:
        """Execute command and return full result."""
        self._last_used = time.monotonic()
        if cwd:
            command = f"cd {shlex.quote(cwd)} && {command}"

        if self._is_local:
            return await self._run_local(command, timeout)
        return await self._run_ssh(command, timeout)

    async def _run_ssh(self, command: str, timeout: int) -> CommandResult:
        try:
            assert self._conn is not None
            result = await asyncio.wait_for(
                self._conn.run(command, check=False),
                timeout=timeout,
            )
            stdout = (
                result.stdout.decode("utf-8", errors="replace")
                if isinstance(result.stdout, bytes)
                else (result.stdout or "")
            )
            stderr = (
                result.stderr.decode("utf-8", errors="replace")
                if isinstance(result.stderr, bytes)
                else (result.stderr or "")
            )
            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=result.exit_status or 0,
            )
        except TimeoutError:
            return CommandResult(stdout="", stderr=f"Command timed out after {timeout}s", exit_code=124)

    async def _run_local(self, command: str, timeout: int) -> CommandResult:
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return CommandResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
            )
        except TimeoutError:
            proc.kill()
            return CommandResult(stdout="", stderr=f"Command timed out after {timeout}s", exit_code=124)

    async def read_file(self, path: str) -> str:
        result = await self.run(f"cat {shlex.quote(path)}", timeout=30)
        return result

    async def write_file(self, path: str, content: str) -> None:
        if self._is_local:
            import aiofiles  # type: ignore[import-untyped]

            async with aiofiles.open(path, "w") as f:
                await f.write(content)
        else:
            assert self._conn is not None
            async with self._conn.start_sftp_client() as sftp:
                async with sftp.open(path, "w") as f:
                    await f.write(content)

    async def read_file_bytes(self, path: str) -> bytes:
        if self._is_local:
            import aiofiles  # type: ignore[import-untyped]

            async with aiofiles.open(path, "rb") as f:
                return await f.read()
        else:
            assert self._conn is not None
            async with self._conn.start_sftp_client() as sftp:
                async with sftp.open(path, "rb") as f:
                    return await f.read()

    async def file_exists(self, path: str) -> bool:
        result = await self.run_full(f"test -e {shlex.quote(path)}")
        return result.ok

    async def list_dir(self, path: str) -> list[str]:
        result = await self.run(f"ls -1a {shlex.quote(path)}")
        return [f for f in result.strip().split("\n") if f and f not in (".", "..")]

    async def probe_capabilities(self, refresh: bool = False) -> ServerCapabilities:
        """Detect command, package, and service capabilities on the target host."""
        if not refresh and self._capabilities and (time.monotonic() - self._capabilities_at) < 300:
            return self._capabilities

        result = await self.run_full(capability_probe_command(), timeout=20)
        capabilities = parse_capability_output(result.stdout)
        self._capabilities = capabilities
        self._capabilities_at = time.monotonic()
        return capabilities


class SSHPool:
    """Connection pool with auto-reconnect and health checking."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._is_local = settings.is_localhost
        self._connections: list[SSHConnection] = []
        self._semaphore = asyncio.Semaphore(settings.ssh_pool_size)
        self._lock = asyncio.Lock()
        self._closed = False
        self._connect_failures = 0
        self._max_failures = 5

    async def acquire(self) -> SSHConnection:
        """Get a connection from the pool."""
        if self._closed:
            raise RuntimeError("Pool is closed")

        await self._semaphore.acquire()

        if self._is_local:
            conn = SSHConnection(conn=None, is_local=True)
            return conn

        async with self._lock:
            # Reuse alive connection
            for c in self._connections:
                if c.is_alive:
                    return c

            # Create new connection
            conn = await self._create_connection()
            self._connections.append(conn)
            return conn

    def backend_metadata(self) -> dict[str, str]:
        backend_host = self._settings.ssh_host if self._is_local else self._settings.resolved_ssh_host
        return {
            "backend_kind": "local" if self._is_local else "ssh",
            "backend_instance": f"{self._settings.ssh_user}@{backend_host}:{self._settings.ssh_port}",
        }

    def release(self, conn: SSHConnection):
        """Release connection back to pool."""
        self._semaphore.release()

    async def _create_connection(self) -> SSHConnection:
        """Create a new SSH connection with retry."""
        last_error = None
        for attempt in range(3):
            try:
                kwargs = dict(
                    host=self._settings.resolved_ssh_host,
                    port=self._settings.ssh_port,
                    username=self._settings.ssh_user,
                    known_hosts=None,
                    keepalive_interval=15,
                    keepalive_count_max=3,
                )
                if self._settings.ssh_key_path:
                    kwargs["client_keys"] = [self._settings.ssh_key_path]
                elif self._settings.ssh_password:
                    kwargs["password"] = self._settings.ssh_password

                raw_conn = await asyncio.wait_for(
                    asyncssh.connect(**kwargs),
                    timeout=15,
                )
                self._connect_failures = 0
                logger.info(
                    "SSH connection established to %s:%d",
                    self._settings.resolved_ssh_host,
                    self._settings.ssh_port,
                )
                return SSHConnection(raw_conn)

            except Exception as e:
                last_error = e
                logger.warning("SSH connect attempt %d failed: %s", attempt + 1, e)
                if attempt < 2:
                    await asyncio.sleep(1 * (attempt + 1))

        self._connect_failures += 1
        raise ConnectionError(f"SSH connection failed after 3 attempts: {last_error}")

    async def health_check(self) -> dict:
        """Check pool health."""
        try:
            conn = await self.acquire()
            try:
                result = await conn.run("echo nexus-ok", timeout=5)
                return {
                    "status": "healthy" if "nexus-ok" in result else "degraded",
                    "mode": "local" if self._is_local else "ssh",
                    "pool_size": len(self._connections),
                    "failures": self._connect_failures,
                }
            finally:
                self.release(conn)
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "failures": self._connect_failures,
            }

    async def close(self):
        """Close all connections."""
        self._closed = True
        async with self._lock:
            for c in self._connections:
                if c._conn and not c._is_local:
                    c._conn.close()
            self._connections.clear()
