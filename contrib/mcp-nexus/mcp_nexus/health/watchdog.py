"""Health watchdog — monitors SSH connection and auto-recovers services."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from mcp_nexus.config import Settings
from mcp_nexus.transport.ssh import SSHPool

logger = logging.getLogger(__name__)


@dataclass
class WatchdogState:
    last_check: float = 0
    consecutive_failures: int = 0
    total_restarts: int = 0
    restart_window_start: float = 0
    restarts_in_window: int = 0
    services_restarted: list[str] = field(default_factory=list)


class Watchdog:
    """Background health monitor with auto-recovery.

    Monitors services listed in ``settings.watchdog_services``.  If no
    services are configured, the watchdog only checks SSH connectivity.
    """

    def __init__(self, pool: SSHPool, settings: Settings):
        self._pool = pool
        self._settings = settings
        self._state = WatchdogState()
        self._running = False

    async def run(self):
        """Main watchdog loop — runs until cancelled."""
        self._running = True
        services = self._settings.watchdog_services
        logger.info(
            "Watchdog started — interval=%ds services=%s",
            self._settings.watchdog_interval,
            services or "(ssh-only)",
        )

        while self._running:
            try:
                await self._check_cycle()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Watchdog cycle error: %s", e)

            await asyncio.sleep(self._settings.watchdog_interval)

    def stop(self):
        self._running = False

    async def _check_cycle(self):
        """One health check cycle."""
        self._state.last_check = time.time()

        # Check SSH connectivity
        health = await self._pool.health_check()
        if health["status"] == "unhealthy":
            self._state.consecutive_failures += 1
            logger.warning(
                "Health check failed (%d consecutive): %s",
                self._state.consecutive_failures,
                health.get("error", "unknown"),
            )
            return

        self._state.consecutive_failures = 0

        # Check configured services (if any)
        services = self._settings.watchdog_services
        if not services:
            return

        conn = await self._pool.acquire()
        try:
            for service in services:
                result = await conn.run_full(f"systemctl is-active {service} 2>/dev/null")
                status = result.stdout.strip()

                if status not in ("active", "activating"):
                    logger.warning("Service %s is %s — attempting restart", service, status)
                    await self._try_restart(conn, service)
        finally:
            self._pool.release(conn)

    async def _try_restart(self, conn, service: str):
        """Attempt to restart a failed service with rate limiting."""
        now = time.time()

        # Reset window if cooldown has passed
        if now - self._state.restart_window_start > self._settings.restart_cooldown:
            self._state.restart_window_start = now
            self._state.restarts_in_window = 0

        # Check if we've hit the restart limit
        if self._state.restarts_in_window >= self._settings.max_restart_attempts:
            logger.error(
                "Restart limit reached (%d in %ds window) — skipping %s",
                self._state.restarts_in_window,
                self._settings.restart_cooldown,
                service,
            )
            return

        result = await conn.run_full(f"systemctl restart {service}", timeout=30)
        self._state.restarts_in_window += 1
        self._state.total_restarts += 1

        if result.ok:
            # Verify it actually started
            await asyncio.sleep(2)
            check = await conn.run_full(f"systemctl is-active {service}")
            if check.stdout.strip() == "active":
                logger.info("Successfully restarted %s", service)
                self._state.services_restarted.append(f"{service}@{int(now)}")
            else:
                logger.error("Service %s failed to start after restart", service)
        else:
            logger.error("Failed to restart %s: %s", service, result.stderr.strip())

    def get_state(self) -> dict:
        return {
            "last_check": self._state.last_check,
            "consecutive_failures": self._state.consecutive_failures,
            "total_restarts": self._state.total_restarts,
            "restarts_in_window": self._state.restarts_in_window,
            "recent_restarts": self._state.services_restarted[-10:],
        }
