"""Server monitoring — health, disk, memory, CPU, network."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_nexus.server import get_pool


def register(mcp: FastMCP):

    @mcp.tool()
    async def server_health(services: list[str] | None = None, ports: list[int] | None = None) -> str:
        """Comprehensive server health check — resources, services, connectivity.

        Args:
            services: List of systemd services to check (auto-detects running services if empty).
            ports: List of ports to verify (checks common ports if empty).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            checks = {}

            # Uptime & load
            r = await conn.run_full("uptime", timeout=5)
            checks["uptime"] = r.stdout.strip() if r.ok else "unavailable"

            # Memory
            r = await conn.run_full("free -h | grep -E 'Mem|Swap'", timeout=5)
            checks["memory"] = r.stdout.strip() if r.ok else "unavailable"

            # Disk
            r = await conn.run_full("df -h / | tail -1", timeout=5)
            checks["disk_root"] = r.stdout.strip() if r.ok else "unavailable"

            # Services
            if services:
                for svc in services:
                    r = await conn.run_full(f"systemctl is-active {svc} 2>/dev/null")
                    checks[f"service_{svc}"] = r.stdout.strip() if r.ok else "inactive"

            # Docker containers
            r = await conn.run_full("docker ps --format '{{.Names}}: {{.Status}}' 2>/dev/null", timeout=10)
            checks["docker"] = r.stdout.strip() if r.ok else "unavailable"

            # Port checks
            if ports:
                for port in ports:
                    r = await conn.run_full(f"ss -tlnp | grep :{port}", timeout=5)
                    checks[f"port_{port}"] = "listening" if r.ok and r.stdout.strip() else "not_listening"

            return json.dumps(checks, indent=2)
        finally:
            pool.release(conn)

    @mcp.tool()
    async def disk_usage(path: str = "/") -> str:
        """Show disk usage.

        Args:
            path: Path to check (default: root).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            result = await conn.run("df -h", timeout=10)
            du = await conn.run_full(f"du -sh {path} 2>/dev/null")
            return json.dumps(
                {
                    "filesystems": result.strip(),
                    "path_usage": du.stdout.strip() if du.ok else "N/A",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def memory_usage() -> str:
        """Show detailed memory usage."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            free = await conn.run("free -h", timeout=5)
            top = await conn.run("ps aux --sort=-%mem | head -11", timeout=5)
            return json.dumps(
                {
                    "free": free.strip(),
                    "top_processes": top.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def cpu_usage() -> str:
        """Show CPU usage and top processes."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            load = await conn.run("cat /proc/loadavg", timeout=5)
            cpuinfo = await conn.run("nproc", timeout=5)
            top = await conn.run("ps aux --sort=-%cpu | head -11", timeout=5)
            return json.dumps(
                {
                    "load_avg": load.strip(),
                    "cpu_cores": cpuinfo.strip(),
                    "top_processes": top.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def network_stats() -> str:
        """Show network interfaces and connection statistics."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            interfaces = await conn.run_full("ip addr show | grep -E 'inet |state'", timeout=5)
            connections = await conn.run_full("ss -s", timeout=5)
            return json.dumps(
                {
                    "interfaces": interfaces.stdout.strip() if interfaces.ok else "N/A",
                    "connections": connections.stdout.strip() if connections.ok else "N/A",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def active_connections(port: int = 0) -> str:
        """Show active network connections, optionally filtered by port.

        Args:
            port: Filter by port number (0 = show all).
        """
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if port:
                cmd = f"ss -tlnp | grep :{port}"
            else:
                cmd = "ss -tlnp"
            result = await conn.run(cmd, timeout=10)
            return json.dumps({"connections": result.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def nginx_status() -> str:
        """Show Nginx status, config test, and recent error logs."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            status = await conn.run_full("systemctl status nginx --no-pager -l", timeout=10)
            config_test = await conn.run_full("nginx -t 2>&1", timeout=10)
            errors = await conn.run_full("tail -30 /var/log/nginx/error.log 2>/dev/null", timeout=5)
            return json.dumps(
                {
                    "status": status.stdout.strip() if status.ok else status.stderr.strip(),
                    "config_test": (config_test.stdout + config_test.stderr).strip(),
                    "recent_errors": errors.stdout.strip() if errors.ok else "No error log found",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def docker_status() -> str:
        """Show Docker container status and resource usage."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            ps_fmt = "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            ps = await conn.run_full(f"docker ps -a --format '{ps_fmt}' 2>/dev/null", timeout=10)
            stats_fmt = "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
            stats = await conn.run_full(
                f"docker stats --no-stream --format '{stats_fmt}' 2>/dev/null",
                timeout=15,
            )
            return json.dumps(
                {
                    "containers": ps.stdout.strip() if ps.ok else "Docker not available",
                    "stats": stats.stdout.strip() if stats.ok else "N/A",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def server_resources() -> str:
        """Summarize CPU, memory, disk, and top consumers in one payload."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            uptime = await conn.run_full("uptime", timeout=5)
            memory = await conn.run_full("free -h 2>/dev/null || vm_stat", timeout=5)
            disk = await conn.run_full("df -h / | tail -1", timeout=5)
            cpu_top = await conn.run_full("ps aux --sort=-%cpu | head -11", timeout=5)
            mem_top = await conn.run_full("ps aux --sort=-%mem | head -11", timeout=5)
            return json.dumps(
                {
                    "uptime": uptime.stdout.strip(),
                    "memory": memory.stdout.strip(),
                    "disk_root": disk.stdout.strip(),
                    "top_cpu": cpu_top.stdout.strip(),
                    "top_memory": mem_top.stdout.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def io_activity() -> str:
        """Inspect disk I/O pressure with the best available host command."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            iostat = await conn.run_full("which iostat 2>/dev/null")
            if iostat.ok:
                cmd = "iostat -dx 1 2 2>/dev/null || iostat 1 2"
            else:
                cmd = "vmstat 1 2 2>/dev/null"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps({"io": (result.stdout + result.stderr).strip()})
        finally:
            pool.release(conn)
