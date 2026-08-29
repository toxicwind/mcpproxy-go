"""CLI entry point: python -m mcp_nexus."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

import uvicorn

from mcp_nexus.config import Settings
from mcp_nexus.server import create_app, create_server


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-nexus",
        description="MCP Nexus — Remote server management via Model Context Protocol",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Start the MCP server")
    serve_p.add_argument("--host", default=None, help="Bind host (default: from .env)")
    serve_p.add_argument("--port", type=int, default=None, help="Bind port (default: from .env)")
    serve_p.add_argument("--transport", choices=["streamable-http", "stdio"], default="streamable-http")
    serve_p.add_argument("--no-watchdog", action="store_true", help="Disable health watchdog")
    serve_p.add_argument("--log-level", default=None, choices=["debug", "info", "warning", "error"])

    init_p = sub.add_parser("init", help="Scaffold a self-hosted MCP Nexus runtime directory")
    init_p.add_argument("target_dir", nargs="?", default=".", help="Directory where scaffold files will be written")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    init_p.add_argument("--systemd", action="store_true", help="Also write a systemd unit example")
    init_p.add_argument("--service-name", default="mcp-nexus", help="Systemd service name when --systemd is used")
    init_p.add_argument("--service-user", default=None, help="Systemd service user (defaults to current user)")
    init_p.add_argument("--ssh-host", default=None, help="Target SSH host to place into the generated .env")
    init_p.add_argument("--ssh-port", type=int, default=None, help="Target SSH port to place into the generated .env")
    init_p.add_argument("--ssh-user", default=None, help="Target SSH user to place into the generated .env")
    init_p.add_argument("--ssh-key-path", default=None, help="Target SSH key path to place into the generated .env")
    init_p.add_argument("--public-base-url", default=None, help="Public HTTPS origin used for OAuth discovery")
    oauth_group = init_p.add_mutually_exclusive_group()
    oauth_group.add_argument("--oauth", dest="oauth_enabled", action="store_true", default=None)
    oauth_group.add_argument("--no-oauth", dest="oauth_enabled", action="store_false")

    sub.add_parser("health", help="Check server health")
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "version":
        from mcp_nexus import __version__

        print(f"mcp-nexus {__version__}")
        return

    if args.command == "health":
        asyncio.run(_health_check())
        return

    if args.command == "init":
        _init_product(args)
        return

    if args.command == "serve":
        settings = Settings()
        if args.host:
            settings.host = args.host
        if args.port:
            settings.port = args.port
        if args.log_level:
            settings.log_level = args.log_level

        logging.basicConfig(
            level=getattr(logging, settings.log_level.upper()),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        if args.transport == "stdio":
            asyncio.run(_serve_stdio(settings))
        else:
            _serve_http(settings, enable_watchdog=not args.no_watchdog)


def _serve_http(settings: Settings, enable_watchdog: bool = True):
    app = create_app(settings, enable_watchdog=enable_watchdog)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level.lower())


async def _serve_stdio(settings: Settings):
    server = create_server(settings)
    await server.run_stdio_async()


def _init_product(args) -> None:
    from mcp_nexus.scaffold import default_exec_command, write_scaffold

    settings = Settings()
    if args.ssh_host is not None:
        settings.ssh_host = args.ssh_host
    if args.ssh_port is not None:
        settings.ssh_port = args.ssh_port
    if args.ssh_user is not None:
        settings.ssh_user = args.ssh_user
    if args.ssh_key_path is not None:
        settings.ssh_key_path = args.ssh_key_path
    if args.public_base_url is not None:
        settings.public_base_url = args.public_base_url.rstrip("/")
    if args.oauth_enabled is not None:
        settings.oauth_enabled = args.oauth_enabled
    elif not settings.public_base_url:
        settings.oauth_enabled = False

    target_dir = Path(args.target_dir).expanduser().resolve()
    try:
        written = write_scaffold(
            target_dir,
            settings=settings,
            force=args.force,
            include_systemd=args.systemd,
            service_name=args.service_name,
            service_user=args.service_user,
            exec_command=default_exec_command(port=settings.port),
        )
    except FileExistsError as exc:
        print(f"mcp-nexus init: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"Initialized MCP Nexus scaffold in {target_dir}")
    for path in written:
        print(f"  wrote {path}")
    print("Next steps:")
    print(f"  1. Edit {target_dir / '.env'}")
    if args.systemd:
        service_path = target_dir / f"{args.service_name}.service"
        print(f"  2. Review {service_path} before installing it into /etc/systemd/system/")
        print(f"  3. Start the server with: cd {target_dir} && mcp-nexus serve")
    else:
        print(f"  2. Start the server with: cd {target_dir} && mcp-nexus serve")


async def _health_check():
    from mcp_nexus.transport.ssh import SSHPool

    settings = Settings()
    pool = SSHPool(settings)
    try:
        conn = await pool.acquire()
        result = await conn.run("echo ok", timeout=5)
        if result.strip() == "ok":
            print("SSH connection: OK")
        else:
            print("SSH connection: DEGRADED")
            sys.exit(1)
    except Exception as exc:
        print(f"SSH connection: FAILED — {exc}")
        sys.exit(1)
    finally:
        await pool.close()


if __name__ == "__main__":
    main()
