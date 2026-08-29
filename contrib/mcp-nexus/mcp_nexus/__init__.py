"""MCP Nexus — Remote server management through the Model Context Protocol."""

__version__ = "1.3.0"
__author__ = "Lightcap AI"

__all__ = ["create_server", "__version__"]


def create_server(*args, **kwargs):
    """Lazily import the server factory to keep package metadata imports lightweight."""
    from mcp_nexus.server import create_server as _create_server

    return _create_server(*args, **kwargs)
