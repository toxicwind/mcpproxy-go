"""Helpers for proxying MCP Nexus public OAuth/MCP routes through another ASGI app."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from fastapi import FastAPI, Request, Response
else:
    FastAPI = Any
    Request = Any
    Response = Any

DEFAULT_PUBLIC_PROXY_PATH_PREFIXES: tuple[str, ...] = (
    "/mcp",
    "/mcp/nexus",
    "/mcp-nexus",
    "/tool-registry",
    "/tool-registry/nexus",
    "/.well-known/nexus-tool-registry",
    "/authorize",
    "/token",
    "/register",
    "/oauth/consent",
    "/oauth/token",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/health/nexus",
    "/ready/nexus",
    "/version/nexus",
    "/info/nexus",
)


def normalize_public_proxy_prefixes(prefixes: Sequence[str] | None = None) -> tuple[str, ...]:
    raw_prefixes = prefixes or DEFAULT_PUBLIC_PROXY_PATH_PREFIXES
    normalized: list[str] = []
    seen: set[str] = set()
    for prefix in raw_prefixes:
        value = prefix.strip()
        if not value:
            continue
        if not value.startswith("/"):
            value = f"/{value}"
        if value != "/":
            value = value.rstrip("/")
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return tuple(normalized)


def should_proxy_public_path(path: str, prefixes: Sequence[str] | None = None) -> bool:
    normalized_path = path if path == "/" else path.rstrip("/")
    for prefix in normalize_public_proxy_prefixes(prefixes):
        if normalized_path == prefix or normalized_path.startswith(f"{prefix}/"):
            return True
    return False


def _load_fastapi() -> tuple[type[Any], type[Any], type[Any]]:
    try:
        from fastapi import FastAPI as _FastAPI
        from fastapi import Request as _Request
        from fastapi import Response as _Response
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "install_fastapi_public_proxy requires FastAPI. Install the optional extra with "
            "`pip install 'mcp-nexus[fastapi]'`."
        ) from exc
    return _FastAPI, _Request, _Response


def install_fastapi_public_proxy(
    app: FastAPI,
    *,
    upstream_base_url: str,
    path_prefixes: Sequence[str] | None = None,
    timeout_seconds: float = 120.0,
    connect_timeout_seconds: float = 10.0,
) -> None:
    """Install a same-origin reverse proxy for MCP Nexus OAuth/MCP public routes.

    Use this when your existing FastAPI app owns the public origin and MCP Nexus
    runs on an internal port such as ``http://127.0.0.1:8766``.
    """

    normalized_base_url = upstream_base_url.rstrip("/")
    normalized_prefixes = normalize_public_proxy_prefixes(path_prefixes)
    _, _, response_cls = _load_fastapi()

    @app.middleware("http")
    async def _mcp_nexus_public_proxy(request: Request, call_next):
        if not should_proxy_public_path(request.url.path, normalized_prefixes):
            return await call_next(request)

        upstream_headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in {"host", "content-length", "connection"}
        }
        if request.headers.get("host"):
            upstream_headers["x-forwarded-host"] = request.headers["host"]
        if request.client and request.client.host:
            forwarded_for = request.headers.get("x-forwarded-for", "").strip()
            chain = [value for value in [forwarded_for, request.client.host] if value]
            upstream_headers["x-forwarded-for"] = ", ".join(chain)
        upstream_headers["x-forwarded-proto"] = request.url.scheme

        upstream_url = f"{normalized_base_url}{request.url.path}"
        if request.url.query:
            upstream_url = f"{upstream_url}?{request.url.query}"

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds, connect=connect_timeout_seconds),
            trust_env=False,
        ) as client:
            upstream_response = await client.request(
                request.method,
                upstream_url,
                headers=upstream_headers,
                content=await request.body(),
            )

        response_headers = {
            name: value
            for name, value in upstream_response.headers.items()
            if name.lower() not in {"content-length", "transfer-encoding", "connection"}
        }
        return response_cls(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
        )
