"""Session recovery behavior for MCP request middleware."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_nexus.config import Settings
from mcp_nexus.server import NexusRequestContextMiddleware, create_server


class _DummySessionManager:
    def __init__(self):
        self._server_instances: dict[str, object] = {}


def _test_settings(tmp_path) -> Settings:
    settings = Settings()
    settings.mcp_path = "/mcp/nexus"
    settings.mcp_path_aliases = []
    settings.intelligence_enabled = False
    settings.oauth_enabled = False
    settings.state_root = str(tmp_path / "state")
    settings.data_dir = str(tmp_path / "data")
    return settings


def _activate_session(mcp_server, session_id: str) -> None:
    session_manager = getattr(mcp_server, "_session_manager", None)
    assert session_manager is not None
    server_instances = getattr(session_manager, "_server_instances", None)
    assert isinstance(server_instances, dict)
    server_instances[session_id] = object()


async def _echo_session_header(request):
    seen_session_id = request.headers.get("mcp-session-id")
    response_headers = {"mcp-session-id": seen_session_id or "fresh-session-id"}
    return JSONResponse({"seen_session_id": seen_session_id}, headers=response_headers)


def _build_test_app(settings: Settings):
    mcp_server = create_server(settings)
    setattr(mcp_server, "_session_manager", _DummySessionManager())
    app = Starlette(routes=[Route(settings.mcp_path, _echo_session_header, methods=["POST"])])
    app.add_middleware(NexusRequestContextMiddleware, settings=settings, mcp_server=mcp_server)
    return app, mcp_server


def test_stale_session_header_is_recovered_instead_of_returning_not_found(tmp_path):
    settings = _test_settings(tmp_path)
    app, _ = _build_test_app(settings)

    with TestClient(app) as client:
        response = client.post(settings.mcp_path, json={"probe": True}, headers={"mcp-session-id": "stale-123"})

    assert response.status_code == 200
    assert response.json()["seen_session_id"] is None
    assert response.headers.get("x-nexus-session-recovery") == "stale-session-id-ignored"
    assert response.headers.get("x-nexus-stale-session-id") == "stale-123"
    assert response.headers.get("x-nexus-recovered-session-id") == "fresh-session-id"


def test_active_session_header_is_preserved_without_recovery_markers(tmp_path):
    settings = _test_settings(tmp_path)
    app, mcp_server = _build_test_app(settings)
    _activate_session(mcp_server, "live-123")

    with TestClient(app) as client:
        response = client.post(settings.mcp_path, json={"probe": True}, headers={"mcp-session-id": "live-123"})

    assert response.status_code == 200
    assert response.json()["seen_session_id"] == "live-123"
    assert response.headers.get("x-nexus-session-recovery") is None
    assert response.headers.get("x-nexus-stale-session-id") is None
    assert response.headers.get("x-nexus-recovered-session-id") is None
