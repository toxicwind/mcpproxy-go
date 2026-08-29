"""OAuth and MCP auth route regressions."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

from mcp_nexus.config import Settings
from mcp_nexus.server import _transport_security_settings, create_app


def _pkce_pair(verifier: str) -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _oauth_settings() -> Settings:
    settings = Settings()
    settings.public_base_url = "https://example.com"
    settings.oauth_issuer = "https://example.com"
    settings.mcp_path = "/mcp/nexus"
    settings.mcp_path_aliases = ["/mcp"]
    settings.ssh_host = "127.0.0.1"
    settings.ssh_user = "root"
    settings.ssh_password = ""
    settings.ssh_port = 22
    return settings


def test_mcp_requires_auth_and_exposes_metadata():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app) as client:
        response = client.post("/mcp/nexus", json={})
        assert response.status_code == 401
        header = response.headers["www-authenticate"]
        assert 'error="invalid_token"' in header
        assert (
            'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp/nexus"' in header
        )

        protected_resource = client.get("/.well-known/oauth-protected-resource/mcp/nexus")
        assert protected_resource.status_code == 200
        assert protected_resource.json()["resource"] == "https://example.com/mcp/nexus"

        metadata = client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200
        payload = metadata.json()
        assert payload["authorization_endpoint"] == "https://example.com/authorize"
        assert payload["token_endpoint"] == "https://example.com/token"
        assert payload["registration_endpoint"] == "https://example.com/register"


def test_public_host_header_is_accepted_for_local_bind_when_public_origin_is_configured():
    settings = _oauth_settings()
    settings.host = "127.0.0.1"
    settings.oauth_client_redirect_uris = ["https://chatgpt.com/connector/oauth/test"]
    app = create_app(settings, enable_watchdog=False)

    with TestClient(app, base_url="https://example.com") as client:
        response = client.post(
            "/mcp/nexus",
            json={},
            headers={"origin": "https://chatgpt.com"},
        )
        assert response.status_code == 401


def test_transport_security_settings_only_allow_configured_public_hosts():
    settings = _oauth_settings()
    settings.host = "127.0.0.1"
    security = _transport_security_settings(settings)
    assert security is not None
    assert "example.com" in security.allowed_hosts
    assert "evil.example.com" not in security.allowed_hosts


def test_health_alias_route_exists():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app) as client:
        response = client.get("/health/nexus")
        assert response.status_code == 200


def test_tool_registry_alias_routes_exist():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app) as client:
        alias_response = client.get("/tool-registry/nexus")
        well_known_response = client.get("/.well-known/nexus-tool-registry")
        assert alias_response.status_code == 200
        assert well_known_response.status_code == 200
        assert alias_response.json()["tool_count"] == well_known_response.json()["tool_count"]


def test_tool_alias_routes_require_bearer_and_support_runtime_binding():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app, base_url="https://example.com") as client:
        unauthorized = client.post("/mcp-nexus/nexus_tool_catalog", json={})
        assert unauthorized.status_code == 401
        assert unauthorized.json()["error_code"] == "AUTH_REQUIRED"

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "127.0.0.1",
                "client_secret": "",
                "ssh_user": "root",
                "ssh_port": "22",
            },
        )
        assert token_response.status_code == 200
        token = token_response.json()["access_token"]

        auth_headers = {"authorization": f"Bearer {token}"}
        alias_response = client.post("/mcp-nexus/nexus_tool_catalog", json={}, headers=auth_headers)
        assert alias_response.status_code == 200
        alias_payload = alias_response.json()
        assert alias_payload["ok"] is True
        assert alias_payload["tool"]["name"] == "nexus_tool_catalog"
        assert alias_payload["result"]["surface_scope"] == "server_catalog"

        registry = client.get("/version/nexus").json()
        server_instance_id = registry["server_instance_id"]
        runtime_response = client.post(
            f"/mcp-nexus/runtime/{server_instance_id}/nexus_tool_catalog",
            json={},
            headers=auth_headers,
        )
        assert runtime_response.status_code == 200

        stale_response = client.post(
            "/mcp-nexus/runtime/stale-instance/nexus_tool_catalog",
            json={},
            headers=auth_headers,
        )
        assert stale_response.status_code == 409
        assert stale_response.json()["error_code"] == "SERVER_INSTANCE_MISMATCH"


def test_version_exposes_control_plane_paths():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app) as client:
        response = client.get("/version/nexus")
        assert response.status_code == 200
        payload = response.json()
        assert "/tool-registry" in payload["control_plane"]["tool_registry"]
        assert "/.well-known/nexus-tool-registry" in payload["control_plane"]["tool_registry"]
        assert any(path.startswith("/mcp-nexus/") for path in payload["control_plane"]["tool_alias"])


def test_mcp_browser_get_renders_connect_landing_without_breaking_auth_surface():
    app = create_app(_oauth_settings(), enable_watchdog=False)

    with TestClient(app) as client:
        landing = client.get("/mcp/nexus", headers={"Accept": "text/html"})
        assert landing.status_code == 200
        assert "Connect your AI to a real server." in landing.text
        assert "View On GitHub" in landing.text
        assert "Manual OAuth Values" in landing.text
        assert "Registration URL" in landing.text
        assert "Resource:" in landing.text

        api_like = client.get("/mcp/nexus", headers={"Accept": "application/json"})
        assert api_like.status_code == 401


def test_oauth_authorization_code_flow_completes_against_consent_route():
    app = create_app(_oauth_settings(), enable_watchdog=False)
    verifier, challenge = _pkce_pair("codex-test-verifier")

    with TestClient(app) as client:
        registration = client.post(
            "/register",
            json={
                "redirect_uris": ["https://chat.openai.com/aip/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        assert registration.status_code == 201
        client_info = registration.json()

        authorize = client.get(
            "/authorize",
            params={
                "client_id": client_info["client_id"],
                "redirect_uri": "https://chat.openai.com/aip/callback",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-1",
                "resource": "https://example.com/mcp/nexus",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302

        consent_location = urlparse(authorize.headers["location"])
        assert consent_location.path == "/oauth/consent"
        request_id = parse_qs(consent_location.query)["request_id"][0]

        consent_page = client.get(f"/oauth/consent?request_id={request_id}")
        assert consent_page.status_code == 200
        assert "Authorize ChatGPT" in consent_page.text

        approval = client.post(
            "/oauth/consent",
            data={
                "request_id": request_id,
                "decision": "approve",
                "ssh_host": "127.0.0.1",
                "ssh_user": "root",
                "ssh_port": "22",
                "ssh_password": "",
            },
            follow_redirects=False,
        )
        assert approval.status_code == 302

        callback_location = urlparse(approval.headers["location"])
        assert callback_location.path == "/aip/callback"
        callback_query = parse_qs(callback_location.query)
        code = callback_query["code"][0]
        assert callback_query["state"] == ["state-1"]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chat.openai.com/aip/callback",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "code_verifier": verifier,
                "resource": "https://example.com/mcp/nexus",
            },
        )
        assert token.status_code == 200
        token_payload = token.json()
        assert token_payload["token_type"] == "Bearer"
        assert token_payload["access_token"]
        assert token_payload["refresh_token"]
        assert token_payload["scope"] == "nexus"


def test_static_oauth_client_authorization_code_flow_completes_without_dynamic_registration():
    settings = _oauth_settings()
    settings.oauth_client_id = "chatgpt-manual"
    settings.oauth_client_secret = "static-secret"
    settings.oauth_client_redirect_uris = ["https://chatgpt.com/connector/oauth/test"]
    app = create_app(settings, enable_watchdog=False)
    verifier, challenge = _pkce_pair("codex-static-client-verifier")

    with TestClient(app) as client:
        authorize = client.get(
            "/authorize",
            params={
                "client_id": "chatgpt-manual",
                "redirect_uri": "https://chatgpt.com/connector/oauth/test",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-static",
                "resource": "https://example.com/mcp/nexus",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302

        consent_location = urlparse(authorize.headers["location"])
        request_id = parse_qs(consent_location.query)["request_id"][0]

        approval = client.post(
            "/oauth/consent",
            data={
                "request_id": request_id,
                "decision": "approve",
                "ssh_host": "127.0.0.1",
                "ssh_user": "root",
                "ssh_port": "22",
                "ssh_password": "",
            },
            follow_redirects=False,
        )
        assert approval.status_code == 302

        callback_location = urlparse(approval.headers["location"])
        callback_query = parse_qs(callback_location.query)
        code = callback_query["code"][0]
        assert callback_query["state"] == ["state-static"]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chatgpt.com/connector/oauth/test",
                "client_id": "chatgpt-manual",
                "client_secret": "static-secret",
                "code_verifier": verifier,
                "resource": "https://example.com/mcp/nexus",
            },
        )
        assert token.status_code == 200
        token_payload = token.json()
        assert token_payload["token_type"] == "Bearer"
        assert token_payload["access_token"]


def test_dynamic_oauth_state_survives_restart(tmp_path):
    settings = _oauth_settings()
    settings.state_root = str(tmp_path / "state")
    verifier, challenge = _pkce_pair("codex-persisted-state-verifier")

    app = create_app(settings, enable_watchdog=False)
    with TestClient(app) as client:
        registration = client.post(
            "/register",
            json={
                "redirect_uris": ["https://chat.openai.com/aip/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        assert registration.status_code == 201
        client_info = registration.json()

        authorize = client.get(
            "/authorize",
            params={
                "client_id": client_info["client_id"],
                "redirect_uri": "https://chat.openai.com/aip/callback",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-restart",
                "resource": "https://example.com/mcp/nexus",
            },
            follow_redirects=False,
        )
        request_id = parse_qs(urlparse(authorize.headers["location"]).query)["request_id"][0]

        approval = client.post(
            "/oauth/consent",
            data={
                "request_id": request_id,
                "decision": "approve",
                "ssh_host": "127.0.0.1",
                "ssh_user": "root",
                "ssh_port": "22",
                "ssh_password": "",
            },
            follow_redirects=False,
        )
        code = parse_qs(urlparse(approval.headers["location"]).query)["code"][0]

        token_response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chat.openai.com/aip/callback",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "code_verifier": verifier,
                "resource": "https://example.com/mcp/nexus",
            },
        )
        assert token_response.status_code == 200
        token_payload = token_response.json()

    restarted_app = create_app(settings, enable_watchdog=False)
    with TestClient(restarted_app) as restarted_client:
        refresh_response = restarted_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": token_payload["refresh_token"],
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
            },
        )
        assert refresh_response.status_code == 200

        authenticated_post = restarted_client.post(
            "/mcp/nexus",
            json={},
            headers={"Authorization": f"Bearer {token_payload['access_token']}"},
        )
        assert authenticated_post.status_code != 401
