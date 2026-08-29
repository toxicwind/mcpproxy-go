"""OAuth 2.1 provider for ChatGPT-compatible MCP connections."""

from __future__ import annotations

import html
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenVerifier,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.responses import HTMLResponse

from mcp_nexus.config import Settings
from mcp_nexus.gateway import GatewayAccessToken, GatewayBinding, GatewayManager
from mcp_nexus.state import EncryptedStateStore

logger = logging.getLogger(__name__)

CONSENT_CSS = """
:root {
  color-scheme: light;
  --bg: #f5f7f2;
  --panel: rgba(255, 255, 255, 0.9);
  --panel-strong: #ffffff;
  --border: rgba(15, 23, 42, 0.1);
  --text: #122033;
  --muted: #526174;
  --accent: #0f6cbd;
  --accent-strong: #0a4e89;
  --accent-soft: rgba(15, 108, 189, 0.12);
  --warn-bg: #fff1f2;
  --warn-text: #9f1239;
  --shadow: 0 32px 80px rgba(18, 32, 51, 0.12);
  --radius-xl: 28px;
  --radius-lg: 18px;
  --radius-md: 14px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  background:
    radial-gradient(circle at top left, rgba(215, 230, 251, 0.9), transparent 34rem),
    radial-gradient(circle at bottom right, rgba(255, 226, 192, 0.6), transparent 32rem),
    linear-gradient(180deg, #f8faf6 0%, var(--bg) 100%);
  font-family: "SF Pro Display", "Segoe UI", "Helvetica Neue", sans-serif;
}
.shell {
  width: min(1080px, calc(100% - 32px));
  margin: 0 auto;
  padding: 40px 0 56px;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(320px, 0.85fr);
  gap: 24px;
  align-items: stretch;
}
.panel {
  background: var(--panel);
  backdrop-filter: blur(16px);
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow);
}
.panel-main {
  padding: 32px;
}
.panel-side {
  padding: 24px;
  display: grid;
  gap: 18px;
}
.eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.72);
  border: 1px solid rgba(15, 23, 42, 0.08);
  color: var(--accent-strong);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: linear-gradient(135deg, #0f6cbd 0%, #6aa7dd 100%);
}
h1 {
  margin: 18px 0 12px;
  font-size: clamp(34px, 5vw, 52px);
  line-height: 0.96;
  letter-spacing: -0.04em;
}
.lede {
  margin: 0;
  color: var(--muted);
  font-size: 17px;
  line-height: 1.6;
}
.meta-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin: 24px 0 0;
}
.meta-card, .side-card {
  padding: 16px 18px;
  border-radius: var(--radius-lg);
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: var(--panel-strong);
}
.meta-label, .side-label {
  display: block;
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.meta-value, .codeish {
  margin: 0;
  font-family: "SFMono-Regular", "SF Mono", Consolas, "Liberation Mono", monospace;
  font-size: 13px;
  line-height: 1.6;
  word-break: break-word;
}
.steps {
  display: grid;
  gap: 12px;
}
.step {
  display: grid;
  grid-template-columns: 32px minmax(0, 1fr);
  gap: 12px;
  align-items: start;
}
.step-index {
  display: inline-grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent-strong);
  font-weight: 700;
}
.step-title {
  margin: 0 0 4px;
  font-size: 15px;
  font-weight: 700;
}
.step-copy {
  margin: 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.55;
}
.error {
  margin: 20px 0 0;
  padding: 14px 16px;
  border-radius: var(--radius-md);
  border: 1px solid rgba(159, 18, 57, 0.12);
  background: var(--warn-bg);
  color: var(--warn-text);
  font-size: 14px;
  line-height: 1.5;
}
form {
  margin-top: 28px;
  display: grid;
  gap: 16px;
}
.field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
label {
  display: grid;
  gap: 8px;
}
.field-span {
  grid-column: 1 / -1;
}
.label-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 14px;
  font-weight: 700;
}
.label-hint {
  color: var(--muted);
  font-size: 12px;
  font-weight: 500;
}
input {
  width: 100%;
  border: 1px solid rgba(15, 23, 42, 0.12);
  border-radius: var(--radius-md);
  background: rgba(255, 255, 255, 0.96);
  color: var(--text);
  padding: 14px 16px;
  font-size: 15px;
}
input:focus {
  outline: none;
  border-color: rgba(15, 108, 189, 0.45);
  box-shadow: 0 0 0 4px rgba(15, 108, 189, 0.12);
}
.actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 4px;
}
button {
  appearance: none;
  border: 0;
  border-radius: 999px;
  cursor: pointer;
  padding: 14px 20px;
  font-size: 14px;
  font-weight: 700;
}
.button-primary {
  background: linear-gradient(135deg, #0f6cbd 0%, #0a4e89 100%);
  color: white;
  box-shadow: 0 16px 30px rgba(15, 108, 189, 0.24);
}
.button-secondary {
  background: white;
  color: var(--text);
  border: 1px solid rgba(15, 23, 42, 0.12);
}
.trust, .footer-note {
  margin: 10px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.6;
}
@media (max-width: 920px) {
  .hero, .field-grid, .meta-grid {
    grid-template-columns: 1fr;
  }
  .panel-main, .panel-side {
    padding: 24px;
  }
}
"""


class GatewayAuthorizationCode(AuthorizationCode):
    binding_id: str
    ssh_host: str
    ssh_port: int
    ssh_user: str


class GatewayRefreshToken(RefreshToken):
    resource: str | None = None
    binding_id: str
    ssh_host: str
    ssh_port: int
    ssh_user: str


@dataclass
class AuthorizationRequestState:
    request_id: str
    client_id: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    code_challenge: str
    state: str | None
    scopes: list[str]
    resource: str | None
    created_at: float


class GatewayOAuthProvider(
    OAuthAuthorizationServerProvider[GatewayAuthorizationCode, GatewayRefreshToken, GatewayAccessToken],
    TokenVerifier,
):
    """OAuth provider that binds each ChatGPT connection to an SSH target."""

    def __init__(
        self,
        settings: Settings,
        gateway: GatewayManager,
        *,
        state_store: EncryptedStateStore | None = None,
    ):
        self._settings = settings
        self._gateway = gateway
        self._state_store = state_store
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._authorization_requests: dict[str, AuthorizationRequestState] = {}
        self._authorization_codes: dict[str, GatewayAuthorizationCode] = {}
        self._refresh_tokens: dict[str, GatewayRefreshToken] = {}
        self._restore_state()
        self._register_static_client()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        client_id = client_info.client_id
        if not client_id:
            raise ValueError("client_info.client_id must be set")
        if client_id in self._clients:
            raise ValueError(f"client_id {client_id!r} already exists")
        self._clients[client_id] = client_info
        self._persist_state()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        request_id = secrets.token_urlsafe(24)
        self._authorization_requests[request_id] = AuthorizationRequestState(
            request_id=request_id,
            client_id=client.client_id or "",
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            state=params.state,
            scopes=params.scopes or self._default_scopes_for_client(client),
            resource=params.resource or self._settings.oauth_resource_server_url or None,
            created_at=time.time(),
        )
        self._persist_state()
        return f"{self._settings.oauth_consent_url}?{urlencode({'request_id': request_id})}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> GatewayAuthorizationCode | None:
        self._prune_expired_state()
        code = self._authorization_codes.get(authorization_code)
        if code is None:
            return None
        if code.client_id != (client.client_id or ""):
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: GatewayAuthorizationCode,
    ) -> OAuthToken:
        self._authorization_codes.pop(authorization_code.code, None)
        binding = self._binding_from_code(authorization_code)
        access_token = await self._gateway.issue_access_token(
            binding,
            client_id=client.client_id or "",
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
            expires_in=self._settings.oauth_token_ttl_seconds,
        )
        refresh_token = self._create_refresh_token(
            client_id=client.client_id or "",
            scopes=authorization_code.scopes,
            binding=binding,
            resource=authorization_code.resource,
        )
        self._refresh_tokens[refresh_token.token] = refresh_token
        self._persist_state()
        return OAuthToken(
            access_token=access_token.access_token,
            expires_in=access_token.expires_in,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token.token,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> GatewayRefreshToken | None:
        self._prune_expired_state()
        token = self._refresh_tokens.get(refresh_token)
        if token is None:
            return None
        if token.client_id != (client.client_id or ""):
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: GatewayRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
        binding = self._binding_from_refresh_token(refresh_token)
        effective_scopes = scopes or refresh_token.scopes
        access_token = await self._gateway.issue_access_token(
            binding,
            client_id=client.client_id or "",
            scopes=effective_scopes,
            resource=refresh_token.resource,
            expires_in=self._settings.oauth_token_ttl_seconds,
        )
        rotated_refresh_token = self._create_refresh_token(
            client_id=client.client_id or "",
            scopes=effective_scopes,
            binding=binding,
            resource=refresh_token.resource,
        )
        self._refresh_tokens[rotated_refresh_token.token] = rotated_refresh_token
        self._persist_state()
        return OAuthToken(
            access_token=access_token.access_token,
            expires_in=access_token.expires_in,
            scope=" ".join(effective_scopes),
            refresh_token=rotated_refresh_token.token,
        )

    async def load_access_token(self, token: str) -> GatewayAccessToken | None:
        return self._gateway.verify_access_token(token)

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self.load_access_token(token)

    async def revoke_token(self, token: GatewayAccessToken | GatewayRefreshToken) -> None:
        if isinstance(token, GatewayRefreshToken):
            self._refresh_tokens.pop(token.token, None)
            self._persist_state()
            return
        self._gateway.revoke_access_token(token.token)

    def get_authorization_request(self, request_id: str) -> AuthorizationRequestState | None:
        self._prune_expired_state()
        return self._authorization_requests.get(request_id)

    async def complete_authorization(
        self,
        request_id: str,
        *,
        decision: str,
        ssh_host: str,
        ssh_user: str,
        ssh_port: int,
        ssh_password: str,
    ) -> str:
        self._prune_expired_state()
        request = self._authorization_requests.get(request_id)
        if request is None:
            raise KeyError(request_id)

        if decision != "approve":
            self._authorization_requests.pop(request_id, None)
            self._persist_state()
            return construct_redirect_uri(
                str(request.redirect_uri),
                error="access_denied",
                error_description="The authorization request was denied.",
                state=request.state,
            )

        binding = await self._gateway.bind_target(
            ssh_host,
            ssh_password,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
        )
        if binding is None:
            raise ValueError("SSH authentication failed")

        self._authorization_requests.pop(request_id, None)
        code = GatewayAuthorizationCode(
            code=secrets.token_urlsafe(32),
            scopes=request.scopes,
            expires_at=time.time() + self._settings.oauth_authorization_code_ttl_seconds,
            client_id=request.client_id,
            code_challenge=request.code_challenge,
            redirect_uri=request.redirect_uri,
            redirect_uri_provided_explicitly=request.redirect_uri_provided_explicitly,
            resource=request.resource,
            binding_id=binding.binding_id,
            ssh_host=binding.ssh_host,
            ssh_port=binding.ssh_port,
            ssh_user=binding.ssh_user,
        )
        self._authorization_codes[code.code] = code
        self._persist_state()
        return construct_redirect_uri(
            str(request.redirect_uri),
            code=code.code,
            state=request.state,
        )

    def render_consent_page(self, request_id: str, *, error_message: str = "") -> HTMLResponse:
        request = self.get_authorization_request(request_id)
        if request is None:
            return HTMLResponse(
                self._render_error_page(
                    "Authorization request expired",
                    "Retry Connect from ChatGPT so a fresh authorization request can be created.",
                ),
                status_code=410,
            )

        target_host = html.escape(self._settings.ssh_host or "127.0.0.1")
        target_user = html.escape(self._settings.ssh_user or "root")
        target_port = html.escape(str(self._settings.ssh_port or 22))
        resource = html.escape(request.resource or self._settings.oauth_resource_server_url)
        scopes = html.escape(" ".join(request.scopes) if request.scopes else "nexus")
        error_block = ""
        if error_message:
            error_block = f'<div class="error">{html.escape(error_message)}</div>'

        page = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>MCP Nexus Authorization</title>
    <style>{CONSENT_CSS}</style>
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <section class="panel panel-main">
          <span class="eyebrow"><span class="dot"></span> Lightcap Hosted Gateway</span>
          <h1>Authorize ChatGPT</h1>
          <p class="lede">
            Bind this ChatGPT connection to your own server. Enter the server host, SSH user,
            SSH port, and SSH password below. MCP Nexus uses them only to create the live backend
            binding for this connection.
          </p>
          {error_block}
          <div class="meta-grid">
            <div class="meta-card">
              <span class="meta-label">Requested Resource</span>
              <p class="meta-value">{resource}</p>
            </div>
            <div class="meta-card">
              <span class="meta-label">Granted Scopes</span>
              <p class="meta-value">{scopes}</p>
            </div>
          </div>
          <form method="post" action="{html.escape(self._settings.oauth_consent_path)}">
            <input type="hidden" name="request_id" value="{html.escape(request_id)}" />
            <div class="field-grid">
              <label class="field-span">
                <span class="label-title">
                  <span>Server host</span>
                  <span class="label-hint">public IP or DNS name</span>
                </span>
                <input name="ssh_host" value="{target_host}" placeholder="149.102.155.77" required />
              </label>
              <label>
                <span class="label-title">
                  <span>SSH user</span>
                  <span class="label-hint">usually root or deploy</span>
                </span>
                <input name="ssh_user" value="{target_user}" placeholder="root" required />
              </label>
              <label>
                <span class="label-title">
                  <span>SSH port</span>
                  <span class="label-hint">default 22</span>
                </span>
                <input name="ssh_port" value="{target_port}" type="number" min="1" max="65535" required />
              </label>
              <label class="field-span">
                <span class="label-title">
                  <span>SSH password</span>
                  <span class="label-hint">used to validate and bind this target</span>
                </span>
                <input
                  name="ssh_password"
                  type="password"
                  autocomplete="current-password"
                  placeholder="Enter the SSH password for this server"
                />
              </label>
            </div>
            <div class="actions">
              <button type="submit" name="decision" value="approve" class="button-primary">Connect Server</button>
              <button type="submit" name="decision" value="deny" class="button-secondary">Cancel</button>
            </div>
            <p class="trust">
              OAuth client ID and secret are not your server credentials. Your server IP, SSH user,
              SSH port, and SSH password belong only in this form.
            </p>
          </form>
          <p class="footer-note">
            After approval, ChatGPT receives an access token bound to this target and every MCP call
            routes through the matching backend pool.
          </p>
        </section>
        <aside class="panel panel-side">
          <div class="side-card">
            <span class="side-label">What You Will Enter</span>
            <div class="steps">
              <div class="step">
                <span class="step-index">1</span>
                <div>
                  <p class="step-title">Server host</p>
                  <p class="step-copy">The IP or hostname of the machine you want ChatGPT to manage.</p>
                </div>
              </div>
              <div class="step">
                <span class="step-index">2</span>
                <div>
                  <p class="step-title">SSH credentials</p>
                  <p class="step-copy">The SSH user, port, and password that prove access to that server.</p>
                </div>
              </div>
              <div class="step">
                <span class="step-index">3</span>
                <div>
                  <p class="step-title">Approve access</p>
                  <p class="step-copy">A token is minted for this exact target, not for a generic shared session.</p>
                </div>
              </div>
            </div>
          </div>
          <div class="side-card">
            <span class="side-label">Why MCP Nexus</span>
            <p class="step-copy">
              One connection unlocks terminal, files, git, deploy, database, monitoring, process
              control, debugging, and audit-aware automation on the same server.
            </p>
          </div>
          <div class="side-card">
            <span class="side-label">Manual OAuth Reminder</span>
            <p class="codeish">
              Auth URL: /authorize<br />
              Token URL: /token<br />
              Client ID / secret: OAuth values only<br />
              Server IP / SSH password: enter here, not in OAuth fields
            </p>
          </div>
        </aside>
      </section>
    </main>
  </body>
</html>
"""
        return HTMLResponse(page)

    def _create_refresh_token(
        self,
        *,
        client_id: str,
        scopes: list[str],
        binding: GatewayBinding,
        resource: str | None,
    ) -> GatewayRefreshToken:
        expires_at = int(time.time()) + self._settings.oauth_refresh_ttl_seconds
        return GatewayRefreshToken(
            token=secrets.token_urlsafe(48),
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            binding_id=binding.binding_id,
            ssh_host=binding.ssh_host,
            ssh_port=binding.ssh_port,
            ssh_user=binding.ssh_user,
        )

    def _default_scopes_for_client(self, client: OAuthClientInformationFull) -> list[str]:
        if client.scope:
            return client.scope.split()
        return self._settings.oauth_required_scopes

    def _restore_state(self) -> None:
        if self._state_store is None:
            return

        payload = self._state_store.read_section("oauth")

        clients_payload = payload.get("clients", {})
        if isinstance(clients_payload, dict):
            for client_id, client_payload in clients_payload.items():
                if isinstance(client_payload, dict):
                    self._clients[client_id] = OAuthClientInformationFull.model_validate(client_payload)

        requests_payload = payload.get("authorization_requests", {})
        if isinstance(requests_payload, dict):
            for request_id, request_payload in requests_payload.items():
                if not isinstance(request_payload, dict):
                    continue
                self._authorization_requests[request_id] = AuthorizationRequestState(
                    request_id=str(request_payload.get("request_id", request_id)),
                    client_id=str(request_payload.get("client_id", "")),
                    redirect_uri=cast(AnyUrl, str(request_payload.get("redirect_uri", ""))),
                    redirect_uri_provided_explicitly=bool(
                        request_payload.get("redirect_uri_provided_explicitly", False)
                    ),
                    code_challenge=str(request_payload.get("code_challenge", "")),
                    state=str(request_payload["state"]) if request_payload.get("state") is not None else None,
                    scopes=[str(item) for item in request_payload.get("scopes", [])],
                    resource=str(request_payload["resource"]) if request_payload.get("resource") is not None else None,
                    created_at=float(request_payload.get("created_at", time.time())),
                )

        codes_payload = payload.get("authorization_codes", {})
        if isinstance(codes_payload, dict):
            for code_id, code_payload in codes_payload.items():
                if not isinstance(code_payload, dict):
                    continue
                self._authorization_codes[code_id] = GatewayAuthorizationCode.model_validate(
                    {"code": code_id, **code_payload}
                )

        refresh_payload = payload.get("refresh_tokens", {})
        if isinstance(refresh_payload, dict):
            for token_id, token_payload in refresh_payload.items():
                if not isinstance(token_payload, dict):
                    continue
                self._refresh_tokens[token_id] = GatewayRefreshToken.model_validate(
                    {"token": token_id, **token_payload}
                )

        self._prune_expired_state()

    def _persist_state(self) -> None:
        if self._state_store is None:
            return

        clients_payload = {
            client_id: client.model_dump(mode="json", exclude_none=True)
            for client_id, client in self._clients.items()
        }
        payload = {
            "clients": clients_payload,
            "authorization_requests": {
                request_id: {
                    "request_id": request.request_id,
                    "client_id": request.client_id,
                    "redirect_uri": str(request.redirect_uri),
                    "redirect_uri_provided_explicitly": request.redirect_uri_provided_explicitly,
                    "code_challenge": request.code_challenge,
                    "state": request.state,
                    "scopes": list(request.scopes),
                    "resource": request.resource,
                    "created_at": request.created_at,
                }
                for request_id, request in self._authorization_requests.items()
            },
            "authorization_codes": {
                code_id: {
                    key: value
                    for key, value in code.model_dump(mode="json", exclude_none=True).items()
                    if key != "code"
                }
                for code_id, code in self._authorization_codes.items()
            },
            "refresh_tokens": {
                token_id: {
                    key: value
                    for key, value in token.model_dump(mode="json", exclude_none=True).items()
                    if key != "token"
                }
                for token_id, token in self._refresh_tokens.items()
            },
        }
        self._state_store.write_section("oauth", payload)

    def _register_static_client(self) -> None:
        if not self._settings.oauth_static_client_enabled:
            return

        auth_method: Literal["none", "client_secret_post"] = (
            "client_secret_post" if self._settings.oauth_client_secret else "none"
        )
        redirect_uris = [cast(AnyUrl, uri) for uri in self._settings.oauth_client_redirect_uris]
        client_info = OAuthClientInformationFull(
            client_id=self._settings.oauth_client_id,
            client_secret=self._settings.oauth_client_secret or None,
            client_id_issued_at=int(time.time()),
            client_secret_expires_at=None,
            redirect_uris=redirect_uris,
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method=auth_method,
            client_name="MCP Nexus Static Client",
            scope=" ".join(self._settings.oauth_default_scopes or self._settings.oauth_required_scopes),
        )
        self._clients[client_info.client_id or ""] = client_info
        self._persist_state()

    def _binding_from_code(self, code: GatewayAuthorizationCode) -> GatewayBinding:
        binding = self._gateway.get_binding(code.binding_id)
        if binding is None:
            raise ValueError("Authorization code references an expired target binding.")
        return binding

    def _binding_from_refresh_token(self, token: GatewayRefreshToken) -> GatewayBinding:
        binding = self._gateway.get_binding(token.binding_id)
        if binding is None:
            raise ValueError("Refresh token references an expired target binding.")
        return binding

    def _prune_expired_state(self) -> None:
        now = time.time()
        request_ttl = self._settings.oauth_authorization_code_ttl_seconds
        changed = False
        for request_id, request in list(self._authorization_requests.items()):
            if request.created_at + request_ttl < now:
                self._authorization_requests.pop(request_id, None)
                changed = True

        for code_id, code in list(self._authorization_codes.items()):
            if code.expires_at < now:
                self._authorization_codes.pop(code_id, None)
                changed = True

        for token_id, token in list(self._refresh_tokens.items()):
            if token.expires_at is not None and token.expires_at < now:
                self._refresh_tokens.pop(token_id, None)
                changed = True

        if changed:
            self._persist_state()

    def _render_error_page(self, title: str, message: str) -> str:
        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{html.escape(title)}</title>
    <style>{CONSENT_CSS}</style>
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <section class="panel panel-main">
          <span class="eyebrow"><span class="dot"></span> MCP Nexus</span>
          <h1>{html.escape(title)}</h1>
          <p class="lede">{html.escape(message)}</p>
        </section>
      </section>
    </main>
  </body>
</html>
"""
