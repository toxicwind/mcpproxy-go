"""Browser-facing landing page for the MCP HTTP entrypoint."""

from __future__ import annotations

from html import escape
from importlib import metadata

from starlette.responses import HTMLResponse

from mcp_nexus.config import Settings

LANDING_CSS = """
:root {
  color-scheme: light;
  --bg: #f4f7f1;
  --paper: rgba(255, 255, 255, 0.88);
  --paper-strong: #ffffff;
  --text: #132033;
  --muted: #58687d;
  --line: rgba(19, 32, 51, 0.1);
  --blue: #0f6cbd;
  --blue-deep: #0c4b82;
  --blue-soft: rgba(15, 108, 189, 0.12);
  --gold-soft: rgba(227, 167, 51, 0.14);
  --shadow: 0 28px 80px rgba(19, 32, 51, 0.12);
  --radius-xl: 30px;
  --radius-lg: 20px;
  --radius-md: 14px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(198, 224, 255, 0.85), transparent 28rem),
    radial-gradient(circle at bottom right, rgba(255, 225, 181, 0.52), transparent 26rem),
    linear-gradient(180deg, #f8faf6 0%, var(--bg) 100%);
  color: var(--text);
  font-family: "SF Pro Display", "Segoe UI", "Helvetica Neue", sans-serif;
}
.page {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 36px 0 56px;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1.18fr) minmax(320px, 0.82fr);
  gap: 22px;
}
.panel {
  background: var(--paper);
  backdrop-filter: blur(18px);
  border: 1px solid var(--line);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow);
}
.panel-main {
  padding: 34px;
}
.panel-side {
  padding: 24px;
  display: grid;
  gap: 16px;
}
.eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid rgba(19, 32, 51, 0.08);
  background: rgba(255, 255, 255, 0.75);
  color: var(--blue-deep);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.orb {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: linear-gradient(135deg, #0f6cbd 0%, #86bdec 100%);
}
h1 {
  margin: 18px 0 12px;
  font-size: clamp(38px, 6vw, 58px);
  line-height: 0.95;
  letter-spacing: -0.045em;
}
.lede {
  margin: 0;
  max-width: 44rem;
  color: var(--muted);
  font-size: 17px;
  line-height: 1.65;
}
.cta-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 24px;
}
.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 14px 18px;
  border-radius: 999px;
  text-decoration: none;
  font-size: 14px;
  font-weight: 700;
}
.button-primary {
  background: linear-gradient(135deg, var(--blue) 0%, var(--blue-deep) 100%);
  color: #fff;
  box-shadow: 0 16px 30px rgba(15, 108, 189, 0.24);
}
.button-secondary {
  background: #fff;
  color: var(--text);
  border: 1px solid rgba(19, 32, 51, 0.12);
}
.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin-top: 26px;
}
.card, .side-card {
  background: var(--paper-strong);
  border: 1px solid rgba(19, 32, 51, 0.08);
  border-radius: var(--radius-lg);
  padding: 16px 18px;
}
.label {
  display: block;
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.value, code, pre {
  font-family: "SFMono-Regular", "SF Mono", Consolas, "Liberation Mono", monospace;
}
.value {
  margin: 0;
  font-size: 13px;
  line-height: 1.65;
  word-break: break-word;
}
.side-card {
  display: grid;
  gap: 12px;
}
.steps {
  display: grid;
  gap: 12px;
}
.step {
  display: grid;
  grid-template-columns: 32px minmax(0, 1fr);
  gap: 12px;
}
.step-index {
  width: 32px;
  height: 32px;
  border-radius: 999px;
  display: inline-grid;
  place-items: center;
  background: var(--blue-soft);
  color: var(--blue-deep);
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
  line-height: 1.58;
}
.callout {
  padding: 14px 16px;
  border-radius: var(--radius-md);
  background: var(--gold-soft);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
}
.caption {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.6;
}
.footer {
  margin-top: 22px;
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  color: var(--muted);
  font-size: 13px;
}
.footer a {
  color: var(--blue-deep);
  text-decoration: none;
  font-weight: 700;
}
@media (max-width: 940px) {
  .hero, .grid {
    grid-template-columns: 1fr;
  }
  .panel-main, .panel-side {
    padding: 24px;
  }
}
"""


def _project_urls() -> dict[str, str]:
    urls: dict[str, str] = {}
    try:
        entries = metadata.metadata("mcp-nexus").get_all("Project-URL") or []
    except metadata.PackageNotFoundError:
        return urls
    for entry in entries:
        if "," not in entry:
            continue
        name, url = entry.split(",", 1)
        urls[name.strip().lower()] = url.strip()
    return urls


def _manual_client_secret(settings: Settings) -> str:
    if settings.oauth_client_secret:
        return settings.oauth_client_secret
    return "Configure NEXUS_OAUTH_CLIENT_SECRET on your server"


def render_mcp_entry_page(settings: Settings) -> HTMLResponse:
    project_urls = _project_urls()
    github_url = project_urls.get("repository", "https://github.com/farukalpay/mcp-nexus")
    docs_url = project_urls.get("documentation", github_url)
    public_base_url = settings.public_base_url.rstrip("/") if settings.public_base_url else ""
    mcp_url = f"{public_base_url}{settings.mcp_path}" if public_base_url else settings.mcp_path
    metadata_url = (
        f"{settings.oauth_issuer_url.rstrip('/')}/.well-known/oauth-authorization-server"
        if settings.oauth_issuer_url
        else "/.well-known/oauth-authorization-server"
    )
    protected_resource_url = (
        f"{settings.oauth_issuer_url.rstrip('/')}/.well-known/oauth-protected-resource"
        f"{settings.mcp_path}"
        if settings.oauth_issuer_url
        else f"/.well-known/oauth-protected-resource{settings.mcp_path}"
    )
    auth_url = f"{settings.oauth_issuer_url.rstrip('/')}/authorize" if settings.oauth_issuer_url else "/authorize"
    token_url = f"{settings.oauth_issuer_url.rstrip('/')}/token" if settings.oauth_issuer_url else "/token"
    register_url = f"{settings.oauth_issuer_url.rstrip('/')}/register" if settings.oauth_issuer_url else "/register"
    authorization_server_base = settings.oauth_issuer_url or public_base_url or "/"

    manual_client_id = settings.oauth_client_id or "Configure NEXUS_OAUTH_CLIENT_ID on your server"
    manual_client_secret = _manual_client_secret(settings)

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>MCP Nexus Connect</title>
    <style>{LANDING_CSS}</style>
  </head>
  <body>
    <main class="page">
      <section class="hero">
        <section class="panel panel-main">
          <span class="eyebrow"><span class="orb"></span> MCP Nexus Hosted Gateway</span>
          <h1>Connect your AI to a real server.</h1>
          <p class="lede">
            This endpoint is the live MCP surface for terminal, files, git, databases, deploy,
            monitoring, process control, and debugging. Human visitors get a guided connect page.
            MCP clients use the exact same URL as their entrypoint.
          </p>
          <div class="cta-row">
            <a class="button button-primary" href="{escape(docs_url)}">Read The Docs</a>
            <a class="button button-secondary" href="{escape(github_url)}">View On GitHub</a>
          </div>
          <div class="grid">
            <div class="card">
              <span class="label">MCP URL</span>
              <p class="value">{escape(mcp_url)}</p>
            </div>
            <div class="card">
              <span class="label">OAuth Discovery</span>
              <p class="value">{escape(metadata_url)}</p>
            </div>
            <div class="card">
              <span class="label">Protected Resource Metadata</span>
              <p class="value">{escape(protected_resource_url)}</p>
            </div>
            <div class="card">
              <span class="label">GitHub</span>
              <p class="value">{escape(github_url)}</p>
            </div>
          </div>
          <p class="caption">
            If your client supports discovery, you usually only need the MCP URL. Manual OAuth
            fields are here for clients that still ask for them.
          </p>
          <div class="footer">
            <span>ChatGPT, Claude, and custom MCP clients</span>
            <a href="{escape(metadata_url)}">OAuth metadata</a>
            <a href="{escape(protected_resource_url)}">Protected resource</a>
          </div>
        </section>
        <aside class="panel panel-side">
          <div class="side-card">
            <span class="label">Quick Connect</span>
            <div class="steps">
              <div class="step">
                <span class="step-index">1</span>
                <div>
                  <p class="step-title">Add the MCP URL</p>
                  <p class="step-copy">Use <code>{escape(mcp_url)}</code> as the MCP server URL.</p>
                </div>
              </div>
              <div class="step">
                <span class="step-index">2</span>
                <div>
                  <p class="step-title">If manual OAuth appears</p>
                  <p class="step-copy">Use the Auth URL, Token URL, Client ID, and Client Secret shown below.</p>
                </div>
              </div>
              <div class="step">
                <span class="step-index">3</span>
                <div>
                  <p class="step-title">On the consent screen</p>
                  <p class="step-copy">Enter your own server host, SSH user, SSH port, and SSH password.</p>
                </div>
              </div>
            </div>
          </div>
          <div class="side-card">
            <span class="label">Manual OAuth Values</span>
            <p class="value">MCP URL: {escape(mcp_url)}</p>
            <p class="value">Auth URL: {escape(auth_url)}</p>
            <p class="value">Token URL: {escape(token_url)}</p>
            <p class="value">Registration URL: {escape(register_url)}</p>
            <p class="value">Authorization Server Base: {escape(authorization_server_base)}</p>
            <p class="value">Resource: {escape(mcp_url)}</p>
            <p class="value">Client ID: {escape(manual_client_id)}</p>
            <p class="value">Client Secret: {escape(manual_client_secret)}</p>
            <p class="value">Scope: nexus</p>
          </div>
          <div class="side-card">
            <span class="label">Important</span>
            <div class="callout">
              Your OAuth client ID and secret are not your server credentials. Your server IP, SSH
              user, SSH port, and SSH password belong only on the MCP Nexus consent form.
            </div>
          </div>
        </aside>
      </section>
    </main>
  </body>
</html>
"""
    return HTMLResponse(html)
