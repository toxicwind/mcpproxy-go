"""MCP Nexus server — registers tools, registry state, and HTTP diagnostics."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import time
from http import HTTPStatus
from typing import Any, cast
from uuid import uuid4

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, BaseModel, ValidationError

from mcp_nexus.auth.oauth import GatewayOAuthProvider
from mcp_nexus.config import Settings
from mcp_nexus.gateway import GatewayManager
from mcp_nexus.intelligence.memory import MemoryEngine
from mcp_nexus.landing import render_mcp_entry_page
from mcp_nexus.middleware.audit import AuditEntry, AuditLog
from mcp_nexus.middleware.rate_limit import RateLimiter
from mcp_nexus.registry import ToolRegistry, apply_registry_metadata, build_tool_registry
from mcp_nexus.results import ArtifactManager, ToolExecutionContext
from mcp_nexus.state import EncryptedStateStore
from mcp_nexus.telemetry import (
    RequestTrace,
    SessionStateStore,
    get_request_trace,
    reset_request_trace,
    set_request_trace,
)
from mcp_nexus.tool_resolution import enable_tool_name_resolution
from mcp_nexus.transport.ssh import SSHPool

logger = logging.getLogger(__name__)

# Global state shared across tools and routes.
_gateway: GatewayManager | None = None
_settings: Settings | None = None
_memory: MemoryEngine | None = None
_audit: AuditLog | None = None
_rate_limiter: RateLimiter | None = None
_tool_registry: ToolRegistry | None = None
_session_store: SessionStateStore | None = None
_artifacts: ArtifactManager | None = None
_server_instance_id: str | None = None
_oauth_provider: GatewayOAuthProvider | None = None
_state_store: EncryptedStateStore | None = None

# Per-request pool context (set by request middleware).
_current_pool: contextvars.ContextVar[SSHPool | None] = contextvars.ContextVar("_current_pool", default=None)


def _transport_security_settings(settings: Settings) -> TransportSecuritySettings | None:
    allowed_hosts = settings.transport_allowed_hosts
    allowed_origins = settings.transport_allowed_origins
    if not allowed_hosts and not allowed_origins:
        return None
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def get_pool() -> SSHPool:
    """Get the SSH pool for the current request."""
    pool = _current_pool.get()
    if pool is not None:
        return pool

    assert _gateway is not None, "Gateway not initialized — call create_server() first"
    return _gateway.get_owner_pool()


def set_current_pool(pool: SSHPool):
    """Set the SSH pool for the current request context."""
    return _current_pool.set(pool)


def reset_current_pool(token):
    _current_pool.reset(token)


def get_gateway() -> GatewayManager:
    assert _gateway is not None, "Gateway not initialized"
    return _gateway


def get_settings() -> Settings:
    assert _settings is not None, "Settings not initialized"
    return _settings


def get_memory() -> MemoryEngine | None:
    return _memory


def get_audit() -> AuditLog | None:
    return _audit


def get_registry() -> ToolRegistry:
    assert _tool_registry is not None, "Tool registry not initialized"
    return _tool_registry


def get_session_store() -> SessionStateStore:
    assert _session_store is not None, "Session store not initialized"
    return _session_store


def get_artifacts() -> ArtifactManager:
    assert _artifacts is not None, "Artifact manager not initialized"
    return _artifacts


def get_server_instance_id() -> str:
    assert _server_instance_id is not None, "Server instance not initialized"
    return _server_instance_id


def get_oauth_provider() -> GatewayOAuthProvider | None:
    return _oauth_provider


def tool_context(tool_name: str) -> ToolExecutionContext:
    """Return stable execution context for a tool invocation."""
    registry = get_registry()
    binding = registry.tool(tool_name)
    trace = get_request_trace()
    backend = get_pool().backend_metadata()
    return ToolExecutionContext(
        tool_name=tool_name,
        stable_name=binding.stable_name if binding else tool_name,
        resolved_runtime_id=binding.resolved_runtime_id if binding else tool_name,
        server_instance_id=registry.server_instance_id,
        registry_version=registry.registry_version,
        request_id=trace.request_id if trace else "offline",
        trace_id=trace.trace_id if trace else "offline",
        session_id=trace.session_id if trace else None,
        backend_kind=str(backend["backend_kind"]),
        backend_instance=str(backend["backend_instance"]),
    )


def create_server(settings: Settings | None = None) -> FastMCP:
    """Create and configure the MCP server with all tools."""
    global _gateway, _settings, _memory, _audit, _rate_limiter, _tool_registry, _session_store, _artifacts
    global _server_instance_id, _oauth_provider, _state_store

    if settings is None:
        settings = Settings()
    _settings = settings
    _server_instance_id = uuid4().hex
    _state_store = EncryptedStateStore(
        settings.expanded_path(settings.state_root),
        settings.state_encryption_key,
    )
    _gateway = GatewayManager(settings, state_store=_state_store)
    _oauth_provider = None

    audit_log_file = settings.audit_log_file or f"{settings.expanded_path(settings.data_dir)}/audit.jsonl"
    _audit = AuditLog(max_entries=5000, log_file=audit_log_file)
    _rate_limiter = RateLimiter(rpm=settings.rate_limit_rpm, burst=settings.rate_limit_burst)
    _session_store = SessionStateStore()
    _artifacts = ArtifactManager(settings.expanded_path(settings.artifact_root))

    if settings.intelligence_enabled:
        _memory = MemoryEngine(data_dir=settings.data_dir)
        _memory.open()
        logger.info("Intelligence engine enabled — data at %s", settings.data_dir)

    auth_settings = None
    if settings.oauth_ready:
        issuer_url = AnyHttpUrl(settings.oauth_issuer_url)
        resource_server_url = AnyHttpUrl(settings.oauth_resource_server_url)
        service_documentation_url = (
            AnyHttpUrl(settings.oauth_service_documentation_url) if settings.oauth_service_documentation_url else None
        )
        _oauth_provider = GatewayOAuthProvider(settings, _gateway, state_store=_state_store)
        auth_settings = AuthSettings(
            issuer_url=issuer_url,
            service_documentation_url=service_documentation_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=settings.oauth_valid_scopes,
                default_scopes=settings.oauth_default_scopes or settings.oauth_required_scopes,
            ),
            required_scopes=settings.oauth_required_scopes,
            resource_server_url=resource_server_url,
        )

    mcp = FastMCP(
        "nexus",
        instructions=(
            "MCP Nexus provides remote server management with explicit registry metadata and session diagnostics. "
            "Use tools to inspect files, execute commands, query databases, manage services, and deploy code. "
            "Registry metadata includes stable tool bindings, server instance id, and registry version. "
            "Prefer db_profiles and db_use to select database backends without exposing secrets in tool arguments. "
            "Use web_retrieve for end-to-end webpage retrieval when the goal is to actually recover accessible "
            "content through bounded escalation, including automatic visual capture and a single grounded click "
            "when one clear target is present. "
            "Use http_fetch for direct HTTP retrieval or access diagnostics instead of ad hoc curl or Python scraping "
            "when you need to understand redirects, blocking, or challenge pages. "
            "Use web_page_diagnose when a webpage is blocked and you want a single tool call to combine "
            "HTTP evidence, host runtime discovery, browser escalation, and grounded visual follow-up without "
            "provisioning new runtimes. "
            "Use browser_bootstrap to install a Chromium-family runtime on the host when browser escalation is needed "
            "but no supported runtime is available yet. "
            "Use browser_fetch when a Chromium-family runtime is available and you need headless DOM retrieval; "
            "when the DOM-only step still leaves the page blocked, it can return bounded visual follow-up "
            "artifacts and grounded interaction targets in the same result. "
            "If browser_screenshot or browser_coordinate_click are not callable on the current caller-exported "
            "surface, continue through browser_fetch by providing manual_click_x/manual_click_y for a single "
            "deliberate coordinate click instead of stopping. "
            "Use browser_screenshot only when the current callable surface explicitly exposes it and you need a "
            "visual capture of a challenge page; it returns a raw screenshot plus a coordinate-grid overlay "
            "artifact and grounded interaction targets for follow-up actions. "
            "Use browser_coordinate_click only when the current callable surface explicitly exposes it and only "
            "for a deliberate single coordinate click in viewport pixels after a grounded visual plan exists; "
            "it is not a generic retry loop. "
            "browser_fetch is a read-only DOM-capture path unless its structured response explicitly says "
            "click_supported=true; when it returns interaction_capability or surface_summary, report what DOM "
            "controls or visual elements were observed and explain whether interaction was actually possible "
            "instead of implying that a click or CAPTCHA solve happened. "
            "When webpage content matters and no browser runtime is available yet, prefer web_retrieve with "
            "allow_bootstrap=true over manually chaining http_fetch, browser_runtime_status, browser_bootstrap, "
            "and browser_fetch. "
            "When http_fetch or web_page_diagnose classifies a page as challenge_page, forbidden, "
            "rate_limited, content_gated, or authentication_required, do not retry the same origin with "
            "alternate headers, cookies, query parameters, AMP/mobile variants, or shell scraping; "
            "either use browser_fetch once if retry_guidance recommends it, use browser_bootstrap first if the "
            "runtime is missing, continue to browser_screenshot when the structured continuation says visual review "
            "is still available, or stop and report blocked access only after the browser-aware continuation is "
            "actually exhausted. "
            "When a network tool returns continuation.state=invoke_tool with a recommended next_step, call that tool "
            "immediately and treat the current result as incomplete workflow state, not as a final obstacle report. "
            "When continuation or handoff metadata says callable_surface_confirmed=false, do not jump directly to "
            "browser_screenshot, browser_coordinate_click, or nexus_tool_registry speculatively; prefer "
            "browser_fetch or web_retrieve for page work, and prefer http_fetch against the control-plane "
            "registry endpoint for surface verification. "
            "When a structured next_step or recommended_tool is http_fetch with alternate_tool, treat that as a "
            "surface-verification gate and do not skip ahead to the alternate tool. "
            "If browser_screenshot or web_retrieve/web_page_diagnose returns grounded interaction targets or a "
            "browser_coordinate_click continuation, use that evidence instead of stopping at the DOM-only "
            "browser result. "
            "If web_page_diagnose is unavailable or client-side tool policy rejects it, fall back to "
            "http_fetch and keep following its runtime-aware retry_guidance and recommendations until the "
            "browser escalation path is exhausted. "
            "nexus_tool_catalog describes the active server catalog, not the caller's current exported callable "
            "surface. nexus_tool_registry describes the active server registry snapshot, which can still be "
            "broader than the caller's visible tool surface. "
            "If a specialized workflow fails and the next valid tool is unclear, call nexus_tool_handoff with "
            "the current_tool and outcome to get the next registry-aware specialized tool sequence instead of "
            "guessing. "
            "If a tool call appears missing, stale, or returns resource-not-found style transport errors, "
            "use nexus_tool_registry to inspect the active server registry snapshot; if that tool is itself absent "
            "or the caller's surface looks narrower, use http_fetch on /tool-registry or "
            "/.well-known/nexus-tool-registry and report a tool-surface mismatch instead of substituting generic "
            "shell or Python tools. "
            "If the connector export itself disappears, use the server control-plane registry endpoints "
            "(/tool-registry or /.well-known/nexus-tool-registry) to verify the active server registry snapshot "
            "instead of "
            "searching for hidden URIs. "
            "Generic terminal tools may reject ad hoc webpage retrieval with SPECIALIZED_TOOL_REQUIRED; "
            "follow the redirect metadata and switch to the recommended network tool "
            "instead of retrying shell or Python fetches. "
            "Use execute_script for multi-step shell workflows instead of long quoted one-liners. "
            "Use db_client_status or db_client_bootstrap before Python-based database work "
            "when driver availability is unclear. "
            "When using execute_python, execute_python_file, or execute_script, reference already-authorized "
            "resources instead of embedding raw passwords or long-lived tokens into code. "
            "Prefer db_export_csv with output_path plus tabular_dataset_profile or train_tabular_classifier "
            "for data workflows instead of long inline shell or Python payloads."
        ),
        host=settings.host,
        port=settings.port,
        streamable_http_path=settings.mcp_path,
        auth=auth_settings,
        auth_server_provider=_oauth_provider,
        transport_security=_transport_security_settings(settings),
    )

    from mcp_nexus.tools import (
        analysis,
        database,
        debug,
        deploy,
        filesystem,
        git,
        intelligence,
        logs,
        monitor,
        network,
        packages,
        process,
        terminal,
    )

    filesystem.register(mcp)
    terminal.register(mcp)
    analysis.register(mcp)
    git.register(mcp)
    process.register(mcp)
    database.register(mcp)
    monitor.register(mcp)
    deploy.register(mcp)
    network.register(mcp)
    debug.register(mcp)
    packages.register(mcp)
    intelligence.register(mcp)
    logs.register(mcp)
    enable_tool_name_resolution(mcp)

    _tool_registry = build_tool_registry(
        mcp,
        server_instance_id=_server_instance_id,
        alias_base=settings.tool_alias_base,
    )
    apply_registry_metadata(mcp, _tool_registry)
    _register_registry_resources(mcp)
    _wrap_tools_with_tracking(mcp)

    logger.info(
        "MCP Nexus initialized — target=%s:%d mode=%s registry=%s server_instance=%s",
        settings.ssh_host,
        settings.ssh_port,
        "local" if settings.is_localhost else "ssh",
        _tool_registry.registry_version,
        _tool_registry.server_instance_id,
    )
    return mcp


def _register_registry_resources(mcp: FastMCP):
    """Expose inspectable registry/session resources through MCP resources."""

    @mcp.resource("nexus://tool-registry", name="tool_registry", description="Current Nexus tool registry snapshot")
    async def tool_registry_resource() -> str:
        return json.dumps(get_registry().to_dict(), indent=2)

    @mcp.resource("nexus://version", name="version", description="Server version and binding metadata")
    async def version_resource() -> str:
        from mcp_nexus import __version__

        registry = get_registry()
        settings = get_settings()
        return json.dumps(
            {
                "name": "mcp-nexus",
                "version": __version__,
                "server_instance_id": registry.server_instance_id,
                "registry_version": registry.registry_version,
                "bind": {
                    "host": settings.host,
                    "port": settings.port,
                    "mcp_path": settings.mcp_path,
                },
                "transport": "streamable-http",
            },
            indent=2,
        )

    @mcp.resource("nexus://session/{session_id}", name="session", description="Session-scoped Nexus state snapshot")
    async def session_resource(session_id: str) -> str:
        state = get_session_store().get_session(session_id)
        return json.dumps(
            {
                "session_id": session_id,
                "state": state,
                "active": session_id in _active_session_ids(cast(Any, getattr(mcp, "_session_manager", None))),
            },
            indent=2,
        )


def _result_payload(result: Any) -> dict[str, Any] | None:
    if isinstance(result, BaseModel):
        return cast(dict[str, Any], result.model_dump(exclude_none=True))
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _wrap_tools_with_tracking(mcp: FastMCP):
    """Inject audit logging and intelligence tracking into every tool call."""
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return

    for name, tool in list(manager._tools.items()):
        if name.startswith("nexus_"):
            continue
        original_fn = tool.fn

        async def tracked_fn(*args, _orig=original_fn, _name=name, **kwargs) -> Any:
            start = time.monotonic()
            success = True
            error_msg = None
            audit_metadata = None
            trace = get_request_trace()
            try:
                result = await _orig(*args, **kwargs)
                payload = _result_payload(result)
                if isinstance(payload, dict):
                    audit_metadata = {
                        key: payload[key]
                        for key in (
                            "usage",
                            "resource_usage",
                            "profile",
                            "error_code",
                            "error_stage",
                            "request_id",
                            "trace_id",
                            "session_id",
                            "backend_kind",
                            "backend_instance",
                            "server_instance_id",
                            "registry_version",
                        )
                        if key in payload
                    } or None
                return result
            except Exception as exc:
                success = False
                error_msg = str(exc)
                raise
            finally:
                duration = (time.monotonic() - start) * 1000
                session_id = trace.session_id if trace else None
                if _audit:
                    _audit.record(
                        AuditEntry(
                            timestamp=time.time(),
                            tool=_name,
                            client_id=(trace.session_id if trace and trace.session_id else "default"),
                            args=kwargs,
                            success=success,
                            duration_ms=duration,
                            error=error_msg,
                            metadata=audit_metadata,
                            request_id=trace.request_id if trace else None,
                            trace_id=trace.trace_id if trace else None,
                            session_id=session_id,
                            backend_kind=tool_context(_name).backend_kind,
                            backend_instance=tool_context(_name).backend_instance,
                            registry_version=get_registry().registry_version,
                            server_instance_id=get_registry().server_instance_id,
                        )
                    )

                get_session_store().note_tool_result(session_id, _name, success, error_message=error_msg)

                if _memory:
                    try:
                        await _memory.record(
                            _name,
                            kwargs,
                            success,
                            duration,
                            result_payload=payload if isinstance(payload, dict) else None,
                            error_message=error_msg,
                            client_session_id=session_id,
                        )
                    except Exception:
                        pass

        tool.fn = tracked_fn


def _protected_resource_metadata_enabled(mcp_server: FastMCP) -> bool:
    auth = getattr(mcp_server.settings, "auth", None)
    return bool(auth and getattr(auth, "resource_server_url", None))


def _normalize_tool_alias_base(alias_base: str) -> str:
    normalized = "/" + str(alias_base or "").strip("/")
    return normalized if normalized != "//" else "/"


def _extract_bearer_token_value(auth_header: str) -> str:
    value = auth_header.strip()
    if not value.lower().startswith("bearer "):
        return ""
    return value.split(None, 1)[1].strip() if " " in value else ""


def _coerce_tool_alias_arguments(payload: Any) -> dict[str, Any]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    if "arguments" in payload:
        arguments = payload.get("arguments")
        if arguments is None:
            return {}
        if not isinstance(arguments, dict):
            raise ValueError("`arguments` must be a JSON object.")
        return dict(arguments)
    if "params" in payload:
        params = payload.get("params")
        if params is None:
            return {}
        if not isinstance(params, dict):
            raise ValueError("`params` must be a JSON object.")
        nested = params.get("arguments")
        if nested is None:
            return dict(params)
        if not isinstance(nested, dict):
            raise ValueError("`params.arguments` must be a JSON object.")
        return dict(nested)
    return dict(payload)


def _json_compatible_result(value: Any) -> Any:
    payload = _result_payload(value)
    if payload is not None:
        return payload
    if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
        return value
    return str(value)


def _control_plane_paths(settings: Settings) -> dict[str, Any]:
    tool_alias_base = _normalize_tool_alias_base(settings.tool_alias_base)
    tool_alias_paths = (
        []
        if tool_alias_base == "/"
        else [
            f"{tool_alias_base}/{{tool_name}}",
            f"{tool_alias_base}/runtime/{{server_instance_id}}/{{tool_name}}",
        ]
    )
    return {
        "mcp": {
            "primary": settings.mcp_path,
            "aliases": list(settings.mcp_path_aliases),
        },
        "health": ["/health", "/health/nexus"],
        "ready": ["/ready", "/ready/nexus"],
        "version": ["/version", "/version/nexus"],
        "info": ["/info", "/info/nexus"],
        "tool_registry": [
            "/tool-registry",
            "/tool-registry/nexus",
            "/.well-known/nexus-tool-registry",
        ],
        "tool_alias": tool_alias_paths,
        "session_template": "/session/{session_id}",
    }


def _absolute_control_plane_url(base_url: str, path: str) -> str:
    normalized_base = base_url.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{normalized_base}{normalized_path}"


def control_plane_reference() -> dict[str, Any]:
    """Return stable control-plane URLs plus scope metadata for surface verification."""
    try:
        settings = get_settings()
    except AssertionError:
        settings = Settings()
    control_plane = _control_plane_paths(settings)
    public_base_url = settings.public_base_url.rstrip("/")
    active_server_instance_id = None
    try:
        active_server_instance_id = get_registry().server_instance_id
    except AssertionError:
        active_server_instance_id = None

    def _paths_for(key: str) -> list[str]:
        value = control_plane.get(key)
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, dict):
            primary = str(value.get("primary") or "")
            aliases = [str(item) for item in value.get("aliases", [])]
            return [item for item in [primary, *aliases] if item]
        if isinstance(value, str):
            return [value]
        return []

    def _urls_for(paths: list[str]) -> list[str]:
        if not public_base_url:
            return []
        return [_absolute_control_plane_url(public_base_url, path) for path in paths]

    tool_registry_paths = _paths_for("tool_registry")
    tool_registry_urls = _urls_for(tool_registry_paths)
    preferred_tool_registry_path = next(
        (path for path in tool_registry_paths if path.endswith("/.well-known/nexus-tool-registry")),
        tool_registry_paths[0] if tool_registry_paths else None,
    )
    preferred_tool_registry_url = next(
        (url for url in tool_registry_urls if url.endswith("/.well-known/nexus-tool-registry")),
        tool_registry_urls[0] if tool_registry_urls else None,
    )
    tool_alias_paths = _paths_for("tool_alias")
    tool_alias_urls = _urls_for(tool_alias_paths)
    stable_tool_alias_path = next((path for path in tool_alias_paths if "/runtime/" not in path), None)
    stable_tool_alias_url = next((url for url in tool_alias_urls if "/runtime/" not in url), None)
    runtime_tool_alias_path_template = next((path for path in tool_alias_paths if "/runtime/" in path), None)
    runtime_tool_alias_url_template = next((url for url in tool_alias_urls if "/runtime/" in url), None)

    runtime_tool_alias_path = runtime_tool_alias_path_template
    runtime_tool_alias_url = runtime_tool_alias_url_template
    if active_server_instance_id:
        if runtime_tool_alias_path:
            runtime_tool_alias_path = runtime_tool_alias_path.replace(
                "{server_instance_id}",
                active_server_instance_id,
            )
        if runtime_tool_alias_url:
            runtime_tool_alias_url = runtime_tool_alias_url.replace(
                "{server_instance_id}",
                active_server_instance_id,
            )

    return {
        "surface_scope": "server_registry_snapshot",
        "callable_surface_confirmed": False,
        "availability_note": (
            "This describes the active server registry snapshot. The current client-exported callable surface "
            "may still be narrower."
        ),
        "tool_registry_paths": tool_registry_paths,
        "tool_registry_urls": tool_registry_urls,
        "preferred_tool_registry_path": preferred_tool_registry_path,
        "preferred_tool_registry_url": preferred_tool_registry_url,
        "tool_registry_http_fetch_call_template": (
            {
                "url": preferred_tool_registry_url,
                "method": "GET",
                "headers": {},
                "timeout_sec": 20,
                "browser_profile": False,
                "max_body_chars": 12000,
            }
            if preferred_tool_registry_url
            else None
        ),
        "tool_alias_paths": tool_alias_paths,
        "tool_alias_urls": tool_alias_urls,
        "stable_tool_alias_path_template": stable_tool_alias_path,
        "stable_tool_alias_url_template": stable_tool_alias_url,
        "runtime_tool_alias_path_template": runtime_tool_alias_path_template,
        "runtime_tool_alias_url_template": runtime_tool_alias_url_template,
        "runtime_tool_alias_path": runtime_tool_alias_path,
        "runtime_tool_alias_url": runtime_tool_alias_url,
        "tool_alias_http_call_template": (
            {
                "url": stable_tool_alias_url,
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"arguments": {}},
            }
            if stable_tool_alias_url
            else None
        ),
        "runtime_tool_alias_http_call_template": (
            {
                "url": runtime_tool_alias_url,
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"arguments": {}},
            }
            if runtime_tool_alias_url
            else None
        ),
        "info_paths": _paths_for("info"),
        "info_urls": _urls_for(_paths_for("info")),
    }


def _current_transport_metadata(mcp_server: FastMCP, settings: Settings) -> dict[str, Any]:
    trace = get_request_trace()
    auth_settings = getattr(mcp_server.settings, "auth", None)
    protected_resource_metadata_url = None
    authorization_server_metadata_url = None
    if auth_settings and auth_settings.resource_server_url:
        from mcp.server.auth.routes import build_resource_metadata_url

        protected_resource_metadata_url = str(build_resource_metadata_url(auth_settings.resource_server_url))
        authorization_server_metadata_url = (
            f"{str(auth_settings.issuer_url).rstrip('/')}/.well-known/oauth-authorization-server"
        )
    auth_metadata = {
        "enabled": bool(auth_settings),
        "issuer_url": str(auth_settings.issuer_url) if auth_settings else None,
        "resource_server_url": str(auth_settings.resource_server_url) if auth_settings else None,
        "required_scopes": list(auth_settings.required_scopes or []) if auth_settings else [],
        "authorization_server_metadata_url": authorization_server_metadata_url,
        "protected_resource_metadata_url": protected_resource_metadata_url,
        "consent_url": settings.oauth_consent_url if auth_settings else None,
        "legacy_token_endpoint": (
            f"{settings.oauth_issuer_url.rstrip('/')}/oauth/token"
            if auth_settings and settings.oauth_issuer_url
            else None
        ),
        "client_registration_enabled": bool(
            auth_settings
            and auth_settings.client_registration_options
            and auth_settings.client_registration_options.enabled
        ),
        "static_client_enabled": settings.oauth_static_client_enabled if auth_settings else False,
        "static_client_id": (
            settings.oauth_client_id if auth_settings and settings.oauth_static_client_enabled else None
        ),
        "static_client_redirect_uris": (
            list(settings.oauth_client_redirect_uris) if auth_settings and settings.oauth_static_client_enabled else []
        ),
    }
    return {
        "transport": trace.transport if trace else "streamable-http",
        "bind": {
            "host": settings.host,
            "port": settings.port,
            "mcp_path": settings.mcp_path,
            "mcp_path_aliases": settings.mcp_path_aliases,
        },
        "control_plane": _control_plane_paths(settings),
        "auth_mode": trace.auth_mode if trace else "none",
        "auth": auth_metadata,
        "forwarded_headers": trace.forwarded_headers if trace else {},
        "forwarded_headers_supported": settings.forwarded_headers,
        "protected_resource_metadata": _protected_resource_metadata_enabled(mcp_server),
    }


def _active_session_ids(session_manager: Any | None) -> set[str]:
    if session_manager is None:
        return set()
    server_instances = getattr(session_manager, "_server_instances", None)
    if not isinstance(server_instances, dict):
        return set()
    return set(server_instances.keys())


def _typed_session_error(session_id: str) -> dict[str, Any]:
    registry = get_registry()
    state = get_session_store().get_session(session_id)
    error_code = "SESSION_NOT_FOUND"
    message = "Session is unknown to this server instance."

    if state and state.get("status") == "closed":
        error_code = "SESSION_CLOSED"
        message = "Session existed earlier but its live runtime binding is no longer active."

    previous_registry_version = state.get("registry_version") if state else None
    if previous_registry_version and previous_registry_version != registry.registry_version:
        error_code = "REGISTRY_VERSION_CHANGED"
        message = (
            "tool disappeared because registry_version changed "
            f"from {previous_registry_version} to {registry.registry_version}"
        )

    return {
        "jsonrpc": "2.0",
        "id": "server-error",
        "error": {
            "code": -32600,
            "message": "Session not found",
            "data": {
                "ok": False,
                "error_code": error_code,
                "error_stage": "transport",
                "message": message,
                "session_id": session_id,
                "server_instance_id": registry.server_instance_id,
                "registry_version": registry.registry_version,
                "previous_registry_version": previous_registry_version,
                "session_state": state,
            },
        },
    }


def _drop_header_from_scope(scope: dict[str, Any], header_name: str) -> tuple[dict[str, Any], bool]:
    header_key = header_name.lower().encode("latin-1")
    raw_headers = scope.get("headers")
    if not isinstance(raw_headers, (list, tuple)):
        return scope, False

    filtered_headers: list[tuple[bytes, bytes]] = []
    removed = False
    for entry in raw_headers:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        key, value = entry
        if not isinstance(key, (bytes, bytearray)) or not isinstance(value, (bytes, bytearray)):
            continue
        key_bytes = bytes(key)
        value_bytes = bytes(value)
        if key_bytes.lower() == header_key:
            removed = True
            continue
        filtered_headers.append((key_bytes, value_bytes))

    if not removed:
        return scope, False

    updated_scope = dict(scope)
    updated_scope["headers"] = filtered_headers
    return updated_scope, True


def _is_mcp_request(path: str, settings: Settings) -> bool:
    normalized_path = path.rstrip("/") or "/"
    normalized_mcp_path = settings.mcp_path.rstrip("/") or "/"
    return normalized_path == normalized_mcp_path


def _resolve_mcp_path(path: str, settings: Settings) -> str:
    normalized_path = path.rstrip("/") or "/"
    for alias in settings.mcp_path_aliases:
        normalized_alias = alias.rstrip("/") or "/"
        if normalized_path == normalized_alias:
            return settings.mcp_path
    return path


def _is_browser_html_request(method: str, accept_header: str) -> bool:
    if method.upper() != "GET":
        return False
    accept = accept_header.lower()
    return "text/html" in accept and "application/json" not in accept


class NexusRequestContextMiddleware:
    """Inject request/session metadata and typed transport errors."""

    def __init__(self, app, *, settings: Settings, mcp_server: FastMCP):
        self.app = app
        self.settings = settings
        self.mcp_server = mcp_server

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.datastructures import Headers, MutableHeaders
        from starlette.responses import JSONResponse

        headers = Headers(scope=scope)
        resolved_scope = scope
        original_path = scope.get("path", "")
        path = _resolve_mcp_path(original_path, self.settings)
        if path != original_path:
            resolved_scope = dict(scope)
            resolved_scope["path"] = path
            resolved_scope["raw_path"] = path.encode()
        if _is_mcp_request(path, self.settings) and _is_browser_html_request(
            scope.get("method", "GET"),
            headers.get("accept", ""),
        ):
            response = render_mcp_entry_page(self.settings)
            await response(scope, receive, send)
            return
        request_id = headers.get("x-request-id") or uuid4().hex
        trace_id = headers.get("x-trace-id") or request_id
        session_id = headers.get("mcp-session-id")
        auth_header = headers.get("authorization", "")
        auth_mode = "bearer" if auth_header.lower().startswith("bearer ") else "none"
        forwarded_headers = {name: value for name in self.settings.forwarded_headers if (value := headers.get(name))}
        transport = "streamable-http" if _is_mcp_request(path, self.settings) else "http"
        stale_session_id: str | None = None

        pool_token = None
        if auth_mode == "bearer":
            token_value = auth_header.split(None, 1)[1].strip() if " " in auth_header else ""
            pool = get_gateway().get_pool_for_token(token_value) if token_value else None
            if pool is not None:
                pool_token = set_current_pool(pool)
                auth_mode = "gateway-token"
            else:
                auth_mode = "invalid-bearer"

        active_session_ids = _active_session_ids(getattr(self.mcp_server, "_session_manager", None))
        if _is_mcp_request(path, self.settings) and session_id and session_id not in active_session_ids:
            recovered_scope, stripped = _drop_header_from_scope(resolved_scope, "mcp-session-id")
            if stripped:
                stale_session_id = session_id
                session_id = None
                resolved_scope = recovered_scope
                logger.info(
                    "Recovered stale MCP session binding by clearing mcp-session-id and continuing request: %s",
                    stale_session_id,
                )
            else:
                response = JSONResponse(_typed_session_error(session_id), status_code=HTTPStatus.NOT_FOUND)
                await response(scope, receive, send)
                if pool_token is not None:
                    reset_current_pool(pool_token)
                return

        trace_token = set_request_trace(
            RequestTrace(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                transport=transport,
                auth_mode=auth_mode,
                forwarded_headers=forwarded_headers,
            )
        )

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_session_id = response_headers.get("mcp-session-id") or session_id
                if _is_mcp_request(path, self.settings) and response_session_id:
                    get_session_store().touch(
                        response_session_id,
                        request_id=request_id,
                        trace_id=trace_id,
                        transport=transport,
                        registry_version=get_registry().registry_version,
                        server_instance_id=get_registry().server_instance_id,
                    )
                response_headers["x-request-id"] = request_id
                response_headers["x-trace-id"] = trace_id
                response_headers["x-nexus-server-instance-id"] = get_registry().server_instance_id
                response_headers["x-nexus-registry-version"] = get_registry().registry_version
                if stale_session_id:
                    response_headers["x-nexus-session-recovery"] = "stale-session-id-ignored"
                    response_headers["x-nexus-stale-session-id"] = stale_session_id
                    if response_session_id and response_session_id != stale_session_id:
                        response_headers["x-nexus-recovered-session-id"] = response_session_id
            await send(message)

        try:
            await self.app(resolved_scope, receive, send_wrapper)
        finally:
            get_session_store().sync_active(
                _active_session_ids(getattr(self.mcp_server, "_session_manager", None)),
                registry_version=get_registry().registry_version,
                server_instance_id=get_registry().server_instance_id,
            )
            reset_request_trace(trace_token)
            if pool_token is not None:
                reset_current_pool(pool_token)


def create_app(settings: Settings | None = None, enable_watchdog: bool = True):
    """Create a Starlette/ASGI app for streamable-http transport."""
    from starlette.responses import JSONResponse, RedirectResponse
    from starlette.routing import Route

    if settings is None:
        settings = Settings()

    mcp_server = create_server(settings)
    gateway = get_gateway()

    watchdog_task = None
    cleanup_task = None

    async def on_startup():
        nonlocal watchdog_task, cleanup_task
        if enable_watchdog and settings.watchdog_services:
            from mcp_nexus.health.watchdog import Watchdog

            wd = Watchdog(gateway.get_owner_pool(), settings)
            watchdog_task = asyncio.create_task(wd.run())
            logger.info("Watchdog started (interval=%ds)", settings.watchdog_interval)

        async def cleanup_loop():
            while True:
                await asyncio.sleep(300)
                await gateway.cleanup()

        cleanup_task = asyncio.create_task(cleanup_loop())

    async def on_shutdown():
        if watchdog_task:
            watchdog_task.cancel()
        if cleanup_task:
            cleanup_task.cancel()
        if _memory:
            _memory.close()
        await gateway.close_all()
        logger.info("MCP Nexus shut down")

    async def health_endpoint(request):
        pool_health = await gateway.get_owner_pool().health_check()
        status_code = 200 if pool_health["status"] == "healthy" else 503
        health = {
            **pool_health,
            "gateway": gateway.stats(),
            "registry": {
                "server_instance_id": get_registry().server_instance_id,
                "registry_version": get_registry().registry_version,
                "tool_count": len(get_registry().tools),
            },
            "transport": _current_transport_metadata(mcp_server, settings),
            "sessions": {
                "active": len(_active_session_ids(getattr(mcp_server, "_session_manager", None))),
                "tracked": len(get_session_store().list_sessions()),
            },
        }
        if _audit:
            health["audit"] = _audit.stats()
        return JSONResponse(health, status_code=status_code)

    async def ready_endpoint(request):
        pool_health = await gateway.get_owner_pool().health_check()
        ready = pool_health["status"] == "healthy" and get_registry().tool("execute_command") is not None
        return JSONResponse(
            {
                "ready": ready,
                "checks": {
                    "gateway": pool_health["status"],
                    "registry": "ready" if get_registry().tools else "missing",
                },
                "server_instance_id": get_registry().server_instance_id,
                "registry_version": get_registry().registry_version,
            },
            status_code=200 if ready else 503,
        )

    async def version_endpoint(request):
        from mcp_nexus import __version__

        return JSONResponse(
            {
                "name": "mcp-nexus",
                "version": __version__,
                "server_instance_id": get_registry().server_instance_id,
                "registry_version": get_registry().registry_version,
                **_current_transport_metadata(mcp_server, settings),
            }
        )

    async def info_endpoint(request):
        from mcp_nexus import __version__

        return JSONResponse(
            {
                "name": "mcp-nexus",
                "version": __version__,
                "mode": "gateway",
                "gateway": gateway.stats(),
                "registry": {
                    "server_instance_id": get_registry().server_instance_id,
                    "registry_version": get_registry().registry_version,
                },
                **_current_transport_metadata(mcp_server, settings),
            }
        )

    async def tool_registry_endpoint(request):
        registry = get_registry()
        return JSONResponse(
            {
                **registry.to_dict(),
                "sessions": {
                    "active": len(_active_session_ids(getattr(mcp_server, "_session_manager", None))),
                },
            }
        )

    async def sessions_endpoint(request):
        return JSONResponse({"sessions": get_session_store().list_sessions()})

    async def session_endpoint(request):
        session_id = request.path_params["session_id"]
        state = get_session_store().get_session(session_id)
        if state is None:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "SESSION_NOT_FOUND",
                    "error_stage": "lookup",
                    "session_id": session_id,
                    "server_instance_id": get_registry().server_instance_id,
                    "registry_version": get_registry().registry_version,
                },
                status_code=404,
            )
        return JSONResponse(
            {
                "session": state,
                "active": session_id in _active_session_ids(getattr(mcp_server, "_session_manager", None)),
            }
        )

    async def token_endpoint(request):
        if request.method != "POST":
            return JSONResponse({"error": "method_not_allowed"}, status_code=405)

        content_type = request.headers.get("content-type", "")
        if "json" in content_type:
            body = await request.json()
        else:
            body_bytes = await request.body()
            from urllib.parse import parse_qs

            parsed = parse_qs(body_bytes.decode())
            body = {k: v[0] for k, v in parsed.items()}

        grant_type = body.get("grant_type", "client_credentials")
        if grant_type != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        client_id = body.get("client_id", "")
        client_secret = body.get("client_secret", "")
        ssh_user = body.get("ssh_user", "root")
        ssh_port = int(body.get("ssh_port", 22))

        if not client_id:
            return JSONResponse({"error": "client_id (server IP) is required"}, status_code=400)

        token = await gateway.authenticate(client_id, client_secret, ssh_user, ssh_port)
        if token is None:
            return JSONResponse(
                {
                    "error": "invalid_client",
                    "message": "SSH authentication failed. Check your server IP, username, and password.",
                },
                status_code=401,
            )

        binding = gateway.get_binding(token.binding_id)
        if binding is None:
            return JSONResponse({"error": "binding_unavailable"}, status_code=500)
        return JSONResponse(token.response_payload(binding))

    async def oauth_consent_get_endpoint(request):
        provider = get_oauth_provider()
        if provider is None:
            return JSONResponse({"error": "oauth_not_enabled"}, status_code=404)

        request_id = request.query_params.get("request_id", "")
        return provider.render_consent_page(request_id)

    async def oauth_consent_post_endpoint(request):
        provider = get_oauth_provider()
        if provider is None:
            return JSONResponse({"error": "oauth_not_enabled"}, status_code=404)

        form = await request.form()
        request_id = str(form.get("request_id", ""))
        decision = str(form.get("decision", "deny"))
        ssh_host = str(form.get("ssh_host", settings.ssh_host)).strip()
        ssh_user = str(form.get("ssh_user", settings.ssh_user or "root")).strip() or "root"
        ssh_password = str(form.get("ssh_password", ""))
        ssh_port_raw = str(form.get("ssh_port", settings.ssh_port or 22)).strip()
        try:
            ssh_port = int(ssh_port_raw or settings.ssh_port or 22)
        except ValueError:
            return provider.render_consent_page(request_id, error_message="SSH port must be a valid integer.")

        try:
            redirect_url = await provider.complete_authorization(
                request_id,
                decision=decision,
                ssh_host=ssh_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_password=ssh_password,
            )
        except KeyError:
            return provider.render_consent_page(
                request_id,
                error_message="This authorization request expired. Retry Connect from ChatGPT.",
            )
        except ValueError as exc:
            return provider.render_consent_page(request_id, error_message=str(exc))

        return RedirectResponse(url=redirect_url, status_code=302, headers={"Cache-Control": "no-store"})

    tool_alias_base = _normalize_tool_alias_base(settings.tool_alias_base)
    tool_alias_auth_required = bool(getattr(mcp_server.settings, "auth", None))

    def _tool_alias_auth_error(*, error_code: str, message: str, status_code: int = 401) -> JSONResponse:
        registry = get_registry()
        return JSONResponse(
            {
                "ok": False,
                "error_code": error_code,
                "error_stage": "authorization",
                "message": message,
                "server_instance_id": registry.server_instance_id,
                "registry_version": registry.registry_version,
            },
            status_code=status_code,
        )

    async def _tool_alias_invoke(request, *, runtime_scoped: bool) -> JSONResponse:
        if tool_alias_auth_required:
            token_value = _extract_bearer_token_value(request.headers.get("authorization", ""))
            if not token_value:
                return _tool_alias_auth_error(
                    error_code="AUTH_REQUIRED",
                    message="Bearer token is required for tool-alias invocation.",
                    status_code=401,
                )
            if gateway.verify_access_token(token_value) is None:
                return _tool_alias_auth_error(
                    error_code="INVALID_TOKEN",
                    message="Bearer token is invalid or expired for tool-alias invocation.",
                    status_code=401,
                )

        registry = get_registry()
        if runtime_scoped:
            requested_server_instance_id = str(request.path_params.get("server_instance_id", "") or "")
            if requested_server_instance_id != registry.server_instance_id:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "SERVER_INSTANCE_MISMATCH",
                        "error_stage": "routing",
                        "message": (
                            "Runtime tool alias is scoped to a different server instance. "
                            "Refresh registry metadata and retry."
                        ),
                        "requested_server_instance_id": requested_server_instance_id,
                        "server_instance_id": registry.server_instance_id,
                        "registry_version": registry.registry_version,
                    },
                    status_code=409,
                )

        manager = getattr(mcp_server, "_tool_manager", None)
        if manager is None:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "TOOL_MANAGER_UNAVAILABLE",
                    "error_stage": "routing",
                    "message": "Tool manager is not initialized.",
                    "server_instance_id": registry.server_instance_id,
                    "registry_version": registry.registry_version,
                },
                status_code=503,
            )

        tool_name = str(request.path_params.get("tool_name", "") or "").strip()
        resolved_tool = manager.get_tool(tool_name)
        if resolved_tool is None:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "TOOL_NOT_FOUND",
                    "error_stage": "routing",
                    "message": "Tool alias does not resolve to a registered tool.",
                    "tool_name": tool_name,
                    "server_instance_id": registry.server_instance_id,
                    "registry_version": registry.registry_version,
                },
                status_code=404,
            )

        body_payload: Any | None = None
        if request.method.upper() != "GET":
            raw_body = await request.body()
            if raw_body:
                try:
                    body_payload = json.loads(raw_body.decode())
                except json.JSONDecodeError:
                    return JSONResponse(
                        {
                            "ok": False,
                            "error_code": "INVALID_JSON",
                            "error_stage": "input_validation",
                            "message": "Tool alias request body must be valid JSON.",
                            "server_instance_id": registry.server_instance_id,
                            "registry_version": registry.registry_version,
                        },
                        status_code=400,
                    )

        try:
            if request.method.upper() == "GET":
                arguments = dict(request.query_params)
            else:
                arguments = _coerce_tool_alias_arguments(body_payload)
        except ValueError as exc:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "INVALID_ARGUMENTS",
                    "error_stage": "input_validation",
                    "message": str(exc),
                    "server_instance_id": registry.server_instance_id,
                    "registry_version": registry.registry_version,
                },
                status_code=400,
            )

        if request.query_params and request.method.upper() != "GET":
            arguments = {**arguments, **dict(request.query_params)}

        try:
            raw_result = await manager.call_tool(resolved_tool.name, arguments)
        except (TypeError, ValidationError, ValueError) as exc:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "INVALID_ARGUMENTS",
                    "error_stage": "input_validation",
                    "message": str(exc),
                    "tool_name": resolved_tool.name,
                    "server_instance_id": registry.server_instance_id,
                    "registry_version": registry.registry_version,
                },
                status_code=400,
            )
        except Exception as exc:
            logger.exception("Tool alias invocation failed for %s", resolved_tool.name)
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "TOOL_EXECUTION_FAILED",
                    "error_stage": "execution",
                    "message": str(exc),
                    "tool_name": resolved_tool.name,
                    "server_instance_id": registry.server_instance_id,
                    "registry_version": registry.registry_version,
                },
                status_code=500,
            )

        binding = registry.tool(resolved_tool.name)
        return JSONResponse(
            {
                "ok": True,
                "tool": {
                    "name": resolved_tool.name,
                    "stable_path": binding.stable_path if binding else None,
                    "runtime_path": binding.runtime_path if binding else None,
                    "resolved_runtime_id": binding.resolved_runtime_id if binding else None,
                },
                "server_instance_id": registry.server_instance_id,
                "registry_version": registry.registry_version,
                "result": _json_compatible_result(raw_result),
            }
        )

    async def tool_alias_endpoint(request):
        return await _tool_alias_invoke(request, runtime_scoped=False)

    async def runtime_tool_alias_endpoint(request):
        return await _tool_alias_invoke(request, runtime_scoped=True)

    custom_routes = [
        Route("/health", health_endpoint, methods=["GET"]),
        Route("/health/nexus", health_endpoint, methods=["GET"]),
        Route("/ready", ready_endpoint, methods=["GET"]),
        Route("/ready/nexus", ready_endpoint, methods=["GET"]),
        Route("/version", version_endpoint, methods=["GET"]),
        Route("/version/nexus", version_endpoint, methods=["GET"]),
        Route("/info", info_endpoint, methods=["GET"]),
        Route("/info/nexus", info_endpoint, methods=["GET"]),
        Route("/tool-registry", tool_registry_endpoint, methods=["GET"]),
        Route("/tool-registry/nexus", tool_registry_endpoint, methods=["GET"]),
        Route("/.well-known/nexus-tool-registry", tool_registry_endpoint, methods=["GET"]),
        Route("/sessions", sessions_endpoint, methods=["GET"]),
        Route("/session/{session_id}", session_endpoint, methods=["GET"]),
        Route("/oauth/token", token_endpoint, methods=["POST"]),
        Route(settings.oauth_consent_path, oauth_consent_get_endpoint, methods=["GET"]),
        Route(settings.oauth_consent_path, oauth_consent_post_endpoint, methods=["POST"]),
    ]
    if tool_alias_base != "/":
        custom_routes.extend(
            [
                Route(f"{tool_alias_base}/{{tool_name}}", tool_alias_endpoint, methods=["GET", "POST"]),
                Route(
                    f"{tool_alias_base}/runtime/{{server_instance_id}}/{{tool_name}}",
                    runtime_tool_alias_endpoint,
                    methods=["GET", "POST"],
                ),
            ]
        )

    setattr(
        mcp_server,
        "_custom_starlette_routes",
        custom_routes,
    )

    app = mcp_server.streamable_http_app()
    app.add_middleware(NexusRequestContextMiddleware, settings=settings, mcp_server=mcp_server)

    existing_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(inner_app):
        async with existing_lifespan(inner_app):
            await on_startup()
            try:
                yield
            finally:
                await on_shutdown()

    app.router.lifespan_context = lifespan

    return app
