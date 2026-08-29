"""Configuration management with environment variable support."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from dotenv import load_dotenv

# Load .env from project root (walk up from this file)
_root = Path(__file__).resolve().parent.parent
for _candidate in [_root / ".env", Path.cwd() / ".env"]:
    if _candidate.exists():
        load_dotenv(_candidate)
        break


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int = 0) -> int:
    v = os.getenv(key)
    return int(v) if v else default


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key, "").lower()
    return v in ("1", "true", "yes") if v else default


def _env_bool_or_none(key: str) -> bool | None:
    v = os.getenv(key)
    if v is None or not v.strip():
        return None
    return v.lower() in ("1", "true", "yes")


def _env_list(key: str, default: str = "") -> list[str]:
    v = os.getenv(key, default)
    return [s.strip() for s in v.split(",") if s.strip()] if v else []


def _join_url(base: str, path: str) -> str:
    normalized_base = base.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"
    if not normalized_base:
        return ""
    return f"{normalized_base}{normalized_path}"


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
WILDCARD_BIND_HOSTS = {"0.0.0.0", "::"}


def _host_is_loopback(host: str) -> bool:
    return host.strip().lower() in LOOPBACK_HOSTS


def _append_unique(values: list[str], candidate: str) -> None:
    if candidate and candidate not in values:
        values.append(candidate)


def _host_literal(host: str) -> str:
    candidate = host.strip().lower()
    if ":" in candidate and not candidate.startswith("["):
        return f"[{candidate}]"
    return candidate


def _origin_components(value: str) -> tuple[list[str], list[str]]:
    candidate = value.strip()
    if not candidate:
        return [], []

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return [], []

    host = _host_literal(parsed.hostname)
    hosts = [host, f"{host}:*"]
    origins = [f"{parsed.scheme.lower()}://{host}", f"{parsed.scheme.lower()}://{host}:*"]
    if parsed.port is not None:
        _append_unique(hosts, f"{host}:{parsed.port}")
        _append_unique(origins, f"{parsed.scheme.lower()}://{host}:{parsed.port}")
    return hosts, origins


def _detect_container_runtime() -> bool:
    override = _env_bool_or_none("NEXUS_RUNNING_IN_CONTAINER")
    if override is not None:
        return override

    if Path("/.dockerenv").exists():
        return True

    for candidate in ("/proc/1/cgroup", "/proc/self/cgroup"):
        try:
            content = Path(candidate).read_text(encoding="utf-8")
        except OSError:
            continue
        lowered = content.lower()
        if any(marker in lowered for marker in ("docker", "containerd", "kubepods", "podman")):
            return True
    return False


def _resolve_container_host_bridge() -> str:
    explicit = _env("NEXUS_HOST_BRIDGE_ADDRESS", "").strip()
    if explicit:
        return explicit

    try:
        socket.gethostbyname("host.docker.internal")
    except OSError:
        pass
    else:
        return "host.docker.internal"

    route_path = Path("/proc/net/route")
    if not route_path.exists():
        return ""

    try:
        lines = route_path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return ""

    for line in lines:
        columns = line.split()
        if len(columns) < 3 or columns[1] != "00000000":
            continue
        gateway_hex = columns[2]
        try:
            return socket.inet_ntoa(bytes.fromhex(gateway_hex)[::-1])
        except (OSError, ValueError):
            continue
    return ""


@dataclass(frozen=True)
class DatabaseProfile:
    """Named PostgreSQL connection profile resolved from the environment."""

    name: str
    host: str
    port: int
    database: str
    user: str
    password: str
    connect_host: str = ""
    sslmode: str = ""

    def with_connect_host(self, connect_host: str) -> DatabaseProfile:
        return DatabaseProfile(
            name=self.name,
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password,
            connect_host=connect_host,
            sslmode=self.sslmode,
        )

    @property
    def dsn(self) -> str:
        target_host = self.connect_host or self.host
        encoded_user = quote(self.user, safe="")
        encoded_password = quote(self.password, safe="")
        encoded_database = quote(self.database, safe="")
        base = f"postgresql://{encoded_user}:{encoded_password}@{target_host}:{self.port}/{encoded_database}"
        if self.sslmode:
            return f"{base}?{urlencode({'sslmode': self.sslmode})}"
        return base

    def redacted(self) -> dict[str, object]:
        return {
            "name": self.name,
            "host": self.host,
            "connect_host": (self.connect_host or None) if self.connect_host != self.host else None,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "sslmode": self.sslmode or None,
            "has_password": bool(self.password),
        }


def parse_postgres_dsn(
    value: str,
    *,
    name: str,
    resolve_connect_host: Callable[[str], str] | None = None,
) -> DatabaseProfile:
    candidate = value.strip()
    if not candidate:
        raise ValueError("Database URI is required.")

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"postgresql", "postgres"}:
        raise ValueError("Database URI must start with postgresql:// or postgres://.")
    if parsed.fragment:
        raise ValueError(
            "Database URI must not contain a fragment. If the password contains '#', URL-encode it as %23."
        )
    if not parsed.hostname:
        raise ValueError("Database URI must include a hostname.")
    if parsed.username is None:
        raise ValueError("Database URI must include a username.")

    database_name = parsed.path.lstrip("/")
    if not database_name:
        raise ValueError("Database URI must include a database name.")

    query = parse_qs(parsed.query, keep_blank_values=True)
    host = parsed.hostname
    return DatabaseProfile(
        name=name,
        host=host,
        port=parsed.port or 5432,
        database=unquote(database_name),
        user=unquote(parsed.username),
        password=unquote(parsed.password or ""),
        connect_host=resolve_connect_host(host) if resolve_connect_host else host,
        sslmode=query.get("sslmode", [""])[-1],
    )


@dataclass
class Settings:
    """All configuration, populated from environment variables."""

    # SSH
    ssh_host: str = field(default_factory=lambda: _env("NEXUS_SSH_HOST", "127.0.0.1"))
    ssh_port: int = field(default_factory=lambda: _env_int("NEXUS_SSH_PORT", 22))
    ssh_user: str = field(default_factory=lambda: _env("NEXUS_SSH_USER", "root"))
    ssh_password: str = field(default_factory=lambda: _env("NEXUS_SSH_PASSWORD", ""))
    ssh_key_path: str = field(default_factory=lambda: _env("NEXUS_SSH_KEY_PATH", ""))
    ssh_pool_size: int = field(default_factory=lambda: _env_int("NEXUS_SSH_POOL_SIZE", 4))

    # OAuth2
    oauth_client_id: str = field(default_factory=lambda: _env("NEXUS_OAUTH_CLIENT_ID", "nexus-default"))
    oauth_client_secret: str = field(default_factory=lambda: _env("NEXUS_OAUTH_CLIENT_SECRET", ""))
    oauth_client_redirect_uris: list[str] = field(
        default_factory=lambda: _env_list("NEXUS_OAUTH_CLIENT_REDIRECT_URIS", "")
    )
    oauth_issuer: str = field(default_factory=lambda: _env("NEXUS_OAUTH_ISSUER", ""))
    oauth_enabled: bool = field(default_factory=lambda: _env_bool("NEXUS_OAUTH_ENABLED", True))
    public_base_url: str = field(default_factory=lambda: _env("NEXUS_PUBLIC_BASE_URL", ""))
    runtime_container: bool = field(default_factory=_detect_container_runtime)
    allow_container_localhost_exec: bool = field(
        default_factory=lambda: _env_bool("NEXUS_ALLOW_CONTAINER_LOCALHOST_EXEC", False)
    )
    host_bridge_address: str = field(default_factory=_resolve_container_host_bridge)
    state_root: str = field(default_factory=lambda: _env("NEXUS_STATE_ROOT", "~/.mcp-nexus/state"))
    state_encryption_key: str = field(default_factory=lambda: _env("NEXUS_STATE_ENCRYPTION_KEY", ""))
    oauth_scopes: list[str] = field(default_factory=lambda: _env_list("NEXUS_OAUTH_SCOPES", "nexus"))
    oauth_default_scopes: list[str] = field(default_factory=lambda: _env_list("NEXUS_OAUTH_DEFAULT_SCOPES", "nexus"))
    oauth_token_ttl_seconds: int = field(default_factory=lambda: _env_int("NEXUS_OAUTH_TOKEN_TTL_SECONDS", 3600))
    oauth_refresh_ttl_seconds: int = field(
        default_factory=lambda: _env_int("NEXUS_OAUTH_REFRESH_TTL_SECONDS", 2592000)
    )
    oauth_authorization_code_ttl_seconds: int = field(
        default_factory=lambda: _env_int("NEXUS_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS", 600)
    )
    oauth_consent_path: str = field(default_factory=lambda: _env("NEXUS_OAUTH_CONSENT_PATH", "/oauth/consent"))

    # Server
    host: str = field(default_factory=lambda: _env("NEXUS_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("NEXUS_PORT", 8766))
    mcp_path: str = field(default_factory=lambda: _env("NEXUS_MCP_PATH", "/mcp"))
    mcp_path_aliases: list[str] = field(default_factory=lambda: _env_list("NEXUS_MCP_PATH_ALIASES", ""))
    log_level: str = field(default_factory=lambda: _env("NEXUS_LOG_LEVEL", "info"))
    max_concurrent: int = field(default_factory=lambda: _env_int("NEXUS_MAX_CONCURRENT", 8))
    workers: int = field(default_factory=lambda: _env_int("NEXUS_WORKERS", 2))
    default_cwd: str = field(default_factory=lambda: _env("NEXUS_DEFAULT_CWD", ""))
    default_command_timeout: int = field(default_factory=lambda: _env_int("NEXUS_COMMAND_TIMEOUT", 60))
    output_limit_bytes: int = field(default_factory=lambda: _env_int("NEXUS_OUTPUT_LIMIT_BYTES", 50000))
    error_limit_bytes: int = field(default_factory=lambda: _env_int("NEXUS_ERROR_LIMIT_BYTES", 10000))
    output_preview_bytes: int = field(default_factory=lambda: _env_int("NEXUS_OUTPUT_PREVIEW_BYTES", 4000))
    error_preview_bytes: int = field(default_factory=lambda: _env_int("NEXUS_ERROR_PREVIEW_BYTES", 2000))
    sandbox_root: str = field(default_factory=lambda: _env("NEXUS_SANDBOX_ROOT", "~/.mcp-nexus/sandboxes"))
    release_root: str = field(default_factory=lambda: _env("NEXUS_RELEASE_ROOT", "/opt/mcp-nexus/releases"))
    current_release_link: str = field(
        default_factory=lambda: _env("NEXUS_CURRENT_RELEASE_LINK", "/opt/mcp-nexus/current")
    )
    audit_log_file: str = field(default_factory=lambda: _env("NEXUS_AUDIT_LOG_FILE", ""))
    artifact_root: str = field(default_factory=lambda: _env("NEXUS_ARTIFACT_ROOT", "~/.mcp-nexus/artifacts"))
    job_root: str = field(default_factory=lambda: _env("NEXUS_JOB_ROOT", "/var/tmp/mcp-nexus/jobs"))
    tool_alias_base: str = field(default_factory=lambda: _env("NEXUS_TOOL_ALIAS_BASE", "/mcp-nexus"))
    analysis_thread_limit: int = field(default_factory=lambda: _env_int("NEXUS_ANALYSIS_THREAD_LIMIT", 1))
    forwarded_headers: list[str] = field(
        default_factory=lambda: _env_list(
            "NEXUS_FORWARDED_HEADERS",
            "forwarded,x-forwarded-for,x-forwarded-host,x-forwarded-port,x-forwarded-proto",
        )
    )

    # Database (optional)
    db_host: str = field(default_factory=lambda: _env("NEXUS_DB_HOST", ""))
    db_dsn_value: str = field(default_factory=lambda: _env("NEXUS_DB_DSN", ""))
    db_port: int = field(default_factory=lambda: _env_int("NEXUS_DB_PORT", 5432))
    db_name: str = field(default_factory=lambda: _env("NEXUS_DB_NAME", ""))
    db_user: str = field(default_factory=lambda: _env("NEXUS_DB_USER", ""))
    db_password: str = field(default_factory=lambda: _env("NEXUS_DB_PASSWORD", ""))
    db_sslmode: str = field(default_factory=lambda: _env("NEXUS_DB_SSLMODE", ""))
    db_default_profile: str = field(default_factory=lambda: _env("NEXUS_DB_DEFAULT_PROFILE", "default"))
    db_profiles_json: str = field(default_factory=lambda: _env("NEXUS_DB_PROFILES_JSON", ""))

    # Rate limiting
    rate_limit_rpm: int = field(default_factory=lambda: _env_int("NEXUS_RATE_LIMIT_RPM", 120))
    rate_limit_burst: int = field(default_factory=lambda: _env_int("NEXUS_RATE_LIMIT_BURST", 20))

    # Health & Recovery
    watchdog_interval: int = field(default_factory=lambda: _env_int("NEXUS_WATCHDOG_INTERVAL", 30))
    watchdog_services: list[str] = field(default_factory=lambda: _env_list("NEXUS_WATCHDOG_SERVICES", ""))
    max_restart_attempts: int = field(default_factory=lambda: _env_int("NEXUS_MAX_RESTART_ATTEMPTS", 10))
    restart_cooldown: int = field(default_factory=lambda: _env_int("NEXUS_RESTART_COOLDOWN", 120))

    # Intelligence
    intelligence_enabled: bool = field(default_factory=lambda: _env_bool("NEXUS_INTELLIGENCE", True))
    data_dir: str = field(default_factory=lambda: _env("NEXUS_DATA_DIR", "~/.mcp-nexus"))

    @property
    def is_localhost(self) -> bool:
        """Detect if the target host can be executed directly from this runtime."""
        return self.is_local_execution_host(self.ssh_host)

    @property
    def resolved_ssh_host(self) -> str:
        return self.resolve_connect_host(self.ssh_host)

    def is_local_execution_host(self, host: str) -> bool:
        candidate = host.strip()
        if not candidate:
            return False
        if self.runtime_container and not self.allow_container_localhost_exec:
            return False
        if _host_is_loopback(candidate):
            return True
        if self.runtime_container:
            return False
        try:
            local_ips = {addr[4][0] for info in socket.getaddrinfo(socket.gethostname(), None) for addr in [info]}
            local_ips.add("127.0.0.1")
            return candidate in local_ips
        except Exception:
            return False

    def resolve_connect_host(self, host: str) -> str:
        candidate = host.strip()
        if not candidate:
            return candidate
        if self.runtime_container and not self.allow_container_localhost_exec and _host_is_loopback(candidate):
            return self.host_bridge_address or candidate
        return candidate

    def resolve_database_connect_host(self, host: str, *, execution_backend: str) -> str:
        candidate = host.strip()
        if not candidate:
            return candidate
        if execution_backend == "local":
            return self.resolve_connect_host(candidate)
        return candidate

    def materialize_db_profile(self, profile: DatabaseProfile, *, execution_backend: str) -> DatabaseProfile:
        return profile.with_connect_host(
            self.resolve_database_connect_host(profile.host, execution_backend=execution_backend)
        )

    def resolve_requested_db_profile(
        self,
        *,
        profile_name: str = "",
        database: str = "",
        execution_backend: str = "",
    ) -> DatabaseProfile | None:
        if database.strip():
            profile = parse_postgres_dsn(database, name=profile_name.strip() or "adhoc")
        else:
            profile = self.resolve_db_profile(profile_name)
            if profile is None:
                return None
        if execution_backend:
            return self.materialize_db_profile(profile, execution_backend=execution_backend)
        return profile

    @property
    def db_dsn(self) -> str:
        profile = self.resolve_db_profile()
        return profile.dsn if profile else ""

    @property
    def oauth_issuer_url(self) -> str:
        issuer = self.oauth_issuer or self.public_base_url
        return issuer.rstrip("/")

    @property
    def oauth_resource_server_url(self) -> str:
        if not self.public_base_url:
            return ""
        return _join_url(self.public_base_url, self.mcp_path)

    @property
    def oauth_consent_url(self) -> str:
        return _join_url(self.oauth_issuer_url, self.oauth_consent_path)

    @property
    def oauth_service_documentation_url(self) -> str:
        if not self.public_base_url:
            return ""
        return _join_url(self.public_base_url, "/info/nexus")

    @property
    def oauth_valid_scopes(self) -> list[str]:
        return self.oauth_scopes or self.oauth_default_scopes or ["nexus"]

    @property
    def oauth_required_scopes(self) -> list[str]:
        return self.oauth_default_scopes or self.oauth_valid_scopes or ["nexus"]

    @property
    def oauth_ready(self) -> bool:
        return self.oauth_enabled and bool(self.oauth_issuer_url and self.oauth_resource_server_url)

    @property
    def oauth_static_client_enabled(self) -> bool:
        return bool(self.oauth_enabled and self.oauth_client_id and self.oauth_client_redirect_uris)

    @property
    def transport_allowed_hosts(self) -> list[str]:
        allowed: list[str] = []

        bind_host = self.host.strip().lower()
        if bind_host in {"127.0.0.1", "localhost", "::1"}:
            for candidate in ("127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*", "[::1]", "[::1]:*"):
                _append_unique(allowed, candidate)
        elif bind_host and bind_host not in WILDCARD_BIND_HOSTS:
            literal = _host_literal(bind_host)
            _append_unique(allowed, literal)
            _append_unique(allowed, f"{literal}:*")

        for value in (self.public_base_url, self.oauth_issuer):
            hosts, _ = _origin_components(value)
            for candidate in hosts:
                _append_unique(allowed, candidate)

        return allowed

    @property
    def transport_allowed_origins(self) -> list[str]:
        allowed: list[str] = []

        bind_host = self.host.strip().lower()
        if bind_host in {"127.0.0.1", "localhost", "::1"}:
            for candidate in ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"):
                _append_unique(allowed, candidate)

        for value in (self.public_base_url, self.oauth_issuer, *self.oauth_client_redirect_uris):
            _, origins = _origin_components(value)
            for candidate in origins:
                _append_unique(allowed, candidate)

        return allowed

    def expanded_path(self, value: str) -> str:
        return str(Path(value).expanduser()) if value else value

    def database_profiles(self) -> dict[str, DatabaseProfile]:
        profiles: dict[str, DatabaseProfile] = {}

        if self.db_profiles_json:
            raw_profiles = json.loads(self.db_profiles_json)
            if not isinstance(raw_profiles, dict):
                raise ValueError("NEXUS_DB_PROFILES_JSON must be a JSON object keyed by profile name")
            for name, payload in raw_profiles.items():
                if isinstance(payload, str):
                    profiles[name] = parse_postgres_dsn(
                        payload,
                        name=name,
                    )
                    continue
                if not isinstance(payload, dict):
                    raise ValueError(f"Database profile {name!r} must be a JSON object or PostgreSQL URI string")
                dsn_value = str(payload.get("dsn") or payload.get("uri") or payload.get("url") or "").strip()
                if dsn_value:
                    profiles[name] = parse_postgres_dsn(
                        dsn_value,
                        name=name,
                    )
                    continue
                host = str(payload.get("host", ""))
                profiles[name] = DatabaseProfile(
                    name=name,
                    host=host,
                    port=int(payload.get("port", 5432)),
                    database=str(payload.get("database") or payload.get("dbname") or payload.get("name") or ""),
                    user=str(payload.get("user", "")),
                    password=str(payload.get("password", "")),
                    connect_host=host,
                    sslmode=str(payload.get("sslmode", "")),
                )

        if self.db_dsn_value:
            legacy_name = self.db_default_profile or ("default" if not profiles else "legacy")
            profiles.setdefault(
                legacy_name,
                parse_postgres_dsn(
                    self.db_dsn_value,
                    name=legacy_name,
                ),
            )
        elif self.db_host:
            legacy_name = self.db_default_profile or ("default" if not profiles else "legacy")
            profiles.setdefault(
                legacy_name,
                DatabaseProfile(
                    name=legacy_name,
                    host=self.db_host,
                    port=self.db_port,
                    database=self.db_name,
                    user=self.db_user,
                    password=self.db_password,
                    connect_host=self.db_host,
                    sslmode=self.db_sslmode,
                ),
            )

        return {
            name: profile for name, profile in profiles.items() if profile.host and profile.database and profile.user
        }

    def resolve_db_profile(self, name: str = "") -> DatabaseProfile | None:
        profiles = self.database_profiles()
        if not profiles:
            return None
        if name:
            return profiles.get(name)
        if self.db_default_profile and self.db_default_profile in profiles:
            return profiles[self.db_default_profile]
        return next(iter(profiles.values()))
