"""Tests for configuration module."""

import json

import pytest

from mcp_nexus.config import Settings, parse_postgres_dsn


def test_default_settings():
    s = Settings()
    assert s.port == 8766 or isinstance(s.port, int)
    assert s.mcp_path.startswith("/mcp")
    assert s.ssh_port == 22 or isinstance(s.ssh_port, int)
    assert s.analysis_thread_limit >= 1


def test_localhost_detection():
    s = Settings()
    s.ssh_host = "127.0.0.1"
    assert s.is_localhost is True

    s.ssh_host = "localhost"
    assert s.is_localhost is True

    s.ssh_host = "8.8.8.8"
    assert s.is_localhost is False


def test_db_dsn():
    s = Settings()
    s.db_host = ""
    assert s.db_dsn == ""

    s.db_host = "localhost"
    s.db_port = 5432
    s.db_name = "test"
    s.db_user = "user"
    s.db_password = "pass"
    assert "postgresql://user:pass@localhost:5432/test" == s.db_dsn


def test_database_profiles_from_json(monkeypatch):
    monkeypatch.setenv(
        "NEXUS_DB_PROFILES_JSON",
        json.dumps(
            {
                "warehouse": {
                    "host": "db.internal",
                    "port": 5433,
                    "database": "analytics",
                    "user": "readonly",
                    "password": "secret",
                }
            }
        ),
    )
    monkeypatch.setenv("NEXUS_DB_DEFAULT_PROFILE", "warehouse")

    settings = Settings()
    profile = settings.resolve_db_profile()
    assert profile is not None
    assert profile.name == "warehouse"
    assert profile.host == "db.internal"
    assert profile.database == "analytics"


def test_database_profiles_legacy_fallback(monkeypatch):
    monkeypatch.delenv("NEXUS_DB_PROFILES_JSON", raising=False)
    monkeypatch.setenv("NEXUS_DB_HOST", "localhost")
    monkeypatch.setenv("NEXUS_DB_PORT", "5432")
    monkeypatch.setenv("NEXUS_DB_NAME", "legacy")
    monkeypatch.setenv("NEXUS_DB_USER", "postgres")
    monkeypatch.setenv("NEXUS_DB_PASSWORD", "pw")
    monkeypatch.setenv("NEXUS_DB_DEFAULT_PROFILE", "default")

    settings = Settings()
    profiles = settings.database_profiles()
    assert "default" in profiles
    assert profiles["default"].database == "legacy"


def test_parse_postgres_dsn_decodes_password_and_query_params() -> None:
    profile = parse_postgres_dsn(
        "postgresql://robot_pipeline_admin:RobotPipe%212026%23PG%21149@127.0.0.1:5433/robot_pipeline?sslmode=require",
        name="adhoc",
    )

    assert profile.user == "robot_pipeline_admin"
    assert profile.password == "RobotPipe!2026#PG!149"
    assert profile.host == "127.0.0.1"
    assert profile.port == 5433
    assert profile.database == "robot_pipeline"
    assert profile.sslmode == "require"


def test_parse_postgres_dsn_rejects_unescaped_fragment() -> None:
    with pytest.raises(ValueError, match="URL-encode it as %23"):
        parse_postgres_dsn(
            "postgresql://robot_pipeline_admin:RobotPipe!2026#PG!149@127.0.0.1:5433/robot_pipeline",
            name="adhoc",
        )


def test_database_profiles_accept_dsn(monkeypatch):
    monkeypatch.delenv("NEXUS_DB_HOST", raising=False)
    monkeypatch.setenv(
        "NEXUS_DB_DSN",
        "postgresql://robot_pipeline_admin:RobotPipe%212026%23PG%21149@127.0.0.1:5433/robot_pipeline",
    )
    monkeypatch.setenv("NEXUS_DB_DEFAULT_PROFILE", "robot")

    settings = Settings()
    profile = settings.resolve_db_profile()
    assert profile is not None
    assert profile.name == "robot"
    assert profile.password == "RobotPipe!2026#PG!149"
    assert profile.dsn == (
        "postgresql://robot_pipeline_admin:RobotPipe%212026%23PG%21149@127.0.0.1:5433/robot_pipeline"
    )


def test_resolve_requested_db_profile_prefers_uri_and_materializes_backend(monkeypatch):
    monkeypatch.delenv("NEXUS_DB_DSN", raising=False)
    monkeypatch.setenv("NEXUS_DB_HOST", "localhost")
    monkeypatch.setenv("NEXUS_DB_PORT", "5432")
    monkeypatch.setenv("NEXUS_DB_NAME", "legacy")
    monkeypatch.setenv("NEXUS_DB_USER", "postgres")
    monkeypatch.setenv("NEXUS_DB_PASSWORD", "pw")
    monkeypatch.setenv("NEXUS_RUNNING_IN_CONTAINER", "true")
    monkeypatch.setenv("NEXUS_HOST_BRIDGE_ADDRESS", "host.docker.internal")

    settings = Settings()

    resolved = settings.resolve_requested_db_profile(
        database="postgresql://robot:secret@localhost:5433/robot_pipeline",
        execution_backend="local",
    )
    assert resolved is not None
    assert resolved.host == "localhost"
    assert resolved.connect_host == "host.docker.internal"

    default_profile = settings.resolve_requested_db_profile(execution_backend="local")
    assert default_profile is not None
    assert default_profile.host == "localhost"
    assert default_profile.connect_host == "host.docker.internal"


def test_db_dsn_encodes_special_characters() -> None:
    settings = Settings()
    settings.db_host = "127.0.0.1"
    settings.db_port = 5433
    settings.db_name = "robot_pipeline"
    settings.db_user = "robot_pipeline_admin"
    settings.db_password = "RobotPipe!2026#PG!149"

    assert settings.db_dsn == (
        "postgresql://robot_pipeline_admin:RobotPipe%212026%23PG%21149@127.0.0.1:5433/robot_pipeline"
    )


def test_containerized_loopback_uses_bridge_instead_of_local_exec(monkeypatch):
    monkeypatch.setenv("NEXUS_RUNNING_IN_CONTAINER", "true")
    monkeypatch.setenv("NEXUS_HOST_BRIDGE_ADDRESS", "host.docker.internal")
    monkeypatch.setenv("NEXUS_SSH_HOST", "127.0.0.1")
    monkeypatch.setenv("NEXUS_DB_HOST", "localhost")
    monkeypatch.setenv("NEXUS_DB_PORT", "5433")
    monkeypatch.setenv("NEXUS_DB_NAME", "robot_pipeline")
    monkeypatch.setenv("NEXUS_DB_USER", "robot")
    monkeypatch.setenv("NEXUS_DB_PASSWORD", "secret")

    settings = Settings()

    assert settings.is_localhost is False
    assert settings.resolved_ssh_host == "host.docker.internal"

    profile = settings.resolve_db_profile()
    assert profile is not None
    assert profile.host == "localhost"
    assert profile.connect_host == "localhost"
    assert profile.dsn == "postgresql://robot:secret@localhost:5433/robot_pipeline"

    local_profile = settings.materialize_db_profile(profile, execution_backend="local")
    assert local_profile.connect_host == "host.docker.internal"
    assert local_profile.dsn == "postgresql://robot:secret@host.docker.internal:5433/robot_pipeline"

    ssh_profile = settings.materialize_db_profile(profile, execution_backend="ssh")
    assert ssh_profile.connect_host == "localhost"
    assert ssh_profile.dsn == "postgresql://robot:secret@localhost:5433/robot_pipeline"


def test_transport_security_derives_public_hosts_and_redirect_origins() -> None:
    settings = Settings()
    settings.host = "127.0.0.1"
    settings.public_base_url = "https://lightcap.ai"
    settings.oauth_issuer = "https://lightcap.ai"
    settings.oauth_client_redirect_uris = ["https://chatgpt.com/connector/oauth/test"]

    assert "127.0.0.1:*" in settings.transport_allowed_hosts
    assert "lightcap.ai" in settings.transport_allowed_hosts
    assert "lightcap.ai:*" in settings.transport_allowed_hosts
    assert "https://lightcap.ai" in settings.transport_allowed_origins
    assert "https://chatgpt.com" in settings.transport_allowed_origins


def test_analysis_thread_limit_reads_environment(monkeypatch) -> None:
    monkeypatch.setenv("NEXUS_ANALYSIS_THREAD_LIMIT", "3")

    settings = Settings()

    assert settings.analysis_thread_limit == 3
