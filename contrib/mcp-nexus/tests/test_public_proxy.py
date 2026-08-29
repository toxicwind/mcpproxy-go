"""Public OAuth/MCP proxy helper tests."""

from __future__ import annotations

from mcp_nexus.public_proxy import (
    DEFAULT_PUBLIC_PROXY_PATH_PREFIXES,
    _load_fastapi,
    normalize_public_proxy_prefixes,
    should_proxy_public_path,
)


def test_normalize_public_proxy_prefixes_deduplicates_and_normalizes() -> None:
    prefixes = normalize_public_proxy_prefixes(["mcp", "/mcp/", "/authorize/", ""])
    assert prefixes == ("/mcp", "/authorize")


def test_should_proxy_public_path_matches_exact_and_nested_paths() -> None:
    assert should_proxy_public_path("/mcp/nexus")
    assert should_proxy_public_path("/mcp-nexus/web_retrieve")
    assert should_proxy_public_path("/mcp-nexus/runtime/instance-1/web_retrieve")
    assert should_proxy_public_path("/tool-registry")
    assert should_proxy_public_path("/tool-registry/nexus")
    assert should_proxy_public_path("/.well-known/nexus-tool-registry")
    assert should_proxy_public_path("/.well-known/oauth-protected-resource/mcp/nexus")
    assert should_proxy_public_path("/oauth/consent")
    assert should_proxy_public_path("/oauth/consent/assets")
    assert not should_proxy_public_path("/api/search/state")


def test_default_public_proxy_prefixes_cover_required_oauth_surface() -> None:
    required = {
        "/mcp/nexus",
        "/mcp-nexus",
        "/tool-registry",
        "/tool-registry/nexus",
        "/.well-known/nexus-tool-registry",
        "/authorize",
        "/token",
        "/register",
        "/oauth/consent",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    }
    assert required.issubset(set(DEFAULT_PUBLIC_PROXY_PATH_PREFIXES))


def test_load_fastapi_raises_clear_error_when_extra_is_missing(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ModuleNotFoundError("No module named 'fastapi'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    try:
        _load_fastapi()
    except RuntimeError as exc:
        assert "mcp-nexus[fastapi]" in str(exc)
    else:
        raise AssertionError("expected RuntimeError when fastapi is unavailable")
