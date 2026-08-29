"""Multi-tenant gateway that manages per-client SSH pools and durable bindings."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from mcp.server.auth.provider import AccessToken

from mcp_nexus.config import Settings
from mcp_nexus.state import EncryptedStateStore
from mcp_nexus.transport.ssh import SSHPool

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GatewayBinding:
    binding_id: str
    ssh_host: str
    connect_host: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str = ""

    @property
    def pool_key(self) -> str:
        return f"{self.ssh_user}@{self.ssh_host}:{self.ssh_port}"

    @property
    def target(self) -> str:
        return self.pool_key

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "ssh_host": self.ssh_host,
            "connect_host": self.connect_host,
            "ssh_port": self.ssh_port,
            "ssh_user": self.ssh_user,
            "ssh_password": self.ssh_password,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> GatewayBinding:
        return cls(
            binding_id=str(payload["binding_id"]),
            ssh_host=str(payload["ssh_host"]),
            connect_host=str(payload.get("connect_host") or payload["ssh_host"]),
            ssh_port=int(payload.get("ssh_port", 22)),
            ssh_user=str(payload.get("ssh_user", "root")),
            ssh_password=str(payload.get("ssh_password", "")),
        )


class GatewayAccessToken(AccessToken):
    binding_id: str
    ssh_host: str
    ssh_port: int
    ssh_user: str


@dataclass
class GatewayToken:
    access_token: str
    binding_id: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    created_at: float = field(default_factory=time.time)
    client_id: str = ""
    scopes: tuple[str, ...] = ()
    resource: str | None = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.expires_in

    def to_access_token(self, binding: GatewayBinding) -> GatewayAccessToken:
        expires_at = int(self.created_at + self.expires_in)
        return GatewayAccessToken(
            token=self.access_token,
            client_id=self.client_id or binding.ssh_host,
            scopes=list(self.scopes),
            expires_at=expires_at,
            resource=self.resource,
            binding_id=self.binding_id,
            ssh_host=binding.ssh_host,
            ssh_port=binding.ssh_port,
            ssh_user=binding.ssh_user,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "binding_id": self.binding_id,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "created_at": self.created_at,
            "client_id": self.client_id,
            "scopes": list(self.scopes),
            "resource": self.resource,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> GatewayToken:
        return cls(
            access_token=str(payload["access_token"]),
            binding_id=str(payload["binding_id"]),
            token_type=str(payload.get("token_type", "Bearer")),
            expires_in=int(payload.get("expires_in", 3600)),
            created_at=float(payload.get("created_at", time.time())),
            client_id=str(payload.get("client_id", "")),
            scopes=tuple(str(item) for item in payload.get("scopes", [])),
            resource=str(payload["resource"]) if payload.get("resource") is not None else None,
        )

    def response_payload(self, binding: GatewayBinding) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "target": binding.target,
            "scope": " ".join(self.scopes) if self.scopes else None,
        }


class GatewayManager:
    """Manages per-client SSH pools for the multi-tenant gateway."""

    def __init__(self, settings: Settings, *, state_store: EncryptedStateStore | None = None):
        self._settings = settings
        self._state_store = state_store
        self._pools: dict[str, SSHPool] = {}
        self._tokens: dict[str, GatewayToken] = {}
        self._bindings: dict[str, GatewayBinding] = {}
        self._lock = asyncio.Lock()
        self._owner_pool = SSHPool(settings)
        self._restore_state()
        self._restore_pools()

    async def authenticate(
        self,
        client_id: str,
        client_secret: str,
        ssh_user: str = "",
        ssh_port: int = 0,
    ) -> GatewayToken | None:
        """Authenticate by validating SSH credentials and issue an access token."""
        binding = await self.bind_target(client_id, client_secret, ssh_user=ssh_user, ssh_port=ssh_port)
        if binding is None:
            return None
        token = await self.issue_access_token(binding)
        logger.info("Gateway token issued for %s", binding.pool_key)
        return token

    async def bind_target(
        self,
        ssh_host: str,
        ssh_password: str,
        *,
        ssh_user: str = "",
        ssh_port: int = 0,
    ) -> GatewayBinding | None:
        """Validate an SSH target and return a reusable binding."""
        normalized_host = ssh_host.strip()
        normalized_user = ssh_user or "root"
        normalized_port = ssh_port or 22

        if not normalized_host:
            return None

        binding = self._build_binding(
            ssh_host=normalized_host,
            ssh_port=normalized_port,
            ssh_user=normalized_user,
            ssh_password=ssh_password,
        )

        if self._is_local_execution_binding(binding):
            if self._settings.ssh_password and ssh_password != self._settings.ssh_password:
                logger.warning("Local binding auth failed for %s", normalized_host)
                return None
        else:
            valid = await self._validate_ssh(binding.connect_host, normalized_port, normalized_user, ssh_password)
            if not valid:
                logger.warning(
                    "Gateway auth failed — SSH to %s@%s:%d",
                    normalized_user,
                    binding.connect_host,
                    normalized_port,
                )
                return None

        self._bindings[binding.binding_id] = binding
        await self._ensure_pool(binding)
        self._persist_state()
        return binding

    async def issue_access_token(
        self,
        binding: GatewayBinding,
        *,
        client_id: str = "",
        scopes: list[str] | None = None,
        resource: str | None = None,
        expires_in: int | None = None,
    ) -> GatewayToken:
        """Issue a bearer token bound to a validated SSH target."""
        await self._ensure_pool(binding)
        effective_scopes = tuple(scopes or self._settings.oauth_required_scopes)
        token = GatewayToken(
            access_token=secrets.token_urlsafe(48),
            binding_id=binding.binding_id,
            expires_in=expires_in or self._settings.oauth_token_ttl_seconds,
            client_id=client_id or binding.ssh_host,
            scopes=effective_scopes,
            resource=resource,
        )
        self._tokens[token.access_token] = token
        self._persist_state()
        return token

    def get_binding(self, binding_id: str) -> GatewayBinding | None:
        return self._bindings.get(binding_id)

    def validate_token(self, token_str: str) -> GatewayToken | None:
        """Validate a gateway access token."""
        token = self._tokens.get(token_str)
        if token is None:
            return None
        if token.is_expired:
            self._tokens.pop(token_str, None)
            self._persist_state()
            return None
        if token.binding_id not in self._bindings:
            self._tokens.pop(token_str, None)
            self._persist_state()
            return None
        return token

    def get_pool_for_token(self, token_str: str) -> SSHPool | None:
        """Get the SSH pool associated with a token."""
        token = self.validate_token(token_str)
        if token is None:
            return None

        binding = self.get_binding(token.binding_id)
        if binding is None:
            return None
        if self._is_local_execution_binding(binding):
            return self._owner_pool
        return self._pools.get(binding.pool_key)

    def get_pool_for_binding(self, binding: GatewayBinding) -> SSHPool | None:
        """Get or resolve the pool associated with a validated binding."""
        if self._is_local_execution_binding(binding):
            return self._owner_pool
        return self._pools.get(binding.pool_key)

    def verify_access_token(self, token_str: str) -> GatewayAccessToken | None:
        """Return MCP auth metadata for a valid bearer token."""
        token = self.validate_token(token_str)
        if token is None:
            return None
        binding = self.get_binding(token.binding_id)
        if binding is None:
            return None
        return token.to_access_token(binding)

    def revoke_access_token(self, token_str: str) -> None:
        """Revoke an issued bearer token if it exists."""
        self._tokens.pop(token_str, None)
        self._persist_state()

    def get_owner_pool(self) -> SSHPool:
        """Get the default pool used when no auth token is present."""
        return self._owner_pool

    async def cleanup(self):
        """Close expired pools and remove expired tokens."""
        expired_tokens = [key for key, token in self._tokens.items() if token.is_expired]
        for key in expired_tokens:
            self._tokens.pop(key, None)

        active_keys = {
            binding.pool_key
            for token in self._tokens.values()
            if (binding := self.get_binding(token.binding_id)) and not self._is_local_execution_binding(binding)
        }
        async with self._lock:
            for key in list(self._pools.keys()):
                if key not in active_keys:
                    await self._pools[key].close()
                    del self._pools[key]
                    logger.info("Closed idle pool for %s", key)
        if expired_tokens:
            self._persist_state()

    async def close_all(self):
        """Shut down all pools."""
        await self._owner_pool.close()
        async with self._lock:
            for pool in self._pools.values():
                await pool.close()
            self._pools.clear()

    def stats(self) -> dict[str, Any]:
        return {
            "active_tokens": len(self._tokens),
            "active_pools": len(self._pools) + 1,
            "targets": [binding.pool_key for binding in self._bindings.values()],
        }

    async def _validate_ssh(self, host: str, port: int, user: str, password: str) -> bool:
        """Validate SSH credentials by attempting a connection."""
        import asyncssh

        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    host=host,
                    port=port,
                    username=user,
                    password=password,
                    known_hosts=None,
                ),
                timeout=10,
            )
            result = await conn.run("echo ok", check=False)
            conn.close()
            stdout = result.stdout.decode() if isinstance(result.stdout, bytes) else (result.stdout or "")
            return stdout.strip() == "ok"
        except Exception as exc:
            logger.debug("SSH validation failed for %s@%s:%d — %s", user, host, port, exc)
            return False

    async def _ensure_pool(self, binding: GatewayBinding) -> None:
        """Create or reuse an SSH pool for the given binding target."""
        if self._is_local_execution_binding(binding):
            return

        async with self._lock:
            self._create_pool(binding)

    def _build_binding(
        self,
        *,
        ssh_host: str,
        ssh_port: int,
        ssh_user: str,
        ssh_password: str,
    ) -> GatewayBinding:
        connect_host = self._settings.resolve_connect_host(ssh_host)
        digest = hashlib.sha256(
            f"{ssh_user}\0{ssh_host}\0{connect_host}\0{ssh_port}\0{ssh_password}".encode()
        ).hexdigest()[:32]
        return GatewayBinding(
            binding_id=digest,
            ssh_host=ssh_host,
            connect_host=connect_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
        )

    def _create_pool(self, binding: GatewayBinding) -> None:
        key = binding.pool_key
        if key in self._pools:
            return
        pool_settings = Settings()
        pool_settings.ssh_host = binding.connect_host
        pool_settings.ssh_port = binding.ssh_port
        pool_settings.ssh_user = binding.ssh_user
        pool_settings.ssh_password = binding.ssh_password
        pool_settings.ssh_pool_size = min(self._settings.ssh_pool_size, 2)
        self._pools[key] = SSHPool(pool_settings)
        logger.info("Created SSH pool for %s via %s", key, binding.connect_host)

    def _is_local_execution_binding(self, binding: GatewayBinding) -> bool:
        return self._settings.is_local_execution_host(binding.ssh_host)

    def _restore_state(self) -> None:
        if self._state_store is None:
            return
        payload = self._state_store.read_section("gateway")
        bindings_payload = payload.get("bindings", {})
        tokens_payload = payload.get("tokens", {})
        if isinstance(bindings_payload, dict):
            self._bindings = {
                binding_id: GatewayBinding.from_dict(binding_payload)
                for binding_id, binding_payload in bindings_payload.items()
                if isinstance(binding_payload, dict)
            }
        if isinstance(tokens_payload, dict):
            for token_id, token_payload in tokens_payload.items():
                if not isinstance(token_payload, dict):
                    continue
                token = GatewayToken.from_dict({"access_token": token_id, **token_payload})
                if token.binding_id in self._bindings and not token.is_expired:
                    self._tokens[token.access_token] = token

    def _restore_pools(self) -> None:
        for token in self._tokens.values():
            binding = self.get_binding(token.binding_id)
            if binding is None or self._is_local_execution_binding(binding):
                continue
            self._create_pool(binding)

    def _persist_state(self) -> None:
        if self._state_store is None:
            return
        payload = {
            "bindings": {binding_id: binding.to_dict() for binding_id, binding in self._bindings.items()},
            "tokens": {
                token_id: {
                    key: value
                    for key, value in token.to_dict().items()
                    if key != "access_token"
                }
                for token_id, token in self._tokens.items()
            },
        }
        self._state_store.write_section("gateway", payload)
