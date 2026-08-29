"""Encrypted durable state for gateway and OAuth lifecycle data."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeVar

from cryptography.fernet import Fernet, InvalidToken

T = TypeVar("T")


class EncryptedStateStore:
    """Persist small amounts of operational state behind a symmetric envelope."""

    def __init__(self, root: str, encryption_key: str = ""):
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self._state_path = self.root / "state.json.enc"
        self._key_path = self.root / "state.key"
        self._lock = threading.RLock()
        self._fernet = Fernet(self._resolve_key(encryption_key))
        self._state = self._load()

    def read_section(self, name: str) -> dict[str, Any]:
        with self._lock:
            value = self._state.get(name, {})
            return deepcopy(value) if isinstance(value, dict) else {}

    def write_section(self, name: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._state[name] = deepcopy(value)
            self._persist()

    def mutate_section(self, name: str, mutator: Callable[[dict[str, Any]], T]) -> T:
        with self._lock:
            section = deepcopy(self._state.get(name, {}))
            if not isinstance(section, dict):
                section = {}
            result = mutator(section)
            self._state[name] = section
            self._persist()
            return result

    def _resolve_key(self, explicit_key: str) -> bytes:
        if explicit_key:
            key = explicit_key.strip().encode("utf-8")
            self._validate_key(key)
            return key

        if self._key_path.exists():
            key = self._key_path.read_text(encoding="utf-8").strip().encode("utf-8")
            self._validate_key(key)
            return key

        key = Fernet.generate_key()
        self._key_path.write_text(key.decode("utf-8"), encoding="utf-8")
        try:
            os.chmod(self._key_path, 0o600)
        except OSError:
            pass
        return key

    def _validate_key(self, key: bytes) -> None:
        try:
            Fernet(key)
        except Exception as exc:  # pragma: no cover - cryptography validates the key shape.
            raise ValueError("NEXUS_STATE_ENCRYPTION_KEY must be a valid Fernet key.") from exc

    def _load(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {}

        payload = self._state_path.read_bytes()
        try:
            decrypted = self._fernet.decrypt(payload)
        except InvalidToken as exc:
            raise RuntimeError(
                "Unable to decrypt persisted Nexus state. Provide the correct "
                "NEXUS_STATE_ENCRYPTION_KEY or clear the state directory."
            ) from exc

        parsed = json.loads(decrypted.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}

    def _persist(self) -> None:
        payload = json.dumps(self._state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        encrypted = self._fernet.encrypt(payload)
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_bytes(encrypted)
        os.replace(tmp_path, self._state_path)
