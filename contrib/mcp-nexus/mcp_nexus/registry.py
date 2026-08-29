"""Stable tool registry generation for MCP Nexus."""

from __future__ import annotations

import hashlib
import inspect
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_nexus.catalog import category_for_tool


@dataclass(frozen=True)
class ToolBinding:
    """Stable, inspectable metadata for a registered MCP tool."""

    name: str
    title: str | None
    description: str
    category: str | None
    stable_name: str
    stable_path: str
    runtime_path: str
    resolved_runtime_id: str
    implementation_fingerprint: str
    parameters: dict[str, Any]
    output_schema: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "stable_name": self.stable_name,
            "stable_path": self.stable_path,
            "runtime_path": self.runtime_path,
            "resolved_runtime_id": self.resolved_runtime_id,
            "implementation_fingerprint": self.implementation_fingerprint,
            "parameters": self.parameters,
            "output_schema": self.output_schema,
        }


@dataclass(frozen=True)
class ToolRegistry:
    """Snapshot of the current tool registry for a single server instance."""

    server_instance_id: str
    registry_version: str
    generated_at: float
    alias_base: str
    tools: tuple[ToolBinding, ...]

    def tool(self, name: str) -> ToolBinding | None:
        for binding in self.tools:
            if binding.name == name:
                return binding
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_instance_id": self.server_instance_id,
            "registry_version": self.registry_version,
            "generated_at": self.generated_at,
            "alias_base": self.alias_base,
            "tool_count": len(self.tools),
            "tools": [binding.to_dict() for binding in self.tools],
        }


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def _function_code_fingerprint(fn: Any) -> dict[str, Any]:
    code = getattr(fn, "__code__", None)
    if code is None:
        return {"kind": "opaque"}
    return {
        "kind": "code",
        "argcount": code.co_argcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "posonlyargcount": getattr(code, "co_posonlyargcount", 0),
        "flags": code.co_flags,
        "bytecode_sha256": _hash_bytes(code.co_code),
        "consts_sha256": _hash_text(repr(code.co_consts)),
        "names_sha256": _hash_text(repr(code.co_names)),
        "varnames_sha256": _hash_text(repr(code.co_varnames)),
    }


def tool_implementation_fingerprint(fn: Any) -> str:
    """Fingerprint tool implementation details, not only the exposed schema."""
    payload: dict[str, Any] = {
        "module": getattr(fn, "__module__", None),
        "qualname": getattr(fn, "__qualname__", None),
    }

    source_file = inspect.getsourcefile(fn) or inspect.getfile(fn)
    if source_file:
        source_path = Path(source_file)
        if source_path.is_file():
            payload["module_source_sha256"] = _hash_bytes(source_path.read_bytes())

    try:
        payload["function_source_sha256"] = _hash_text(inspect.getsource(fn))
    except (OSError, TypeError):
        payload["code_fingerprint"] = _function_code_fingerprint(fn)

    return _hash_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def build_tool_registry(mcp: FastMCP, *, server_instance_id: str, alias_base: str) -> ToolRegistry:
    """Build a stable registry snapshot from the active FastMCP tool manager."""
    manager = getattr(mcp, "_tool_manager", None)
    tools = list(getattr(manager, "_tools", {}).values())
    normalized_alias_base = "/" + alias_base.strip("/")
    implementation_fingerprints = {
        tool.name: tool_implementation_fingerprint(tool.fn) for tool in tools
    }

    fingerprint_payload = [
        {
            "name": tool.name,
            "title": tool.title,
            "description": tool.description,
            "implementation_fingerprint": implementation_fingerprints[tool.name],
            "parameters": tool.parameters,
            "output_schema": tool.output_schema,
            "category": category_for_tool(tool.name),
        }
        for tool in sorted(tools, key=lambda item: item.name)
    ]
    version_payload = json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"))
    registry_version = hashlib.sha256(version_payload.encode("utf-8")).hexdigest()[:16]

    bindings: list[ToolBinding] = []
    for tool in sorted(tools, key=lambda item: item.name):
        stable_name = tool.name
        stable_path = f"{normalized_alias_base}/{stable_name}"
        runtime_path = f"{normalized_alias_base}/runtime/{server_instance_id}/{stable_name}"
        resolved_runtime_id = hashlib.sha256(
            f"{server_instance_id}:{registry_version}:{stable_name}".encode()
        ).hexdigest()[:16]
        bindings.append(
            ToolBinding(
                name=tool.name,
                title=tool.title,
                description=tool.description,
                category=category_for_tool(tool.name),
                stable_name=stable_name,
                stable_path=stable_path,
                runtime_path=runtime_path,
                resolved_runtime_id=resolved_runtime_id,
                implementation_fingerprint=implementation_fingerprints[tool.name],
                parameters=tool.parameters,
                output_schema=tool.output_schema,
            )
        )

    return ToolRegistry(
        server_instance_id=server_instance_id,
        registry_version=registry_version,
        generated_at=time.time(),
        alias_base=normalized_alias_base,
        tools=tuple(bindings),
    )


def apply_registry_metadata(mcp: FastMCP, registry: ToolRegistry):
    """Attach stable registry metadata to each registered tool."""
    manager = getattr(mcp, "_tool_manager", None)
    for tool in getattr(manager, "_tools", {}).values():
        binding = registry.tool(tool.name)
        if binding is None:
            continue
        nexus_meta = {
            "server_instance_id": registry.server_instance_id,
            "registry_version": registry.registry_version,
            "stable_name": binding.stable_name,
            "stable_path": binding.stable_path,
            "runtime_path": binding.runtime_path,
            "resolved_runtime_id": binding.resolved_runtime_id,
            "implementation_fingerprint": binding.implementation_fingerprint,
            "category": binding.category,
        }
        tool.meta = {**(tool.meta or {}), "nexus": nexus_meta}
