"""Structured tool result contracts and artifact helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


@dataclass(frozen=True)
class ToolExecutionContext:
    """Stable request/runtime metadata injected into structured tool results."""

    tool_name: str
    stable_name: str
    resolved_runtime_id: str
    server_instance_id: str
    registry_version: str
    request_id: str
    trace_id: str
    session_id: str | None
    backend_kind: str
    backend_instance: str


class ArtifactRef(BaseModel):
    path: str
    kind: str
    size_bytes: int


class ToolResult(BaseModel):
    ok: bool
    tool_name: str
    stable_name: str
    resolved_runtime_id: str
    error_code: str | None = None
    error_stage: str | None = None
    message: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    artifact_paths: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    server_instance_id: str
    registry_version: str
    request_id: str
    trace_id: str
    session_id: str | None = None
    backend_kind: str
    backend_instance: str
    duration_ms: float
    exit_code: int | None = None
    profile: str | None = None
    data: Any = None
    usage: dict[str, Any] | None = None
    resource_usage: dict[str, Any] | None = None


class ArtifactManager:
    """Writes large outputs to local artifacts instead of overfilling MCP payloads."""

    def __init__(self, root: str):
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)

    def write_text(
        self,
        *,
        tool_name: str,
        channel: str,
        content: str,
        request_id: str,
        suffix: str = ".txt",
    ) -> ArtifactRef:
        safe_tool = tool_name.replace("/", "_")
        target_dir = self.root / safe_tool / request_id
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{channel}-{int(time.time() * 1000)}-{uuid4().hex[:8]}{suffix}"
        path = target_dir / filename
        path.write_text(content, encoding="utf-8")
        return ArtifactRef(path=str(path), kind=channel, size_bytes=path.stat().st_size)

    def write_bytes(
        self,
        *,
        tool_name: str,
        channel: str,
        content: bytes,
        request_id: str,
        suffix: str,
    ) -> ArtifactRef:
        safe_tool = tool_name.replace("/", "_")
        target_dir = self.root / safe_tool / request_id
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{channel}-{int(time.time() * 1000)}-{uuid4().hex[:8]}{suffix}"
        path = target_dir / filename
        path.write_bytes(content)
        return ArtifactRef(path=str(path), kind=channel, size_bytes=path.stat().st_size)


def preview_text(text: str, limit: int) -> str | None:
    if not text:
        return ""
    if limit <= 0 or len(text) <= limit:
        return text
    edge = max(32, limit // 2)
    return f"{text[:edge]}\n...\n{text[-edge:]}"


def _inline_or_artifact(
    *,
    manager: ArtifactManager,
    tool_name: str,
    request_id: str,
    channel: str,
    content: str,
    inline_limit: int,
    preview_limit: int,
    suffix: str = ".txt",
) -> tuple[str | None, str | None, list[ArtifactRef]]:
    if not content:
        return "", "", []
    preview = preview_text(content, preview_limit)
    if inline_limit <= 0 or len(content) <= inline_limit:
        return content, preview, []
    artifact = manager.write_text(
        tool_name=tool_name,
        channel=channel,
        content=content,
        request_id=request_id,
        suffix=suffix,
    )
    return None, preview, [artifact]


def build_tool_result(
    *,
    context: ToolExecutionContext,
    artifacts: ArtifactManager,
    ok: bool,
    duration_ms: float,
    stdout_text: str = "",
    stderr_text: str = "",
    output_limit: int,
    error_limit: int,
    output_preview_limit: int,
    error_preview_limit: int,
    error_code: str | None = None,
    error_stage: str | None = None,
    message: str | None = None,
    data: Any = None,
    exit_code: int | None = None,
    usage: dict[str, Any] | None = None,
    resource_usage: dict[str, Any] | None = None,
    profile: str | None = None,
    extra_artifacts: list[ArtifactRef] | None = None,
) -> ToolResult:
    stdout, stdout_preview, stdout_artifacts = _inline_or_artifact(
        manager=artifacts,
        tool_name=context.tool_name,
        request_id=context.request_id,
        channel="stdout",
        content=stdout_text,
        inline_limit=output_limit,
        preview_limit=output_preview_limit,
    )
    stderr, stderr_preview, stderr_artifacts = _inline_or_artifact(
        manager=artifacts,
        tool_name=context.tool_name,
        request_id=context.request_id,
        channel="stderr",
        content=stderr_text,
        inline_limit=error_limit,
        preview_limit=error_preview_limit,
    )
    all_artifacts = [*stdout_artifacts, *stderr_artifacts, *(extra_artifacts or [])]
    return ToolResult(
        ok=ok,
        tool_name=context.tool_name,
        stable_name=context.stable_name,
        resolved_runtime_id=context.resolved_runtime_id,
        error_code=error_code,
        error_stage=error_stage,
        message=message,
        stdout=stdout,
        stderr=stderr,
        stdout_preview=stdout_preview,
        stderr_preview=stderr_preview,
        artifact_paths=[artifact.path for artifact in all_artifacts],
        artifacts=all_artifacts,
        server_instance_id=context.server_instance_id,
        registry_version=context.registry_version,
        request_id=context.request_id,
        trace_id=context.trace_id,
        session_id=context.session_id,
        backend_kind=context.backend_kind,
        backend_instance=context.backend_instance,
        duration_ms=round(duration_ms, 2),
        exit_code=exit_code,
        profile=profile,
        data=data,
        usage=usage,
        resource_usage=resource_usage,
    )
