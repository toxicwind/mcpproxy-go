"""Capability-aware remote execution helpers."""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass, field

_EXECUTION_META_MARKER = "__NEXUS_EXEC_META__"


@dataclass(frozen=True)
class ServerCapabilities:
    system: str = "unknown"
    distro_id: str = ""
    distro_version: str = ""
    shell: str = ""
    python_command: str = ""
    package_managers: tuple[str, ...] = ()
    service_manager: str = "unknown"
    container_engine: str = ""
    compose_command: str = ""
    time_style: str = "none"
    supports_resource_limits: bool = False
    commands: dict[str, bool] = field(default_factory=dict)

    @property
    def package_manager(self) -> str:
        return self.package_managers[0] if self.package_managers else ""

    def has(self, command_name: str) -> bool:
        return self.commands.get(command_name, False)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["package_managers"] = list(self.package_managers)
        return data


@dataclass(frozen=True)
class ExecutionLimits:
    cpu_seconds: int = 0
    memory_mb: int = 0
    file_size_mb: int = 0
    process_count: int = 0

    def enabled(self) -> bool:
        return any((self.cpu_seconds, self.memory_mb, self.file_size_mb, self.process_count))


@dataclass(frozen=True)
class ExecutionRequest:
    command: str
    cwd: str = ""
    timeout: int = 60
    env: dict[str, str] = field(default_factory=dict)
    capture_usage: bool = True
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)


@dataclass(frozen=True)
class ManagedExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    ok: bool
    usage: dict[str, object] | None


def capability_probe_command() -> str:
    """Return a portable shell probe that emits key=value pairs."""
    return """
set +e
SYSTEM=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')
printf 'system=%s\n' "${SYSTEM:-unknown}"

if [ -f /etc/os-release ]; then
  . /etc/os-release
  printf 'distro_id=%s\n' "${ID:-}"
  printf 'distro_version=%s\n' "${VERSION_ID:-}"
fi

printf 'shell=%s\n' "${SHELL:-/bin/sh}"

for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    printf 'python_command=%s\n' "$candidate"
    break
  fi
done

for candidate in apt-get dnf yum apk pacman zypper brew; do
  if command -v "$candidate" >/dev/null 2>&1; then
    printf 'package_manager=%s\n' "$candidate"
  fi
done

if command -v systemctl >/dev/null 2>&1; then
  printf 'service_manager=systemd\n'
elif command -v launchctl >/dev/null 2>&1; then
  printf 'service_manager=launchctl\n'
elif command -v service >/dev/null 2>&1; then
  printf 'service_manager=service\n'
else
  printf 'service_manager=unknown\n'
fi

if command -v docker >/dev/null 2>&1; then
  printf 'container_engine=docker\n'
  if docker compose version >/dev/null 2>&1; then
    printf 'compose_command=docker compose\n'
  elif command -v docker-compose >/dev/null 2>&1; then
    printf 'compose_command=docker-compose\n'
  fi
elif command -v podman >/dev/null 2>&1; then
  printf 'container_engine=podman\n'
  if podman compose version >/dev/null 2>&1; then
    printf 'compose_command=podman compose\n'
  fi
fi

if /usr/bin/time -v true >/dev/null 2>&1; then
  printf 'time_style=gnu\n'
elif /usr/bin/time -l true >/dev/null 2>&1; then
  printf 'time_style=bsd\n'
else
  printf 'time_style=none\n'
fi

if [ "${SYSTEM}" = "linux" ] || [ "${SYSTEM}" = "darwin" ]; then
  printf 'supports_resource_limits=1\n'
else
  printf 'supports_resource_limits=0\n'
fi

for pair in \
  git:git rg:rg tar:tar rsync:rsync make:make tmux:tmux \
  stdbuf:stdbuf \
  ss:ss netstat:netstat lsof:lsof nc:nc socat:socat iptables:iptables \
  ufw:ufw journalctl:journalctl dig:dig openssl:openssl curl:curl \
  chromium:chromium chromium_browser:chromium-browser \
  google_chrome:google-chrome google_chrome_stable:google-chrome-stable firefox:firefox \
  playwright:playwright npx:npx \
  psql:psql mysql:mysql sqlite3:sqlite3 npm:npm pip3:pip3 pip:pip \
  node:node pytest:pytest ruff:ruff mypy:mypy pyright:pyright docker-compose:docker_compose
do
  KEY=${pair%%:*}
  CMD=${pair#*:}
  if command -v "$CMD" >/dev/null 2>&1; then
    printf 'cmd_%s=1\n' "$KEY"
  fi
done
"""


def parse_capability_output(output: str) -> ServerCapabilities:
    """Parse the capability probe output into a typed structure."""
    values: dict[str, str] = {}
    commands: dict[str, bool] = {}
    package_managers: list[str] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "package_manager":
            package_managers.append(value)
        elif key.startswith("cmd_"):
            commands[key[4:]] = value == "1"
        else:
            values[key] = value

    supports_resource_limits = values.get("supports_resource_limits", "0") == "1" and bool(values.get("python_command"))

    return ServerCapabilities(
        system=values.get("system", "unknown"),
        distro_id=values.get("distro_id", ""),
        distro_version=values.get("distro_version", ""),
        shell=values.get("shell", ""),
        python_command=values.get("python_command", ""),
        package_managers=tuple(package_managers),
        service_manager=values.get("service_manager", "unknown"),
        container_engine=values.get("container_engine", ""),
        compose_command=values.get("compose_command", ""),
        time_style=values.get("time_style", "none"),
        supports_resource_limits=supports_resource_limits,
        commands=commands,
    )


def primary_package_manager(capabilities: ServerCapabilities) -> str:
    return capabilities.package_manager


def build_managed_command(capabilities: ServerCapabilities, request: ExecutionRequest) -> str:
    """Wrap a shell command to capture resource usage and apply optional limits."""
    if not request.capture_usage and not request.limits.enabled():
        return _prefix_command(request.command, request.cwd, request.env)

    if capabilities.supports_resource_limits and capabilities.python_command:
        payload = json.dumps(
            {
                "command": request.command,
                "cwd": request.cwd,
                "env": request.env,
                "capture_usage": request.capture_usage,
                "limits": asdict(request.limits),
            }
        )
        return (
            f"{shlex.quote(capabilities.python_command)} -c {shlex.quote(_python_execution_wrapper())} "
            f"{shlex.quote(payload)}"
        )

    return _prefix_command(request.command, request.cwd, request.env)


def extract_execution_metadata(stderr: str) -> tuple[str, dict[str, object] | None]:
    """Strip execution metadata marker from stderr when present."""
    if _EXECUTION_META_MARKER not in stderr:
        return stderr, None

    cleaned_lines: list[str] = []
    metadata: dict[str, object] | None = None
    for line in stderr.splitlines():
        if line.startswith(_EXECUTION_META_MARKER):
            try:
                metadata = json.loads(line[len(_EXECUTION_META_MARKER) :])
            except json.JSONDecodeError:
                metadata = None
            continue
        cleaned_lines.append(line)

    cleaned = "\n".join(cleaned_lines).strip()
    return cleaned, metadata


def truncate_output(text: str, limit: int) -> tuple[str, bool]:
    if limit <= 0 or len(text) <= limit:
        return text, False
    return text[-limit:], True


def _prefix_command(command: str, cwd: str, env: dict[str, str]) -> str:
    parts: list[str] = []
    if env:
        exports = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
        if exports:
            parts.append(f"export {exports}")
    if cwd:
        parts.append(f"cd {shlex.quote(cwd)}")
    parts.append(command)
    return " && ".join(parts[:-1]) + ((" && " if len(parts) > 1 else "") + parts[-1] if parts else command)


def _python_execution_wrapper() -> str:
    return f"""
import json
import os
import resource
import subprocess
import sys
import time

MARKER = {json.dumps(_EXECUTION_META_MARKER)}
spec = json.loads(sys.argv[1])
limits = spec.get("limits", {{}})
env = os.environ.copy()
env.update({{k: str(v) for k, v in spec.get("env", {{}}).items()}})

def preexec():
    if limits.get("cpu_seconds"):
        resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
    if limits.get("memory_mb"):
        memory_bytes = limits["memory_mb"] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    if limits.get("file_size_mb"):
        file_bytes = limits["file_size_mb"] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    if limits.get("process_count"):
        resource.setrlimit(resource.RLIMIT_NPROC, (limits["process_count"], limits["process_count"]))

start = time.time()
proc = subprocess.run(
    spec["command"],
    shell=True,
    cwd=spec.get("cwd") or None,
    env=env,
    capture_output=True,
    text=True,
    preexec_fn=preexec,
)
elapsed_ms = round((time.time() - start) * 1000, 2)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
rss_kb = int(usage.ru_maxrss / 1024) if sys.platform == "darwin" else int(usage.ru_maxrss)

if proc.stdout:
    sys.stdout.write(proc.stdout)
if proc.stderr:
    sys.stderr.write(proc.stderr)

meta = {{
    "wall_ms": elapsed_ms,
    "user_cpu_s": round(usage.ru_utime, 4),
    "system_cpu_s": round(usage.ru_stime, 4),
    "max_rss_kb": rss_kb,
    "limits": limits,
}}
sys.stderr.write("\\n" + MARKER + json.dumps(meta) + "\\n")
raise SystemExit(proc.returncode)
""".strip()
