"""Reusable task-family routing for specialized tool selection."""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from mcp_nexus.catalog import task_family_policy

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_SHELL_WRAPPERS = frozenset({"bash", "sh", "zsh"})
_WEB_EXECUTABLES = frozenset({"curl", "wget", "http", "httpie", "xh", "lynx", "links", "elinks"})
_BROWSER_IMPORT_PREFIXES = (
    "playwright",
    "pyppeteer",
    "selenium",
)
_HTTP_IMPORT_PREFIXES = (
    "aiohttp",
    "cloudscraper",
    "curl_cffi",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
)
_WEB_IMPORT_PREFIXES = (*_BROWSER_IMPORT_PREFIXES, *_HTTP_IMPORT_PREFIXES)
_HTML_MARKERS = (
    "<title",
    "<meta",
    "accept: text/html",
    "application/xhtml+xml",
    "beautifulsoup",
    "bs4",
    "html.parser",
    "og:title",
    "og:description",
    "user-agent",
)


@dataclass(frozen=True)
class ToolRedirect:
    task_family: str
    recommended_tool: str
    preferred_tools: tuple[str, ...]
    reason: str
    evidence: tuple[str, ...]
    url_candidates: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "task_family": self.task_family,
            "recommended_tool": self.recommended_tool,
            "preferred_tools": list(self.preferred_tools),
            "reason": self.reason,
            "evidence": list(self.evidence),
            "url_candidates": list(self.url_candidates),
        }


def terminal_specialized_redirect(
    tool_name: str,
    *,
    command: str = "",
    commands: Iterable[str] | None = None,
    script: str = "",
    interpreter: str = "",
    code: str = "",
) -> ToolRedirect | None:
    """Redirect ad hoc webpage retrieval from generic terminal tools to network tools."""

    match = _match_web_retrieval(
        tool_name,
        command=command,
        commands=commands,
        script=script,
        interpreter=interpreter,
        code=code,
    )
    if match is None:
        return None

    policy = task_family_policy(match.task_family)
    if policy is None:
        return None
    disallowed_tools = set(policy["disallowed_tools"])
    if tool_name not in disallowed_tools:
        return None

    preferred_tools = tuple(str(tool) for tool in policy["preferred_tools"])
    return ToolRedirect(
        task_family=match.task_family,
        recommended_tool=preferred_tools[0],
        preferred_tools=preferred_tools,
        reason=str(policy["description"]),
        evidence=match.evidence,
        url_candidates=match.url_candidates,
    )


@dataclass(frozen=True)
class _TaskFamilyMatch:
    task_family: str
    evidence: tuple[str, ...]
    url_candidates: tuple[str, ...]


def _match_web_retrieval(
    tool_name: str,
    *,
    command: str,
    commands: Iterable[str] | None,
    script: str,
    interpreter: str,
    code: str,
) -> _TaskFamilyMatch | None:
    if tool_name == "execute_command":
        return _shell_command_match(command)
    if tool_name == "execute_batch":
        for index, item in enumerate(commands or (), start=1):
            match = _shell_command_match(item)
            if match is not None:
                return _TaskFamilyMatch(
                    task_family=match.task_family,
                    evidence=(f"batch_command:{index}", *match.evidence),
                    url_candidates=match.url_candidates,
                )
        return None
    if tool_name == "execute_script":
        return _script_match(script, interpreter)
    if tool_name == "execute_python":
        return _python_code_match(code)
    return None


def _script_match(script: str, interpreter: str) -> _TaskFamilyMatch | None:
    if not script.strip():
        return None
    base = PurePosixPath(interpreter.strip() or "bash").name
    if base in _SHELL_WRAPPERS:
        return _shell_script_match(script)
    if base.startswith("python"):
        return _python_code_match(script)
    return None


def _shell_script_match(script: str) -> _TaskFamilyMatch | None:
    for index, line in enumerate(script.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _shell_command_match(stripped)
        if match is not None:
            return _TaskFamilyMatch(
                task_family=match.task_family,
                evidence=(f"script_line:{index}", *match.evidence),
                url_candidates=match.url_candidates,
            )
    return None


def _shell_command_match(command: str) -> _TaskFamilyMatch | None:
    if not command.strip():
        return None
    url_candidates = _extract_urls(command)
    if not url_candidates:
        return None

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return None

    executable = PurePosixPath(tokens[0]).name
    if executable in _SHELL_WRAPPERS:
        nested = _extract_shell_payload(tokens)
        if nested:
            nested_match = _shell_script_match(nested)
            if nested_match is not None:
                return _TaskFamilyMatch(
                    task_family=nested_match.task_family,
                    evidence=(f"shell_wrapper:{executable}", *nested_match.evidence),
                    url_candidates=nested_match.url_candidates or url_candidates,
                )
    if executable in {"wget", "lynx", "links", "elinks"}:
        return _TaskFamilyMatch(
            task_family="web_retrieval",
            evidence=(f"shell_executable:{executable}", "url_present"),
            url_candidates=url_candidates,
        )
    if executable in {"curl", "http", "httpie", "xh"} and _looks_like_webpage_text(command):
        return _TaskFamilyMatch(
            task_family="web_retrieval",
            evidence=(f"shell_executable:{executable}", "webpage_markers", "url_present"),
            url_candidates=url_candidates,
        )
    if executable.startswith("python") and _contains_python_web_markers(command) and _looks_like_webpage_text(command):
        return _TaskFamilyMatch(
            task_family="web_retrieval",
            evidence=(f"shell_executable:{executable}", "embedded_python_web_client", "webpage_markers", "url_present"),
            url_candidates=url_candidates,
        )
    return None


def _extract_shell_payload(tokens: list[str]) -> str:
    for index, token in enumerate(tokens):
        if token in {"-c", "-lc"} and index + 1 < len(tokens):
            return tokens[index + 1]
    return ""


def _python_code_match(code: str) -> _TaskFamilyMatch | None:
    url_candidates = _extract_urls(code)
    if not url_candidates:
        return None
    imports = _python_imports(code)
    browser_imports = sorted(name for name in imports if _is_browser_import(name))
    http_imports = sorted(name for name in imports if _is_http_import(name))
    if not browser_imports and not http_imports:
        return None
    if not browser_imports and not _looks_like_webpage_text(code):
        return None
    matched_imports = browser_imports or http_imports
    evidence = ["url_present", *[f"python_import:{name}" for name in matched_imports]]
    if _looks_like_webpage_text(code):
        evidence.append("webpage_markers")
    return _TaskFamilyMatch(
        task_family="web_retrieval",
        evidence=tuple(evidence),
        url_candidates=url_candidates,
    )


def _python_imports(code: str) -> set[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _python_imports_from_text(code)

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _python_imports_from_text(code: str) -> set[str]:
    imports: set[str] = set()
    for prefix in _WEB_IMPORT_PREFIXES:
        pattern = rf"(?:^|\n)\s*(?:from|import)\s+{re.escape(prefix)}(?:[.\s]|$)"
        if re.search(pattern, code):
            imports.add(prefix)
    return imports


def _contains_python_web_markers(text: str) -> bool:
    return any(f"import {prefix}" in text or f"from {prefix}" in text for prefix in _WEB_IMPORT_PREFIXES)


def _is_web_import(name: str) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in _WEB_IMPORT_PREFIXES)


def _is_browser_import(name: str) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in _BROWSER_IMPORT_PREFIXES)


def _is_http_import(name: str) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in _HTTP_IMPORT_PREFIXES)


def _looks_like_webpage_text(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _HTML_MARKERS)


def _extract_urls(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return tuple(urls[:5])
