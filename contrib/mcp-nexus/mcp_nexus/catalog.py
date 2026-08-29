"""Explicit tool catalog and task routing metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

TOOL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "filesystem": (
        "read_file",
        "write_file",
        "edit_file",
        "list_directory",
        "search_files",
        "search_content",
        "compare_paths",
        "file_info",
        "move_file",
        "delete_file",
        "create_directory",
        "tree",
        "tail_file",
        "head_file",
        "chmod_file",
        "chown_file",
        "file_exists",
        "batch_read",
        "replace_in_file",
        "count_lines",
    ),
    "terminal": (
        "execute_command",
        "execute_script",
        "execute_batch",
        "execute_python",
        "execute_python_file",
        "environment_info",
        "which_command",
        "server_capabilities",
        "create_python_sandbox",
        "list_python_sandboxes",
        "remove_python_sandbox",
    ),
    "git": (
        "git_status",
        "git_diagnose",
        "git_diff",
        "git_log",
        "git_commit",
        "git_branch",
        "git_pull",
        "git_push",
        "git_stash",
        "git_stage",
        "git_show",
        "git_fetch",
        "git_remotes",
        "git_blame",
        "git_tags",
    ),
    "debug": (
        "lint_python",
        "typecheck",
        "syntax_check",
        "find_todos",
        "code_symbols",
        "compare_files",
        "find_errors",
        "python_trace",
        "find_references",
        "run_tests",
        "format_code",
        "stack_traces",
    ),
    "process": (
        "list_services",
        "service_status",
        "restart_service",
        "start_service",
        "stop_service",
        "view_logs",
        "list_processes",
        "kill_process",
        "cron_list",
        "cron_add",
        "enable_service",
        "disable_service",
        "service_dependencies",
        "process_tree",
        "process_open_files",
        "process_status",
        "run_background_command",
        "background_job_status",
        "background_job_logs",
        "background_job_wait",
        "background_job_stop",
        "list_background_jobs",
        "docker_compose_ps",
        "docker_compose_logs",
    ),
    "database": (
        "db_client_status",
        "db_client_bootstrap",
        "inspect_database",
        "db_profiles",
        "db_use",
        "db_query",
        "db_safe_query",
        "db_tables",
        "db_schema",
        "db_table_inspect",
        "db_sample",
        "db_profile",
        "db_export_csv",
        "db_execute",
        "db_size",
        "db_explain",
        "db_query_explain",
        "db_indexes",
        "db_connections",
        "db_table_stats",
        "db_extensions",
        "db_join_suggest",
    ),
    "monitoring": (
        "server_health",
        "disk_usage",
        "memory_usage",
        "cpu_usage",
        "network_stats",
        "active_connections",
        "nginx_status",
        "docker_status",
        "server_resources",
        "io_activity",
    ),
    "deployment": (
        "deploy_sync",
        "deploy_service",
        "create_backup",
        "list_backups",
        "restore_backup",
        "pip_install",
        "deploy_release",
        "deploy_activate_release",
        "deploy_rollback_release",
        "deploy_compose",
        "deploy_health_check",
    ),
    "network": (
        "check_port",
        "dns_lookup",
        "ssl_info",
        "firewall_rules",
        "web_retrieve",
        "browser_bootstrap",
        "browser_runtime_status",
        "browser_screenshot",
        "browser_coordinate_click",
        "browser_fetch",
        "web_page_diagnose",
        "http_fetch",
        "curl_test",
        "listening_ports",
        "port_forward",
        "list_forwards",
        "remove_forward",
        "iptables_forward",
        "port_scan",
        "network_route",
        "trace_route",
        "ssh_tunnel",
    ),
    "packages": (
        "pip_list",
        "pip_show",
        "apt_list",
        "apt_install",
        "npm_list",
        "package_managers",
        "package_search",
        "package_info",
        "package_install",
        "package_outdated",
        "npm_install",
        "python_virtualenvs",
    ),
    "intelligence": (
        "nexus_recall",
        "nexus_insights",
        "nexus_suggest",
        "nexus_preferences",
        "nexus_workflows",
        "nexus_tool_catalog",
        "nexus_tool_registry",
        "nexus_tool_handoff",
    ),
    "analysis": (
        "tabular_dataset_profile",
        "train_tabular_classifier",
    ),
    "logs": (
        "nexus_audit_recent",
        "nexus_audit_summary",
        "nexus_audit_failures",
        "nexus_slowest_tools",
    ),
}


TOOL_TO_CATEGORY = {tool: category for category, tools in TOOL_CATEGORIES.items() for tool in tools}


TASK_FAMILY_POLICIES: dict[str, dict[str, object]] = {
    "web_retrieval": {
        "description": (
            "Direct webpage retrieval and blocked-access diagnosis should use structured network tools "
            "instead of generic shell or Python execution."
        ),
        "preferred_tools": (
            "web_retrieve",
            "web_page_diagnose",
            "http_fetch",
            "browser_fetch",
            "browser_bootstrap",
        ),
        "disallowed_tools": (
            "execute_command",
            "execute_batch",
            "execute_script",
            "execute_python",
        ),
        "workflow": {
            "outcomes": {
                "tool_unavailable": {
                    "reason": (
                        "A specialized web tool was unavailable or rejected before it could run; "
                        "verify the live registry and continue with the next preferred network tool."
                    ),
                    "next_tools": (
                        "nexus_tool_registry",
                        "web_retrieve",
                        "web_page_diagnose",
                        "http_fetch",
                    ),
                },
                "registry_mismatch": {
                    "reason": "A live registry check is required before retrying another specialized tool.",
                    "next_tools": ("nexus_tool_registry",),
                },
            },
            "transitions": {
                "http_fetch": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "Direct HTTP retrieval already recovered accessible content.",
                    },
                    "blocked_access": {
                        "reason": (
                            "Direct HTTP hit a same-origin challenge or gate; continue with the browser-capable path "
                            "instead of improvising new HTTP variants."
                        ),
                        "next_tools": (
                            "browser_fetch",
                            "web_retrieve",
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": (
                            "The next valid step is to provision or route through a browser-capable workflow."
                        ),
                        "next_tools": (
                            "web_retrieve",
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "nexus_tool_registry",
                        ),
                    },
                },
                "web_page_diagnose": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "Diagnosis already recovered or confirmed the accessible result.",
                    },
                    "interactive_browser_review_required": {
                        "reason": (
                            "The bounded diagnose pass captured a grounded browser review surface and still hit a "
                            "block. Continue with a deliberate coordinate click instead of stopping."
                        ),
                        "next_tools": (
                            "browser_coordinate_click",
                            "browser_screenshot",
                            "nexus_tool_registry",
                        ),
                    },
                    "post_click_review_required": {
                        "reason": (
                            "The bounded diagnose pass already executed one grounded browser click, but the page still "
                            "needs fresh visual review before any further interaction."
                        ),
                        "next_tools": (
                            "browser_screenshot",
                            "browser_coordinate_click",
                            "nexus_tool_registry",
                        ),
                    },
                    "blocked_after_browser_attempt": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": (
                            "The bounded diagnose pass already consumed its browser escalation and still hit a block; "
                            "do not invoke another same-origin retrieval tool."
                        ),
                    },
                    "blocked_access": {
                        "reason": (
                            "The bounded diagnose pass did not recover content; advance to the remaining browser-capable "
                            "workflow instead of repeating the same origin manually."
                        ),
                        "next_tools": (
                            "web_retrieve",
                            "browser_fetch",
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "nexus_tool_registry",
                        ),
                    },
                    "tool_unavailable": {
                        "reason": (
                            "If the one-shot diagnose tool is rejected, continue with the remaining specialized web tools."
                        ),
                        "next_tools": (
                            "nexus_tool_registry",
                            "web_retrieve",
                            "http_fetch",
                        ),
                    },
                },
                "web_retrieve": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "The bounded retrieval workflow already recovered accessible content.",
                    },
                    "interactive_browser_review_required": {
                        "reason": (
                            "The bounded retrieval workflow captured a grounded browser review surface and still hit a "
                            "block. Continue with a deliberate coordinate click instead of stopping."
                        ),
                        "next_tools": (
                            "browser_coordinate_click",
                            "browser_screenshot",
                            "nexus_tool_registry",
                        ),
                    },
                    "post_click_review_required": {
                        "reason": (
                            "The bounded retrieval workflow already executed one grounded browser click, but the page "
                            "still needs fresh visual review before any further interaction."
                        ),
                        "next_tools": (
                            "browser_screenshot",
                            "browser_coordinate_click",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": (
                            "The bounded retrieval workflow still needs a browser runtime to continue."
                        ),
                        "next_tools": (
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "browser_fetch",
                            "nexus_tool_registry",
                        ),
                    },
                    "blocked_after_browser_attempt": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": (
                            "The bounded retrieval workflow already attempted browser escalation and still hit a block; "
                            "do not keep invoking same-origin retrieval tools."
                        ),
                    },
                    "blocked_access": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": (
                            "The bounded browser-aware retrieval workflow is exhausted; do not loop on the same origin."
                        ),
                    },
                },
                "browser_runtime_status": {
                    "ok": {
                        "reason": "A browser runtime is present; continue with a headless fetch.",
                        "next_tools": (
                            "browser_fetch",
                            "web_retrieve",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": "No supported runtime is available yet; bootstrap Chromium or delegate to web_retrieve.",
                        "next_tools": (
                            "browser_bootstrap",
                            "web_retrieve",
                            "nexus_tool_registry",
                        ),
                    },
                },
                "browser_bootstrap": {
                    "ok": {
                        "reason": "A browser runtime is now available; continue with DOM retrieval.",
                        "next_tools": (
                            "browser_fetch",
                            "web_retrieve",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "terminal": True,
                        "action": "report_missing_runtime",
                        "reason": "No supported browser runtime could be provisioned on this host.",
                    },
                },
                "browser_fetch": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "Headless browser retrieval already recovered accessible content.",
                    },
                    "interactive_browser_review_required": {
                        "reason": (
                            "The DOM-only browser fetch hit a block, but interactive browser review remains available "
                            "through screenshot capture."
                        ),
                        "next_tools": (
                            "browser_screenshot",
                            "browser_coordinate_click",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": "The browser fetch cannot run without a browser runtime.",
                        "next_tools": (
                            "browser_bootstrap",
                            "web_retrieve",
                            "nexus_tool_registry",
                        ),
                    },
                    "blocked_after_browser_attempt": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": (
                            "The attempted browser retrieval still hit a block and this path does not support further "
                            "interactive escalation."
                        ),
                    },
                    "blocked_access": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": (
                            "The browser path is already exhausted; further same-origin retries would be redundant."
                        ),
                    },
                },
                "browser_screenshot": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "Visual browser capture recovered accessible page content.",
                    },
                    "visual_review_ready": {
                        "reason": (
                            "A screenshot and coordinate grid are available. Inspect the visual artifacts and continue "
                            "with a deliberate coordinate click if a grounded interaction target is visible."
                        ),
                        "next_tools": (
                            "browser_coordinate_click",
                            "browser_screenshot",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": (
                            "Visual browser review requires both a browser runtime and its supporting automation stack."
                        ),
                        "next_tools": (
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "nexus_tool_registry",
                        ),
                    },
                    "visual_capture_failed": {
                        "terminal": True,
                        "action": "report_blocked_access",
                        "reason": "Visual browser capture failed, so the interactive browser review path cannot continue.",
                    },
                },
                "browser_coordinate_click": {
                    "ok": {
                        "terminal": True,
                        "action": "use_current_result",
                        "reason": "The post-click page state is accessible.",
                    },
                    "post_click_review_required": {
                        "reason": (
                            "A single deliberate click ran, but the page still needs review. Capture a fresh screenshot "
                            "before choosing another grounded interaction."
                        ),
                        "next_tools": (
                            "browser_screenshot",
                            "browser_coordinate_click",
                            "nexus_tool_registry",
                        ),
                    },
                    "runtime_missing": {
                        "reason": (
                            "Coordinate clicks require the browser automation runtime; inspect or provision it before retrying."
                        ),
                        "next_tools": (
                            "browser_runtime_status",
                            "browser_bootstrap",
                            "nexus_tool_registry",
                        ),
                    },
                    "interaction_failed": {
                        "reason": (
                            "The click did not complete cleanly. Re-capture the page visually before deciding whether to retry."
                        ),
                        "next_tools": (
                            "browser_screenshot",
                            "nexus_tool_registry",
                        ),
                    },
                },
            },
        },
    },
}


@dataclass(frozen=True)
class CatalogSummary:
    total_tools: int
    category_counts: dict[str, int]


def _workflow_for_policy(policy: dict[str, object]) -> dict[str, Any]:
    workflow = policy.get("workflow")
    if not isinstance(workflow, dict):
        return {}
    return workflow


def _candidate_tools_from_transition(
    transition: dict[str, Any] | None,
    *,
    preferred_tools: tuple[str, ...],
    current_tool: str,
) -> tuple[str, ...]:
    if isinstance(transition, dict):
        if transition.get("terminal") and "next_tools" not in transition:
            return ()
        next_tools = transition.get("next_tools")
        if isinstance(next_tools, tuple):
            return tuple(str(tool) for tool in next_tools)
        if isinstance(next_tools, list):
            return tuple(str(tool) for tool in next_tools)
    return tuple(tool for tool in preferred_tools if tool != current_tool)


def _annotate_next_tools(
    tools: Iterable[str],
    *,
    available_tools: set[str] | None,
    reason: str,
    availability_scope: str | None = None,
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    annotated: list[dict[str, Any]] = []
    for priority, tool_name in enumerate(tools, start=1):
        tool = str(tool_name).strip()
        if not tool or tool in seen:
            continue
        seen.add(tool)
        annotated.append(
            {
                "tool": tool,
                "priority": priority,
                "available": None if available_tools is None else tool in available_tools,
                "availability_scope": availability_scope,
                "callable_surface_confirmed": None if availability_scope is None else False,
                "reason": reason,
            }
        )
    return annotated


def category_for_tool(tool_name: str) -> str | None:
    """Return the explicit category for a tool when known."""
    return TOOL_TO_CATEGORY.get(tool_name)


def category_counts() -> dict[str, int]:
    return {category: len(tools) for category, tools in TOOL_CATEGORIES.items()}


def catalog_summary() -> CatalogSummary:
    counts = category_counts()
    return CatalogSummary(total_tools=sum(counts.values()), category_counts=counts)


def task_family_for_tool(tool_name: str) -> str | None:
    """Return the task family that explicitly routes this tool, when known."""
    candidate = tool_name.strip()
    if not candidate:
        return None

    for family, policy in TASK_FAMILY_POLICIES.items():
        preferred_tools = tuple(str(tool) for tool in policy.get("preferred_tools", ()))
        disallowed_tools = tuple(str(tool) for tool in policy.get("disallowed_tools", ()))
        workflow = _workflow_for_policy(policy)
        transitions = workflow.get("transitions", {}) if isinstance(workflow, dict) else {}
        if (
            candidate in preferred_tools
            or candidate in disallowed_tools
            or (isinstance(transitions, dict) and candidate in transitions)
        ):
            return family
    return None


def task_family_workflow(task_family: str) -> dict[str, Any] | None:
    """Return the explicit workflow graph for a task family when known."""
    policy = TASK_FAMILY_POLICIES.get(task_family)
    if policy is None:
        return None
    workflow = _workflow_for_policy(policy)
    transitions = workflow.get("transitions", {}) if isinstance(workflow, dict) else {}
    outcomes = workflow.get("outcomes", {}) if isinstance(workflow, dict) else {}
    return {
        "outcomes": {
            str(name): dict(transition)
            for name, transition in outcomes.items()
            if isinstance(transition, dict)
        },
        "transitions": {
            str(tool_name): {
                str(outcome): dict(transition)
                for outcome, transition in tool_transitions.items()
                if isinstance(transition, dict)
            }
            for tool_name, tool_transitions in transitions.items()
            if isinstance(tool_transitions, dict)
        },
    }


def task_family_handoff(
    *,
    task_family: str = "",
    current_tool: str = "",
    outcome: str = "",
    available_tools: Iterable[str] | None = None,
    availability_scope: str | None = None,
) -> dict[str, Any] | None:
    """Resolve the next specialized tool sequence for a task-family handoff."""
    family = task_family.strip() or task_family_for_tool(current_tool) or ""
    if not family:
        return None

    policy = task_family_policy(family)
    if policy is None:
        return None
    workflow = task_family_workflow(family) or {}
    transition: dict[str, Any] | None = None
    current = current_tool.strip()
    normalized_outcome = outcome.strip()

    transitions = workflow.get("transitions", {})
    if current and normalized_outcome and isinstance(transitions, dict):
        tool_transitions = transitions.get(current)
        if isinstance(tool_transitions, dict):
            candidate_transition = tool_transitions.get(normalized_outcome)
            if isinstance(candidate_transition, dict):
                transition = candidate_transition

    if transition is None and normalized_outcome:
        outcomes = workflow.get("outcomes", {})
        if isinstance(outcomes, dict):
            candidate_transition = outcomes.get(normalized_outcome)
            if isinstance(candidate_transition, dict):
                transition = candidate_transition

    preferred_tools = tuple(str(tool) for tool in policy["preferred_tools"])
    disallowed_tools = tuple(str(tool) for tool in policy["disallowed_tools"])
    available_set = set(str(tool) for tool in available_tools) if available_tools is not None else None
    reason = (
        str(transition.get("reason"))
        if isinstance(transition, dict) and transition.get("reason")
        else str(policy["description"])
    )
    next_tools = _annotate_next_tools(
        _candidate_tools_from_transition(transition, preferred_tools=preferred_tools, current_tool=current),
        available_tools=available_set,
        reason=reason,
        availability_scope=availability_scope,
    )
    recommended_tool = next(
        (item["tool"] for item in next_tools if item["available"] is not False),
        None,
    )
    terminal = bool(isinstance(transition, dict) and transition.get("terminal"))
    action = str(transition.get("action")) if isinstance(transition, dict) and transition.get("action") else None

    return {
        "task_family": family,
        "current_tool": current or None,
        "outcome": normalized_outcome or None,
        "reason": reason,
        "recommended_tool": recommended_tool,
        "next_tools": next_tools,
        "terminal": terminal,
        "action": action,
        "availability_scope": availability_scope,
        "preferred_tools": list(preferred_tools),
        "disallowed_tools": list(disallowed_tools),
    }


def task_family_policy(task_family: str) -> dict[str, object] | None:
    """Return the explicit routing policy for a task family when known."""
    policy = TASK_FAMILY_POLICIES.get(task_family)
    if policy is None:
        return None
    return {
        "description": str(policy["description"]),
        "preferred_tools": tuple(str(tool) for tool in policy["preferred_tools"]),
        "disallowed_tools": tuple(str(tool) for tool in policy["disallowed_tools"]),
        "workflow": task_family_workflow(task_family) or {},
    }
