"""Network tools for connectivity, forwarding, and web access inspection."""

from __future__ import annotations

import html
import json
import base64
import hashlib
import math
import re
import shlex
import time
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from mcp_nexus.catalog import task_family_handoff
from mcp_nexus.results import ToolResult, build_tool_result
from mcp_nexus.server import control_plane_reference, get_artifacts, get_pool, get_registry, get_settings, tool_context

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}
_CHALLENGE_MARKERS = (
    "are you a robot",
    "captcha",
    "verify you are human",
    "human verification",
    "access denied",
)
_GATED_CONTENT_MARKERS = (
    "subscribe to continue",
    "subscription required",
    "already a subscriber",
    "sign in to continue",
    "log in to continue",
)
_CURL_EXIT_MARKER = "__NEXUS_CURL_EXIT__"
_CURL_META_MARKER = "__NEXUS_CURL_META__"
_CURL_HEADERS_MARKER = "__NEXUS_CURL_HEADERS__"
_CURL_BODY_MARKER = "__NEXUS_CURL_BODY__"
_BROWSER_SCREENSHOT_STATUS_MARKER = "__NEXUS_BROWSER_SCREENSHOT_STATUS__"
_BROWSER_SCREENSHOT_STDERR_MARKER = "__NEXUS_BROWSER_SCREENSHOT_STDERR__"
_BROWSER_SCREENSHOT_B64_MARKER = "__NEXUS_BROWSER_SCREENSHOT_B64__"
_BROWSER_CANDIDATE_COMMANDS = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "firefox",
    "playwright",
    "node",
    "npm",
    "npx",
    "python3",
)
_CHROMIUM_FAMILY_COMMANDS = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
)
_BROWSER_BOOTSTRAP_TARGETS = ("chromium",)
_BLOCKED_ACCESS_CLASSIFICATIONS = frozenset(
    {
        "challenge_page",
        "forbidden",
        "rate_limited",
        "content_gated",
        "authentication_required",
    }
)
_SURFACE_VERIFICATION_GATED_TOOLS = frozenset(
    {
        "browser_screenshot",
        "browser_coordinate_click",
        "nexus_tool_registry",
    }
)
_BROWSER_CAPABILITY_HINTS = (
    ("chromium", "chromium"),
    ("chromium_browser", "chromium-browser"),
    ("google_chrome", "google-chrome"),
    ("google_chrome_stable", "google-chrome-stable"),
)
_MAX_GROUNDED_CLICK_ATTEMPTS = 3


def _result(
    tool_name: str,
    *,
    ok: bool,
    duration_ms: float,
    stdout_text: str = "",
    stderr_text: str = "",
    error_code: str | None = None,
    error_stage: str | None = None,
    message: str | None = None,
    exit_code: int | None = None,
    data: Any = None,
    usage: dict[str, Any] | None = None,
    extra_artifacts=None,
) -> ToolResult:
    settings = get_settings()
    return build_tool_result(
        context=tool_context(tool_name),
        artifacts=get_artifacts(),
        ok=ok,
        duration_ms=duration_ms,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        output_limit=settings.output_limit_bytes,
        error_limit=settings.error_limit_bytes,
        output_preview_limit=settings.output_preview_bytes,
        error_preview_limit=settings.error_preview_bytes,
        error_code=error_code,
        error_stage=error_stage,
        message=message,
        exit_code=exit_code,
        data=data,
        resource_usage=usage,
        extra_artifacts=extra_artifacts,
    )


def _merge_request_headers(headers: dict[str, str] | None, *, browser_profile: bool) -> dict[str, str]:
    merged = dict(_BROWSER_HEADERS) if browser_profile else {}
    for key, value in (headers or {}).items():
        if not key.strip() or not value.strip():
            continue
        merged[key.strip()] = value.strip()
    return merged


def _header_value(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _extract_html_metadata(body: str) -> dict[str, str]:
    patterns = (
        (r"<title[^>]*>(.*?)</title>", "title"),
        (r'<meta\s+property=["\']og:title["\']\s+content=["\'](.*?)["\']', "og_title"),
        (r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', "og_description"),
        (r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', "description"),
        (r'<meta\s+property=["\']og:url["\']\s+content=["\'](.*?)["\']', "og_url"),
    )
    metadata: dict[str, str] = {}
    for pattern, name in patterns:
        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        value = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
        if value:
            metadata[name] = value
    return metadata


def _strip_html_text(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return text


def _attr_value(raw_attrs: str, name: str) -> str:
    pattern = rf'{re.escape(name)}\s*=\s*["\'](.*?)["\']'
    match = re.search(pattern, raw_attrs, re.IGNORECASE | re.DOTALL)
    if match:
        return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    pattern = rf"{re.escape(name)}\s*=\s*([^\s>]+)"
    match = re.search(pattern, raw_attrs, re.IGNORECASE)
    if match:
        return html.unescape(match.group(1)).strip()
    return ""


def _host_for_src(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.netloc:
        return parsed.netloc
    return None


def _extract_dom_affordances(body: str, *, max_entries: int = 12) -> dict[str, Any]:
    affordances: list[dict[str, Any]] = []
    visual_elements: list[dict[str, Any]] = []
    button_count = 0
    input_count = 0
    iframe_count = 0
    image_count = 0
    canvas_count = 0
    script_count = 0

    for match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", body, re.IGNORECASE | re.DOTALL):
        button_count += 1
        if len(affordances) >= max_entries:
            continue
        attrs, inner = match.groups()
        label = _strip_html_text(inner)
        affordances.append(
            {
                "tag": "button",
                "type": _attr_value(attrs, "type") or "button",
                "label": label or None,
                "id": _attr_value(attrs, "id") or None,
                "name": _attr_value(attrs, "name") or None,
                "aria_label": _attr_value(attrs, "aria-label") or None,
            }
        )

    for match in re.finditer(r"<input\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
        input_count += 1
        if len(affordances) >= max_entries:
            continue
        attrs = match.group(1)
        affordances.append(
            {
                "tag": "input",
                "type": _attr_value(attrs, "type") or "text",
                "label": _attr_value(attrs, "value") or None,
                "id": _attr_value(attrs, "id") or None,
                "name": _attr_value(attrs, "name") or None,
                "aria_label": _attr_value(attrs, "aria-label") or None,
            }
        )

    for match in re.finditer(r"<iframe\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
        iframe_count += 1
        if len(affordances) >= max_entries:
            continue
        attrs = match.group(1)
        src = _attr_value(attrs, "src")
        affordances.append(
            {
                "tag": "iframe",
                "src": src or None,
                "host": _host_for_src(src),
                "title": _attr_value(attrs, "title") or None,
                "id": _attr_value(attrs, "id") or None,
                "name": _attr_value(attrs, "name") or None,
            }
        )

    for match in re.finditer(r"<img\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
        image_count += 1
        if len(visual_elements) >= max_entries:
            continue
        attrs = match.group(1)
        src = _attr_value(attrs, "src")
        visual_elements.append(
            {
                "tag": "img",
                "src": src or None,
                "host": _host_for_src(src),
                "alt": _attr_value(attrs, "alt") or None,
                "title": _attr_value(attrs, "title") or None,
            }
        )

    for match in re.finditer(r"<canvas\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
        canvas_count += 1
        if len(visual_elements) >= max_entries:
            continue
        attrs = match.group(1)
        visual_elements.append(
            {
                "tag": "canvas",
                "id": _attr_value(attrs, "id") or None,
                "aria_label": _attr_value(attrs, "aria-label") or None,
                "title": _attr_value(attrs, "title") or None,
            }
        )

    provider_hosts: list[str] = []
    script_sources: list[str] = []
    for match in re.finditer(r"<script\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
        script_count += 1
        src = _attr_value(match.group(1), "src")
        host = _host_for_src(src)
        if host and host not in provider_hosts:
            provider_hosts.append(host)
        if src and len(script_sources) < max_entries and src not in script_sources:
            script_sources.append(src)

    form_count = len(re.findall(r"<form\b", body, re.IGNORECASE))
    checkbox_count = len(re.findall(r"<input\b[^>]*type\s*=\s*[\"']?checkbox", body, re.IGNORECASE))
    interactive = any(item["tag"] in {"button", "input", "iframe"} for item in affordances)
    visual = any(item["tag"] in {"img", "canvas"} for item in visual_elements)
    return {
        "interactive_elements": affordances,
        "visual_elements": visual_elements,
        "counts": {
            "form": form_count,
            "button": button_count,
            "input": input_count,
            "checkbox": checkbox_count,
            "iframe": iframe_count,
            "image": image_count,
            "canvas": canvas_count,
            "script": script_count,
        },
        "provider_hosts": provider_hosts,
        "script_sources": script_sources,
        "interactive_surface_detected": interactive,
        "visual_surface_detected": visual,
    }


def _browser_interaction_capability(*, wait_ms: int) -> dict[str, Any]:
    return {
        "mode": "read_only_dom_dump",
        "click_supported": False,
        "form_fill_supported": False,
        "captcha_completion_supported": False,
        "wait_ms": max(0, wait_ms),
        "reason": (
            "This browser path is a bounded read-only DOM capture. When continuation is returned, "
            "use the indicated visual or interaction tool for grounded follow-up."
        ),
    }


def _http_interaction_capability() -> dict[str, Any]:
    return {
        "mode": "http_response_only",
        "click_supported": False,
        "form_fill_supported": False,
        "captcha_completion_supported": False,
        "reason": "Direct HTTP retrieval does not execute page scripts or perform interactive actions.",
    }


def _count_fragment(count: int, singular: str, plural: str | None = None) -> str:
    if count <= 0:
        return ""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _surface_observation_summary(
    dom_observation: dict[str, Any] | None,
    interaction_capability: dict[str, Any] | None = None,
    *,
    include_provider_hosts: bool = False,
) -> str:
    if not isinstance(dom_observation, dict):
        return ""

    counts = dom_observation.get("counts")
    if not isinstance(counts, dict):
        counts = {}

    total_inputs = int(counts.get("input") or 0)
    checkbox_inputs = int(counts.get("checkbox") or 0)
    non_checkbox_inputs = max(0, total_inputs - checkbox_inputs)

    control_parts = [
        fragment
        for fragment in (
            _count_fragment(int(counts.get("button") or 0), "button"),
            _count_fragment(checkbox_inputs, "checkbox input", "checkbox inputs"),
            _count_fragment(non_checkbox_inputs, "input"),
            _count_fragment(int(counts.get("iframe") or 0), "iframe"),
        )
        if fragment
    ]
    visual_parts = [
        fragment
        for fragment in (
            _count_fragment(int(counts.get("image") or 0), "image"),
            _count_fragment(int(counts.get("canvas") or 0), "canvas"),
        )
        if fragment
    ]

    summary_parts: list[str] = []
    if control_parts:
        summary_parts.append(f"Captured static DOM controls: {', '.join(control_parts)}.")
    else:
        summary_parts.append("Captured no static button, input, or iframe controls in the DOM dump.")

    if visual_parts:
        summary_parts.append(f"Captured visual DOM elements: {', '.join(visual_parts)}.")

    provider_hosts = dom_observation.get("provider_hosts")
    if include_provider_hosts and isinstance(provider_hosts, list) and provider_hosts:
        summary_parts.append(f"Loaded external scripts from {', '.join(provider_hosts[:3])}.")

    if isinstance(interaction_capability, dict) and interaction_capability.get("reason"):
        summary_parts.append(str(interaction_capability["reason"]))

    return " ".join(summary_parts)


def _display_stdout_text(
    body_preview: str,
    assessment: dict[str, Any],
    *,
    continuation: dict[str, Any] | None = None,
) -> str:
    if assessment.get("accessible"):
        return body_preview
    if isinstance(continuation, dict) and continuation.get("state") == "invoke_tool":
        return ""
    if _is_blocked_access_classification(assessment):
        return ""
    return body_preview


def _truncate_text(value: str, limit: int = 120) -> str:
    normalized = re.sub(r"\s+", " ", value or "").strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(1, limit - 1)].rstrip() + "…"


def _normalize_interaction_targets(
    raw_targets: Any,
    *,
    viewport_width: int,
    viewport_height: int,
    max_entries: int = 32,
) -> list[dict[str, Any]]:
    if not isinstance(raw_targets, list):
        return []

    normalized_targets: list[dict[str, Any]] = []
    for raw_target in raw_targets[: max(1, max_entries)]:
        if not isinstance(raw_target, dict):
            continue
        try:
            center_x = int(round(float(raw_target.get("center_x"))))
            center_y = int(round(float(raw_target.get("center_y"))))
            width = max(0, int(round(float(raw_target.get("width") or 0))))
            height = max(0, int(round(float(raw_target.get("height") or 0))))
            viewport_area = max(1, int(round(float(raw_target.get("viewport_area") or (viewport_width * viewport_height) or 1))))
            visible_area = max(0, int(round(float(raw_target.get("visible_area") or 0))))
            visibility_ratio = max(0.0, min(1.0, float(raw_target.get("visibility_ratio") or 0.0)))
        except (TypeError, ValueError):
            continue

        label = _truncate_text(str(raw_target.get("label") or ""))
        normalized_targets.append(
            {
                "tag": str(raw_target.get("tag") or "").strip() or None,
                "kind": str(raw_target.get("kind") or "").strip() or "generic",
                "role": str(raw_target.get("role") or "").strip() or None,
                "input_type": str(raw_target.get("input_type") or "").strip() or None,
                "label": label or None,
                "title": _truncate_text(str(raw_target.get("title") or "")) or None,
                "aria_label": _truncate_text(str(raw_target.get("aria_label") or "")) or None,
                "selector_hint": str(raw_target.get("selector_hint") or "").strip() or None,
                "associated_control_kind": str(raw_target.get("associated_control_kind") or "").strip() or None,
                "clickable": bool(raw_target.get("clickable")),
                "visible": bool(raw_target.get("visible")),
                "in_viewport": bool(raw_target.get("in_viewport")),
                "disabled": bool(raw_target.get("disabled")),
                "pointer": bool(raw_target.get("pointer")),
                "checked": bool(raw_target.get("checked")),
                "x": max(0, center_x),
                "y": max(0, center_y),
                "width": width,
                "height": height,
                "visible_area": visible_area,
                "visibility_ratio": visibility_ratio,
                "viewport_area": viewport_area,
                "viewport_width": max(1, viewport_width),
                "viewport_height": max(1, viewport_height),
            }
        )
    return normalized_targets


def _interaction_target_summary(targets: list[dict[str, Any]]) -> str:
    visible_targets = [target for target in targets if target.get("visible") and target.get("in_viewport")]
    if not visible_targets:
        return "Detected no visible browser interaction targets with grounded viewport coordinates."

    kinds: list[str] = []
    for target in visible_targets:
        kind = str(target.get("kind") or "generic")
        if kind not in kinds:
            kinds.append(kind)
    count = len(visible_targets)
    count_label = "target" if count == 1 else "targets"
    kind_label = ", ".join(kinds[:4])
    return f"Detected {count} visible browser interaction {count_label} with grounded viewport coordinates: {kind_label}."


def _target_area_ratio(target: dict[str, Any]) -> float:
    viewport_area = max(
        1,
        int(
            target.get("viewport_area")
            or (
                max(1, int(target.get("viewport_width") or 1))
                * max(1, int(target.get("viewport_height") or 1))
            )
        ),
    )
    visible_area = int(target.get("visible_area") or 0)
    width = max(0, int(target.get("width") or 0))
    height = max(0, int(target.get("height") or 0))
    area = max(visible_area, width * height)
    return max(0.0, min(1.0, float(area) / float(viewport_area)))


def _target_center_proximity(target: dict[str, Any]) -> float:
    viewport_width = max(1, int(target.get("viewport_width") or 1))
    viewport_height = max(1, int(target.get("viewport_height") or 1))
    center_x = float(target.get("x") or 0)
    center_y = float(target.get("y") or 0)
    dx = (center_x - (viewport_width / 2.0)) / (viewport_width / 2.0)
    dy = (center_y - (viewport_height / 2.0)) / (viewport_height / 2.0)
    distance = min(1.0, math.sqrt((dx * dx) + (dy * dy)))
    return max(0.0, 1.0 - distance)


def _rank_interaction_candidates(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kind_weight = {
        "checkbox": 0.92,
        "radio": 0.9,
        "button": 0.88,
        "submit": 0.86,
        "role_button": 0.84,
        "role_checkbox": 0.82,
        "label": 0.7,
        "iframe": 0.74,
        "link": 0.62,
        "input": 0.58,
        "generic": 0.48,
    }
    ranked: list[dict[str, Any]] = []
    for target in targets:
        if not (target.get("clickable") and target.get("visible") and target.get("in_viewport")):
            continue
        if target.get("disabled"):
            continue

        kind = str(target.get("kind") or "generic")
        associated = str(target.get("associated_control_kind") or "")
        base = kind_weight.get(kind, 0.48)
        if kind == "label" and associated in {"checkbox", "radio"}:
            base = max(base, 0.8)
        pointer_bonus = 0.08 if target.get("pointer") else 0.0
        text_bonus = 0.04 if any(target.get(field) for field in ("label", "title", "aria_label")) else 0.0
        area_bonus = min(0.14, math.sqrt(_target_area_ratio(target)) * 0.28)
        center_bonus = _target_center_proximity(target) * 0.08
        checked_penalty = -0.04 if target.get("checked") and kind in {"checkbox", "radio", "role_checkbox"} else 0.0
        score = max(
            0.0,
            min(
                1.0,
                base + pointer_bonus + text_bonus + area_bonus + center_bonus + checked_penalty,
            ),
        )
        ranked.append(
            {
                "target": target,
                "score": round(score, 3),
                "score_components": {
                    "base": round(base, 3),
                    "pointer_bonus": round(pointer_bonus, 3),
                    "text_bonus": round(text_bonus, 3),
                    "area_bonus": round(area_bonus, 3),
                    "center_bonus": round(center_bonus, 3),
                    "checked_penalty": round(checked_penalty, 3),
                },
            }
        )
    ranked.sort(
        key=lambda item: (
            float(item.get("score") or 0.0),
            int(item.get("target", {}).get("visible_area") or 0),
        ),
        reverse=True,
    )
    return ranked


def _auto_interaction_suggestion(ranked_candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not ranked_candidates:
        return None
    top = ranked_candidates[0]
    target = top.get("target") or {}
    return {
        "x": int(target.get("x") or 0),
        "y": int(target.get("y") or 0),
        "kind": str(target.get("kind") or "generic"),
        "confidence": float(top.get("score") or 0.0),
    }


def _auto_interaction_plan(
    assessment: dict[str, Any],
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    ranked_candidates = _rank_interaction_candidates(targets)
    candidate_ranking = [
        {
            "kind": str(item.get("target", {}).get("kind") or "generic"),
            "x": int(item.get("target", {}).get("x") or 0),
            "y": int(item.get("target", {}).get("y") or 0),
            "score": float(item.get("score") or 0.0),
            "selector_hint": item.get("target", {}).get("selector_hint"),
            "label": item.get("target", {}).get("label"),
            "score_components": item.get("score_components"),
        }
        for item in ranked_candidates[:5]
    ]
    suggested_click_request = _auto_interaction_suggestion(ranked_candidates)
    if not _is_blocked_access_classification(assessment):
        return {
            "eligible": False,
            "reason": "Automatic browser interaction is reserved for blocked or challenge page states.",
            "selected_target": None,
            "click_request": None,
            "requires_visual_review": False,
            "suggested_click_request": None,
            "candidate_ranking": [],
        }

    high_confidence: list[dict[str, Any]] = []
    iframe_targets: list[dict[str, Any]] = []
    for target in targets:
        if not (target.get("clickable") and target.get("visible") and target.get("in_viewport")):
            continue
        if target.get("disabled"):
            continue

        kind = str(target.get("kind") or "")
        associated = str(target.get("associated_control_kind") or "")
        if kind in {"checkbox", "radio", "button", "submit", "role_button", "role_checkbox"}:
            high_confidence.append(target)
            continue
        if kind == "label" and associated in {"checkbox", "radio"}:
            high_confidence.append(target)
            continue
        if kind == "iframe":
            iframe_targets.append(target)

    selected_target: dict[str, Any] | None = None
    reason = ""
    if len(high_confidence) == 1:
        selected_target = high_confidence[0]
        reason = "Exactly one high-confidence visible interaction target was detected on the blocked page."
    elif not high_confidence and len(iframe_targets) == 1:
        selected_target = iframe_targets[0]
        reason = (
            "No high-confidence semantic control was detected, but a single visible iframe target was present on "
            "the blocked page."
        )
    elif high_confidence:
        reason = (
            "Automatic browser interaction requires a single grounded high-confidence target; "
            f"detected {len(high_confidence)}."
        )
    elif iframe_targets:
        reason = (
            "Automatic browser interaction requires a single grounded iframe target when semantic controls are "
            f"absent; detected {len(iframe_targets)}."
        )
    else:
        reason = "No visible clickable browser target was grounded well enough for an automatic click."

    if selected_target is None:
        if ranked_candidates:
            top = ranked_candidates[0]
            top_target = top.get("target") or {}
            top_score = float(top.get("score") or 0.0)
            second_score = float(ranked_candidates[1].get("score") or 0.0) if len(ranked_candidates) > 1 else 0.0
            margin = top_score - second_score
            top_kind = str(top_target.get("kind") or "generic")
            semantic_top = top_kind in {
                "checkbox",
                "radio",
                "button",
                "submit",
                "role_button",
                "role_checkbox",
            } or (
                top_kind == "label"
                and str(top_target.get("associated_control_kind") or "") in {"checkbox", "radio"}
            )
            minimum_score = 0.62 if semantic_top else 0.72 if top_kind == "iframe" else 0.68
            minimum_margin = 0.05 if semantic_top else 0.08 if top_kind == "iframe" else 0.12
            if top_score >= minimum_score and (len(ranked_candidates) == 1 or margin >= minimum_margin):
                selected_target = top_target
                reason = (
                    "Selected the top-ranked grounded interaction target using semantic role, viewport visibility, "
                    "and confidence margin."
                )
            elif not reason:
                reason = (
                    "Grounded interaction targets were detected, but confidence was not high enough for an automatic "
                    "click without additional visual confirmation."
                )
        elif not reason:
            reason = "No visible clickable browser target was grounded well enough for an automatic click."

    if selected_target is None:
        return {
            "eligible": False,
            "reason": reason,
            "selected_target": None,
            "click_request": None,
            "requires_visual_review": True,
            "suggested_click_request": suggested_click_request,
            "candidate_ranking": candidate_ranking,
        }

    click_request = {
        "x": int(selected_target["x"]),
        "y": int(selected_target["y"]),
    }
    return {
        "eligible": True,
        "reason": reason,
        "selected_target": selected_target,
        "click_request": click_request,
        "requires_visual_review": False,
        "suggested_click_request": suggested_click_request,
        "candidate_ranking": candidate_ranking,
    }


def _auto_interaction_guidance_text(auto_interaction: dict[str, Any] | None) -> str:
    if not isinstance(auto_interaction, dict):
        return ""
    click_request = auto_interaction.get("click_request")
    if isinstance(click_request, dict):
        try:
            x = int(click_request.get("x"))
            y = int(click_request.get("y"))
        except (TypeError, ValueError):
            x = y = None
        if x is not None and y is not None:
            return f"Auto-interaction selected grounded coordinate ({x}, {y})."

    suggested = auto_interaction.get("suggested_click_request")
    if isinstance(suggested, dict):
        try:
            x = int(suggested.get("x"))
            y = int(suggested.get("y"))
        except (TypeError, ValueError):
            x = y = None
        if x is not None and y is not None:
            return (
                f"Suggested grounded manual-click candidate: ({x}, {y}). "
                "Confirm against the current grid before replaying."
            )
    return ""


def _attempt_state_signature(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "classification": None,
            "accessible": None,
            "title": "",
            "final_url": "",
            "body_hash": None,
            "iframe_count": 0,
            "interaction_target_count": 0,
            "auto_click_eligible": False,
            "suggested_click_request": None,
        }

    assessment = payload.get("assessment")
    response = payload.get("response")
    body_preview = str(payload.get("body_preview") or "")
    normalized_body = re.sub(r"\s+", " ", body_preview).strip().lower()
    body_hash = (
        hashlib.sha1(normalized_body.encode("utf-8")).hexdigest()[:16]
        if normalized_body
        else None
    )

    title = ""
    final_url = ""
    iframe_count = 0
    interaction_target_count = 0
    auto_click_eligible = False
    suggested_click_request = None
    if isinstance(response, dict):
        metadata = response.get("metadata")
        if isinstance(metadata, dict):
            title = str(metadata.get("title") or "")
        final_url = str(response.get("final_url") or "")
        dom_observation = response.get("dom_observation")
        if isinstance(dom_observation, dict):
            counts = dom_observation.get("counts")
            if isinstance(counts, dict):
                iframe_count = int(counts.get("iframe") or 0)
        targets = response.get("interaction_targets")
        if isinstance(targets, list):
            interaction_target_count = len(targets)
        auto_interaction = response.get("auto_interaction")
        if isinstance(auto_interaction, dict):
            auto_click_eligible = bool(auto_interaction.get("eligible"))
            suggestion = auto_interaction.get("suggested_click_request") or auto_interaction.get("click_request")
            if isinstance(suggestion, dict):
                try:
                    suggested_click_request = {"x": int(suggestion.get("x")), "y": int(suggestion.get("y"))}
                except (TypeError, ValueError):
                    suggested_click_request = None
    request = payload.get("request")
    if isinstance(request, dict) and not final_url:
        final_url = str(request.get("url") or "")

    return {
        "classification": str(assessment.get("classification") or "") if isinstance(assessment, dict) else "",
        "accessible": bool(assessment.get("accessible")) if isinstance(assessment, dict) else False,
        "title": title,
        "final_url": final_url,
        "body_hash": body_hash,
        "iframe_count": iframe_count,
        "interaction_target_count": interaction_target_count,
        "auto_click_eligible": auto_click_eligible,
        "suggested_click_request": suggested_click_request,
    }


def _post_click_challenge_diagnostics(
    *,
    pre_payload: dict[str, Any] | None,
    click_payload: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(click_payload, dict):
        return None
    pre_state = _attempt_state_signature(pre_payload)
    post_state = _attempt_state_signature(click_payload)
    state_changes: list[str] = []
    if pre_state["final_url"] and post_state["final_url"] and pre_state["final_url"] != post_state["final_url"]:
        state_changes.append("url_changed")
    if pre_state["title"] and post_state["title"] and pre_state["title"] != post_state["title"]:
        state_changes.append("title_changed")
    if pre_state["classification"] and post_state["classification"] and pre_state["classification"] != post_state["classification"]:
        state_changes.append("classification_changed")
    if pre_state["body_hash"] and post_state["body_hash"] and pre_state["body_hash"] != post_state["body_hash"]:
        state_changes.append("dom_changed")
    state_changed = bool(state_changes)

    blocked_after_click = bool(
        not post_state["accessible"]
        and _is_blocked_access_classification({"classification": post_state["classification"]})
    )
    likely_blockers: list[dict[str, str]] = []
    if blocked_after_click and not state_changed:
        likely_blockers.append(
            {
                "code": "challenge_state_unchanged_after_click",
                "reason": (
                    "Click was executed, but URL/title/classification and DOM fingerprint did not progress. "
                    "The coordinate likely did not advance the challenge state."
                ),
            }
        )
    if blocked_after_click and post_state["iframe_count"] > 0 and post_state["interaction_target_count"] == 0:
        likely_blockers.append(
            {
                "code": "embedded_challenge_requires_in_frame_steps",
                "reason": (
                    "Blocked state still exposes iframe-based challenge surface without grounded post-click targets. "
                    "This usually needs additional in-frame steps and an explicit confirmation control."
                ),
            }
        )
    if blocked_after_click and state_changed and not post_state["accessible"]:
        likely_blockers.append(
            {
                "code": "challenge_progressed_but_not_resolved",
                "reason": (
                    "Click changed page state but did not reach accessible content. "
                    "The verification flow likely has additional steps before completion."
                ),
            }
        )

    if post_state["accessible"]:
        summary = "Post-click page state is accessible."
    elif blocked_after_click:
        summary = (
            "Click executed but page remains in blocked/challenge classification; additional challenge-state "
            "transitions are still required."
        )
    else:
        summary = "Click executed but page is still inaccessible."

    return {
        "pre_click": pre_state,
        "post_click": post_state,
        "state_changed": state_changed,
        "state_changes": state_changes,
        "blocked_after_click": blocked_after_click,
        "likely_blockers": likely_blockers,
        "suggested_click_request": post_state.get("suggested_click_request"),
        "summary": summary,
        "required_success_signal": (
            "Challenge classification must transition to accessible content (e.g., classification=ok with article DOM)."
        ),
    }


def _challenge_diagnostic_note(diagnostics: dict[str, Any] | None) -> str:
    if not isinstance(diagnostics, dict):
        return ""
    if diagnostics.get("post_click", {}).get("accessible"):
        return ""
    note_parts = [str(diagnostics.get("summary") or "").strip()]
    blockers = diagnostics.get("likely_blockers")
    if isinstance(blockers, list):
        reason_bits = [str(item.get("reason") or "").strip() for item in blockers if isinstance(item, dict)]
        reason_bits = [bit for bit in reason_bits if bit]
        if reason_bits:
            note_parts.append(reason_bits[0])
    suggested = diagnostics.get("suggested_click_request")
    if isinstance(suggested, dict):
        try:
            x = int(suggested.get("x"))
            y = int(suggested.get("y"))
            note_parts.append(f"Suggested next grounded click candidate: ({x}, {y}).")
        except (TypeError, ValueError):
            pass
    return " ".join(part for part in note_parts if part)


def _user_assistance_request_note(
    *,
    final_assessment: dict[str, Any] | None,
    final_visual_evidence: dict[str, Any] | None,
    challenge_diagnostics: dict[str, Any] | None,
) -> str:
    if not isinstance(final_assessment, dict):
        return ""
    if final_assessment.get("accessible"):
        return ""
    if not _is_blocked_access_classification(final_assessment):
        return ""
    if not isinstance(final_visual_evidence, dict):
        return ""

    note_parts = [
        "Challenge state remains blocked after bounded interaction attempts.",
        "The latest screen and coordinate-grid artifacts are attached.",
    ]
    suggested = None
    if isinstance(challenge_diagnostics, dict):
        candidate = challenge_diagnostics.get("suggested_click_request")
        if isinstance(candidate, dict):
            suggested = candidate
    if isinstance(suggested, dict):
        try:
            x = int(suggested.get("x"))
            y = int(suggested.get("y"))
            note_parts.append(f"Current grounded suggestion: ({x}, {y}).")
        except (TypeError, ValueError):
            pass
    note_parts.append(
        "Please indicate which visible control should be clicked next so the flow can continue on this same page."
    )
    return " ".join(note_parts).strip()


def _browser_automation_capability(runtime_status: dict[str, Any]) -> dict[str, Any]:
    commands = runtime_status.get("commands")
    if not isinstance(commands, dict):
        commands = {}
    browser_available = bool(runtime_status.get("headless_dom_supported"))
    node_path = commands.get("node")
    return {
        "visual_capture_supported": browser_available,
        "coordinate_click_supported": bool(browser_available and node_path),
        "coordinate_click_runtime": "node_cdp" if browser_available and node_path else None,
        "node_path": node_path,
    }


def _grid_svg_document(
    *,
    png_base64: str,
    width: int,
    height: int,
    grid_step_px: int,
    marker: tuple[int, int] | None = None,
) -> str:
    step = max(25, grid_step_px)
    width = max(1, width)
    height = max(1, height)
    vertical_lines = []
    horizontal_lines = []
    labels = []
    for x in range(0, width + 1, step):
        stroke = "#d94f00" if x % (step * 5) == 0 else "#ffffff"
        opacity = "0.55" if x % (step * 5) == 0 else "0.28"
        vertical_lines.append(
            f'<line x1="{x}" y1="0" x2="{x}" y2="{height}" stroke="{stroke}" stroke-width="1" opacity="{opacity}" />'
        )
        labels.append(
            f'<text x="{min(x + 4, max(8, width - 40))}" y="16" font-size="12" '
            'font-family="monospace" fill="#d94f00">{x}</text>'
        )
    for y in range(0, height + 1, step):
        stroke = "#d94f00" if y % (step * 5) == 0 else "#ffffff"
        opacity = "0.55" if y % (step * 5) == 0 else "0.28"
        horizontal_lines.append(
            f'<line x1="0" y1="{y}" x2="{width}" y2="{y}" stroke="{stroke}" stroke-width="1" opacity="{opacity}" />'
        )
        labels.append(
            f'<text x="6" y="{min(y + 14, max(16, height - 6))}" font-size="12" '
            'font-family="monospace" fill="#d94f00">{y}</text>'
        )

    marker_svg = ""
    if marker is not None:
        x, y = marker
        marker_svg = (
            f'<circle cx="{x}" cy="{y}" r="8" fill="none" stroke="#00d4ff" stroke-width="3" />'
            f'<line x1="{max(0, x - 18)}" y1="{y}" x2="{min(width, x + 18)}" y2="{y}" '
            'stroke="#00d4ff" stroke-width="2" />'
            f'<line x1="{x}" y1="{max(0, y - 18)}" x2="{x}" y2="{min(height, y + 18)}" '
            'stroke="#00d4ff" stroke-width="2" />'
            f'<text x="{min(x + 12, max(24, width - 120))}" y="{max(20, y - 12)}" font-size="14" '
            'font-family="monospace" fill="#00d4ff">click '
            f'({x}, {y})</text>'
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<image href="data:image/png;base64,{png_base64}" width="{width}" height="{height}" />'
        '<rect x="0" y="0" width="100%" height="100%" fill="none" stroke="#000000" stroke-width="2" />'
        f'{"".join(vertical_lines)}'
        f'{"".join(horizontal_lines)}'
        f'{"".join(labels)}'
        f"{marker_svg}"
        "</svg>"
    )


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _is_blocked_access_classification(assessment: dict[str, Any]) -> bool:
    return str(assessment.get("classification") or "unknown") in _BLOCKED_ACCESS_CLASSIFICATIONS


def _parse_header_blocks(raw_headers: str) -> tuple[str | None, dict[str, str]]:
    normalized = raw_headers.replace("\r\n", "\n")
    blocks = [block.strip() for block in normalized.split("\n\n") if block.strip()]
    http_blocks = [block for block in blocks if block.startswith("HTTP/")]
    if not http_blocks:
        return None, {}
    lines = http_blocks[-1].splitlines()
    status_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        candidate = key.strip()
        if candidate:
            headers[candidate] = value.strip()
    return status_line, headers


def _assess_http_access(
    *,
    status_code: int | None,
    headers: dict[str, str],
    body_preview: str,
    metadata: dict[str, str],
    retrieved_hint: bool | None = None,
) -> dict[str, Any]:
    title = metadata.get("title", "")
    combined_text = "\n".join(filter(None, (title, body_preview[:4000])))
    challenge_detected = _contains_marker(combined_text, _CHALLENGE_MARKERS)
    gating_detected = _contains_marker(combined_text, _GATED_CONTENT_MARKERS)
    retry_after = _header_value(headers, "retry-after")
    auth_header = _header_value(headers, "www-authenticate")

    constraints: list[str] = []
    if status_code is not None and status_code >= 400:
        constraints.append(f"http_status_{status_code}")
    if retry_after:
        constraints.append("retry_after_present")
    if auth_header:
        constraints.append("authentication_header_present")
    if challenge_detected:
        constraints.append("challenge_page_detected")
    if gating_detected:
        constraints.append("content_gating_detected")

    if challenge_detected:
        classification = "challenge_page"
    elif status_code == 401 or auth_header:
        classification = "authentication_required"
    elif status_code == 429:
        classification = "rate_limited"
    elif status_code == 403:
        classification = "forbidden"
    elif status_code == 404:
        classification = "not_found"
    elif gating_detected:
        classification = "content_gated"
    elif status_code is not None and status_code >= 400:
        classification = "http_error"
    else:
        classification = "ok"

    retrieved = (
        retrieved_hint
        if retrieved_hint is not None
        else bool(status_code is not None and 200 <= status_code < 300)
    )
    accessible = classification == "ok"
    return {
        "classification": classification,
        "retrieved": retrieved,
        "accessible": accessible,
        "constraints": constraints,
        "evidence": {
            "status_code": status_code,
            "title": title or None,
            "retry_after": retry_after,
            "www_authenticate": auth_header,
            "content_type": _header_value(headers, "content-type"),
        },
    }


def _error_details_for_assessment(
    assessment: dict[str, Any],
    transfer_error: str | None,
) -> tuple[bool, str | None, str | None, str | None]:
    classification = assessment.get("classification")
    if transfer_error and not assessment.get("retrieved") and assessment.get("evidence", {}).get("status_code") is None:
        return False, "HTTP_REQUEST_FAILED", "execution", "HTTP request failed before a usable response was returned."
    if classification == "challenge_page":
        return (
            False,
            "HTTP_CHALLENGE_DETECTED",
            "access",
            "Target returned a challenge page instead of the requested content.",
        )
    if classification == "authentication_required":
        return False, "HTTP_AUTH_REQUIRED", "access", "Target requires authentication."
    if classification == "rate_limited":
        return False, "HTTP_RATE_LIMITED", "access", "Target rate-limited the request."
    if classification == "forbidden":
        return False, "HTTP_FORBIDDEN", "access", "Target forbids this request."
    if classification == "not_found":
        return False, "HTTP_NOT_FOUND", "access", "Target URL was not found."
    if classification == "content_gated":
        return False, "HTTP_CONTENT_GATED", "access", "Target returned a gated or sign-in page."
    if classification == "http_error":
        return False, "HTTP_STATUS_ERROR", "access", "Target returned an HTTP error response."
    return True, None, None, None


def _query_terms_for_runtime_targets(targets: tuple[str, ...] = ("chromium", "google-chrome", "firefox")) -> list[str]:
    ordered: list[str] = []
    for item in targets:
        candidate = item.strip()
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered


def _browser_bootstrap_plan(package_manager: str, *, target: str = "chromium") -> dict[str, str] | None:
    normalized_target = target.strip().lower() or "chromium"
    if normalized_target not in _BROWSER_BOOTSTRAP_TARGETS:
        return None

    snippets = {
        "apt-get": (
            "pkg=chromium; "
            "if ! apt-cache show chromium >/dev/null 2>&1; then pkg=chromium-browser; fi; "
            "$PRIV apt-get update -qq && DEBIAN_FRONTEND=noninteractive $PRIV apt-get install -y -qq \"$pkg\""
        ),
        "dnf": "$PRIV dnf install -y chromium",
        "yum": "$PRIV yum install -y chromium",
        "apk": "$PRIV apk add --no-cache chromium",
        "pacman": "$PRIV pacman -Sy --noconfirm chromium",
        "zypper": "$PRIV zypper --non-interactive install chromium",
        "brew": "brew install --cask chromium",
    }
    snippet = snippets.get(package_manager.strip())
    if not snippet:
        return None
    return {
        "target": normalized_target,
        "package_manager": package_manager.strip(),
        "command": (
            "if [ \"$(id -u)\" -eq 0 ]; then PRIV=''; "
            "elif command -v sudo >/dev/null 2>&1; then PRIV='sudo'; "
            "else echo 'Root or sudo is required to install a browser runtime.' >&2; exit 1; fi; "
            f"{snippet}"
        ),
    }


def _browser_recommendations(
    http_assessment: dict[str, Any],
    runtime_status: dict[str, Any],
    *,
    browser_attempted: bool,
    browser_accessible: bool,
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    classification = str(http_assessment.get("classification") or "unknown")
    automation = runtime_status.get("automation")
    visual_capture_supported = bool(
        isinstance(automation, dict) and automation.get("visual_capture_supported")
    )
    coordinate_click_supported = bool(
        isinstance(automation, dict) and automation.get("coordinate_click_supported")
    )
    if http_assessment.get("accessible"):
        recommendations.append(
            {
                "tool": "http_fetch",
                "reason": "Direct HTTP retrieval already succeeded; no escalation is needed.",
            }
        )
        return recommendations

    if runtime_status.get("headless_dom_supported") and not browser_attempted:
        recommendations.append(
            {
                "tool": "browser_fetch",
                "reason": (
                    "A Chromium-family browser is available on the host, "
                    "so a headless DOM fetch is the next escalation step."
                ),
            }
        )
    elif runtime_status.get("headless_dom_supported") and browser_attempted and browser_accessible:
        recommendations.append(
            {
                "tool": "browser_fetch",
                "reason": "Direct HTTP was blocked, but headless browser DOM retrieval succeeded.",
            }
        )
    elif runtime_status.get("headless_dom_supported") and browser_attempted and visual_capture_supported:
        recommendations.append(
            {
                "tool": "browser_screenshot",
                "reason": (
                    "DOM-only browser retrieval still hit a challenge page; capture a screenshot and coordinate grid "
                    "for grounded interactive follow-up."
                ),
            }
        )
        if coordinate_click_supported:
            recommendations.append(
                {
                    "tool": "browser_coordinate_click",
                    "reason": (
                        "After inspecting the screenshot and grid artifacts, continue with a deliberate coordinate "
                        "click if a grounded target is visible."
                    ),
                }
            )
    elif runtime_status.get("headless_dom_supported") and browser_attempted:
        recommendations.append(
            {
                "action": "report_blocked_access",
                "reason": (
                    "DOM-only browser retrieval is already exhausted and no grounded visual automation path is "
                    "available on this host."
                ),
            }
        )
    else:
        recommendations.append(
            {
                "tool": "browser_bootstrap",
                "reason": "No supported headless browser runtime is available yet; bootstrap Chromium on the host.",
                "search_queries": _query_terms_for_runtime_targets(),
            }
        )
    if classification in _BLOCKED_ACCESS_CLASSIFICATIONS:
        recommendations.append(
            {
                "action": "stop_same_origin_http_retries",
                "reason": (
                    "Do not retry the same origin with alternate headers, cookies, query parameters, "
                    "AMP variants, or shell scraping after this access classification."
                ),
            }
        )
    return recommendations


def _retry_guidance(
    assessment: dict[str, Any],
    runtime_status: dict[str, Any] | None = None,
    *,
    browser_attempted: bool = False,
    browser_accessible: bool = False,
) -> dict[str, Any]:
    classification = str(assessment.get("classification") or "unknown")
    blocked_same_origin = classification in _BLOCKED_ACCESS_CLASSIFICATIONS
    browser_available = bool((runtime_status or {}).get("headless_dom_supported"))
    automation = (runtime_status or {}).get("automation")
    visual_capture_supported = bool(
        isinstance(automation, dict) and automation.get("visual_capture_supported")
    )

    if assessment.get("accessible"):
        return {
            "should_stop": True,
            "same_origin_http_retry_allowed": False,
            "header_variation_allowed": False,
            "query_variant_allowed": False,
            "cookie_replay_allowed": False,
            "browser_escalation_allowed": False,
            "interactive_browser_review_allowed": False,
            "recommended_action": "use_current_result",
            "reason": "The current result is already accessible.",
        }

    if blocked_same_origin and browser_available and not browser_attempted:
        return {
            "should_stop": False,
            "same_origin_http_retry_allowed": False,
            "header_variation_allowed": False,
            "query_variant_allowed": False,
            "cookie_replay_allowed": False,
            "browser_escalation_allowed": True,
            "interactive_browser_review_allowed": False,
            "recommended_action": "try_browser_fetch",
            "reason": "Same-origin HTTP retries are blocked; a single browser escalation is the next step.",
        }

    if blocked_same_origin and browser_attempted and browser_accessible:
        return {
            "should_stop": True,
            "same_origin_http_retry_allowed": False,
            "header_variation_allowed": False,
            "query_variant_allowed": False,
            "cookie_replay_allowed": False,
            "browser_escalation_allowed": False,
            "interactive_browser_review_allowed": False,
            "recommended_action": "use_browser_result",
            "reason": "Browser escalation already recovered accessible content.",
        }

    if blocked_same_origin and browser_attempted and visual_capture_supported:
        return {
            "should_stop": False,
            "same_origin_http_retry_allowed": False,
            "header_variation_allowed": False,
            "query_variant_allowed": False,
            "cookie_replay_allowed": False,
            "browser_escalation_allowed": False,
            "interactive_browser_review_allowed": True,
            "recommended_action": "capture_challenge_screenshot",
            "reason": (
                "Same-origin HTTP and DOM-only browser retrieval are exhausted, but visual browser review is still "
                "available through screenshot capture and grounded coordinate clicks."
            ),
        }

    if blocked_same_origin:
        return {
            "should_stop": True,
            "same_origin_http_retry_allowed": False,
            "header_variation_allowed": False,
            "query_variant_allowed": False,
            "cookie_replay_allowed": False,
            "browser_escalation_allowed": False,
            "interactive_browser_review_allowed": False,
            "recommended_action": "report_blocked_access",
            "reason": (
                "The origin is blocked or gated; stop same-origin retry loops and report the access constraint."
            ),
        }

    return {
        "should_stop": False,
        "same_origin_http_retry_allowed": True,
        "header_variation_allowed": True,
        "query_variant_allowed": True,
        "cookie_replay_allowed": False,
        "browser_escalation_allowed": bool(browser_available and not browser_attempted),
        "interactive_browser_review_allowed": False,
        "recommended_action": "inspect_response",
        "reason": "The response is not classified as a same-origin anti-bot or gating stop condition.",
    }


def _runtime_status_hint_from_capabilities(capabilities: dict[str, Any]) -> dict[str, Any]:
    commands = capabilities.get("commands")
    if not isinstance(commands, dict):
        commands = {}

    chromium_family = [
        {"command": command_name, "path": None}
        for capability_key, command_name in _BROWSER_CAPABILITY_HINTS
        if commands.get(capability_key)
    ]
    firefox_available = bool(commands.get("firefox"))
    playwright_available = bool(commands.get("playwright"))
    runtime_status = {
        "commands": {
            candidate["command"]: candidate["path"]
            for candidate in chromium_family
        },
        "chromium_family": {
            "available": bool(chromium_family),
            "preferred": chromium_family[0]["command"] if chromium_family else None,
            "preferred_path": chromium_family[0]["path"] if chromium_family else None,
            "candidates": chromium_family,
        },
        "firefox": {"available": firefox_available, "path": None},
        "playwright": {"available": playwright_available, "path": None},
        "javascript": {
            "node": "node" if commands.get("node") else None,
            "npm": "npm" if commands.get("npm") else None,
            "npx": "npx" if commands.get("npx") else None,
        },
        "python": {"python3": "python3" if commands.get("python3") else None},
        "headless_dom_supported": bool(chromium_family),
        "recommended_queries": _query_terms_for_runtime_targets(),
        "detection_source": "capability_probe",
    }
    runtime_status["automation"] = _browser_automation_capability(runtime_status)
    return runtime_status


def _web_handoff_outcome(assessment: dict[str, Any]) -> str:
    classification = str(assessment.get("classification") or "unknown")
    if assessment.get("accessible"):
        return "ok"
    if classification == "browser_unavailable":
        return "runtime_missing"
    if classification in _BLOCKED_ACCESS_CLASSIFICATIONS:
        return "blocked_access"
    return "inspect_response"


def _workflow_outcome_for_web_step(
    *,
    http_assessment: dict[str, Any],
    browser_payload: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    runtime_status: dict[str, Any] | None = None,
) -> str:
    if click_payload is not None:
        click_assessment = click_payload.get("assessment")
        if isinstance(click_assessment, dict):
            if click_assessment.get("accessible"):
                return "ok"
            if click_payload.get("ok"):
                return "post_click_review_required"
            if click_payload.get("error_code") == "BROWSER_AUTOMATION_UNAVAILABLE":
                return "runtime_missing"
            return "blocked_after_browser_attempt"
    if screenshot_payload is not None:
        screenshot_assessment = screenshot_payload.get("assessment")
        if isinstance(screenshot_assessment, dict):
            if screenshot_assessment.get("accessible"):
                return "ok"
            if screenshot_payload.get("ok"):
                return "interactive_browser_review_required"
            if screenshot_payload.get("error_code") == "BROWSER_SCREENSHOT_UNAVAILABLE":
                return "runtime_missing"
            return "blocked_after_browser_attempt"
    if browser_payload is not None:
        browser_assessment = browser_payload.get("assessment")
        if isinstance(browser_assessment, dict):
            if browser_assessment.get("accessible"):
                return "ok"
            automation = (runtime_status or {}).get("automation")
            visual_capture_supported = bool(
                isinstance(automation, dict) and automation.get("visual_capture_supported")
            )
            classification = str(browser_assessment.get("classification") or "")
            if visual_capture_supported and classification in _BLOCKED_ACCESS_CLASSIFICATIONS:
                return "interactive_browser_review_required"
            return "blocked_after_browser_attempt"
    return _web_handoff_outcome(http_assessment)


def _available_registry_tools() -> tuple[str, ...] | None:
    try:
        registry = get_registry()
    except AssertionError:
        return None
    return tuple(binding.name for binding in registry.tools)


async def _browser_visual_followup(
    *,
    url: str,
    timeout_sec: int,
    wait_ms: int,
    preferred_browser: str,
    user_agent: str,
    runtime_status: dict[str, Any],
    browser_payload: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[Any]]:
    screenshot_payload: dict[str, Any] | None = None
    click_payload: dict[str, Any] | None = None
    extra_artifacts: list[Any] = []
    if browser_payload is None:
        return screenshot_payload, click_payload, extra_artifacts

    automation = runtime_status.get("automation")
    visual_capture_supported = bool(isinstance(automation, dict) and automation.get("visual_capture_supported"))
    coordinate_click_supported = bool(isinstance(automation, dict) and automation.get("coordinate_click_supported"))
    browser_blocked = bool(
        not browser_payload["assessment"].get("accessible")
        and _is_blocked_access_classification(browser_payload["assessment"])
    )
    if not browser_blocked or not visual_capture_supported:
        return screenshot_payload, click_payload, extra_artifacts

    screenshot_payload, screenshot_artifacts = await _browser_screenshot_payload(
        url=url,
        timeout_sec=max(timeout_sec, 45),
        wait_ms=wait_ms,
        viewport_width=1440,
        viewport_height=2200,
        preferred_browser=preferred_browser,
        user_agent=user_agent,
    )
    extra_artifacts.extend(screenshot_artifacts)
    screenshot_response = screenshot_payload.get("response", {}) if screenshot_payload else {}
    auto_interaction = screenshot_response.get("auto_interaction") if isinstance(screenshot_response, dict) else None
    click_request = auto_interaction.get("click_request") if isinstance(auto_interaction, dict) else None
    if (
        screenshot_payload
        and screenshot_payload.get("ok")
        and coordinate_click_supported
        and isinstance(auto_interaction, dict)
        and auto_interaction.get("eligible")
        and isinstance(click_request, dict)
    ):
        click_payload, click_artifacts = await _browser_coordinate_click_payload(
            url=url,
            x=int(click_request.get("x")),
            y=int(click_request.get("y")),
            timeout_sec=max(timeout_sec, 60),
            wait_before_ms=wait_ms,
            wait_after_ms=3000,
            viewport_width=int(screenshot_response.get("viewport_width") or 1440),
            viewport_height=int(screenshot_response.get("viewport_height") or 2200),
            preferred_browser=preferred_browser,
            user_agent=user_agent,
        )
        extra_artifacts.extend(click_artifacts)
    return screenshot_payload, click_payload, extra_artifacts


def _next_step_call_template(
    tool_name: str,
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
    wait_ms: int,
    browser_profile: bool,
    preferred_browser: str,
) -> dict[str, Any] | None:
    if tool_name == "http_fetch":
        return {
            "url": url,
            "method": method,
            "headers": headers,
            "timeout_sec": timeout_sec,
            "browser_profile": browser_profile,
            "max_body_chars": max_body_chars,
        }
    if tool_name == "browser_fetch":
        return {
            "url": url,
            "timeout_sec": max(timeout_sec, 20),
            "wait_ms": wait_ms,
            "max_body_chars": max_body_chars,
            "preferred_browser": preferred_browser,
            "user_agent": headers.get("User-Agent", _BROWSER_HEADERS["User-Agent"]),
        }
    if tool_name == "browser_screenshot":
        return {
            "url": url,
            "timeout_sec": max(timeout_sec, 45),
            "wait_ms": wait_ms,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "preferred_browser": preferred_browser,
            "user_agent": headers.get("User-Agent", _BROWSER_HEADERS["User-Agent"]),
        }
    if tool_name == "browser_coordinate_click":
        return {
            "url": url,
            "x": "<grid_x>",
            "y": "<grid_y>",
            "timeout_sec": max(timeout_sec, 60),
            "wait_before_ms": wait_ms,
            "wait_after_ms": 3000,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "preferred_browser": preferred_browser,
            "user_agent": headers.get("User-Agent", _BROWSER_HEADERS["User-Agent"]),
            "arg_notes": "Choose x/y from the most recent browser_screenshot grid artifact.",
        }
    if tool_name == "browser_runtime_status":
        return {"refresh": False}
    if tool_name == "browser_bootstrap":
        return {"target": "chromium", "timeout_sec": 900, "refresh": True}
    if tool_name == "web_page_diagnose":
        return {
            "url": url,
            "method": method,
            "headers": headers,
            "timeout_sec": timeout_sec,
            "browser_profile": browser_profile,
            "try_browser": True,
            "wait_ms": wait_ms,
            "max_body_chars": max_body_chars,
            "preferred_browser": preferred_browser,
        }
    if tool_name == "web_retrieve":
        return {
            "url": url,
            "method": method,
            "headers": headers,
            "timeout_sec": timeout_sec,
            "browser_profile": browser_profile,
            "try_browser": True,
            "allow_bootstrap": True,
            "bootstrap_target": "chromium",
            "bootstrap_timeout_sec": 900,
            "wait_ms": wait_ms,
            "max_body_chars": max_body_chars,
            "preferred_browser": preferred_browser,
        }
    return None


def _surface_verification_reference() -> dict[str, Any]:
    reference = control_plane_reference()
    fallback_call_template = reference.get("tool_registry_http_fetch_call_template")
    if not isinstance(fallback_call_template, dict):
        fallback_call_template = None
    return {
        **reference,
        "fallback_tool": "http_fetch" if fallback_call_template is not None else None,
        "fallback_call_template": fallback_call_template,
        "fallback_reason": (
            "If the current caller surface cannot invoke nexus_tool_registry or another recommended tool, "
            "verify the active server registry snapshot through the control-plane HTTP endpoint."
        ),
    }


def _surface_verification_reason(
    tool_name: str,
    *,
    surface_verification: dict[str, Any],
) -> str:
    if tool_name == "nexus_tool_registry":
        return str(
            surface_verification.get("fallback_reason")
            or "Verify the active server registry snapshot through the control-plane HTTP endpoint."
        )
    return f"Verify the current caller tool surface before attempting {tool_name}."


def _surface_verification_step(
    item: dict[str, Any],
    *,
    surface_verification: dict[str, Any],
) -> dict[str, Any] | None:
    tool_name = str(item.get("tool") or "")
    if tool_name not in _SURFACE_VERIFICATION_GATED_TOOLS:
        return None
    if not item.get("surface_confirmation_required"):
        return None
    fallback_tool = surface_verification.get("fallback_tool")
    fallback_call_template = surface_verification.get("fallback_call_template")
    if not fallback_tool or not isinstance(fallback_call_template, dict):
        return None

    if tool_name in {"browser_screenshot", "browser_coordinate_click"}:
        original_call_template = item.get("call_template")
        if isinstance(original_call_template, dict):
            browser_fetch_call_template: dict[str, Any] = {
                "url": original_call_template.get("url"),
                "timeout_sec": max(1, int(original_call_template.get("timeout_sec") or 45)),
                "wait_ms": max(0, int(original_call_template.get("wait_ms") or original_call_template.get("wait_before_ms") or 5000)),
                "max_body_chars": 12000,
                "preferred_browser": original_call_template.get("preferred_browser") or "",
                "user_agent": original_call_template.get("user_agent") or _BROWSER_HEADERS["User-Agent"],
            }
            if tool_name == "browser_coordinate_click":
                browser_fetch_call_template.update(
                    {
                        "manual_click_x": original_call_template.get("x", "<grid_x>"),
                        "manual_click_y": original_call_template.get("y", "<grid_y>"),
                        "manual_click_wait_after_ms": max(
                            0,
                            int(original_call_template.get("wait_after_ms") or 3000),
                        ),
                        "manual_click_viewport_width": max(
                            320,
                            int(original_call_template.get("viewport_width") or 1440),
                        ),
                        "manual_click_viewport_height": max(
                            240,
                            int(original_call_template.get("viewport_height") or 2200),
                        ),
                    }
                )
                in_band_reason = (
                    "Current caller tool surface may not expose browser_coordinate_click. "
                    "Continue with browser_fetch using manual_click_x/manual_click_y."
                )
            else:
                in_band_reason = (
                    "Current caller tool surface may not expose browser_screenshot. "
                    "Continue with browser_fetch to keep bounded visual follow-up in-band."
                )
            return {
                "tool": "browser_fetch",
                "priority": item.get("priority"),
                "available": item.get("available", True),
                "availability_scope": item.get("availability_scope"),
                "callable_surface_confirmed": False,
                "surface_confirmation_required": False,
                "verifies_callable_surface": False,
                "alternate_tool": tool_name,
                "reason": in_band_reason,
                "call_template": browser_fetch_call_template,
                "fallback_tool": fallback_tool,
                "fallback_reason": _surface_verification_reason(
                    tool_name,
                    surface_verification=surface_verification,
                ),
                "fallback_call_template": fallback_call_template,
            }

    reason = _surface_verification_reason(tool_name, surface_verification=surface_verification)
    return {
        "tool": fallback_tool,
        "priority": item.get("priority"),
        "available": item.get("available", True),
        "availability_scope": item.get("availability_scope"),
        "callable_surface_confirmed": False,
        "surface_confirmation_required": False,
        "verifies_callable_surface": True,
        "alternate_tool": tool_name,
        "reason": reason,
        "call_template": fallback_call_template,
    }


def _attach_surface_verification(handoff: dict[str, Any] | None) -> dict[str, Any] | None:
    if handoff is None:
        return None
    surface_verification = _surface_verification_reference()
    handoff["surface_verification"] = surface_verification
    next_tools = handoff.get("next_tools")
    if isinstance(next_tools, list):
        normalized_next_tools: list[dict[str, Any]] = []
        for item in next_tools:
            if not isinstance(item, dict):
                continue
            if item.get("availability_scope") == "server_registry_snapshot":
                item["surface_confirmation_required"] = True
            tool_name = str(item.get("tool") or "")
            if tool_name in _SURFACE_VERIFICATION_GATED_TOOLS:
                item["fallback_tool"] = surface_verification.get("fallback_tool")
                item["fallback_reason"] = _surface_verification_reason(
                    tool_name,
                    surface_verification=surface_verification,
                )
                item["fallback_call_template"] = surface_verification.get("fallback_call_template")
                if item.get("surface_confirmation_required"):
                    item["deferred_until_surface_verified"] = True
            normalized_next_tools.append(item)
        primary_item = next((item for item in normalized_next_tools if item.get("available") is not False), None)
        effective_step = (
            _surface_verification_step(primary_item, surface_verification=surface_verification)
            if isinstance(primary_item, dict)
            else None
        )
        if effective_step is not None:
            normalized_next_tools = [effective_step, *normalized_next_tools]
        handoff["next_tools"] = normalized_next_tools
        handoff["recommended_tool"] = next(
            (item["tool"] for item in normalized_next_tools if item.get("available") is not False),
            None,
        )
    return handoff


def _interaction_click_hint(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    response = payload.get("response")
    if not isinstance(response, dict):
        return None
    auto_interaction = response.get("auto_interaction")
    if not isinstance(auto_interaction, dict):
        return None

    def _normalize_hint(candidate: Any, *, source: str) -> dict[str, Any] | None:
        if not isinstance(candidate, dict):
            return None
        try:
            x = int(candidate.get("x"))
            y = int(candidate.get("y"))
        except (TypeError, ValueError):
            return None
        hint = {
            "x": x,
            "y": y,
            "source": source,
            "kind": candidate.get("kind"),
            "confidence": candidate.get("confidence"),
        }
        return hint

    click_hint = _normalize_hint(auto_interaction.get("click_request"), source="auto_click_request")
    if click_hint is not None:
        return click_hint
    suggested_hint = _normalize_hint(auto_interaction.get("suggested_click_request"), source="suggested_click_request")
    if suggested_hint is not None:
        return suggested_hint
    ranking = auto_interaction.get("candidate_ranking")
    if isinstance(ranking, list) and ranking:
        top = ranking[0]
        fallback_hint = _normalize_hint(top, source="candidate_ranking")
        if fallback_hint is not None:
            fallback_hint["kind"] = top.get("kind")
            fallback_hint["confidence"] = top.get("score")
            return fallback_hint
    return None


def _interaction_click_candidates(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    response = payload.get("response")
    if not isinstance(response, dict):
        return []
    auto_interaction = response.get("auto_interaction")
    if not isinstance(auto_interaction, dict):
        return []

    source_priority = {
        "auto_click_request": 3,
        "suggested_click_request": 2,
        "candidate_ranking": 1,
    }
    candidate_by_coordinate: dict[tuple[int, int], dict[str, Any]] = {}

    def _register_candidate(
        candidate: Any,
        *,
        source: str,
        confidence: float | None = None,
        kind: str | None = None,
    ) -> None:
        if not isinstance(candidate, dict):
            return
        try:
            x = int(candidate.get("x"))
            y = int(candidate.get("y"))
        except (TypeError, ValueError):
            return
        rank_score = confidence if confidence is not None else candidate.get("score")
        try:
            numeric_score = float(rank_score or 0.0)
        except (TypeError, ValueError):
            numeric_score = 0.0
        normalized = {
            "x": x,
            "y": y,
            "source": source,
            "confidence": max(0.0, min(1.0, numeric_score)),
            "kind": kind or candidate.get("kind"),
            "priority": source_priority.get(source, 0),
        }
        coordinate = (x, y)
        existing = candidate_by_coordinate.get(coordinate)
        if existing is None:
            candidate_by_coordinate[coordinate] = normalized
            return
        if (
            normalized["priority"],
            normalized["confidence"],
        ) > (
            existing.get("priority", 0),
            existing.get("confidence", 0.0),
        ):
            candidate_by_coordinate[coordinate] = normalized

    _register_candidate(auto_interaction.get("click_request"), source="auto_click_request")
    _register_candidate(auto_interaction.get("suggested_click_request"), source="suggested_click_request")

    ranking = auto_interaction.get("candidate_ranking")
    if isinstance(ranking, list):
        for item in ranking:
            if not isinstance(item, dict):
                continue
            _register_candidate(
                item,
                source="candidate_ranking",
                confidence=float(item.get("score") or 0.0),
                kind=str(item.get("kind") or "generic"),
            )

    candidates = list(candidate_by_coordinate.values())
    candidates.sort(
        key=lambda item: (int(item.get("priority") or 0), float(item.get("confidence") or 0.0)),
        reverse=True,
    )
    return candidates


def _payload_click_coordinate(payload: dict[str, Any] | None) -> tuple[int, int] | None:
    if not isinstance(payload, dict):
        return None
    request = payload.get("request")
    if not isinstance(request, dict):
        return None
    try:
        return int(request.get("x")), int(request.get("y"))
    except (TypeError, ValueError):
        return None


def _attempted_click_coordinates(attempts: list[dict[str, Any]]) -> set[tuple[int, int]]:
    attempted: set[tuple[int, int]] = set()
    for payload in attempts:
        coordinate = _payload_click_coordinate(payload)
        if coordinate is not None:
            attempted.add(coordinate)
    return attempted


def _grounded_followup_exhausted(
    *,
    final_assessment: dict[str, Any] | None,
    click_attempts: list[dict[str, Any]],
    final_click_payload: dict[str, Any] | None,
    fallback_payload: dict[str, Any] | None = None,
) -> bool:
    if not isinstance(final_assessment, dict):
        return False
    if final_assessment.get("accessible"):
        return False
    if not _is_blocked_access_classification(final_assessment):
        return False
    attempted_coordinates = _attempted_click_coordinates(click_attempts)
    if not attempted_coordinates:
        latest_coordinate = _payload_click_coordinate(final_click_payload)
        if latest_coordinate is not None:
            attempted_coordinates.add(latest_coordinate)
    if not attempted_coordinates:
        return False
    next_candidate = _next_grounded_click_candidate(
        attempted_coordinates=attempted_coordinates,
        primary_payload=final_click_payload,
        fallback_payload=fallback_payload,
    )
    return next_candidate is None


def _next_grounded_click_candidate(
    *,
    attempted_coordinates: set[tuple[int, int]],
    primary_payload: dict[str, Any] | None,
    fallback_payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    merged_by_coordinate: dict[tuple[int, int], dict[str, Any]] = {}
    for payload in (primary_payload, fallback_payload):
        for candidate in _interaction_click_candidates(payload):
            coordinate = (int(candidate["x"]), int(candidate["y"]))
            if coordinate in attempted_coordinates:
                continue
            existing = merged_by_coordinate.get(coordinate)
            if existing is None:
                merged_by_coordinate[coordinate] = candidate
                continue
            if (
                int(candidate.get("priority") or 0),
                float(candidate.get("confidence") or 0.0),
            ) > (
                int(existing.get("priority") or 0),
                float(existing.get("confidence") or 0.0),
            ):
                merged_by_coordinate[coordinate] = candidate
    if not merged_by_coordinate:
        return None
    candidates = list(merged_by_coordinate.values())
    candidates.sort(
        key=lambda item: (int(item.get("priority") or 0), float(item.get("confidence") or 0.0)),
        reverse=True,
    )
    return candidates[0]


def _click_attempt_records(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, payload in enumerate(attempts, start=1):
        request = payload.get("request")
        assessment = payload.get("assessment")
        response = payload.get("response")
        auto_interaction = response.get("auto_interaction") if isinstance(response, dict) else None
        record: dict[str, Any] = {
            "attempt": index,
            "ok": bool(payload.get("ok")),
            "error_code": payload.get("error_code"),
            "error_stage": payload.get("error_stage"),
            "classification": assessment.get("classification") if isinstance(assessment, dict) else None,
            "accessible": bool(assessment.get("accessible")) if isinstance(assessment, dict) else False,
        }
        if isinstance(request, dict):
            try:
                record["x"] = int(request.get("x"))
                record["y"] = int(request.get("y"))
            except (TypeError, ValueError):
                pass
        if isinstance(auto_interaction, dict):
            suggested = auto_interaction.get("suggested_click_request")
            if isinstance(suggested, dict):
                try:
                    record["suggested_click_request"] = {
                        "x": int(suggested.get("x")),
                        "y": int(suggested.get("y")),
                    }
                except (TypeError, ValueError):
                    pass
        records.append(record)
    return records


def _visual_evidence_for_payload(payload: dict[str, Any] | None, *, source: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    screenshot_path = None
    grid_path = None
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path:
            continue
        lowered = path.lower()
        if screenshot_path is None and lowered.endswith(".png"):
            screenshot_path = path
        if grid_path is None and lowered.endswith(".svg"):
            grid_path = path
    if not screenshot_path and not grid_path:
        return None
    return {
        "source": source,
        "screenshot_path": screenshot_path,
        "grid_path": grid_path,
    }


def _final_visual_evidence(
    *,
    click_attempts: list[dict[str, Any]],
    screenshot_payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    for payload in reversed(click_attempts):
        evidence = _visual_evidence_for_payload(payload, source="browser_coordinate_click")
        if evidence is not None:
            return evidence
    return _visual_evidence_for_payload(screenshot_payload, source="browser_screenshot")


async def _bounded_click_followup_sequence(
    *,
    url: str,
    timeout_sec: int,
    wait_before_ms: int,
    wait_after_ms: int,
    viewport_width: int,
    viewport_height: int,
    preferred_browser: str,
    user_agent: str,
    pre_click_payload: dict[str, Any] | None,
    initial_click_payload: dict[str, Any] | None,
    fallback_candidate_payload: dict[str, Any] | None = None,
    max_total_attempts: int = _MAX_GROUNDED_CLICK_ATTEMPTS,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[Any], list[dict[str, Any]]]:
    if not isinstance(initial_click_payload, dict):
        return None, [], [], []

    attempts: list[dict[str, Any]] = [initial_click_payload]
    diagnostics: list[dict[str, Any]] = []
    first_diagnostic = _post_click_challenge_diagnostics(
        pre_payload=pre_click_payload,
        click_payload=initial_click_payload,
    )
    if isinstance(first_diagnostic, dict):
        diagnostics.append(first_diagnostic)

    attempted_coordinates: set[tuple[int, int]] = set()
    initial_coordinate = _payload_click_coordinate(initial_click_payload)
    if initial_coordinate is not None:
        attempted_coordinates.add(initial_coordinate)

    additional_artifacts: list[Any] = []
    current_payload = initial_click_payload
    previous_payload = initial_click_payload
    remaining_attempts = max(0, max_total_attempts - 1)
    while remaining_attempts > 0:
        assessment = current_payload.get("assessment")
        if not isinstance(assessment, dict):
            break
        if assessment.get("accessible"):
            break
        if not _is_blocked_access_classification(assessment):
            break

        candidate = _next_grounded_click_candidate(
            attempted_coordinates=attempted_coordinates,
            primary_payload=current_payload,
            fallback_payload=fallback_candidate_payload,
        )
        if candidate is None:
            break

        candidate_x = int(candidate["x"])
        candidate_y = int(candidate["y"])
        attempted_coordinates.add((candidate_x, candidate_y))
        viewport_width_value = max(
            320,
            int((current_payload.get("response") or {}).get("viewport_width") or viewport_width),
        )
        viewport_height_value = max(
            240,
            int((current_payload.get("response") or {}).get("viewport_height") or viewport_height),
        )
        next_payload, next_artifacts = await _browser_coordinate_click_payload(
            url=url,
            x=candidate_x,
            y=candidate_y,
            timeout_sec=max(1, timeout_sec),
            wait_before_ms=max(0, wait_before_ms),
            wait_after_ms=max(0, wait_after_ms),
            viewport_width=viewport_width_value,
            viewport_height=viewport_height_value,
            preferred_browser=preferred_browser,
            user_agent=user_agent,
        )
        attempts.append(next_payload)
        additional_artifacts.extend(next_artifacts)
        diagnostic = _post_click_challenge_diagnostics(
            pre_payload=previous_payload,
            click_payload=next_payload,
        )
        if isinstance(diagnostic, dict):
            diagnostics.append(diagnostic)
        current_payload = next_payload
        previous_payload = next_payload
        remaining_attempts -= 1

    return current_payload, attempts, additional_artifacts, diagnostics


def _apply_click_hint_to_handoff(
    handoff: dict[str, Any] | None,
    click_hint: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if handoff is None or not isinstance(click_hint, dict):
        return handoff
    try:
        x = int(click_hint.get("x"))
        y = int(click_hint.get("y"))
    except (TypeError, ValueError):
        return handoff
    next_tools = handoff.get("next_tools")
    if not isinstance(next_tools, list):
        return handoff

    for item in next_tools:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool") or "")
        alternate_tool = str(item.get("alternate_tool") or "")
        if tool_name != "browser_fetch":
            continue
        call_template = item.get("call_template")
        if not isinstance(call_template, dict):
            continue
        if alternate_tool and alternate_tool != "browser_coordinate_click" and "manual_click_x" not in call_template:
            continue
        call_template["manual_click_x"] = x
        call_template["manual_click_y"] = y
        call_template["manual_click_wait_after_ms"] = max(0, int(call_template.get("manual_click_wait_after_ms") or 3000))
        call_template["manual_click_viewport_width"] = max(
            320, int(call_template.get("manual_click_viewport_width") or 1440)
        )
        call_template["manual_click_viewport_height"] = max(
            240, int(call_template.get("manual_click_viewport_height") or 2200)
        )
        source = str(click_hint.get("source") or "interaction_hint")
        existing_notes = str(call_template.get("arg_notes") or "").strip()
        hint_note = (
            f"Prefilled from grounded {source}: ({x}, {y}). "
            "Confirm against the latest grid artifact before replaying."
        )
        call_template["arg_notes"] = f"{existing_notes} {hint_note}".strip() if existing_notes else hint_note
    handoff["interaction_hint"] = click_hint
    return handoff


def _web_workflow_handoff(
    *,
    current_tool: str,
    assessment: dict[str, Any],
    outcome_override: str | None,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
    wait_ms: int,
    browser_profile: bool,
    preferred_browser: str,
) -> dict[str, Any] | None:
    handoff = task_family_handoff(
        task_family="web_retrieval",
        current_tool=current_tool,
        outcome=(outcome_override.strip() if outcome_override else "") or _web_handoff_outcome(assessment),
        available_tools=_available_registry_tools(),
        availability_scope="server_registry_snapshot",
    )
    if handoff is None:
        return None
    surface_verification = _surface_verification_reference()
    next_tools = handoff.get("next_tools")
    if isinstance(next_tools, list):
        for item in next_tools:
            if not isinstance(item, dict):
                continue
            item["availability_scope"] = "server_registry_snapshot"
            item["callable_surface_confirmed"] = False
            tool_name = str(item.get("tool") or "")
            call_template = _next_step_call_template(
                tool_name,
                url=url,
                method=method,
                headers=headers,
                timeout_sec=timeout_sec,
                max_body_chars=max_body_chars,
                wait_ms=wait_ms,
                browser_profile=browser_profile,
                preferred_browser=preferred_browser,
            )
            if call_template:
                item["call_template"] = call_template
            if tool_name == "nexus_tool_registry":
                item["fallback_tool"] = surface_verification.get("fallback_tool")
                item["fallback_reason"] = surface_verification.get("fallback_reason")
                item["fallback_call_template"] = surface_verification.get("fallback_call_template")
    return _attach_surface_verification(handoff)


def _continuation_from_handoff(handoff: dict[str, Any] | None) -> dict[str, Any] | None:
    if handoff is None:
        return None
    next_tools = handoff.get("next_tools")
    next_step = None
    if isinstance(next_tools, list):
        recommended_tool = handoff.get("recommended_tool")
        if recommended_tool:
            next_step = next((item for item in next_tools if item.get("tool") == recommended_tool), None)
        if next_step is None:
            next_step = next((item for item in next_tools if isinstance(item, dict)), None)
    fallback_next_step = None
    if isinstance(next_step, dict):
        if next_step.get("verifies_callable_surface") and isinstance(next_step.get("call_template"), dict):
            fallback_next_step = {
                "tool": next_step.get("tool"),
                "reason": next_step.get("reason"),
                "call_template": next_step.get("call_template"),
            }
        original_tool = str(next_step.get("tool") or "")
        surface_confirmation_required = bool(next_step.get("surface_confirmation_required")) or (
            original_tool in _SURFACE_VERIFICATION_GATED_TOOLS
            and next_step.get("availability_scope") == "server_registry_snapshot"
            and next_step.get("callable_surface_confirmed") is False
        )
        fallback_tool = next_step.get("fallback_tool")
        fallback_call_template = next_step.get("fallback_call_template")
        if fallback_next_step is None and fallback_tool and isinstance(fallback_call_template, dict):
            fallback_next_step = {
                "tool": fallback_tool,
                "reason": next_step.get("fallback_reason"),
                "call_template": fallback_call_template,
            }
        if (
            original_tool in {"browser_screenshot", "browser_coordinate_click", "nexus_tool_registry"}
            and surface_confirmation_required
            and isinstance(fallback_next_step, dict)
        ):
            next_step = {
                **fallback_next_step,
                "alternate_tool": original_tool,
            }
    state = "stop" if handoff.get("terminal") else "invoke_tool"
    if next_step is None and not handoff.get("terminal"):
        state = "no_available_tool"
    return {
        "state": state,
        "reason": handoff.get("reason"),
        "action": handoff.get("action"),
        "task_family": handoff.get("task_family"),
        "terminal": bool(handoff.get("terminal")),
        "next_step": next_step,
        "fallback_next_step": fallback_next_step,
        "next_tools": next_tools if isinstance(next_tools, list) else [],
        "surface_verification": handoff.get("surface_verification"),
    }


def _attempt_trace_entry(
    *,
    stage: str,
    tool_name: str,
    invoked: bool,
    payload: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "stage": stage,
        "tool": tool_name,
        "invoked": invoked,
    }
    if payload:
        assessment = payload.get("assessment", {})
        response = payload.get("response", {})
        entry.update(
            {
                "ok": payload.get("ok"),
                "error_code": payload.get("error_code"),
                "error_stage": payload.get("error_stage"),
                "classification": assessment.get("classification"),
                "accessible": assessment.get("accessible"),
                "message": payload.get("message"),
            }
        )
        if isinstance(response, dict):
            if response.get("browser"):
                entry["browser"] = response.get("browser")
            if response.get("browser_path"):
                entry["browser_path"] = response.get("browser_path")
            if response.get("status_code") is not None:
                entry["status_code"] = response.get("status_code")
            if response.get("surface_summary"):
                entry["surface_summary"] = response.get("surface_summary")
            interaction_capability = response.get("interaction_capability")
            if isinstance(interaction_capability, dict) and interaction_capability.get("click_supported") is not None:
                entry["click_supported"] = bool(interaction_capability.get("click_supported"))
            interaction_targets = response.get("interaction_targets")
            if isinstance(interaction_targets, list):
                entry["interaction_target_count"] = len(interaction_targets)
            auto_interaction = response.get("auto_interaction")
            if isinstance(auto_interaction, dict):
                entry["auto_click_eligible"] = bool(auto_interaction.get("eligible"))
                click_request = auto_interaction.get("click_request")
                if isinstance(click_request, dict):
                    try:
                        entry["auto_click_request"] = {
                            "x": int(click_request.get("x")),
                            "y": int(click_request.get("y")),
                        }
                    except (TypeError, ValueError):
                        pass
                suggested_click = auto_interaction.get("suggested_click_request")
                if isinstance(suggested_click, dict):
                    try:
                        entry["suggested_click_request"] = {
                            "x": int(suggested_click.get("x")),
                            "y": int(suggested_click.get("y")),
                        }
                    except (TypeError, ValueError):
                        pass
    if extra:
        entry.update(extra)
    return entry


def _web_feedback_state(
    *,
    http_payload: dict[str, Any],
    browser_payload: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    continuation: dict[str, Any] | None,
) -> str:
    if http_payload["assessment"].get("accessible"):
        return "http_accessible"
    next_step = continuation.get("next_step") if isinstance(continuation, dict) else None
    next_tool = str(next_step.get("tool") or "") if isinstance(next_step, dict) else ""
    if click_payload and click_payload["assessment"].get("accessible"):
        return "browser_click_accessible"
    if screenshot_payload and screenshot_payload["assessment"].get("accessible"):
        return "browser_visual_accessible"
    if browser_payload and browser_payload["assessment"].get("accessible"):
        return "browser_accessible"
    if click_payload:
        if continuation and continuation.get("state") == "invoke_tool":
            return "browser_click_continuation_available"
        return "browser_click_exhausted"
    if screenshot_payload:
        if continuation and continuation.get("state") == "invoke_tool":
            return "browser_visual_continuation_available"
        return "browser_visual_exhausted"
    if browser_payload:
        if continuation and continuation.get("state") == "invoke_tool":
            return "browser_attempted_continuation_available"
        return "browser_attempted_exhausted"
    if next_tool == "browser_fetch":
        return "browser_escalation_pending"
    if next_tool in {"browser_bootstrap", "web_retrieve"}:
        return "browser_runtime_required"
    if next_tool == "nexus_tool_registry":
        return "registry_check_required"
    return "blocked_access"


def _web_feedback_summary(
    *,
    http_payload: dict[str, Any],
    browser_payload: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    continuation: dict[str, Any] | None,
) -> str:
    http_classification = str(http_payload["assessment"].get("classification") or "unknown")
    next_step = continuation.get("next_step") if isinstance(continuation, dict) else None
    next_tool = str(next_step.get("tool") or "") if isinstance(next_step, dict) else ""
    alternate_tool = str(next_step.get("alternate_tool") or "") if isinstance(next_step, dict) else ""
    browser_surface_summary = ""
    for candidate_payload in (click_payload, screenshot_payload, browser_payload):
        if not candidate_payload:
            continue
        candidate_response = candidate_payload.get("response")
        if isinstance(candidate_response, dict) and candidate_response.get("surface_summary"):
            browser_surface_summary = str(candidate_response.get("surface_summary") or "")
            break
    if http_payload["assessment"].get("accessible"):
        return "Direct HTTP retrieval recovered accessible content."
    if click_payload and click_payload["assessment"].get("accessible"):
        summary = (
            "Direct HTTP was blocked; a bounded browser interaction clicked a grounded target and recovered "
            "accessible content."
        )
        return f"{summary} {browser_surface_summary}".strip()
    if screenshot_payload and screenshot_payload["assessment"].get("accessible"):
        summary = "Direct HTTP was blocked; visual browser capture recovered accessible content."
        return f"{summary} {browser_surface_summary}".strip()
    if browser_payload and browser_payload["assessment"].get("accessible"):
        browser = browser_payload.get("response", {}).get("browser") or "the configured browser"
        summary = f"Direct HTTP was blocked; headless browser retrieval via {browser} recovered accessible content."
        return f"{summary} {browser_surface_summary}".strip()
    if click_payload:
        if continuation and continuation.get("state") == "invoke_tool" and next_tool:
            if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
                summary = (
                    f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                    "and the page still needs review. If browser_coordinate_click is not callable on the current "
                    "caller surface, use browser_fetch with manual_click_x/manual_click_y."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
                summary = (
                    f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                    "and the page still needs review. If browser_screenshot is not callable on the current "
                    "caller surface, this in-band path keeps visual follow-up available."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "http_fetch" and alternate_tool:
                summary = (
                    f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                    "A bounded browser click already ran on a grounded target, and the page still needs review."
                )
                return f"{summary} {browser_surface_summary}".strip()
            summary = (
                f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                "and the page still needs review."
            )
            return f"{summary} {browser_surface_summary}".strip()
        summary = (
            "A bounded browser click already ran on a grounded target and the browser-aware continuation is now exhausted."
        )
        return f"{summary} {browser_surface_summary}".strip()
    if screenshot_payload:
        if continuation and continuation.get("state") == "invoke_tool" and next_tool:
            if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
                summary = (
                    f"Continue with {next_tool}. Visual browser capture completed and the page still needs grounded "
                    "follow-up. If browser_coordinate_click is not callable on the current caller surface, use "
                    "browser_fetch with manual_click_x/manual_click_y."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
                summary = (
                    f"Continue with {next_tool}. Visual browser capture completed and the page still needs grounded "
                    "follow-up. If browser_screenshot is not callable on the current caller surface, this in-band "
                    "path keeps visual follow-up available."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "http_fetch" and alternate_tool:
                summary = (
                    f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                    "Visual browser capture completed and the page still needs grounded follow-up."
                )
                return f"{summary} {browser_surface_summary}".strip()
            summary = (
                f"Continue with {next_tool}. Visual browser capture completed and the page still needs grounded follow-up."
            )
            return f"{summary} {browser_surface_summary}".strip()
        summary = (
            "Visual browser capture completed but no further bounded continuation remains."
        )
        return f"{summary} {browser_surface_summary}".strip()
    if browser_payload:
        browser = browser_payload.get("response", {}).get("browser") or "the configured browser"
        if continuation and continuation.get("state") == "invoke_tool" and next_tool:
            if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
                summary = (
                    f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and still needs "
                    "grounded follow-up. If browser_coordinate_click is not callable on the current caller surface, "
                    "use browser_fetch with manual_click_x/manual_click_y."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
                summary = (
                    f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and still needs "
                    "grounded follow-up. If browser_screenshot is not callable on the current caller surface, this "
                    "in-band path keeps visual follow-up available."
                )
                return f"{summary} {browser_surface_summary}".strip()
            if next_tool == "http_fetch" and alternate_tool:
                summary = (
                    f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                    f"Headless browser retrieval via {browser} completed and still needs grounded follow-up."
                )
                return f"{summary} {browser_surface_summary}".strip()
            summary = (
                f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and still needs "
                "grounded follow-up."
            )
            return f"{summary} {browser_surface_summary}".strip()
        summary = (
            f"Headless browser retrieval via {browser} completed and the bounded browser-aware path is now exhausted. "
            "Report blocked access instead of "
            "invoking another same-origin retrieval tool."
        )
        return f"{summary} {browser_surface_summary}".strip()
    if next_tool == "browser_fetch":
        return (
            f"Invoke {next_tool} next. Direct HTTP did not recover an accessible page state."
        )
    if next_tool in {"browser_bootstrap", "web_retrieve"}:
        return (
            f"Invoke {next_tool} next. A browser-capable escalation path is still available."
        )
    if next_tool == "nexus_tool_registry":
        return (
            "Verify the active server registry snapshot before choosing the next specialized tool. "
            "If the current caller surface cannot invoke nexus_tool_registry, use the control-plane registry "
            "HTTP endpoint instead."
        )
    return "No further bounded continuation is available for this HTTP retrieval path."


def _workflow_error_code(
    *,
    http_payload: dict[str, Any],
    browser_payload: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    continuation: dict[str, Any] | None,
) -> str | None:
    if (
        http_payload["assessment"].get("accessible")
        or (browser_payload and browser_payload["assessment"].get("accessible"))
        or (screenshot_payload and screenshot_payload["assessment"].get("accessible"))
        or (click_payload and click_payload["assessment"].get("accessible"))
    ):
        return None
    next_step = continuation.get("next_step") if isinstance(continuation, dict) else None
    next_tool = str(next_step.get("tool") or "") if isinstance(next_step, dict) else ""
    if click_payload or screenshot_payload or browser_payload:
        if continuation and continuation.get("state") == "invoke_tool" and next_tool:
            return "WEB_ACCESS_CONTINUATION_REQUIRED"
        return "WEB_ACCESS_BLOCKED_AFTER_BROWSER_ATTEMPT"
    if next_tool == "browser_fetch":
        return "WEB_ACCESS_REQUIRES_BROWSER_ESCALATION"
    if next_tool == "browser_screenshot":
        return "WEB_ACCESS_REQUIRES_VISUAL_BROWSER_REVIEW"
    if next_tool in {"browser_bootstrap", "web_retrieve"}:
        return "WEB_ACCESS_REQUIRES_BROWSER_RUNTIME"
    if next_tool == "nexus_tool_registry":
        return "WEB_ACCESS_REQUIRES_REGISTRY_CHECK"
    if _is_blocked_access_classification(http_payload["assessment"]):
        return "WEB_ACCESS_BLOCKED"
    return None


def _workflow_error_stage(
    *,
    browser_payload: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    continuation: dict[str, Any] | None,
) -> str | None:
    next_step = continuation.get("next_step") if isinstance(continuation, dict) else None
    next_tool = str(next_step.get("tool") or "") if isinstance(next_step, dict) else ""
    if click_payload or screenshot_payload or browser_payload:
        return "continuation" if continuation and continuation.get("state") == "invoke_tool" else "access"
    if next_tool in {"browser_fetch", "browser_screenshot", "browser_bootstrap", "web_retrieve", "nexus_tool_registry"}:
        return "continuation"
    return None


def _web_feedback_loop(
    *,
    http_payload: dict[str, Any],
    browser_payload: dict[str, Any] | None,
    bootstrap_attempt: dict[str, Any] | None,
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    click_attempts: list[dict[str, Any]] | None = None,
    continuation: dict[str, Any] | None,
) -> dict[str, Any]:
    attempts = [
        _attempt_trace_entry(stage="http", tool_name="http_fetch", invoked=True, payload=http_payload),
    ]
    if bootstrap_attempt is not None:
        attempts.append(
            _attempt_trace_entry(
                stage="bootstrap",
                tool_name="browser_bootstrap",
                invoked=True,
                extra={
                    "ok": bootstrap_attempt.get("ok"),
                    "error_code": bootstrap_attempt.get("error_code"),
                    "error_stage": bootstrap_attempt.get("error_stage"),
                    "message": bootstrap_attempt.get("message"),
                    "installed": bootstrap_attempt.get("installed"),
                    "target": bootstrap_attempt.get("target"),
                },
            )
        )
    if browser_payload is not None:
        attempts.append(
            _attempt_trace_entry(stage="browser", tool_name="browser_fetch", invoked=True, payload=browser_payload)
        )
    if screenshot_payload is not None:
        attempts.append(
            _attempt_trace_entry(stage="visual", tool_name="browser_screenshot", invoked=True, payload=screenshot_payload)
        )
    if click_payload is not None:
        attempt_payloads = [item for item in (click_attempts or []) if isinstance(item, dict)]
        if not attempt_payloads:
            attempt_payloads = [click_payload]
        for index, attempt_payload in enumerate(attempt_payloads, start=1):
            attempts.append(
                _attempt_trace_entry(
                    stage="interaction",
                    tool_name="browser_coordinate_click",
                    invoked=True,
                    payload=attempt_payload,
                    extra={"attempt": index},
                )
            )
    return {
        "state": _web_feedback_state(
            http_payload=http_payload,
            browser_payload=browser_payload,
            screenshot_payload=screenshot_payload,
            click_payload=click_payload,
            continuation=continuation,
        ),
        "summary": _web_feedback_summary(
            http_payload=http_payload,
            browser_payload=browser_payload,
            screenshot_payload=screenshot_payload,
            click_payload=click_payload,
            continuation=continuation,
        ),
        "attempt_trace": attempts,
        "continuation": continuation,
    }


def _browser_feedback_loop(
    *,
    browser_payload: dict[str, Any],
    screenshot_payload: dict[str, Any] | None = None,
    click_payload: dict[str, Any] | None = None,
    click_attempts: list[dict[str, Any]] | None = None,
    continuation: dict[str, Any] | None,
) -> dict[str, Any]:
    browser = browser_payload.get("response", {}).get("browser") or "the configured browser"
    browser_response = browser_payload.get("response")
    browser_surface_summary = ""
    if isinstance(browser_response, dict):
        browser_surface_summary = str(browser_response.get("surface_summary") or "")
    next_step = continuation.get("next_step") if isinstance(continuation, dict) else None
    next_tool = str(next_step.get("tool") or "") if isinstance(next_step, dict) else ""
    alternate_tool = str(next_step.get("alternate_tool") or "") if isinstance(next_step, dict) else ""
    if click_payload and click_payload["assessment"].get("accessible"):
        state = "browser_click_accessible"
        summary = (
            f"Headless browser retrieval via {browser} continued through a bounded browser click "
            "and recovered accessible content."
        )
    elif screenshot_payload and screenshot_payload["assessment"].get("accessible"):
        state = "browser_visual_accessible"
        summary = (
            f"Headless browser retrieval via {browser} continued through bounded visual review "
            "and recovered accessible content."
        )
    elif browser_payload["assessment"].get("accessible"):
        state = "browser_accessible"
        summary = f"Headless browser retrieval via {browser} recovered accessible content."
    elif click_payload:
        if continuation and continuation.get("state") == "invoke_tool":
            state = "browser_click_continuation_required"
            if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
                summary = (
                    f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                    "and the page still needs review. If browser_coordinate_click is not callable on the current "
                    "caller surface, use browser_fetch with manual_click_x/manual_click_y."
                )
            elif next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
                summary = (
                    f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                    "and the page still needs review. If browser_screenshot is not callable on the current "
                    "caller surface, this in-band path keeps visual follow-up available."
                )
            elif next_tool == "http_fetch" and alternate_tool:
                summary = (
                    f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                    "A bounded browser click already ran on a grounded target, and the page still needs review."
                )
            else:
                summary = (
                    f"Continue with {next_tool}. A bounded browser click already ran on a grounded target, "
                    "and the page still needs review."
                )
        else:
            state = "browser_blocked"
            summary = (
                "A bounded browser click already ran on a grounded target and no further bounded continuation "
                "remains. Report blocked access instead of invoking another same-origin retrieval tool."
            )
    elif screenshot_payload:
        if continuation and continuation.get("state") == "invoke_tool":
            state = "browser_visual_continuation_required"
            if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
                summary = (
                    f"Continue with {next_tool}. Visual browser capture completed and the page still needs "
                    "grounded follow-up. If browser_coordinate_click is not callable on the current caller "
                    "surface, use browser_fetch with manual_click_x/manual_click_y."
                )
            elif next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
                summary = (
                    f"Continue with {next_tool}. Visual browser capture completed and the page still needs "
                    "grounded follow-up. If browser_screenshot is not callable on the current caller surface, "
                    "this in-band path keeps visual follow-up available."
                )
            elif next_tool == "http_fetch" and alternate_tool:
                summary = (
                    f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                    "Visual browser capture completed and the page still needs grounded follow-up."
                )
            else:
                summary = (
                    f"Continue with {next_tool}. Visual browser capture completed and the page still needs "
                    "grounded follow-up."
                )
        else:
            state = "browser_blocked"
            summary = (
                "Visual browser capture completed and no further bounded continuation remains. "
                "Report blocked access instead of invoking another same-origin retrieval tool."
            )
    elif continuation and continuation.get("state") == "invoke_tool":
        state = "browser_continuation_required"
        if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
            summary = (
                f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and needs "
                "grounded follow-up. If browser_coordinate_click is not callable on the current caller surface, "
                "use browser_fetch with manual_click_x/manual_click_y."
            )
        elif next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
            summary = (
                f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and needs "
                "grounded follow-up. If browser_screenshot is not callable on the current caller surface, this "
                "in-band path keeps visual follow-up available."
            )
        elif next_tool == "http_fetch" and alternate_tool:
            summary = (
                f"Verify the current caller tool surface with {next_tool} before attempting {alternate_tool}. "
                f"Headless browser retrieval via {browser} completed and needs grounded follow-up."
            )
        else:
            summary = (
                f"Continue with {next_tool}. Headless browser retrieval via {browser} completed and needs grounded follow-up."
            )
    else:
        state = "browser_blocked"
        summary = (
            f"Headless browser retrieval via {browser} completed and no further bounded continuation remains. "
            "Report blocked access instead of invoking another same-origin retrieval tool."
        )
    if browser_surface_summary:
        summary = f"{summary} {browser_surface_summary}".strip()
    attempts = [
        _attempt_trace_entry(stage="browser", tool_name="browser_fetch", invoked=True, payload=browser_payload),
    ]
    if screenshot_payload is not None:
        attempts.append(
            _attempt_trace_entry(stage="visual", tool_name="browser_screenshot", invoked=True, payload=screenshot_payload)
        )
    if click_payload is not None:
        attempt_payloads = [item for item in (click_attempts or []) if isinstance(item, dict)]
        if not attempt_payloads:
            attempt_payloads = [click_payload]
        for index, attempt_payload in enumerate(attempt_payloads, start=1):
            attempts.append(
                _attempt_trace_entry(
                    stage="interaction",
                    tool_name="browser_coordinate_click",
                    invoked=True,
                    payload=attempt_payload,
                    extra={"attempt": index},
                )
            )
    return {
        "state": state,
        "summary": summary,
        "attempt_trace": attempts,
        "continuation": continuation,
    }


def _visual_workflow_outcome_for_screenshot(payload: dict[str, Any]) -> str:
    assessment = payload.get("assessment")
    if isinstance(assessment, dict) and assessment.get("accessible"):
        return "ok"
    if payload.get("ok"):
        return "visual_review_ready"
    if payload.get("error_code") == "BROWSER_SCREENSHOT_UNAVAILABLE":
        return "runtime_missing"
    return "visual_capture_failed"


def _visual_workflow_outcome_for_click(payload: dict[str, Any]) -> str:
    assessment = payload.get("assessment")
    if isinstance(assessment, dict) and assessment.get("accessible"):
        return "ok"
    if payload.get("ok"):
        return "post_click_review_required"
    if payload.get("error_code") == "BROWSER_AUTOMATION_UNAVAILABLE":
        return "runtime_missing"
    return "interaction_failed"


def _visual_feedback_loop(
    *,
    current_tool: str,
    payload: dict[str, Any],
    continuation: dict[str, Any] | None,
) -> dict[str, Any]:
    tool_label = "Browser screenshot capture" if current_tool == "browser_screenshot" else "Coordinate-based browser click"
    response = payload.get("response")
    surface_summary = ""
    if isinstance(response, dict):
        surface_summary = str(response.get("surface_summary") or "")
    assessment = payload.get("assessment")
    accessible = bool(isinstance(assessment, dict) and assessment.get("accessible"))
    if accessible:
        summary = f"{tool_label} recovered an accessible post-interaction page state."
        state = "visual_accessible"
    elif continuation and continuation.get("state") == "invoke_tool":
        next_step = continuation.get("next_step") or {}
        next_tool = str(next_step.get("tool") or "")
        alternate_tool = str(next_step.get("alternate_tool") or "")
        if next_tool == "browser_fetch" and alternate_tool == "browser_coordinate_click":
            summary = (
                f"{tool_label} completed. Continue with {next_tool}. If browser_coordinate_click is not callable "
                "on the current caller surface, use browser_fetch with manual_click_x/manual_click_y."
            )
        elif next_tool == "browser_fetch" and alternate_tool == "browser_screenshot":
            summary = (
                f"{tool_label} completed. Continue with {next_tool}. If browser_screenshot is not callable on "
                "the current caller surface, this in-band path keeps visual follow-up available."
            )
        elif next_tool == "http_fetch" and alternate_tool:
            summary = (
                f"{tool_label} completed. Verify the current caller tool surface with {next_tool} "
                f"before attempting {alternate_tool}."
            )
        else:
            summary = f"{tool_label} completed. Continue with {next_tool}."
        state = "visual_continuation_required"
    else:
        summary = str(payload.get("message") or f"{tool_label} did not recover accessible content.")
        state = "visual_blocked"
    if surface_summary:
        summary = f"{summary} {surface_summary}".strip()
    return {
        "state": state,
        "summary": summary,
        "attempt_trace": [
            _attempt_trace_entry(stage="browser", tool_name=current_tool, invoked=True, payload=payload),
        ],
        "continuation": continuation,
    }


def _build_curl_probe_command(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
) -> str:
    header_args = ""
    for key, value in headers.items():
        header_args += f" -H {shlex.quote(f'{key}: {value}')}"
    return (
        "header_file=$(mktemp) && "
        "body_file=$(mktemp) && "
        "meta_file=$(mktemp) && "
        f"curl -sS -L --compressed -X {shlex.quote(method)}{header_args} "
        f"--max-time {timeout_sec} -D \"$header_file\" -o \"$body_file\" "
        f"-w '%{{http_code}}\\n%{{url_effective}}\\n%{{content_type}}\\n%{{size_download}}\\n%{{time_total}}\\n' "
        f"{shlex.quote(url)} > \"$meta_file\"; "
        "curl_status=$?; "
        f"printf '{_CURL_EXIT_MARKER}\\n%s\\n' \"$curl_status\"; "
        f"printf '{_CURL_META_MARKER}\\n'; cat \"$meta_file\"; "
        f"printf '{_CURL_HEADERS_MARKER}\\n'; cat \"$header_file\"; printf '\\n'; "
        f"printf '{_CURL_BODY_MARKER}\\n'; head -c {max_body_chars} \"$body_file\"; "
        "rm -f \"$header_file\" \"$body_file\" \"$meta_file\""
    )


def _parse_curl_probe_output(stdout: str, stderr: str) -> dict[str, Any]:
    exit_section = f"{_CURL_EXIT_MARKER}\n"
    meta_section = f"{_CURL_META_MARKER}\n"
    headers_section = f"{_CURL_HEADERS_MARKER}\n"
    body_section = f"{_CURL_BODY_MARKER}\n"
    if (
        exit_section not in stdout
        or meta_section not in stdout
        or headers_section not in stdout
        or body_section not in stdout
    ):
        return {
            "transport": "curl",
            "transport_ok": False,
            "transfer_error": stderr.strip() or "Could not parse curl probe output.",
        }

    _, after_exit = stdout.split(exit_section, 1)
    exit_text, after_meta_marker = after_exit.split(meta_section, 1)
    meta_text, after_headers_marker = after_meta_marker.split(headers_section, 1)
    headers_text, body_text = after_headers_marker.split(body_section, 1)

    meta_lines = [line.strip() for line in meta_text.splitlines() if line.strip()]
    status_code = int(meta_lines[0]) if len(meta_lines) > 0 and meta_lines[0].isdigit() else None
    elapsed = float(meta_lines[4]) if len(meta_lines) > 4 and meta_lines[4] else None
    _, parsed_headers = _parse_header_blocks(headers_text)
    return {
        "transport": "curl",
        "transport_ok": exit_text.strip() == "0",
        "status_code": status_code,
        "final_url": meta_lines[1] if len(meta_lines) > 1 else None,
        "content_type": meta_lines[2] if len(meta_lines) > 2 else None,
        "downloaded_bytes": int(float(meta_lines[3])) if len(meta_lines) > 3 and meta_lines[3] else None,
        "elapsed_seconds": elapsed,
        "headers": parsed_headers,
        "body_preview": body_text,
        "transfer_error": stderr.strip() or None,
    }


async def _fetch_with_curl(
    conn,
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
) -> dict[str, Any]:
    command = _build_curl_probe_command(
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
    )
    result = await conn.run_full(command, timeout=timeout_sec + 10)
    if not result.ok and not result.stdout:
        return {
            "transport": "curl",
            "transport_ok": False,
            "transfer_error": result.stderr.strip() or result.stdout.strip() or "curl request failed.",
        }
    return _parse_curl_probe_output(result.stdout, result.stderr)


async def _fetch_with_python(
    conn,
    *,
    python_bin: str,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
) -> dict[str, Any]:
    payload = json.dumps(
        {
            "url": url,
            "method": method,
            "headers": headers,
            "timeout_sec": timeout_sec,
            "max_body_chars": max_body_chars,
        },
        ensure_ascii=True,
    )
    script = r"""
import json
import ssl
import sys
import urllib.error
import urllib.request

payload = json.loads(sys.argv[1])
request = urllib.request.Request(
    payload["url"],
    headers=payload.get("headers") or {},
    method=(payload.get("method") or "GET").upper(),
)
ctx = ssl.create_default_context()
max_chars = max(256, int(payload.get("max_body_chars") or 5000))
max_bytes = max_chars * 4
result = {"transport": "python", "transport_ok": False}

def capture(response, error_text=None):
    body = response.read(max_bytes + 1)
    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]
    text = body.decode("utf-8", "ignore")
    result.update(
        {
            "transport_ok": True,
            "status_code": getattr(response, "status", None) or response.getcode(),
            "final_url": response.geturl(),
            "headers": dict(response.headers.items()) if getattr(response, "headers", None) else {},
            "body_preview": text[:max_chars],
            "body_truncated": truncated or len(text) > max_chars,
            "transfer_error": error_text,
        }
    )

try:
    with urllib.request.urlopen(request, context=ctx, timeout=int(payload.get("timeout_sec") or 20)) as response:
        capture(response)
except urllib.error.HTTPError as exc:
    capture(exc, repr(exc))
except Exception as exc:
    result["transfer_error"] = repr(exc)

print(json.dumps(result, ensure_ascii=True))
"""
    command = f"{shlex.quote(python_bin)} -c {shlex.quote(script)} {shlex.quote(payload)}"
    result = await conn.run_full(command, timeout=timeout_sec + 10)
    if not result.ok:
        return {
            "transport": "python",
            "transport_ok": False,
            "transfer_error": result.stderr.strip() or result.stdout.strip() or "Python request failed.",
        }
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "transport": "python",
            "transport_ok": False,
            "transfer_error": result.stderr.strip() or "Could not parse Python HTTP probe output.",
        }
    parsed.setdefault("transport", "python")
    return parsed if isinstance(parsed, dict) else {"transport": "python", "transport_ok": False}


async def _fetch_http_probe(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities()
        capability_data = capabilities.to_dict()
        if capabilities.has("curl"):
            return (
                await _fetch_with_curl(
                    conn,
                    url=url,
                    method=method,
                    headers=headers,
                    timeout_sec=timeout_sec,
                    max_body_chars=max_body_chars,
                ),
                capability_data,
            )
        if capabilities.python_command:
            return (
                await _fetch_with_python(
                    conn,
                    python_bin=capabilities.python_command,
                    url=url,
                    method=method,
                    headers=headers,
                    timeout_sec=timeout_sec,
                    max_body_chars=max_body_chars,
                ),
                capability_data,
            )
        return (
            {
                "transport": None,
                "transport_ok": False,
                "transfer_error": "Neither curl nor Python is available on the target host.",
            },
            capability_data,
        )
    finally:
        pool.release(conn)


async def _http_probe_payload(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
    browser_profile: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = time.monotonic()
    response, capabilities = await _fetch_http_probe(
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
    )
    body_preview = str(response.get("body_preview") or "")
    metadata = _extract_html_metadata(body_preview)
    dom_observation = _extract_dom_affordances(body_preview)
    interaction_capability = _http_interaction_capability()
    surface_summary = _surface_observation_summary(dom_observation, interaction_capability)
    merged_headers = dict(response.get("headers") or {})
    if response.get("content_type") and "Content-Type" not in merged_headers:
        merged_headers["Content-Type"] = str(response["content_type"])
    assessment = _assess_http_access(
        status_code=response.get("status_code"),
        headers=merged_headers,
        body_preview=body_preview,
        metadata=metadata,
    )
    ok, error_code, error_stage, message = _error_details_for_assessment(
        assessment,
        str(response.get("transfer_error") or "") or None,
    )
    runtime_status: dict[str, Any] = {}
    recommendations: list[dict[str, Any]] = []
    if _is_blocked_access_classification(assessment):
        runtime_status = _runtime_status_hint_from_capabilities(capabilities)
        try:
            _, live_runtime_status = await _runtime_status_snapshot(refresh=False)
        except Exception:
            live_runtime_status = {}
        if live_runtime_status:
            runtime_status = live_runtime_status
        recommendations = _browser_recommendations(
            assessment,
            runtime_status,
            browser_attempted=False,
            browser_accessible=False,
        )

    retry_guidance = _retry_guidance(assessment, runtime_status)
    workflow_handoff = _web_workflow_handoff(
        current_tool="http_fetch",
        assessment=assessment,
        outcome_override=None,
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
        wait_ms=5000,
        browser_profile=browser_profile,
        preferred_browser="",
    )
    continuation = _continuation_from_handoff(workflow_handoff)
    feedback_loop = _web_feedback_loop(
        http_payload={
            "ok": ok,
            "error_code": error_code,
            "error_stage": error_stage,
            "message": message,
            "assessment": assessment,
            "response": {
                "status_code": response.get("status_code"),
            },
        },
        browser_payload=None,
        bootstrap_attempt=None,
        continuation=continuation,
    )
    workflow_error_code = _workflow_error_code(
        http_payload={
            "assessment": assessment,
        },
        browser_payload=None,
        continuation=continuation,
    )
    workflow_error_stage = _workflow_error_stage(browser_payload=None, continuation=continuation)
    workflow_message = feedback_loop["summary"]
    payload = {
        "request": {
            "url": url,
            "method": method,
            "headers": headers,
            "timeout_sec": timeout_sec,
            "max_body_chars": max_body_chars,
        },
        "response": {
            "transport": response.get("transport"),
            "transport_ok": response.get("transport_ok"),
            "status_code": response.get("status_code"),
            "final_url": response.get("final_url"),
            "headers": merged_headers,
            "content_type": response.get("content_type") or _header_value(merged_headers, "content-type"),
            "elapsed_seconds": response.get("elapsed_seconds"),
            "downloaded_bytes": response.get("downloaded_bytes"),
            "body_preview_truncated": response.get("body_truncated", False),
            "transfer_error": response.get("transfer_error"),
            "metadata": metadata,
            "dom_observation": dom_observation,
            "interaction_capability": interaction_capability,
            "surface_summary": surface_summary,
        },
        "assessment": assessment,
        "retry_guidance": retry_guidance,
        "capabilities": capabilities,
        "runtime_status": runtime_status,
        "recommendations": recommendations,
        "workflow_handoff": workflow_handoff,
        "continuation": continuation,
        "feedback_loop": feedback_loop,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "ok": ok,
        "error_code": workflow_error_code or error_code,
        "error_stage": workflow_error_stage or error_stage,
        "message": workflow_message or message,
        "body_preview": body_preview,
    }
    return payload, response


async def _probe_browser_runtimes(conn, *, timeout_sec: int = 15) -> dict[str, Any]:
    command_list = " ".join(shlex.quote(item) for item in _BROWSER_CANDIDATE_COMMANDS)
    command = (
        "for cmd in "
        f"{command_list}; "
        "do path=$(command -v \"$cmd\" 2>/dev/null || true); "
        "if [ -n \"$path\" ]; then printf '%s\\t%s\\n' \"$cmd\" \"$path\"; fi; "
        "done"
    )
    result = await conn.run_full(command, timeout=timeout_sec)
    commands: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        name, path = line.split("\t", 1)
        if name and path:
            commands[name.strip()] = path.strip()

    chromium_family = [
        {"command": name, "path": commands[name]}
        for name in _CHROMIUM_FAMILY_COMMANDS
        if name in commands
    ]
    firefox_path = commands.get("firefox")
    playwright_path = commands.get("playwright")
    runtime_status = {
        "commands": commands,
        "chromium_family": {
            "available": bool(chromium_family),
            "preferred": chromium_family[0]["command"] if chromium_family else None,
            "preferred_path": chromium_family[0]["path"] if chromium_family else None,
            "candidates": chromium_family,
        },
        "firefox": {"available": bool(firefox_path), "path": firefox_path},
        "playwright": {"available": bool(playwright_path), "path": playwright_path},
        "javascript": {
            "node": commands.get("node"),
            "npm": commands.get("npm"),
            "npx": commands.get("npx"),
        },
        "python": {"python3": commands.get("python3")},
        "headless_dom_supported": bool(chromium_family),
        "recommended_queries": _query_terms_for_runtime_targets(),
    }
    runtime_status["automation"] = _browser_automation_capability(runtime_status)
    return runtime_status


def _resolve_browser_command(
    runtime_status: dict[str, Any],
    preferred_browser: str = "",
) -> tuple[str | None, str | None]:
    commands = runtime_status.get("commands", {})
    if not isinstance(commands, dict):
        commands = {}
    preferred = preferred_browser.strip()
    if preferred and preferred in commands:
        return preferred, str(commands[preferred])
    chromium_family = runtime_status.get("chromium_family", {})
    if isinstance(chromium_family, dict) and chromium_family.get("preferred") and chromium_family.get("preferred_path"):
        return str(chromium_family["preferred"]), str(chromium_family["preferred_path"])
    return None, None


def _browser_interaction_introspection_js() -> str:
    return r"""
(() => {
  function normalizeText(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
  }

  function selectorHint(element) {
    const tag = element.tagName ? element.tagName.toLowerCase() : "node";
    const id = normalizeText(element.id || "");
    const className = normalizeText(element.className || "");
    const classBits = className ? className.split(" ").filter(Boolean).slice(0, 2).map((item) => `.${item}`).join("") : "";
    return `${tag}${id ? `#${id}` : ""}${classBits}`;
  }

  function labelText(element) {
    if (!element || typeof element.getAttribute !== "function") {
      return "";
    }
    const candidates = [
      element.getAttribute("aria-label"),
      element.getAttribute("value"),
      element.innerText,
      element.textContent,
      element.getAttribute("title"),
      element.getAttribute("alt"),
      element.getAttribute("name"),
      element.id,
    ];
    for (const candidate of candidates) {
      const normalized = normalizeText(candidate);
      if (normalized) {
        return normalized;
      }
    }
    return "";
  }

  function gatherRoots(root, roots = []) {
    if (!root) {
      return roots;
    }
    roots.push(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    let node = walker.nextNode();
    while (node) {
      if (node.shadowRoot) {
        gatherRoots(node.shadowRoot, roots);
      }
      node = walker.nextNode();
    }
    return roots;
  }

  function queryInRoots(roots, selector) {
    const collected = [];
    for (const root of roots) {
      try {
        collected.push(...Array.from(root.querySelectorAll(selector)));
      } catch (error) {
      }
    }
    return collected;
  }

  const viewportWidth = Math.max(window.innerWidth || 0, document.documentElement ? document.documentElement.clientWidth || 0 : 0);
  const viewportHeight = Math.max(window.innerHeight || 0, document.documentElement ? document.documentElement.clientHeight || 0 : 0);
  const viewportArea = Math.max(1, viewportWidth * viewportHeight);
  const selectors = [
    "button",
    "input",
    "label",
    "iframe",
    "a[href]",
    "textarea",
    "select",
    "summary",
    "[role='button']",
    "[role='checkbox']",
    "[role='radio']",
    "[role='link']",
    "[tabindex]",
    "[onclick]",
  ];
  const roots = gatherRoots(document, []);
  const elements = Array.from(
    new Set(selectors.flatMap((selector) => queryInRoots(roots, selector)))
  );
  const targets = [];
  for (const element of elements) {
    if (!(element instanceof Element)) {
      continue;
    }
    const rect = element.getBoundingClientRect();
    if (!Number.isFinite(rect.width) || !Number.isFinite(rect.height)) {
      continue;
    }
    const tag = element.tagName.toLowerCase();
    const intersectionLeft = Math.max(0, Math.min(viewportWidth, rect.left));
    const intersectionTop = Math.max(0, Math.min(viewportHeight, rect.top));
    const intersectionRight = Math.max(0, Math.min(viewportWidth, rect.right));
    const intersectionBottom = Math.max(0, Math.min(viewportHeight, rect.bottom));
    const intersectionWidth = Math.max(0, intersectionRight - intersectionLeft);
    const intersectionHeight = Math.max(0, intersectionBottom - intersectionTop);
    const inViewport = intersectionWidth >= 1 && intersectionHeight >= 1;
    if (!inViewport) {
      continue;
    }
    const style = window.getComputedStyle(element);
    const opacity = Number(style.opacity || "1");
    const displayVisible = style.display !== "none" && style.visibility !== "hidden" && style.visibility !== "collapse";
    const pointerEventsVisible = style.pointerEvents !== "none";
    const visibleGeometry = rect.width >= 1 && rect.height >= 1;
    const opacityVisible = tag === "iframe" ? opacity >= 0 : opacity > 0.01;
    const visible = Boolean(visibleGeometry && displayVisible && pointerEventsVisible && opacityVisible);
    if (!visible && tag !== "iframe") {
      continue;
    }

    const role = normalizeText(element.getAttribute("role") || "").toLowerCase();
    const inputType = tag === "input" ? normalizeText(element.getAttribute("type") || "text").toLowerCase() : "";
    const pointer = Boolean(element.getAttribute("onclick")) || style.cursor === "pointer";
    const disabled = Boolean(element.disabled || element.getAttribute("aria-disabled") === "true");
    const associatedControl = tag === "label"
      ? (element.control || (element.htmlFor ? document.getElementById(element.htmlFor) : null))
      : null;
    const associatedControlKind = associatedControl && associatedControl.tagName && associatedControl.tagName.toLowerCase() === "input"
      ? normalizeText(associatedControl.getAttribute("type") || "text").toLowerCase()
      : "";

    let kind = "generic";
    if (tag === "iframe") {
      kind = "iframe";
    } else if (tag === "a") {
      kind = "link";
    } else if (tag === "button") {
      kind = "button";
    } else if (tag === "label") {
      kind = "label";
    } else if (tag === "input") {
      if (inputType === "checkbox") {
        kind = "checkbox";
      } else if (inputType === "radio") {
        kind = "radio";
      } else if (inputType === "submit" || inputType === "button") {
        kind = "submit";
      } else {
        kind = "input";
      }
    } else if (role === "button") {
      kind = "role_button";
    } else if (role === "checkbox") {
      kind = "role_checkbox";
    }

    const area = Math.max(0, rect.width) * Math.max(0, rect.height);
    const visibleArea = Math.max(0, intersectionWidth) * Math.max(0, intersectionHeight);
    const rootNode = element.getRootNode();
    const sourceRoot = rootNode === document ? "document" : "shadow";
    targets.push({
      tag,
      kind,
      role: role || null,
      input_type: inputType || null,
      associated_control_kind: associatedControlKind || null,
      label: labelText(element) || null,
      title: normalizeText(element.getAttribute("title") || "") || null,
      aria_label: normalizeText(element.getAttribute("aria-label") || "") || null,
      selector_hint: selectorHint(element),
      clickable: !disabled,
      visible,
      in_viewport: inViewport,
      disabled,
      pointer,
      checked: Boolean(element.checked),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      center_x: Math.round(intersectionLeft + (intersectionWidth / 2)),
      center_y: Math.round(intersectionTop + (intersectionHeight / 2)),
      visible_area: Math.round(visibleArea),
      visibility_ratio: area > 0 ? Math.min(1, visibleArea / area) : 0,
      viewport_area: viewportArea,
      source_root: sourceRoot,
    });
  }
  return {
    viewport_width: viewportWidth,
    viewport_height: viewportHeight,
    interaction_targets: targets.slice(0, 64),
  };
})()
"""


def _browser_dom_command(
    *,
    browser_path: str,
    url: str,
    wait_ms: int,
    user_agent: str,
) -> str:
    return (
        "profile_dir=$(mktemp -d) && "
        f"{shlex.quote(browser_path)} "
        "--headless "
        "--disable-gpu "
        "--no-sandbox "
        "--disable-dev-shm-usage "
        f"--virtual-time-budget={max(0, wait_ms)} "
        "--lang=en-US "
        f"--user-data-dir=\"$profile_dir\" "
        f"--user-agent={shlex.quote(user_agent)} "
        "--dump-dom "
        f"{shlex.quote(url)}; "
        "status=$?; "
        "rm -rf \"$profile_dir\"; "
        "exit $status"
    )


def _browser_screenshot_command(
    *,
    browser_path: str,
    python_bin: str,
    url: str,
    wait_ms: int,
    user_agent: str,
    width: int,
    height: int,
) -> str:
    return (
        "profile_dir=$(mktemp -d) && "
        "shot_tmp=$(mktemp /tmp/nexus-browser-shot-XXXXXX) && "
        "shot_file=\"${shot_tmp}.png\" && "
        "rm -f \"$shot_tmp\" && "
        "stderr_file=$(mktemp) && "
        f"{shlex.quote(browser_path)} "
        "--headless "
        "--disable-gpu "
        "--no-sandbox "
        "--disable-dev-shm-usage "
        "--hide-scrollbars "
        f"--virtual-time-budget={max(0, wait_ms)} "
        f"--window-size={max(320, width)},{max(240, height)} "
        "--lang=en-US "
        f"--user-data-dir=\"$profile_dir\" "
        f"--user-agent={shlex.quote(user_agent)} "
        "--run-all-compositor-stages-before-draw "
        "--screenshot=\"$shot_file\" "
        f"{shlex.quote(url)} >/dev/null 2>\"$stderr_file\"; "
        "status=$?; "
        "for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do "
        "[ -s \"$shot_file\" ] && break; "
        "sleep 0.2; "
        "done; "
        f"printf '{_BROWSER_SCREENSHOT_STATUS_MARKER}\\n%s\\n' \"$status\"; "
        f"printf '{_BROWSER_SCREENSHOT_STDERR_MARKER}\\n'; cat \"$stderr_file\"; printf '\\n'; "
        "if [ -s \"$shot_file\" ]; then "
        f"printf '{_BROWSER_SCREENSHOT_B64_MARKER}\\n'; "
        f"{shlex.quote(python_bin)} -c "
        + shlex.quote(
            "import base64, pathlib, sys; "
            "print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode('ascii'))"
        )
        + " \"$shot_file\"; printf '\\n'; "
        "fi; "
        "rm -rf \"$profile_dir\" \"$stderr_file\"; "
        "rm -f \"$shot_file\""
    )


def _browser_visual_capture_command(
    *,
    browser_path: str,
    url: str,
    wait_ms: int,
    width: int,
    height: int,
    user_agent: str,
) -> str:
    payload = json.dumps(
        {
            "browser_path": browser_path,
            "url": url,
            "wait_ms": max(0, wait_ms),
            "width": max(320, width),
            "height": max(240, height),
            "user_agent": user_agent,
        },
        ensure_ascii=True,
    )
    interaction_expression = json.dumps(_browser_interaction_introspection_js(), ensure_ascii=True)
    script = r"""
const childProcess = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const payload = JSON.parse(process.argv[2]);
const interactionExpression = __NEXUS_INTERACTION_EXPRESSION__;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpJson(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      let data = "";
      response.on("data", (chunk) => {
        data += chunk;
      });
      response.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("error", reject);
  });
}

function allocatePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
    server.on("error", reject);
  });
}

async function waitForPageTarget(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const targets = await httpJson(`http://127.0.0.1:${port}/json/list`);
      if (Array.isArray(targets)) {
        const page = targets.find((item) => item && item.type === "page" && item.webSocketDebuggerUrl);
        if (page) {
          return page;
        }
      }
    } catch (error) {
    }
    await sleep(100);
  }
  throw new Error("Timed out waiting for DevTools page target.");
}

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    if (typeof WebSocket !== "function") {
      throw new Error("Global WebSocket is unavailable in this Node runtime.");
    }
    this.socket = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("Timed out connecting to DevTools WebSocket.")), 5000);
      this.socket.addEventListener("open", () => {
        clearTimeout(timeout);
        resolve();
      });
      this.socket.addEventListener("error", (event) => {
        clearTimeout(timeout);
        reject(event.error || new Error("DevTools WebSocket connection failed."));
      });
    });
    this.socket.addEventListener("message", (event) => {
      let payload = null;
      try {
        payload = JSON.parse(String(event.data));
      } catch (error) {
        return;
      }
      if (!payload || !payload.id) {
        return;
      }
      const pending = this.pending.get(payload.id);
      if (!pending) {
        return;
      }
      this.pending.delete(payload.id);
      if (payload.error) {
        pending.reject(new Error(payload.error.message || "CDP command failed."));
        return;
      }
      pending.resolve(payload.result || {});
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async close() {
    if (!this.socket) {
      return;
    }
    try {
      this.socket.close();
    } catch (error) {
    }
  }
}

async function main() {
  const port = await allocatePort();
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-browser-"));
  const args = [
    "--headless",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--hide-scrollbars",
    `--remote-debugging-port=${port}`,
    `--window-size=${payload.width},${payload.height}`,
    "--lang=en-US",
    `--user-data-dir=${profileDir}`,
    `--user-agent=${payload.user_agent}`,
    payload.url,
  ];
  const browser = childProcess.spawn(payload.browser_path, args, {
    stdio: ["ignore", "ignore", "pipe"],
  });

  let browserStderr = "";
  browser.stderr.on("data", (chunk) => {
    browserStderr += String(chunk);
  });

  let client = null;
  try {
    const page = await waitForPageTarget(port, 10000);
    client = new CdpClient(page.webSocketDebuggerUrl);
    await client.connect();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await sleep(payload.wait_ms);
    const htmlResult = await client.send("Runtime.evaluate", {
      expression: "document.documentElement ? document.documentElement.outerHTML : ''",
      returnByValue: true,
    });
    const titleResult = await client.send("Runtime.evaluate", {
      expression: "document.title || ''",
      returnByValue: true,
    });
    const hrefResult = await client.send("Runtime.evaluate", {
      expression: "location.href",
      returnByValue: true,
    });
    const interactionResult = await client.send("Runtime.evaluate", {
      expression: interactionExpression,
      returnByValue: true,
    });
    const metrics = await client.send("Page.getLayoutMetrics");
    const screenshot = await client.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
      fromSurface: true,
    });
    const cssViewport = metrics.cssVisualViewport || {};
    const cssContent = metrics.cssContentSize || {};
    const interactionValue = (interactionResult.result || {}).value || {};
    console.log(JSON.stringify({
      ok: true,
      screenshot_base64: screenshot.data || "",
      body_preview: String((htmlResult.result || {}).value || ""),
      title: String((titleResult.result || {}).value || ""),
      final_url: String((hrefResult.result || {}).value || payload.url),
      viewport_width: Number(interactionValue.viewport_width || cssViewport.clientWidth || payload.width),
      viewport_height: Number(interactionValue.viewport_height || cssViewport.clientHeight || payload.height),
      content_width: Number(cssContent.width || payload.width),
      content_height: Number(cssContent.height || payload.height),
      interaction_targets: Array.isArray(interactionValue.interaction_targets) ? interactionValue.interaction_targets : [],
      browser_stderr: browserStderr.trim() || null,
    }));
  } finally {
    if (client) {
      await client.close();
    }
    try {
      browser.kill("SIGKILL");
    } catch (error) {
    }
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.log(JSON.stringify({
    ok: false,
    error: error && error.message ? error.message : String(error),
  }));
  process.exit(1);
});
"""
    script = script.replace("__NEXUS_INTERACTION_EXPRESSION__", interaction_expression)
    return f"node --experimental-websocket - {shlex.quote(payload)} <<'NEXUS_NODE_EOF'\n{script}\nNEXUS_NODE_EOF"


def _parse_marker_section(text: str, marker: str, next_markers: tuple[str, ...]) -> str:
    start = text.find(marker)
    if start < 0:
        return ""
    start += len(marker)
    if start < len(text) and text[start] == "\n":
        start += 1
    end = len(text)
    for next_marker in next_markers:
        idx = text.find(next_marker, start)
        if idx >= 0:
            end = min(end, idx)
    return text[start:end].strip()


def _parse_browser_screenshot_output(stdout: str) -> dict[str, Any]:
    status_text = _parse_marker_section(
        stdout,
        _BROWSER_SCREENSHOT_STATUS_MARKER,
        (_BROWSER_SCREENSHOT_STDERR_MARKER, _BROWSER_SCREENSHOT_B64_MARKER),
    )
    stderr_text = _parse_marker_section(
        stdout,
        _BROWSER_SCREENSHOT_STDERR_MARKER,
        (_BROWSER_SCREENSHOT_B64_MARKER,),
    )
    screenshot_b64 = _parse_marker_section(stdout, _BROWSER_SCREENSHOT_B64_MARKER, ())
    return {
        "exit_code": int(status_text) if status_text.isdigit() else None,
        "stderr": stderr_text,
        "screenshot_base64": screenshot_b64,
    }


def _write_browser_visual_artifacts(
    *,
    tool_name: str,
    screenshot_base64: str,
    width: int,
    height: int,
    grid_step_px: int,
    marker: tuple[int, int] | None = None,
) -> list[Any]:
    if not screenshot_base64:
        return []
    context = tool_context(tool_name)
    artifacts = get_artifacts()
    png_bytes = base64.b64decode(screenshot_base64)
    png_artifact = artifacts.write_bytes(
        tool_name=tool_name,
        channel="screenshot",
        content=png_bytes,
        request_id=context.request_id,
        suffix=".png",
    )
    grid_svg = _grid_svg_document(
        png_base64=screenshot_base64,
        width=width,
        height=height,
        grid_step_px=grid_step_px,
        marker=marker,
    )
    grid_artifact = artifacts.write_text(
        tool_name=tool_name,
        channel="grid",
        content=grid_svg,
        request_id=context.request_id,
        suffix=".svg",
    )
    return [png_artifact, grid_artifact]


def _browser_render_assessment(
    *,
    body_preview: str,
    title_hint: str = "",
    failure_constraint: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    metadata = _extract_html_metadata(body_preview)
    if title_hint and not metadata.get("title"):
        metadata["title"] = title_hint
    dom_observation = _extract_dom_affordances(body_preview)
    if body_preview.strip():
        assessment = _assess_http_access(
            status_code=None,
            headers={},
            body_preview=body_preview,
            metadata=metadata,
            retrieved_hint=True,
        )
    else:
        assessment = {
            "classification": "http_error",
            "retrieved": False,
            "accessible": False,
            "constraints": [failure_constraint],
            "evidence": {
                "status_code": None,
                "title": metadata.get("title") or None,
                "retry_after": None,
                "www_authenticate": None,
                "content_type": None,
            },
        }
    return metadata, dom_observation, assessment


def _browser_coordinate_click_command(
    *,
    browser_path: str,
    url: str,
    x: int,
    y: int,
    wait_before_ms: int,
    wait_after_ms: int,
    width: int,
    height: int,
    user_agent: str,
) -> str:
    payload = json.dumps(
        {
            "browser_path": browser_path,
            "url": url,
            "x": x,
            "y": y,
            "wait_before_ms": max(0, wait_before_ms),
            "wait_after_ms": max(0, wait_after_ms),
            "width": max(320, width),
            "height": max(240, height),
            "user_agent": user_agent,
        },
        ensure_ascii=True,
    )
    interaction_expression = json.dumps(_browser_interaction_introspection_js(), ensure_ascii=True)
    script = r"""
const childProcess = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const payload = JSON.parse(process.argv[2]);
const interactionExpression = __NEXUS_INTERACTION_EXPRESSION__;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpJson(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      let data = "";
      response.on("data", (chunk) => {
        data += chunk;
      });
      response.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("error", reject);
  });
}

function allocatePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
    server.on("error", reject);
  });
}

async function waitForPageTarget(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const targets = await httpJson(`http://127.0.0.1:${port}/json/list`);
      if (Array.isArray(targets)) {
        const page = targets.find((item) => item && item.type === "page" && item.webSocketDebuggerUrl);
        if (page) {
          return page;
        }
      }
    } catch (error) {
    }
    await sleep(100);
  }
  throw new Error("Timed out waiting for DevTools page target.");
}

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    if (typeof WebSocket !== "function") {
      throw new Error("Global WebSocket is unavailable in this Node runtime.");
    }
    this.socket = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("Timed out connecting to DevTools WebSocket.")), 5000);
      this.socket.addEventListener("open", () => {
        clearTimeout(timeout);
        resolve();
      });
      this.socket.addEventListener("error", (event) => {
        clearTimeout(timeout);
        reject(event.error || new Error("DevTools WebSocket connection failed."));
      });
    });
    this.socket.addEventListener("message", (event) => {
      let payload = null;
      try {
        payload = JSON.parse(String(event.data));
      } catch (error) {
        return;
      }
      if (!payload || !payload.id) {
        return;
      }
      const pending = this.pending.get(payload.id);
      if (!pending) {
        return;
      }
      this.pending.delete(payload.id);
      if (payload.error) {
        pending.reject(new Error(payload.error.message || "CDP command failed."));
        return;
      }
      pending.resolve(payload.result || {});
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async close() {
    if (!this.socket) {
      return;
    }
    try {
      this.socket.close();
    } catch (error) {
    }
  }
}

async function main() {
  const port = await allocatePort();
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-browser-"));
  const args = [
    "--headless",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--hide-scrollbars",
    `--remote-debugging-port=${port}`,
    `--window-size=${payload.width},${payload.height}`,
    "--lang=en-US",
    `--user-data-dir=${profileDir}`,
    `--user-agent=${payload.user_agent}`,
    payload.url,
  ];
  const browser = childProcess.spawn(payload.browser_path, args, {
    stdio: ["ignore", "ignore", "pipe"],
  });

  let browserStderr = "";
  browser.stderr.on("data", (chunk) => {
    browserStderr += String(chunk);
  });

  let client = null;
  try {
    const page = await waitForPageTarget(port, 10000);
    client = new CdpClient(page.webSocketDebuggerUrl);
    await client.connect();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await sleep(payload.wait_before_ms);
    await client.send("Input.dispatchMouseEvent", {
      type: "mouseMoved",
      x: payload.x,
      y: payload.y,
      button: "left",
      buttons: 1,
    });
    await client.send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x: payload.x,
      y: payload.y,
      button: "left",
      clickCount: 1,
    });
    await client.send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x: payload.x,
      y: payload.y,
      button: "left",
      clickCount: 1,
    });
    await sleep(payload.wait_after_ms);
    const htmlResult = await client.send("Runtime.evaluate", {
      expression: "document.documentElement ? document.documentElement.outerHTML : ''",
      returnByValue: true,
    });
    const titleResult = await client.send("Runtime.evaluate", {
      expression: "document.title || ''",
      returnByValue: true,
    });
    const hrefResult = await client.send("Runtime.evaluate", {
      expression: "location.href",
      returnByValue: true,
    });
    const interactionResult = await client.send("Runtime.evaluate", {
      expression: interactionExpression,
      returnByValue: true,
    });
    const metrics = await client.send("Page.getLayoutMetrics");
    const screenshot = await client.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
      fromSurface: true,
    });
    const cssViewport = metrics.cssVisualViewport || {};
    const cssContent = metrics.cssContentSize || {};
    const interactionValue = (interactionResult.result || {}).value || {};
    console.log(JSON.stringify({
      ok: true,
      screenshot_base64: screenshot.data || "",
      body_preview: String((htmlResult.result || {}).value || ""),
      title: String((titleResult.result || {}).value || ""),
      final_url: String((hrefResult.result || {}).value || payload.url),
      viewport_width: Number(interactionValue.viewport_width || cssViewport.clientWidth || payload.width),
      viewport_height: Number(interactionValue.viewport_height || cssViewport.clientHeight || payload.height),
      content_width: Number(cssContent.width || payload.width),
      content_height: Number(cssContent.height || payload.height),
      interaction_targets: Array.isArray(interactionValue.interaction_targets) ? interactionValue.interaction_targets : [],
      browser_stderr: browserStderr.trim() || null,
    }));
  } finally {
    if (client) {
      await client.close();
    }
    try {
      browser.kill("SIGKILL");
    } catch (error) {
    }
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.log(JSON.stringify({
    ok: false,
    error: error && error.message ? error.message : String(error),
  }));
  process.exit(1);
});
"""
    script = script.replace("__NEXUS_INTERACTION_EXPRESSION__", interaction_expression)
    return f"node --experimental-websocket - {shlex.quote(payload)} <<'NEXUS_NODE_EOF'\n{script}\nNEXUS_NODE_EOF"

async def _runtime_status_snapshot(*, refresh: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities(refresh=refresh)
        runtime_status = await _probe_browser_runtimes(conn)
    finally:
        pool.release(conn)
    return capabilities.to_dict(), runtime_status


async def _browser_fetch_payload(
    *,
    url: str,
    timeout_sec: int,
    wait_ms: int,
    max_body_chars: int,
    preferred_browser: str = "",
    user_agent: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = time.monotonic()
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities()
        runtime_status = await _probe_browser_runtimes(conn)
        browser_name, browser_path = _resolve_browser_command(runtime_status, preferred_browser=preferred_browser)
        if not browser_name or not browser_path:
            interaction_capability = _browser_interaction_capability(wait_ms=wait_ms)
            dom_observation = _extract_dom_affordances("")
            payload = {
                "ok": False,
                "error_code": "BROWSER_RUNTIME_UNAVAILABLE",
                "error_stage": "capability_probe",
                "message": "No Chromium-family headless browser is available on the target host.",
                "request": {
                    "url": url,
                    "timeout_sec": timeout_sec,
                    "wait_ms": wait_ms,
                    "preferred_browser": preferred_browser or None,
                },
                "response": {
                    "transport": "browser_dom",
                    "browser": None,
                    "browser_path": None,
                    "transfer_error": None,
                    "metadata": {},
                    "dom_observation": dom_observation,
                    "interaction_capability": interaction_capability,
                    "surface_summary": _surface_observation_summary(
                        dom_observation,
                        interaction_capability,
                    ),
                },
                "assessment": {
                    "classification": "browser_unavailable",
                    "retrieved": False,
                    "accessible": False,
                    "constraints": ["browser_runtime_unavailable"],
                    "evidence": {
                        "status_code": None,
                        "title": None,
                        "retry_after": None,
                        "www_authenticate": None,
                        "content_type": None,
                    },
                },
                "runtime_status": runtime_status,
                "capabilities": capabilities.to_dict(),
                "body_preview": "",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
            return payload, runtime_status

        command = _browser_dom_command(
            browser_path=browser_path,
            url=url,
            wait_ms=max(0, wait_ms),
            user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
        )
        result = await conn.run_full(command, timeout=max(1, timeout_sec) + 15)
    finally:
        pool.release(conn)

    body_preview = result.stdout[: max(512, max_body_chars)]
    metadata = _extract_html_metadata(body_preview)
    dom_observation = _extract_dom_affordances(body_preview)
    interaction_capability = _browser_interaction_capability(wait_ms=wait_ms)
    surface_summary = _surface_observation_summary(dom_observation, interaction_capability)
    assessment = _assess_http_access(
        status_code=None,
        headers={},
        body_preview=body_preview,
        metadata=metadata,
        retrieved_hint=bool(body_preview.strip()),
    )
    if not result.ok and not body_preview.strip():
        ok = False
        error_code = "BROWSER_FETCH_FAILED"
        error_stage = "execution"
        message = "Headless browser fetch failed."
    else:
        ok, error_code, error_stage, message = _error_details_for_assessment(assessment, result.stderr.strip() or None)
    payload = {
        "ok": ok,
        "error_code": error_code,
        "error_stage": error_stage,
        "message": message,
        "request": {
            "url": url,
            "timeout_sec": timeout_sec,
            "wait_ms": wait_ms,
            "preferred_browser": preferred_browser or browser_name,
        },
        "response": {
            "transport": "browser_dom",
            "browser": browser_name,
            "browser_path": browser_path,
            "exit_code": result.exit_code,
            "transfer_error": result.stderr.strip() or None,
            "metadata": metadata,
            "dom_observation": dom_observation,
            "interaction_capability": interaction_capability,
            "surface_summary": surface_summary,
            "body_preview_truncated": len(result.stdout) > max(512, max_body_chars),
        },
        "assessment": assessment,
        "runtime_status": runtime_status,
        "body_preview": body_preview,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }
    return payload, runtime_status


async def _browser_screenshot_payload(
    *,
    url: str,
    timeout_sec: int,
    wait_ms: int,
    viewport_width: int,
    viewport_height: int,
    preferred_browser: str = "",
    user_agent: str = "",
) -> tuple[dict[str, Any], list[Any]]:
    started = time.monotonic()
    dom_payload, runtime_status = await _browser_fetch_payload(
        url=url,
        timeout_sec=timeout_sec,
        wait_ms=wait_ms,
        max_body_chars=16000,
        preferred_browser=preferred_browser,
        user_agent=user_agent,
    )
    response = dom_payload.get("response", {})
    browser_name = str(response.get("browser") or "")
    browser_path = str(response.get("browser_path") or "")
    transfer_error = str(response.get("transfer_error") or "")
    capabilities_data: dict[str, Any] | None = None
    node_path = ""
    empty_auto_plan = {
        "eligible": False,
        "reason": "No grounded browser interaction target is available.",
        "selected_target": None,
        "click_request": None,
        "requires_visual_review": True,
    }
    if not browser_name or not browser_path:
        payload = {
            "ok": False,
            "error_code": "BROWSER_SCREENSHOT_UNAVAILABLE",
            "error_stage": "capability_probe",
            "message": "No Chromium-family runtime is available for screenshot capture.",
            "request": {
                "url": url,
                "timeout_sec": timeout_sec,
                "wait_ms": wait_ms,
                "viewport_width": viewport_width,
                "viewport_height": viewport_height,
                "preferred_browser": preferred_browser or None,
            },
            "response": {
                "browser": browser_name or None,
                "browser_path": browser_path or None,
                "viewport_width": viewport_width,
                "viewport_height": viewport_height,
                "screenshot_available": False,
                "grid_available": False,
                "metadata": response.get("metadata") or {},
                "dom_observation": response.get("dom_observation") or {},
                "interaction_targets": [],
                "interaction_target_summary": _interaction_target_summary([]),
                "auto_interaction": empty_auto_plan,
                "interaction_capability": {
                    "mode": "visual_capture_only",
                    "click_supported": False,
                    "reason": "Screenshot capture requires a Chromium-family browser runtime.",
                },
            },
            "assessment": dom_payload.get("assessment") or {},
            "runtime_status": runtime_status,
            "capabilities": capabilities_data,
            "artifacts": [],
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
        return payload, []

    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities()
        capabilities_data = capabilities.to_dict()
        runtime_commands = runtime_status.get("commands")
        if isinstance(runtime_commands, dict):
            node_path = str(runtime_commands.get("node") or "")
        python_bin = capabilities.python_command
        if not python_bin and not node_path:
            payload = {
                "ok": False,
                "error_code": "BROWSER_SCREENSHOT_UNAVAILABLE",
                "error_stage": "capability_probe",
                "message": "Screenshot capture requires either Node-backed browser automation or Python-backed packaging.",
                "request": {
                    "url": url,
                    "timeout_sec": timeout_sec,
                    "wait_ms": wait_ms,
                    "viewport_width": viewport_width,
                    "viewport_height": viewport_height,
                    "preferred_browser": preferred_browser or browser_name,
                },
                "response": {
                    "browser": browser_name,
                    "browser_path": browser_path,
                    "viewport_width": viewport_width,
                    "viewport_height": viewport_height,
                    "screenshot_available": False,
                    "grid_available": False,
                    "metadata": response.get("metadata") or {},
                    "dom_observation": response.get("dom_observation") or {},
                    "interaction_targets": [],
                    "interaction_target_summary": _interaction_target_summary([]),
                    "auto_interaction": empty_auto_plan,
                    "interaction_capability": {
                        "mode": "visual_capture_only",
                        "click_supported": False,
                        "reason": "Screenshot capture requires Node-backed browser automation or Python-backed packaging.",
                    },
                },
                "assessment": dom_payload.get("assessment") or {},
                "runtime_status": runtime_status,
                "capabilities": capabilities_data,
                "artifacts": [],
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
            return payload, []

        capture_backend = "chromium_cli"
        if node_path:
            capture_backend = "node_cdp"
            command = _browser_visual_capture_command(
                browser_path=browser_path,
                url=url,
                wait_ms=wait_ms,
                width=viewport_width,
                height=viewport_height,
                user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
            )
        else:
            command = _browser_screenshot_command(
                browser_path=browser_path,
                python_bin=python_bin,
                url=url,
                wait_ms=wait_ms,
                user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                width=viewport_width,
                height=viewport_height,
            )
        result = await conn.run_full(command, timeout=max(1, timeout_sec) + 20)
    finally:
        pool.release(conn)

    if node_path:
        try:
            parsed = json.loads(result.stdout.strip() or "{}")
        except json.JSONDecodeError:
            parsed = {"ok": False, "error": result.stderr.strip() or "Could not parse browser screenshot result."}
        screenshot_b64 = str(parsed.get("screenshot_base64") or "")
        body_preview = str(parsed.get("body_preview") or "")[:16000]
        metadata, dom_observation, assessment = _browser_render_assessment(
            body_preview=body_preview,
            title_hint=str(parsed.get("title") or ""),
            failure_constraint="browser_screenshot_failed",
        )
        capture_stderr = str(parsed.get("browser_stderr") or result.stderr.strip() or transfer_error or "")
        capture_exit_code = result.exit_code
        final_url = str(parsed.get("final_url") or url)
        viewport_width_value = int(parsed.get("viewport_width") or max(320, viewport_width))
        viewport_height_value = int(parsed.get("viewport_height") or max(240, viewport_height))
        interaction_targets = _normalize_interaction_targets(
            parsed.get("interaction_targets"),
            viewport_width=viewport_width_value,
            viewport_height=viewport_height_value,
        )
    else:
        parsed = _parse_browser_screenshot_output(result.stdout)
        screenshot_b64 = str(parsed.get("screenshot_base64") or "")
        body_preview = dom_payload.get("body_preview") or ""
        metadata, dom_observation, assessment = _browser_render_assessment(
            body_preview=body_preview,
            title_hint=str((response.get("metadata") or {}).get("title") or ""),
            failure_constraint="browser_screenshot_failed",
        )
        capture_stderr = str(parsed.get("stderr") or transfer_error or "")
        capture_exit_code = parsed.get("exit_code")
        final_url = str(response.get("final_url") or url)
        viewport_width_value = max(320, viewport_width)
        viewport_height_value = max(240, viewport_height)
        interaction_targets = []
    interaction_target_summary = _interaction_target_summary(interaction_targets)
    auto_interaction = _auto_interaction_plan(assessment, interaction_targets)
    auto_interaction_guidance = _auto_interaction_guidance_text(auto_interaction)
    surface_summary = _surface_observation_summary(
        dom_observation,
        {
            "mode": "visual_capture_only",
            "click_supported": False,
            "reason": (
                "This tool captures a screenshot and grid overlay for visual inspection; "
                "use browser_coordinate_click for deliberate coordinate-based interaction."
            ),
        },
    )
    if interaction_target_summary:
        surface_summary = f"{surface_summary} {interaction_target_summary}".strip()
    if auto_interaction_guidance:
        surface_summary = f"{surface_summary} {auto_interaction_guidance}".strip()
    visual_artifacts = _write_browser_visual_artifacts(
        tool_name="browser_screenshot",
        screenshot_base64=screenshot_b64,
        width=viewport_width_value,
        height=viewport_height_value,
        grid_step_px=100,
        marker=None,
    )
    payload = {
        "ok": bool(screenshot_b64),
        "error_code": None if screenshot_b64 else "BROWSER_SCREENSHOT_FAILED",
        "error_stage": None if screenshot_b64 else "visual_capture",
        "message": (
            "Captured a browser screenshot and coordinate grid."
            if screenshot_b64
            else "Headless browser screenshot capture did not produce an image."
        ),
        "request": {
            "url": url,
            "timeout_sec": timeout_sec,
            "wait_ms": wait_ms,
            "viewport_width": viewport_width,
            "viewport_height": viewport_height,
            "preferred_browser": preferred_browser or browser_name,
        },
        "response": {
            "browser": browser_name,
            "browser_path": browser_path,
            "node_path": node_path or None,
            "capture_backend": capture_backend,
            "final_url": final_url,
            "viewport_width": viewport_width_value,
            "viewport_height": viewport_height_value,
            "screenshot_available": bool(screenshot_b64),
            "grid_available": bool(visual_artifacts),
            "metadata": metadata,
            "dom_observation": dom_observation,
            "interaction_targets": interaction_targets,
            "interaction_target_summary": interaction_target_summary,
            "auto_interaction": auto_interaction,
            "surface_summary": surface_summary,
            "interaction_capability": {
                "mode": "visual_capture_only",
                "click_supported": False,
                "reason": (
                    "This tool captures a screenshot and grid overlay for visual inspection; "
                    "use browser_coordinate_click for deliberate coordinate-based interaction."
                ),
            },
            "capture_stderr": capture_stderr,
            "capture_exit_code": capture_exit_code,
        },
        "assessment": assessment,
        "runtime_status": runtime_status,
        "capabilities": capabilities_data,
        "artifacts": [
            {
                "kind": artifact.kind,
                "path": artifact.path,
                "size_bytes": artifact.size_bytes,
            }
            for artifact in visual_artifacts
        ],
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "body_preview": body_preview,
    }
    return payload, visual_artifacts


async def _browser_coordinate_click_payload(
    *,
    url: str,
    x: int,
    y: int,
    timeout_sec: int,
    wait_before_ms: int,
    wait_after_ms: int,
    viewport_width: int,
    viewport_height: int,
    preferred_browser: str = "",
    user_agent: str = "",
) -> tuple[dict[str, Any], list[Any]]:
    started = time.monotonic()
    capabilities, runtime_status = await _runtime_status_snapshot(refresh=False)
    browser_name, browser_path = _resolve_browser_command(runtime_status, preferred_browser=preferred_browser)
    commands = runtime_status.get("commands")
    if not isinstance(commands, dict):
        commands = {}
    node_path = str(commands.get("node") or "")
    if not browser_name or not browser_path or not node_path:
        payload = {
            "ok": False,
            "error_code": "BROWSER_AUTOMATION_UNAVAILABLE",
            "error_stage": "capability_probe",
            "message": "Coordinate-based browser interaction requires both a Chromium-family browser and Node.js.",
            "request": {
                "url": url,
                "x": x,
                "y": y,
                "timeout_sec": timeout_sec,
                "wait_before_ms": wait_before_ms,
                "wait_after_ms": wait_after_ms,
                "viewport_width": viewport_width,
                "viewport_height": viewport_height,
                "preferred_browser": preferred_browser or None,
            },
            "response": {
                "browser": browser_name or None,
                "browser_path": browser_path or None,
                "node_path": node_path or None,
                "coordinate_space": "viewport_pixels",
                "click_performed": False,
                "interaction_targets": [],
                "interaction_target_summary": _interaction_target_summary([]),
                "auto_interaction": {
                    "eligible": False,
                    "reason": "No grounded browser interaction target is available.",
                    "selected_target": None,
                    "click_request": None,
                    "requires_visual_review": True,
                },
                "interaction_capability": {
                    "mode": "coordinate_click",
                    "click_supported": False,
                    "reason": "Coordinate clicks require Chromium plus Node-backed DevTools automation.",
                },
            },
            "assessment": {
                "classification": "browser_unavailable",
                "retrieved": False,
                "accessible": False,
                "constraints": ["browser_automation_unavailable"],
                "evidence": {
                    "status_code": None,
                    "title": None,
                    "retry_after": None,
                    "www_authenticate": None,
                    "content_type": None,
                },
            },
            "runtime_status": runtime_status,
            "capabilities": capabilities,
            "artifacts": [],
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
        return payload, []

    pool = get_pool()
    conn = await pool.acquire()
    try:
        command = _browser_coordinate_click_command(
            browser_path=browser_path,
            url=url,
            x=x,
            y=y,
            wait_before_ms=wait_before_ms,
            wait_after_ms=wait_after_ms,
            width=viewport_width,
            height=viewport_height,
            user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
        )
        result = await conn.run_full(command, timeout=max(1, timeout_sec) + 20)
    finally:
        pool.release(conn)

    try:
        parsed = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError:
        parsed = {"ok": False, "error": result.stderr.strip() or "Could not parse coordinate-click result."}

    screenshot_b64 = str(parsed.get("screenshot_base64") or "")
    body_preview = str(parsed.get("body_preview") or "")[:16000]
    metadata, dom_observation, assessment = _browser_render_assessment(
        body_preview=body_preview,
        title_hint=str(parsed.get("title") or ""),
        failure_constraint="browser_coordinate_click_failed",
    )
    viewport_width_value = int(parsed.get("viewport_width") or max(320, viewport_width))
    viewport_height_value = int(parsed.get("viewport_height") or max(240, viewport_height))
    interaction_targets = _normalize_interaction_targets(
        parsed.get("interaction_targets"),
        viewport_width=viewport_width_value,
        viewport_height=viewport_height_value,
    )
    interaction_target_summary = _interaction_target_summary(interaction_targets)
    auto_interaction = _auto_interaction_plan(assessment, interaction_targets)
    auto_interaction_guidance = _auto_interaction_guidance_text(auto_interaction)
    surface_summary = _surface_observation_summary(
        dom_observation,
        {
            "mode": "coordinate_click",
            "click_supported": True,
        },
    )
    if interaction_target_summary:
        surface_summary = f"{surface_summary} {interaction_target_summary}".strip()
    if auto_interaction_guidance:
        surface_summary = f"{surface_summary} {auto_interaction_guidance}".strip()
    visual_artifacts = _write_browser_visual_artifacts(
        tool_name="browser_coordinate_click",
        screenshot_base64=screenshot_b64,
        width=viewport_width_value,
        height=viewport_height_value,
        grid_step_px=100,
        marker=(x, y),
    )
    ok = bool(parsed.get("ok") and screenshot_b64)
    error_text = str(parsed.get("error") or result.stderr.strip() or "")
    payload = {
        "ok": ok,
        "error_code": None if ok else "BROWSER_COORDINATE_CLICK_FAILED",
        "error_stage": None if ok else "interaction",
        "message": (
            "Performed a coordinate-based browser click and captured the post-click state."
            if ok
            else "Coordinate-based browser click did not complete successfully."
        ),
        "request": {
            "url": url,
            "x": x,
            "y": y,
            "timeout_sec": timeout_sec,
            "wait_before_ms": wait_before_ms,
            "wait_after_ms": wait_after_ms,
            "viewport_width": viewport_width,
            "viewport_height": viewport_height,
            "preferred_browser": preferred_browser or browser_name,
        },
        "response": {
            "browser": browser_name,
            "browser_path": browser_path,
            "node_path": node_path,
            "coordinate_space": "viewport_pixels",
            "click_performed": bool(parsed.get("ok")),
            "final_url": parsed.get("final_url") or url,
            "metadata": metadata,
            "dom_observation": dom_observation,
            "interaction_targets": interaction_targets,
            "interaction_target_summary": interaction_target_summary,
            "auto_interaction": auto_interaction,
            "surface_summary": surface_summary,
            "interaction_capability": {
                "mode": "coordinate_click",
                "click_supported": True,
                "reason": "This tool uses bounded DevTools automation to click a viewport coordinate once.",
            },
            "capture_stderr": error_text or str(parsed.get("browser_stderr") or ""),
        },
        "assessment": assessment,
        "runtime_status": runtime_status,
        "capabilities": capabilities,
        "artifacts": [
            {
                "kind": artifact.kind,
                "path": artifact.path,
                "size_bytes": artifact.size_bytes,
            }
            for artifact in visual_artifacts
        ],
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "body_preview": body_preview,
    }
    return payload, visual_artifacts


async def _bootstrap_browser_runtime(
    *,
    target: str,
    timeout_sec: int,
    refresh: bool = True,
) -> dict[str, Any]:
    started = time.monotonic()
    pool = get_pool()
    conn = await pool.acquire()
    try:
        capabilities = await conn.probe_capabilities(refresh=refresh)
        runtime_status_before = await _probe_browser_runtimes(conn)
        if runtime_status_before.get("headless_dom_supported"):
            return {
                "ok": True,
                "error_code": None,
                "error_stage": None,
                "message": "A supported headless browser runtime is already available.",
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "target": target,
                "already_available": True,
                "installed": False,
                "install_plan": None,
                "runtime_status_before": runtime_status_before,
                "runtime_status": runtime_status_before,
                "capabilities": capabilities.to_dict(),
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }

        plan = _browser_bootstrap_plan(capabilities.package_manager, target=target)
        if plan is None:
            return {
                "ok": False,
                "error_code": "BROWSER_BOOTSTRAP_UNSUPPORTED",
                "error_stage": "configuration",
                "message": "No supported package-manager install plan is available for this host/browser target.",
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "target": target,
                "already_available": False,
                "installed": False,
                "install_plan": None,
                "runtime_status_before": runtime_status_before,
                "runtime_status": runtime_status_before,
                "capabilities": capabilities.to_dict(),
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }

        install_result = await conn.run_full(plan["command"], timeout=max(30, timeout_sec))
        runtime_status_after = await _probe_browser_runtimes(conn)
        ok = bool(install_result.ok and runtime_status_after.get("headless_dom_supported"))
        return {
            "ok": ok,
            "error_code": None if ok else "BROWSER_BOOTSTRAP_FAILED",
            "error_stage": None if ok else "installation",
            "message": (
                "Installed a headless browser runtime."
                if ok
                else "Browser installation completed without exposing a usable runtime."
            ),
            "stdout": install_result.stdout,
            "stderr": install_result.stderr,
            "exit_code": install_result.exit_code,
            "target": target,
            "already_available": False,
            "installed": ok,
            "install_plan": {
                "target": plan["target"],
                "package_manager": plan["package_manager"],
            },
            "runtime_status_before": runtime_status_before,
            "runtime_status": runtime_status_after,
            "capabilities": capabilities.to_dict(),
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error_code": "BROWSER_BOOTSTRAP_FAILED",
            "error_stage": "installation",
            "message": "Failed to bootstrap a browser runtime.",
            "stdout": "",
            "stderr": str(exc),
            "exit_code": None,
            "target": target,
            "already_available": False,
            "installed": False,
            "install_plan": None,
            "runtime_status_before": {},
            "runtime_status": {},
            "capabilities": {},
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    finally:
        pool.release(conn)


async def _web_retrieval_payload(
    *,
    current_tool: str = "web_retrieve",
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
    browser_profile: bool,
    try_browser: bool,
    wait_ms: int,
    preferred_browser: str = "",
    allow_bootstrap: bool = False,
    bootstrap_target: str = "chromium",
    bootstrap_timeout_sec: int = 900,
) -> dict[str, Any]:
    http_payload, _ = await _http_probe_payload(
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
        browser_profile=browser_profile,
    )

    capabilities, runtime_status_before = await _runtime_status_snapshot(refresh=False)
    runtime_status = runtime_status_before
    bootstrap_attempt: dict[str, Any] | None = None
    browser_payload: dict[str, Any] | None = None
    screenshot_payload: dict[str, Any] | None = None
    click_payload: dict[str, Any] | None = None
    click_attempt_payloads: list[dict[str, Any]] = []
    challenge_diagnostic_trace: list[dict[str, Any]] = []
    challenge_diagnostics: dict[str, Any] | None = None
    final_visual_evidence: dict[str, Any] | None = None
    extra_artifacts: list[Any] = []
    if try_browser and not http_payload["assessment"]["accessible"]:
        if not runtime_status.get("headless_dom_supported") and allow_bootstrap:
            bootstrap_attempt = await _bootstrap_browser_runtime(
                target=bootstrap_target,
                timeout_sec=bootstrap_timeout_sec,
                refresh=True,
            )
            runtime_status = bootstrap_attempt["runtime_status"]
            capabilities = bootstrap_attempt["capabilities"]
        if runtime_status.get("headless_dom_supported"):
            browser_payload, runtime_status = await _browser_fetch_payload(
                url=url,
                timeout_sec=max(timeout_sec, 20),
                wait_ms=wait_ms,
                max_body_chars=max_body_chars,
                preferred_browser=preferred_browser,
                user_agent=headers.get("User-Agent") if browser_profile else "",
            )
            screenshot_payload, click_payload, followup_artifacts = await _browser_visual_followup(
                url=url,
                timeout_sec=timeout_sec,
                wait_ms=wait_ms,
                preferred_browser=preferred_browser,
                user_agent=headers.get("User-Agent") if browser_profile else _BROWSER_HEADERS["User-Agent"],
                runtime_status=runtime_status,
                browser_payload=browser_payload,
            )
            extra_artifacts.extend(followup_artifacts)
            if click_payload is not None:
                click_payload, click_attempt_payloads, click_followup_artifacts, challenge_diagnostic_trace = (
                    await _bounded_click_followup_sequence(
                        url=url,
                        timeout_sec=max(1, timeout_sec),
                        wait_before_ms=max(0, wait_ms),
                        wait_after_ms=3000,
                        viewport_width=1440,
                        viewport_height=2200,
                        preferred_browser=preferred_browser,
                        user_agent=headers.get("User-Agent") if browser_profile else _BROWSER_HEADERS["User-Agent"],
                        pre_click_payload=screenshot_payload or browser_payload,
                        initial_click_payload=click_payload,
                        fallback_candidate_payload=screenshot_payload,
                    )
                )
                extra_artifacts.extend(click_followup_artifacts)
                if challenge_diagnostic_trace:
                    challenge_diagnostics = challenge_diagnostic_trace[-1]
            if challenge_diagnostics is None:
                challenge_diagnostics = _post_click_challenge_diagnostics(
                    pre_payload=screenshot_payload or browser_payload,
                    click_payload=click_payload,
                )

    final_visual_evidence = _final_visual_evidence(
        click_attempts=click_attempt_payloads,
        screenshot_payload=screenshot_payload,
    )
    grounded_followup_exhausted = _grounded_followup_exhausted(
        final_assessment=click_payload.get("assessment") if isinstance(click_payload, dict) else None,
        click_attempts=click_attempt_payloads,
        final_click_payload=click_payload,
        fallback_payload=screenshot_payload,
    )

    recommendations = _browser_recommendations(
        http_payload["assessment"],
        runtime_status,
        browser_attempted=browser_payload is not None,
        browser_accessible=bool(browser_payload and browser_payload["assessment"]["accessible"]),
    )
    retry_guidance = _retry_guidance(
        http_payload["assessment"],
        runtime_status,
        browser_attempted=browser_payload is not None,
        browser_accessible=bool(browser_payload and browser_payload["assessment"]["accessible"]),
    )
    final_strategy = "http"
    final_assessment = http_payload["assessment"]
    final_response = http_payload["response"]
    final_body = http_payload["body_preview"]
    ok = bool(http_payload["ok"])
    error_code = http_payload["error_code"]
    error_stage = http_payload["error_stage"]
    message = http_payload["message"]
    strategy_suffix = "_after_bootstrap" if bootstrap_attempt else ""
    if click_payload and click_payload["assessment"]["accessible"]:
        final_strategy = f"browser_coordinate_click{strategy_suffix}"
        final_assessment = click_payload["assessment"]
        final_response = click_payload["response"]
        final_body = click_payload["body_preview"]
        ok = bool(click_payload["ok"])
        error_code = click_payload["error_code"]
        error_stage = click_payload["error_stage"]
        message = click_payload["message"]
    elif screenshot_payload and screenshot_payload["assessment"]["accessible"]:
        final_strategy = f"browser_visual_capture{strategy_suffix}"
        final_assessment = screenshot_payload["assessment"]
        final_response = screenshot_payload["response"]
        final_body = screenshot_payload["body_preview"]
        ok = bool(screenshot_payload["ok"])
        error_code = screenshot_payload["error_code"]
        error_stage = screenshot_payload["error_stage"]
        message = screenshot_payload["message"]
    elif browser_payload and browser_payload["assessment"]["accessible"]:
        final_strategy = "browser_dom"
        final_assessment = browser_payload["assessment"]
        final_response = browser_payload["response"]
        final_body = browser_payload["body_preview"]
        ok = bool(browser_payload["ok"])
        error_code = browser_payload["error_code"]
        error_stage = browser_payload["error_stage"]
        message = browser_payload["message"]
        if bootstrap_attempt:
            final_strategy = "browser_dom_after_bootstrap"
    elif click_payload:
        final_strategy = f"browser_coordinate_click{strategy_suffix}"
        final_assessment = click_payload["assessment"]
        final_response = click_payload["response"]
        final_body = click_payload["body_preview"]
        ok = bool(click_payload["ok"])
        error_code = click_payload["error_code"]
        error_stage = click_payload["error_stage"]
        message = click_payload["message"]
    elif screenshot_payload:
        final_strategy = f"browser_visual_capture{strategy_suffix}"
        final_assessment = screenshot_payload["assessment"]
        final_response = screenshot_payload["response"]
        final_body = screenshot_payload["body_preview"]
        ok = bool(screenshot_payload["ok"])
        error_code = screenshot_payload["error_code"]
        error_stage = screenshot_payload["error_stage"]
        message = screenshot_payload["message"]

    workflow_outcome = (
        "blocked_after_browser_attempt"
        if grounded_followup_exhausted
        else _workflow_outcome_for_web_step(
            http_assessment=http_payload["assessment"],
            browser_payload=browser_payload,
            screenshot_payload=screenshot_payload,
            click_payload=click_payload,
            runtime_status=runtime_status,
        )
    )
    workflow_handoff = _web_workflow_handoff(
        current_tool=current_tool,
        assessment=final_assessment,
        outcome_override=workflow_outcome,
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
        wait_ms=wait_ms,
        browser_profile=browser_profile,
        preferred_browser=preferred_browser,
    )
    click_hint = _interaction_click_hint(click_payload) or _interaction_click_hint(screenshot_payload)
    workflow_handoff = _apply_click_hint_to_handoff(workflow_handoff, click_hint)
    continuation = _continuation_from_handoff(workflow_handoff)
    feedback_loop = _web_feedback_loop(
        http_payload=http_payload,
        browser_payload=browser_payload,
        bootstrap_attempt=bootstrap_attempt,
        screenshot_payload=screenshot_payload,
        click_payload=click_payload,
        click_attempts=click_attempt_payloads,
        continuation=continuation,
    )
    workflow_error_code = _workflow_error_code(
        http_payload=http_payload,
        browser_payload=browser_payload,
        screenshot_payload=screenshot_payload,
        click_payload=click_payload,
        continuation=continuation,
    )
    workflow_error_stage = _workflow_error_stage(
        browser_payload=browser_payload,
        screenshot_payload=screenshot_payload,
        click_payload=click_payload,
        continuation=continuation,
    )
    workflow_message = str(feedback_loop["summary"] or message)
    diagnostic_note = _challenge_diagnostic_note(challenge_diagnostics)
    if diagnostic_note:
        workflow_message = f"{workflow_message} {diagnostic_note}".strip()
    user_assistance_note = _user_assistance_request_note(
        final_assessment=final_assessment,
        final_visual_evidence=final_visual_evidence,
        challenge_diagnostics=challenge_diagnostics,
    )
    if user_assistance_note:
        workflow_message = f"{workflow_message} {user_assistance_note}".strip()

    return {
        "ok": ok,
        "error_code": workflow_error_code or error_code,
        "error_stage": workflow_error_stage or error_stage,
        "message": workflow_message,
        "strategy": final_strategy,
        "capabilities": capabilities,
        "runtime_status_before": runtime_status_before,
        "runtime_status": runtime_status,
        "http_attempt": {
            "request": http_payload["request"],
            "response": http_payload["response"],
            "assessment": http_payload["assessment"],
            "retry_guidance": http_payload["retry_guidance"],
            "ok": http_payload["ok"],
            "error_code": http_payload["error_code"],
            "error_stage": http_payload["error_stage"],
            "message": http_payload["message"],
        },
        "browser_attempt": (
            {
                "request": browser_payload["request"],
                "response": browser_payload["response"],
                "assessment": browser_payload["assessment"],
                "ok": browser_payload["ok"],
                "error_code": browser_payload["error_code"],
                "error_stage": browser_payload["error_stage"],
                "message": browser_payload["message"],
            }
            if browser_payload
            else None
        ),
        "screenshot_attempt": (
            {
                "request": screenshot_payload["request"],
                "response": screenshot_payload["response"],
                "assessment": screenshot_payload["assessment"],
                "ok": screenshot_payload["ok"],
                "error_code": screenshot_payload["error_code"],
                "error_stage": screenshot_payload["error_stage"],
                "message": screenshot_payload["message"],
            }
            if screenshot_payload
            else None
        ),
        "interactive_attempt": (
            {
                "request": click_payload["request"],
                "response": click_payload["response"],
                "assessment": click_payload["assessment"],
                "ok": click_payload["ok"],
                "error_code": click_payload["error_code"],
                "error_stage": click_payload["error_stage"],
                "message": click_payload["message"],
            }
            if click_payload
            else None
        ),
        "interaction_attempts": _click_attempt_records(click_attempt_payloads),
        "bootstrap_attempt": bootstrap_attempt,
        "final_response": final_response,
        "final_assessment": final_assessment,
        "retry_guidance": retry_guidance,
        "recommendations": recommendations,
        "workflow_handoff": workflow_handoff,
        "continuation": continuation,
        "feedback_loop": feedback_loop,
        "challenge_diagnostics": challenge_diagnostics,
        "challenge_diagnostics_history": challenge_diagnostic_trace,
        "final_visual_evidence": final_visual_evidence,
        "body_preview": final_body,
        "extra_artifacts": extra_artifacts,
    }


async def _web_page_diagnosis_payload(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_sec: int,
    max_body_chars: int,
    browser_profile: bool,
    try_browser: bool,
    wait_ms: int,
    preferred_browser: str = "",
) -> dict[str, Any]:
    return await _web_retrieval_payload(
        current_tool="web_page_diagnose",
        url=url,
        method=method,
        headers=headers,
        timeout_sec=timeout_sec,
        max_body_chars=max_body_chars,
        browser_profile=browser_profile,
        try_browser=try_browser,
        wait_ms=wait_ms,
        preferred_browser=preferred_browser,
        allow_bootstrap=False,
    )


def register(mcp: FastMCP):

    @mcp.tool(structured_output=True)
    async def browser_bootstrap(target: str = "chromium", timeout_sec: int = 900, refresh: bool = True) -> ToolResult:
        """Install a headless browser runtime on the host for bounded web retrieval escalation."""
        payload = await _bootstrap_browser_runtime(target=target, timeout_sec=timeout_sec, refresh=refresh)
        workflow_handoff = task_family_handoff(
            task_family="web_retrieval",
            current_tool="browser_bootstrap",
            outcome="ok" if payload["ok"] else "runtime_missing",
            available_tools=_available_registry_tools(),
            availability_scope="server_registry_snapshot",
        )
        workflow_handoff = _attach_surface_verification(workflow_handoff)
        return _result(
            "browser_bootstrap",
            ok=bool(payload["ok"]),
            duration_ms=payload["duration_ms"],
            stdout_text=str(payload["stdout"] or ""),
            stderr_text=str(payload["stderr"] or ""),
            error_code=payload["error_code"],
            error_stage=payload["error_stage"],
            message=payload["message"],
            exit_code=payload["exit_code"],
            data={
                "target": payload["target"],
                "already_available": payload["already_available"],
                "installed": payload["installed"],
                "install_plan": payload["install_plan"],
                "runtime_status_before": payload["runtime_status_before"],
                "runtime_status": payload["runtime_status"],
                "capabilities": payload["capabilities"],
                "workflow_handoff": workflow_handoff,
                "continuation": _continuation_from_handoff(workflow_handoff),
            },
        )

    @mcp.tool(structured_output=True)
    async def browser_runtime_status(refresh: bool = False) -> ToolResult:
        """Inspect browser and JavaScript runtimes that can escalate blocked web retrieval."""
        started = time.monotonic()
        try:
            capabilities, runtime_status = await _runtime_status_snapshot(refresh=refresh)
        except Exception as exc:
            return _result(
                "browser_runtime_status",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                stderr_text=str(exc),
                error_code="BROWSER_RUNTIME_PROBE_FAILED",
                error_stage="inspection",
                message="Failed to inspect browser runtimes.",
            )

        workflow_handoff = task_family_handoff(
            task_family="web_retrieval",
            current_tool="browser_runtime_status",
            outcome="ok" if runtime_status.get("headless_dom_supported") else "runtime_missing",
            available_tools=_available_registry_tools(),
            availability_scope="server_registry_snapshot",
        )
        workflow_handoff = _attach_surface_verification(workflow_handoff)
        return _result(
            "browser_runtime_status",
            ok=True,
            duration_ms=(time.monotonic() - started) * 1000,
            data={
                "runtime_status": runtime_status,
                "capabilities": capabilities,
                "workflow_handoff": workflow_handoff,
                "continuation": _continuation_from_handoff(workflow_handoff),
            },
        )

    @mcp.tool(structured_output=True)
    async def browser_fetch(
        url: str,
        timeout_sec: int = 30,
        wait_ms: int = 5000,
        max_body_chars: int = 12000,
        preferred_browser: str = "",
        user_agent: str = "",
        manual_click_x: int | None = None,
        manual_click_y: int | None = None,
        manual_click_wait_after_ms: int = 3000,
        manual_click_viewport_width: int = 1440,
        manual_click_viewport_height: int = 2200,
    ) -> ToolResult:
        """Fetch a page through a headless browser when direct HTTP is blocked.

        Use this as the single escalation step after a blocked `http_fetch` or
        `web_page_diagnose` result. Do not loop through same-origin header or
        query variants before calling it. This tool starts with a bounded
        post-wait DOM snapshot and, when the page still needs grounded review,
        can attach bounded screenshot/click follow-up inside the same result.
        If your caller-exported surface does not expose `browser_screenshot` or
        `browser_coordinate_click`, provide `manual_click_x` and
        `manual_click_y` to seed a bounded in-band coordinate-click progression
        inside this tool.
        When continuation is returned, continue with the recommended grounded
        interaction step instead of stopping at the first DOM-only snapshot.
        """
        started = time.monotonic()
        manual_click_requested = manual_click_x is not None or manual_click_y is not None
        if manual_click_requested and (manual_click_x is None or manual_click_y is None):
            return _result(
                "browser_fetch",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="INVALID_ARGUMENT",
                error_stage="input_validation",
                message="Provide both manual_click_x and manual_click_y to request a deliberate coordinate click.",
                data={
                    "request": {
                        "url": url,
                        "timeout_sec": max(1, timeout_sec),
                        "wait_ms": max(0, wait_ms),
                        "max_body_chars": max(512, max_body_chars),
                        "preferred_browser": preferred_browser or None,
                        "user_agent": user_agent or _BROWSER_HEADERS["User-Agent"],
                        "manual_click_x": manual_click_x,
                        "manual_click_y": manual_click_y,
                        "manual_click_wait_after_ms": max(0, manual_click_wait_after_ms),
                        "manual_click_viewport_width": max(320, manual_click_viewport_width),
                        "manual_click_viewport_height": max(240, manual_click_viewport_height),
                    }
                },
            )
        payload, _ = await _browser_fetch_payload(
            url=url,
            timeout_sec=max(1, timeout_sec),
            wait_ms=max(0, wait_ms),
            max_body_chars=max(512, max_body_chars),
            preferred_browser=preferred_browser,
            user_agent=user_agent,
        )
        screenshot_payload: dict[str, Any] | None = None
        click_payload: dict[str, Any] | None = None
        click_attempt_payloads: list[dict[str, Any]] = []
        challenge_diagnostic_trace: list[dict[str, Any]] = []
        challenge_diagnostics: dict[str, Any] | None = None
        final_visual_evidence: dict[str, Any] | None = None
        extra_artifacts: list[Any] = []
        if manual_click_requested:
            click_payload, click_artifacts = await _browser_coordinate_click_payload(
                url=url,
                x=int(manual_click_x),
                y=int(manual_click_y),
                timeout_sec=max(1, timeout_sec),
                wait_before_ms=max(0, wait_ms),
                wait_after_ms=max(0, manual_click_wait_after_ms),
                viewport_width=max(320, manual_click_viewport_width),
                viewport_height=max(240, manual_click_viewport_height),
                preferred_browser=preferred_browser,
                user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
            )
            extra_artifacts.extend(click_artifacts)
            click_assessment = click_payload.get("assessment") if isinstance(click_payload, dict) else None
            initial_click_blocked = bool(
                isinstance(click_assessment, dict)
                and not click_assessment.get("accessible")
                and _is_blocked_access_classification(click_assessment)
            )
            fallback_candidate_payload = None
            if initial_click_blocked:
                screenshot_payload, screenshot_artifacts = await _browser_screenshot_payload(
                    url=url,
                    timeout_sec=max(45, max(1, timeout_sec)),
                    wait_ms=max(0, wait_ms),
                    viewport_width=max(320, manual_click_viewport_width),
                    viewport_height=max(240, manual_click_viewport_height),
                    preferred_browser=preferred_browser,
                    user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                )
                extra_artifacts.extend(screenshot_artifacts)
                fallback_candidate_payload = screenshot_payload
            click_payload, click_attempt_payloads, click_followup_artifacts, challenge_diagnostic_trace = (
                await _bounded_click_followup_sequence(
                    url=url,
                    timeout_sec=max(1, timeout_sec),
                    wait_before_ms=max(0, wait_ms),
                    wait_after_ms=max(0, manual_click_wait_after_ms),
                    viewport_width=max(320, manual_click_viewport_width),
                    viewport_height=max(240, manual_click_viewport_height),
                    preferred_browser=preferred_browser,
                    user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                    pre_click_payload=payload,
                    initial_click_payload=click_payload,
                    fallback_candidate_payload=fallback_candidate_payload,
                )
            )
            extra_artifacts.extend(click_followup_artifacts)
            final_click_assessment = click_payload.get("assessment") if isinstance(click_payload, dict) else None
            click_still_blocked = bool(
                isinstance(final_click_assessment, dict)
                and not final_click_assessment.get("accessible")
                and _is_blocked_access_classification(final_click_assessment)
            )
            if click_still_blocked and screenshot_payload is None:
                screenshot_payload, screenshot_artifacts = await _browser_screenshot_payload(
                    url=url,
                    timeout_sec=max(45, max(1, timeout_sec)),
                    wait_ms=max(0, wait_ms),
                    viewport_width=max(320, manual_click_viewport_width),
                    viewport_height=max(240, manual_click_viewport_height),
                    preferred_browser=preferred_browser,
                    user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                )
                extra_artifacts.extend(screenshot_artifacts)
        else:
            screenshot_payload, click_payload, extra_artifacts = await _browser_visual_followup(
                url=url,
                timeout_sec=max(1, timeout_sec),
                wait_ms=max(0, wait_ms),
                preferred_browser=preferred_browser,
                user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                runtime_status=payload["runtime_status"],
                browser_payload=payload,
            )
            if click_payload is not None:
                click_payload, click_attempt_payloads, click_followup_artifacts, challenge_diagnostic_trace = (
                    await _bounded_click_followup_sequence(
                        url=url,
                        timeout_sec=max(1, timeout_sec),
                        wait_before_ms=max(0, wait_ms),
                        wait_after_ms=3000,
                        viewport_width=1440,
                        viewport_height=2200,
                        preferred_browser=preferred_browser,
                        user_agent=user_agent or _BROWSER_HEADERS["User-Agent"],
                        pre_click_payload=screenshot_payload or payload,
                        initial_click_payload=click_payload,
                        fallback_candidate_payload=screenshot_payload,
                    )
                )
                extra_artifacts.extend(click_followup_artifacts)
        if challenge_diagnostic_trace:
            challenge_diagnostics = challenge_diagnostic_trace[-1]
        elif click_payload is not None:
            challenge_diagnostics = _post_click_challenge_diagnostics(
                pre_payload=screenshot_payload or payload,
                click_payload=click_payload,
            )
        final_visual_evidence = _final_visual_evidence(
            click_attempts=click_attempt_payloads,
            screenshot_payload=screenshot_payload,
        )
        final_strategy = "browser_dom"
        final_assessment = payload["assessment"]
        final_response = payload["response"]
        final_body = payload["body_preview"]
        final_ok = bool(payload["ok"])
        final_error_code = payload["error_code"]
        final_error_stage = payload["error_stage"]
        grounded_followup_exhausted = False
        if click_payload is not None:
            final_strategy = "browser_coordinate_click"
            final_assessment = click_payload["assessment"]
            final_response = click_payload["response"]
            final_body = click_payload["body_preview"]
            final_ok = bool(click_payload["ok"])
            final_error_code = click_payload["error_code"]
            final_error_stage = click_payload["error_stage"]
            grounded_followup_exhausted = _grounded_followup_exhausted(
                final_assessment=final_assessment,
                click_attempts=click_attempt_payloads,
                final_click_payload=click_payload,
                fallback_payload=screenshot_payload,
            )
            if grounded_followup_exhausted:
                handoff_tool = "browser_fetch"
                handoff_outcome = "blocked_after_browser_attempt"
            else:
                handoff_tool = "browser_coordinate_click"
                handoff_outcome = _visual_workflow_outcome_for_click(click_payload)
        elif screenshot_payload is not None:
            final_strategy = "browser_visual_capture"
            final_assessment = screenshot_payload["assessment"]
            final_response = screenshot_payload["response"]
            final_body = screenshot_payload["body_preview"]
            final_ok = bool(screenshot_payload["ok"])
            final_error_code = screenshot_payload["error_code"]
            final_error_stage = screenshot_payload["error_stage"]
            handoff_tool = "browser_screenshot"
            handoff_outcome = _visual_workflow_outcome_for_screenshot(screenshot_payload)
        else:
            handoff_tool = "browser_fetch"
            handoff_outcome = _workflow_outcome_for_web_step(
                http_assessment={"accessible": False, "classification": "browser_only"},
                browser_payload=payload,
                runtime_status=payload.get("runtime_status"),
            )
        workflow_handoff = _web_workflow_handoff(
            current_tool=handoff_tool,
            assessment=final_assessment,
            outcome_override=handoff_outcome,
            url=url,
            method="GET",
            headers={"User-Agent": user_agent or _BROWSER_HEADERS["User-Agent"]},
            timeout_sec=max(1, timeout_sec),
            max_body_chars=max(512, max_body_chars),
            wait_ms=max(0, wait_ms),
            browser_profile=True,
            preferred_browser=preferred_browser,
        )
        click_hint = _interaction_click_hint(click_payload) or _interaction_click_hint(screenshot_payload)
        workflow_handoff = _apply_click_hint_to_handoff(workflow_handoff, click_hint)
        continuation = _continuation_from_handoff(workflow_handoff)
        feedback_loop = _browser_feedback_loop(
            browser_payload=payload,
            screenshot_payload=screenshot_payload,
            click_payload=click_payload,
            click_attempts=click_attempt_payloads,
            continuation=continuation,
        )
        message_with_diagnostics = str(feedback_loop["summary"] or payload["message"])
        diagnostic_note = _challenge_diagnostic_note(challenge_diagnostics)
        if diagnostic_note:
            message_with_diagnostics = f"{message_with_diagnostics} {diagnostic_note}".strip()
        user_assistance_note = _user_assistance_request_note(
            final_assessment=final_assessment,
            final_visual_evidence=final_visual_evidence,
            challenge_diagnostics=challenge_diagnostics,
        )
        if user_assistance_note:
            message_with_diagnostics = f"{message_with_diagnostics} {user_assistance_note}".strip()
        final_stderr = ""
        if isinstance(final_response, dict):
            final_stderr = str(final_response.get("capture_stderr") or final_response.get("transfer_error") or "")
        return _result(
            "browser_fetch",
            ok=final_ok,
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=_display_stdout_text(
                final_body,
                final_assessment,
                continuation=continuation,
            ),
            stderr_text=final_stderr,
            error_code=_workflow_error_code(
                http_payload={"assessment": {"accessible": False, "classification": "browser_only"}},
                browser_payload=payload,
                screenshot_payload=screenshot_payload,
                click_payload=click_payload,
                continuation=continuation,
            )
            or final_error_code,
            error_stage=_workflow_error_stage(
                browser_payload=payload,
                screenshot_payload=screenshot_payload,
                click_payload=click_payload,
                continuation=continuation,
            )
            or final_error_stage,
            message=message_with_diagnostics,
            extra_artifacts=extra_artifacts,
            data={
                "request": payload["request"],
                "response": final_response,
                "assessment": final_assessment,
                "strategy": final_strategy,
                "manual_click_request": (
                    {
                        "requested": True,
                        "x": int(manual_click_x),
                        "y": int(manual_click_y),
                        "wait_after_ms": max(0, manual_click_wait_after_ms),
                        "viewport_width": max(320, manual_click_viewport_width),
                        "viewport_height": max(240, manual_click_viewport_height),
                    }
                    if manual_click_requested
                    else {
                        "requested": False,
                    }
                ),
                "browser_attempt": {
                    "request": payload["request"],
                    "response": payload["response"],
                    "assessment": payload["assessment"],
                    "ok": payload["ok"],
                    "error_code": payload["error_code"],
                    "error_stage": payload["error_stage"],
                    "message": payload["message"],
                },
                "screenshot_attempt": (
                    {
                        "request": screenshot_payload["request"],
                        "response": screenshot_payload["response"],
                        "assessment": screenshot_payload["assessment"],
                        "ok": screenshot_payload["ok"],
                        "error_code": screenshot_payload["error_code"],
                        "error_stage": screenshot_payload["error_stage"],
                        "message": screenshot_payload["message"],
                    }
                    if screenshot_payload
                    else None
                ),
                "interactive_attempt": (
                    {
                        "request": click_payload["request"],
                        "response": click_payload["response"],
                        "assessment": click_payload["assessment"],
                        "ok": click_payload["ok"],
                        "error_code": click_payload["error_code"],
                        "error_stage": click_payload["error_stage"],
                        "message": click_payload["message"],
                    }
                    if click_payload
                    else None
                ),
                "interaction_attempts": _click_attempt_records(click_attempt_payloads),
                "retry_guidance": _retry_guidance(
                    final_assessment,
                    payload["runtime_status"],
                    browser_attempted=True,
                    browser_accessible=bool(final_assessment.get("accessible")),
                ),
                "runtime_status": payload["runtime_status"],
                "artifacts": (
                    click_payload["artifacts"]
                    if click_payload
                    else screenshot_payload["artifacts"]
                    if screenshot_payload
                    else []
                ),
                "workflow_handoff": workflow_handoff,
                "continuation": continuation,
                "feedback_loop": feedback_loop,
                "challenge_diagnostics": challenge_diagnostics,
                "challenge_diagnostics_history": challenge_diagnostic_trace,
                "final_visual_evidence": final_visual_evidence,
            },
        )

    @mcp.tool(structured_output=True)
    async def browser_screenshot(
        url: str,
        timeout_sec: int = 45,
        wait_ms: int = 5000,
        viewport_width: int = 1440,
        viewport_height: int = 2200,
        preferred_browser: str = "",
        user_agent: str = "",
    ) -> ToolResult:
        """Capture a browser screenshot, coordinate grid, and grounded interaction targets."""
        payload, visual_artifacts = await _browser_screenshot_payload(
            url=url,
            timeout_sec=max(1, timeout_sec),
            wait_ms=max(0, wait_ms),
            viewport_width=max(320, viewport_width),
            viewport_height=max(240, viewport_height),
            preferred_browser=preferred_browser,
            user_agent=user_agent,
        )
        workflow_handoff = _web_workflow_handoff(
            current_tool="browser_screenshot",
            assessment=payload["assessment"],
            outcome_override=_visual_workflow_outcome_for_screenshot(payload),
            url=url,
            method="GET",
            headers={"User-Agent": user_agent or _BROWSER_HEADERS["User-Agent"]},
            timeout_sec=max(1, timeout_sec),
            max_body_chars=16000,
            wait_ms=max(0, wait_ms),
            browser_profile=True,
            preferred_browser=preferred_browser,
        )
        continuation = _continuation_from_handoff(workflow_handoff)
        feedback_loop = _visual_feedback_loop(
            current_tool="browser_screenshot",
            payload=payload,
            continuation=continuation,
        )
        continuation_required = bool(continuation and continuation.get("state") == "invoke_tool")
        return _result(
            "browser_screenshot",
            ok=bool(payload["ok"]),
            duration_ms=payload["duration_ms"],
            stdout_text=_display_stdout_text(
                payload["body_preview"],
                payload["assessment"],
                continuation=continuation,
            ),
            stderr_text=str(payload["response"].get("capture_stderr") or ""),
            error_code="WEB_ACCESS_CONTINUATION_REQUIRED" if continuation_required else payload["error_code"],
            error_stage="continuation" if continuation_required else payload["error_stage"],
            message=str(feedback_loop["summary"] or payload["message"]),
            data={
                "request": payload["request"],
                "response": payload["response"],
                "assessment": payload["assessment"],
                "runtime_status": payload["runtime_status"],
                "capabilities": payload.get("capabilities"),
                "artifacts": payload["artifacts"],
                "workflow_handoff": workflow_handoff,
                "continuation": continuation,
                "feedback_loop": feedback_loop,
            },
            extra_artifacts=visual_artifacts,
        )

    @mcp.tool(structured_output=True)
    async def browser_coordinate_click(
        url: str,
        x: int,
        y: int,
        timeout_sec: int = 60,
        wait_before_ms: int = 5000,
        wait_after_ms: int = 3000,
        viewport_width: int = 1440,
        viewport_height: int = 2200,
        preferred_browser: str = "",
        user_agent: str = "",
    ) -> ToolResult:
        """Click a single grounded viewport coordinate in a browser and capture the post-click state."""
        payload, visual_artifacts = await _browser_coordinate_click_payload(
            url=url,
            x=x,
            y=y,
            timeout_sec=max(1, timeout_sec),
            wait_before_ms=max(0, wait_before_ms),
            wait_after_ms=max(0, wait_after_ms),
            viewport_width=max(320, viewport_width),
            viewport_height=max(240, viewport_height),
            preferred_browser=preferred_browser,
            user_agent=user_agent,
        )
        workflow_handoff = _web_workflow_handoff(
            current_tool="browser_coordinate_click",
            assessment=payload["assessment"],
            outcome_override=_visual_workflow_outcome_for_click(payload),
            url=url,
            method="GET",
            headers={"User-Agent": user_agent or _BROWSER_HEADERS["User-Agent"]},
            timeout_sec=max(1, timeout_sec),
            max_body_chars=16000,
            wait_ms=max(0, wait_before_ms),
            browser_profile=True,
            preferred_browser=preferred_browser,
        )
        continuation = _continuation_from_handoff(workflow_handoff)
        feedback_loop = _visual_feedback_loop(
            current_tool="browser_coordinate_click",
            payload=payload,
            continuation=continuation,
        )
        continuation_required = bool(continuation and continuation.get("state") == "invoke_tool")
        return _result(
            "browser_coordinate_click",
            ok=bool(payload["ok"]),
            duration_ms=payload["duration_ms"],
            stdout_text=_display_stdout_text(
                payload["body_preview"],
                payload["assessment"],
                continuation=continuation,
            ),
            stderr_text=str(payload["response"].get("capture_stderr") or ""),
            error_code="WEB_ACCESS_CONTINUATION_REQUIRED" if continuation_required else payload["error_code"],
            error_stage="continuation" if continuation_required else payload["error_stage"],
            message=str(feedback_loop["summary"] or payload["message"]),
            data={
                "request": payload["request"],
                "response": payload["response"],
                "assessment": payload["assessment"],
                "runtime_status": payload["runtime_status"],
                "capabilities": payload["capabilities"],
                "artifacts": payload["artifacts"],
                "workflow_handoff": workflow_handoff,
                "continuation": continuation,
                "feedback_loop": feedback_loop,
            },
            extra_artifacts=visual_artifacts,
        )

    @mcp.tool(structured_output=True)
    async def web_page_diagnose(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout_sec: int = 20,
        browser_profile: bool = True,
        try_browser: bool = True,
        wait_ms: int = 5000,
        max_body_chars: int = 12000,
        preferred_browser: str = "",
    ) -> ToolResult:
        """Diagnose blocked web access in one pass without same-origin retry loops.

        This tool performs direct HTTP inspection first and, when allowed,
        escalates through browser DOM capture, visual inspection, and a single
        bounded grounded click progression when one clear target is present. It
        is preferred over
        manual header, cookie, query-string, or AMP retries.
        """
        started = time.monotonic()
        prepared_headers = _merge_request_headers(headers, browser_profile=browser_profile)
        payload = await _web_page_diagnosis_payload(
            url=url,
            method=method.upper(),
            headers=prepared_headers,
            timeout_sec=max(1, timeout_sec),
            max_body_chars=max(512, max_body_chars),
            browser_profile=browser_profile,
            try_browser=try_browser,
            wait_ms=max(0, wait_ms),
            preferred_browser=preferred_browser,
        )
        return _result(
            "web_page_diagnose",
            ok=bool(payload["ok"]),
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=_display_stdout_text(
                payload["body_preview"],
                payload["final_assessment"],
                continuation=payload["continuation"],
            ),
            stderr_text=str(payload["final_response"].get("transfer_error") or ""),
            error_code=payload["error_code"],
            error_stage=payload["error_stage"],
            message=payload["message"],
            data={
                "strategy": payload["strategy"],
                "capabilities": payload["capabilities"],
                "runtime_status_before": payload["runtime_status_before"],
                "runtime_status": payload["runtime_status"],
                "http_attempt": payload["http_attempt"],
                "bootstrap_attempt": payload["bootstrap_attempt"],
                "browser_attempt": payload["browser_attempt"],
                "screenshot_attempt": payload["screenshot_attempt"],
                "interactive_attempt": payload["interactive_attempt"],
                "interaction_attempts": payload["interaction_attempts"],
                "final_response": payload["final_response"],
                "final_assessment": payload["final_assessment"],
                "retry_guidance": payload["retry_guidance"],
                "recommendations": payload["recommendations"],
                "workflow_handoff": payload["workflow_handoff"],
                "continuation": payload["continuation"],
                "feedback_loop": payload["feedback_loop"],
                "challenge_diagnostics": payload["challenge_diagnostics"],
                "challenge_diagnostics_history": payload["challenge_diagnostics_history"],
                "final_visual_evidence": payload["final_visual_evidence"],
            },
            extra_artifacts=payload["extra_artifacts"],
        )

    @mcp.tool(structured_output=True)
    async def web_retrieve(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout_sec: int = 20,
        browser_profile: bool = True,
        try_browser: bool = True,
        allow_bootstrap: bool = False,
        bootstrap_target: str = "chromium",
        bootstrap_timeout_sec: int = 900,
        wait_ms: int = 5000,
        max_body_chars: int = 12000,
        preferred_browser: str = "",
    ) -> ToolResult:
        """Retrieve webpage content through a bounded escalation workflow.

        This tool starts with direct HTTP inspection, checks browser runtime
        availability, can optionally bootstrap Chromium on the host, performs a
        headless browser fetch when needed, and can continue through visual
        capture plus bounded grounded click progression before stopping.
        """
        started = time.monotonic()
        prepared_headers = _merge_request_headers(headers, browser_profile=browser_profile)
        payload = await _web_retrieval_payload(
            current_tool="web_retrieve",
            url=url,
            method=method.upper(),
            headers=prepared_headers,
            timeout_sec=max(1, timeout_sec),
            max_body_chars=max(512, max_body_chars),
            browser_profile=browser_profile,
            try_browser=try_browser,
            wait_ms=max(0, wait_ms),
            preferred_browser=preferred_browser,
            allow_bootstrap=allow_bootstrap,
            bootstrap_target=bootstrap_target,
            bootstrap_timeout_sec=max(30, bootstrap_timeout_sec),
        )
        return _result(
            "web_retrieve",
            ok=bool(payload["ok"]),
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=_display_stdout_text(
                payload["body_preview"],
                payload["final_assessment"],
                continuation=payload["continuation"],
            ),
            stderr_text=str(payload["final_response"].get("transfer_error") or ""),
            error_code=payload["error_code"],
            error_stage=payload["error_stage"],
            message=payload["message"],
            data={
                "strategy": payload["strategy"],
                "capabilities": payload["capabilities"],
                "runtime_status_before": payload["runtime_status_before"],
                "runtime_status": payload["runtime_status"],
                "http_attempt": payload["http_attempt"],
                "bootstrap_attempt": payload["bootstrap_attempt"],
                "browser_attempt": payload["browser_attempt"],
                "screenshot_attempt": payload["screenshot_attempt"],
                "interactive_attempt": payload["interactive_attempt"],
                "interaction_attempts": payload["interaction_attempts"],
                "final_response": payload["final_response"],
                "final_assessment": payload["final_assessment"],
                "retry_guidance": payload["retry_guidance"],
                "recommendations": payload["recommendations"],
                "workflow_handoff": payload["workflow_handoff"],
                "continuation": payload["continuation"],
                "feedback_loop": payload["feedback_loop"],
                "challenge_diagnostics": payload["challenge_diagnostics"],
                "challenge_diagnostics_history": payload["challenge_diagnostics_history"],
                "final_visual_evidence": payload["final_visual_evidence"],
            },
            extra_artifacts=payload["extra_artifacts"],
        )

    @mcp.tool(structured_output=True)
    async def http_fetch(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout_sec: int = 20,
        browser_profile: bool = True,
        max_body_chars: int = 12000,
    ) -> ToolResult:
        """Fetch a web resource through direct HTTP with structured access diagnostics.

        Use web_page_diagnose if you also want runtime discovery and automatic
        browser escalation in the same tool call. If this tool classifies the
        page as blocked or challenged, do not keep retrying the same origin
        with alternate headers, query variants, or shell scraping. Instead,
        follow the returned runtime-aware retry guidance and recommendations:
        if browser escalation remains available, call `browser_fetch` next
        instead of stopping.
        """
        started = time.monotonic()
        prepared_headers = _merge_request_headers(headers, browser_profile=browser_profile)
        payload, _ = await _http_probe_payload(
            url=url,
            method=method.upper(),
            headers=prepared_headers,
            timeout_sec=max(1, timeout_sec),
            max_body_chars=max(512, max_body_chars),
            browser_profile=browser_profile,
        )
        return _result(
            "http_fetch",
            ok=bool(payload["ok"]),
            duration_ms=(time.monotonic() - started) * 1000,
            stdout_text=_display_stdout_text(
                payload["body_preview"],
                payload["assessment"],
                continuation=payload["continuation"],
            ),
            stderr_text=str(payload["response"].get("transfer_error") or ""),
            error_code=payload["error_code"],
            error_stage=payload["error_stage"],
            message=payload["message"],
            data={
                "request": payload["request"],
                "response": payload["response"],
                "assessment": payload["assessment"],
                "retry_guidance": payload["retry_guidance"],
                "capabilities": payload["capabilities"],
                "runtime_status": payload["runtime_status"],
                "recommendations": payload["recommendations"],
                "workflow_handoff": payload["workflow_handoff"],
                "continuation": payload["continuation"],
                "feedback_loop": payload["feedback_loop"],
            },
        )

    @mcp.tool()
    async def check_port(host: str = "localhost", port: int = 80, timeout_sec: int = 3) -> str:
        """Check if a TCP port is open."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            if capabilities.has("nc"):
                cmd = f"nc -z -w {timeout_sec} {shlex.quote(host)} {port} >/dev/null 2>&1 && echo OPEN || echo CLOSED"
            else:
                cmd = (
                    f"bash -lc 'timeout {timeout_sec} bash -c "
                    f'"echo >/dev/tcp/{host}/{port}" 2>/dev/null && echo OPEN || echo CLOSED\''
                )
            result = await conn.run_full(cmd, timeout=timeout_sec + 5)
            return json.dumps({"host": host, "port": port, "open": "OPEN" in result.stdout})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def dns_lookup(domain: str, record_type: str = "A") -> str:
        """Perform a DNS lookup."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            if capabilities.has("dig"):
                cmd = f"dig +short {shlex.quote(domain)} {shlex.quote(record_type)}"
            else:
                cmd = f"getent ahosts {shlex.quote(domain)}"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps(
                {
                    "domain": domain,
                    "type": record_type,
                    "records": result.stdout.strip() if result.ok else result.stderr.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def ssl_info(domain: str, port: int = 443) -> str:
        """Show SSL certificate information for a domain."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = (
                f"echo | openssl s_client -servername {shlex.quote(domain)} "
                f"-connect {shlex.quote(domain)}:{port} 2>/dev/null | "
                "openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null"
            )
            result = await conn.run_full(cmd, timeout=15)
            return json.dumps(
                {
                    "domain": domain,
                    "port": port,
                    "certificate": result.stdout.strip() if result.ok else "Could not retrieve certificate",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def firewall_rules() -> str:
        """Show current firewall rules."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            if capabilities.has("ufw"):
                cmd = "ufw status verbose 2>/dev/null"
            elif capabilities.has("iptables"):
                cmd = "iptables -L -n 2>/dev/null | head -80"
            else:
                return json.dumps({"error": "No supported firewall tool detected"})
            result = await conn.run_full(cmd, timeout=15)
            return json.dumps({"rules": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def curl_test(url: str, method: str = "GET", headers: dict | None = None, timeout_sec: int = 10) -> str:
        """Make an HTTP request from the server with access diagnostics."""
        prepared_headers = _merge_request_headers(headers, browser_profile=True)
        payload, _ = await _http_probe_payload(
            url=url,
            method=method.upper(),
            headers=prepared_headers,
            timeout_sec=max(1, timeout_sec),
            max_body_chars=5000,
            browser_profile=True,
        )
        response = payload["response"]
        return json.dumps(
            {
                "url": url,
                "method": method.upper(),
                "status_code": response.get("status_code"),
                "time_seconds": response.get("elapsed_seconds"),
                "size_bytes": response.get("downloaded_bytes"),
                "final_url": response.get("final_url"),
                "title": response.get("metadata", {}).get("title"),
                "classification": payload["assessment"]["classification"],
                "accessible": payload["assessment"]["accessible"],
                "constraints": payload["assessment"]["constraints"],
                "retry_guidance": payload["retry_guidance"],
                "workflow_handoff": payload.get("workflow_handoff"),
                "body_preview": payload["body_preview"],
                "transfer_error": response.get("transfer_error"),
            }
        )

    @mcp.tool()
    async def listening_ports() -> str:
        """Show all listening TCP/UDP ports."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            if capabilities.has("ss"):
                cmd = "ss -tulnp"
            elif capabilities.has("netstat"):
                cmd = "netstat -tulnp"
            elif capabilities.has("lsof"):
                cmd = "lsof -i -P -n | grep LISTEN"
            else:
                return json.dumps({"error": "No supported socket inspection command detected"})
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps({"ports": result.stdout.strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def port_forward(
        listen_port: int, target_host: str = "127.0.0.1", target_port: int = 0, protocol: str = "tcp"
    ) -> str:
        """Set up port forwarding using socat (runs in background)."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if target_port == 0:
                target_port = listen_port
            capabilities = await conn.probe_capabilities()
            if not capabilities.has("socat"):
                return json.dumps({"error": "socat not installed"})
            proto = "TCP4" if protocol == "tcp" else "UDP4"
            cmd = (
                f"nohup socat {proto}-LISTEN:{listen_port},fork,reuseaddr "
                f"{proto}:{target_host}:{target_port} >/dev/null 2>&1 & echo $!"
            )
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps(
                {
                    "status": "ok",
                    "listen_port": listen_port,
                    "target": f"{target_host}:{target_port}",
                    "protocol": protocol,
                    "pid": result.stdout.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def list_forwards() -> str:
        """List active port forwards (socat and ssh tunnels)."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = "ps aux | grep -E '(socat|ssh.*-[LR])' | grep -v grep"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps({"forwards": result.stdout.strip() if result.stdout.strip() else "(no active forwards)"})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def remove_forward(listen_port: int) -> str:
        """Remove a port forward by killing the socat process on that port."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"pgrep -f 'socat.*LISTEN:{listen_port}' | xargs -r kill 2>&1 && echo OK || echo NOT_FOUND"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps(
                {"listen_port": listen_port, "status": "removed" if "OK" in result.stdout else "not_found"}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def iptables_forward(src_port: int, dst_host: str, dst_port: int, action: str = "add") -> str:
        """Manage iptables port forwarding (DNAT)."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            if not capabilities.has("iptables"):
                return json.dumps({"error": "iptables is not available on this host"})
            flag = "-A" if action == "add" else "-D"
            cmds = [
                "iptables -t nat "
                f"{flag} PREROUTING -p tcp --dport {src_port} "
                f"-j DNAT --to-destination {dst_host}:{dst_port}",
                f"iptables {flag} FORWARD -p tcp -d {dst_host} --dport {dst_port} -j ACCEPT",
            ]
            if action == "add":
                cmds.insert(0, "echo 1 > /proc/sys/net/ipv4/ip_forward")
            result = await conn.run_full(" && ".join(cmds) + " 2>&1", timeout=10)
            return json.dumps(
                {
                    "action": action,
                    "rule": f":{src_port} -> {dst_host}:{dst_port}",
                    "success": result.exit_code == 0,
                    "output": result.stdout.strip() if result.stdout.strip() else result.stderr.strip(),
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def port_scan(host: str, ports: list[int], timeout_sec: int = 2) -> str:
        """Scan a bounded list of TCP ports from the target host."""
        if not ports:
            return json.dumps({"error": "ports is required"})
        pool = get_pool()
        conn = await pool.acquire()
        try:
            capabilities = await conn.probe_capabilities()
            results = []
            for port in ports[:100]:
                if capabilities.has("nc"):
                    cmd = (
                        f"nc -z -w {timeout_sec} {shlex.quote(host)} {port} >/dev/null 2>&1 && echo open || echo closed"
                    )
                else:
                    cmd = (
                        f"bash -lc 'timeout {timeout_sec} bash -c "
                        f'"echo >/dev/tcp/{host}/{port}" >/dev/null 2>&1 && echo open || echo closed\''
                    )
                result = await conn.run_full(cmd, timeout=timeout_sec + 4)
                results.append({"port": port, "status": result.stdout.strip() or "closed"})
            return json.dumps({"host": host, "ports": results})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def network_route(target: str = "") -> str:
        """Inspect routing table or the route to a specific target."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if target:
                cmd = (
                    f"ip route get {shlex.quote(target)} 2>/dev/null || route -n get {shlex.quote(target)} 2>/dev/null"
                )
            else:
                cmd = "ip route show 2>/dev/null || netstat -rn 2>/dev/null"
            result = await conn.run_full(cmd, timeout=10)
            return json.dumps({"target": target or None, "routes": (result.stdout + result.stderr).strip()})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def trace_route(host: str, max_hops: int = 20) -> str:
        """Run traceroute or tracepath to a host."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            traceroute = await conn.run_full("which traceroute 2>/dev/null")
            if traceroute.ok:
                cmd = f"traceroute -m {max_hops} {shlex.quote(host)}"
            else:
                tracepath = await conn.run_full("which tracepath 2>/dev/null")
                if tracepath.ok:
                    cmd = f"tracepath -m {max_hops} {shlex.quote(host)}"
                else:
                    return json.dumps({"error": "Neither traceroute nor tracepath is installed"})
            result = await conn.run_full(cmd, timeout=120)
            return json.dumps({"host": host, "output": (result.stdout + result.stderr).strip()[-20000:]})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def ssh_tunnel(
        mode: str = "local",
        bind_port: int = 0,
        target_host: str = "127.0.0.1",
        target_port: int = 0,
        gateway_host: str = "",
        gateway_user: str = "",
        gateway_port: int = 22,
    ) -> str:
        """Start a local or reverse SSH tunnel from the target host."""
        if bind_port <= 0 or target_port <= 0 or not gateway_host or not gateway_user:
            return json.dumps({"error": "bind_port, target_port, gateway_host, and gateway_user are required"})
        if mode not in {"local", "reverse"}:
            return json.dumps({"error": "mode must be one of: local, reverse"})

        flag = "-L" if mode == "local" else "-R"
        tunnel_spec = f"{bind_port}:{target_host}:{target_port}"
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = (
                "nohup ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes "
                f"-N {flag} {shlex.quote(tunnel_spec)} -p {gateway_port} "
                f"{shlex.quote(gateway_user)}@{shlex.quote(gateway_host)} >/dev/null 2>&1 & echo $!"
            )
            result = await conn.run_full(cmd, timeout=20)
            return json.dumps(
                {
                    "mode": mode,
                    "bind_port": bind_port,
                    "target": f"{target_host}:{target_port}",
                    "gateway": f"{gateway_user}@{gateway_host}:{gateway_port}",
                    "pid": result.stdout.strip(),
                }
            )
        finally:
            pool.release(conn)
