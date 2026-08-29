"""Unit tests for HTTP access diagnostics helpers."""

import pytest

from mcp_nexus.config import Settings
from mcp_nexus.server import create_server
from mcp_nexus.tools.network import (
    _CURL_BODY_MARKER,
    _CURL_EXIT_MARKER,
    _CURL_HEADERS_MARKER,
    _CURL_META_MARKER,
    _apply_click_hint_to_handoff,
    _assess_http_access,
    _auto_interaction_plan,
    _browser_automation_capability,
    _browser_bootstrap_plan,
    _browser_recommendations,
    _browser_screenshot_command,
    _browser_visual_capture_command,
    _challenge_diagnostic_note,
    _extract_dom_affordances,
    _extract_html_metadata,
    _grid_svg_document,
    _http_probe_payload,
    _parse_curl_probe_output,
    _post_click_challenge_diagnostics,
    _resolve_browser_command,
    _retry_guidance,
    _continuation_from_handoff,
    _web_page_diagnosis_payload,
    _web_retrieval_payload,
)


def test_extract_html_metadata_normalizes_title_and_meta() -> None:
    body = """
    <html>
      <head>
        <title> Example &amp; Test </title>
        <meta property="og:title" content="OG Headline">
        <meta name="description" content="  Summary   text ">
      </head>
    </html>
    """

    metadata = _extract_html_metadata(body)

    assert metadata["title"] == "Example & Test"
    assert metadata["og_title"] == "OG Headline"
    assert metadata["description"] == "Summary text"


def test_extract_dom_affordances_reports_controls_visuals_and_scripts() -> None:
    body = """
    <html>
      <body>
        <form action="/verify">
          <button id="verify-button">Verify</button>
          <input type="checkbox" id="human-check" aria-label="I am human">
          <iframe src="https://captcha.example/widget" title="captcha"></iframe>
          <img src="https://cdn.example/puzzle.png" alt="challenge image">
          <canvas id="captcha-canvas"></canvas>
        </form>
        <script src="https://captcha.example/widget.js"></script>
      </body>
    </html>
    """

    observation = _extract_dom_affordances(body)

    assert observation["interactive_surface_detected"] is True
    assert observation["visual_surface_detected"] is True
    assert observation["counts"]["form"] == 1
    assert observation["counts"]["button"] == 1
    assert observation["counts"]["checkbox"] == 1
    assert observation["counts"]["iframe"] == 1
    assert observation["counts"]["image"] == 1
    assert observation["counts"]["canvas"] == 1
    assert observation["provider_hosts"] == ["captcha.example"]
    assert observation["interactive_elements"][0]["tag"] == "button"
    assert observation["visual_elements"][0]["tag"] == "img"
    assert observation["visual_elements"][0]["host"] == "cdn.example"


def test_browser_automation_capability_requires_browser_and_node() -> None:
    capability = _browser_automation_capability(
        {
            "headless_dom_supported": True,
            "commands": {"chromium": "/usr/bin/chromium", "node": "/usr/bin/node"},
        }
    )

    assert capability["visual_capture_supported"] is True
    assert capability["coordinate_click_supported"] is True
    assert capability["coordinate_click_runtime"] == "node_cdp"


def test_auto_interaction_plan_selects_dominant_iframe_candidate() -> None:
    assessment = {"classification": "challenge_page", "accessible": False}
    targets = [
        {
            "kind": "iframe",
            "clickable": True,
            "visible": True,
            "in_viewport": True,
            "disabled": False,
            "pointer": False,
            "label": None,
            "title": None,
            "aria_label": None,
            "checked": False,
            "x": 720,
            "y": 640,
            "width": 520,
            "height": 360,
            "visible_area": 187200,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "viewport_area": 3168000,
        },
        {
            "kind": "iframe",
            "clickable": True,
            "visible": True,
            "in_viewport": True,
            "disabled": False,
            "pointer": False,
            "label": None,
            "title": None,
            "aria_label": None,
            "checked": False,
            "x": 120,
            "y": 180,
            "width": 90,
            "height": 60,
            "visible_area": 5400,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "viewport_area": 3168000,
        },
    ]

    plan = _auto_interaction_plan(assessment, targets)

    assert plan["eligible"] is True
    assert plan["click_request"] == {"x": 720, "y": 640}
    assert plan["selected_target"]["kind"] == "iframe"
    assert plan["candidate_ranking"][0]["score"] > plan["candidate_ranking"][1]["score"]


def test_auto_interaction_plan_surfaces_suggested_candidate_when_ambiguous() -> None:
    assessment = {"classification": "challenge_page", "accessible": False}
    targets = [
        {
            "kind": "iframe",
            "clickable": True,
            "visible": True,
            "in_viewport": True,
            "disabled": False,
            "pointer": False,
            "label": None,
            "title": None,
            "aria_label": None,
            "checked": False,
            "x": 520,
            "y": 520,
            "width": 320,
            "height": 240,
            "visible_area": 76800,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "viewport_area": 3168000,
        },
        {
            "kind": "iframe",
            "clickable": True,
            "visible": True,
            "in_viewport": True,
            "disabled": False,
            "pointer": False,
            "label": None,
            "title": None,
            "aria_label": None,
            "checked": False,
            "x": 900,
            "y": 560,
            "width": 320,
            "height": 240,
            "visible_area": 76800,
            "viewport_width": 1440,
            "viewport_height": 2200,
            "viewport_area": 3168000,
        },
    ]

    plan = _auto_interaction_plan(assessment, targets)

    assert plan["eligible"] is False
    assert plan["click_request"] is None
    assert plan["requires_visual_review"] is True
    assert plan["suggested_click_request"] is not None
    assert len(plan["candidate_ranking"]) == 2


def test_apply_click_hint_to_handoff_prefills_browser_fetch_manual_click() -> None:
    handoff = {
        "next_tools": [
            {
                "tool": "browser_fetch",
                "alternate_tool": "browser_coordinate_click",
                "call_template": {
                    "url": "https://example.com",
                    "manual_click_x": "<grid_x>",
                    "manual_click_y": "<grid_y>",
                },
            }
        ]
    }
    updated = _apply_click_hint_to_handoff(
        handoff,
        {"x": 512, "y": 448, "source": "suggested_click_request", "confidence": 0.73},
    )

    assert updated is not None
    call_template = updated["next_tools"][0]["call_template"]
    assert call_template["manual_click_x"] == 512
    assert call_template["manual_click_y"] == 448
    assert "Prefilled from grounded suggested_click_request" in call_template["arg_notes"]


def test_post_click_challenge_diagnostics_explains_unchanged_state() -> None:
    pre_payload = {
        "request": {"url": "https://example.com/article"},
        "response": {
            "final_url": "https://example.com/article",
            "metadata": {"title": "Are you a robot?"},
            "dom_observation": {"counts": {"iframe": 1}},
            "interaction_targets": [],
            "auto_interaction": {"eligible": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    click_payload = {
        "request": {"url": "https://example.com/article"},
        "response": {
            "final_url": "https://example.com/article",
            "metadata": {"title": "Are you a robot?"},
            "dom_observation": {"counts": {"iframe": 1}},
            "interaction_targets": [],
            "auto_interaction": {
                "eligible": False,
                "suggested_click_request": {"x": 700, "y": 500},
            },
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }

    diagnostics = _post_click_challenge_diagnostics(pre_payload=pre_payload, click_payload=click_payload)

    assert diagnostics is not None
    assert diagnostics["blocked_after_click"] is True
    assert diagnostics["state_changed"] is False
    blocker_codes = [item["code"] for item in diagnostics["likely_blockers"]]
    assert "challenge_state_unchanged_after_click" in blocker_codes
    assert diagnostics["suggested_click_request"] == {"x": 700, "y": 500}
    note = _challenge_diagnostic_note(diagnostics)
    assert "challenge state" in note.lower()
    assert "(700, 500)" in note


def test_grid_svg_document_embeds_screenshot_and_click_marker() -> None:
    svg = _grid_svg_document(
        png_base64="ZmFrZXBuZw==",
        width=200,
        height=120,
        grid_step_px=50,
        marker=(75, 40),
    )

    assert "data:image/png;base64,ZmFrZXBuZw==" in svg
    assert "click (75, 40)" in svg
    assert "<line" in svg


def test_browser_screenshot_command_waits_for_rendered_file() -> None:
    command = _browser_screenshot_command(
        browser_path="/usr/bin/chromium",
        python_bin="/usr/bin/python3",
        url="https://example.com",
        wait_ms=5000,
        user_agent="ua",
        width=1440,
        height=2200,
    )

    assert "shot_tmp=$(mktemp /tmp/nexus-browser-shot-XXXXXX)" in command
    assert 'shot_file="${shot_tmp}.png"' in command
    assert 'rm -f "$shot_tmp"' in command
    assert "for attempt in 1 2 3 4 5" in command
    assert '[ -s "$shot_file" ] && break' in command
    assert 'rm -rf "$profile_dir" "$stderr_file"' in command
    assert 'rm -f "$shot_file"' in command


def test_browser_visual_capture_command_uses_cdp_screenshot_path() -> None:
    command = _browser_visual_capture_command(
        browser_path="/usr/bin/chromium",
        url="https://example.com",
        wait_ms=5000,
        width=1440,
        height=2200,
        user_agent="ua",
    )

    assert "Page.captureScreenshot" in command
    assert "Runtime.evaluate" in command
    assert "shadowRoot" in command
    assert "node --experimental-websocket -" in command


def test_continuation_prefers_http_fetch_fallback_for_registry_check() -> None:
    continuation = _continuation_from_handoff(
        {
            "terminal": False,
            "reason": "A live registry check is required before retrying another specialized tool.",
            "action": None,
            "task_family": "web_retrieval",
            "next_tools": [
                {
                    "tool": "nexus_tool_registry",
                    "priority": 1,
                    "available": True,
                    "availability_scope": "server_registry_snapshot",
                    "callable_surface_confirmed": False,
                    "fallback_tool": "http_fetch",
                    "fallback_reason": "Verify the active server registry snapshot through the control-plane HTTP endpoint.",
                    "fallback_call_template": {
                        "url": "https://example.com/.well-known/nexus-tool-registry",
                        "method": "GET",
                        "headers": {},
                        "timeout_sec": 20,
                        "browser_profile": False,
                        "max_body_chars": 12000,
                    },
                }
            ],
            "recommended_tool": "nexus_tool_registry",
            "surface_verification": {"surface_scope": "server_registry_snapshot"},
        }
    )

    assert continuation is not None
    assert continuation["next_step"]["tool"] == "http_fetch"
    assert continuation["next_step"]["alternate_tool"] == "nexus_tool_registry"
    assert continuation["fallback_next_step"]["tool"] == "http_fetch"


def test_assess_http_access_detects_challenge_page() -> None:
    assessment = _assess_http_access(
        status_code=403,
        headers={"retry-after": "0", "content-type": "text/html"},
        body_preview="<html><title>Are you a robot?</title><body>Verify you are human</body></html>",
        metadata={"title": "Are you a robot?"},
    )

    assert assessment["classification"] == "challenge_page"
    assert assessment["accessible"] is False
    assert "http_status_403" in assessment["constraints"]
    assert "challenge_page_detected" in assessment["constraints"]


def test_assess_http_access_detects_content_gating() -> None:
    assessment = _assess_http_access(
        status_code=200,
        headers={"content-type": "text/html"},
        body_preview="<html><body>Already a subscriber? Sign in to continue.</body></html>",
        metadata={"title": "Article"},
    )

    assert assessment["classification"] == "content_gated"
    assert assessment["retrieved"] is True
    assert assessment["accessible"] is False


def test_assess_http_access_accepts_browser_retrieval_hint() -> None:
    assessment = _assess_http_access(
        status_code=None,
        headers={},
        body_preview="<html><title>Working DOM</title><body>Article body</body></html>",
        metadata={"title": "Working DOM"},
        retrieved_hint=True,
    )

    assert assessment["classification"] == "ok"
    assert assessment["retrieved"] is True
    assert assessment["accessible"] is True


def test_parse_curl_probe_output_uses_final_response_headers() -> None:
    stdout = (
        f"{_CURL_EXIT_MARKER}\n0\n"
        f"{_CURL_META_MARKER}\n403\nhttps://example.com/article\ntext/html\n13856\n0.11\n"
        f"{_CURL_HEADERS_MARKER}\n"
        "HTTP/2 301 \nlocation: https://example.com/article\n\n"
        "HTTP/2 403 \nretry-after: 0\ncontent-type: text/html\n\n"
        f"{_CURL_BODY_MARKER}\n"
        "<html><title>Are you a robot?</title></html>"
    )

    parsed = _parse_curl_probe_output(stdout, "")

    assert parsed["transport"] == "curl"
    assert parsed["transport_ok"] is True
    assert parsed["status_code"] == 403
    assert parsed["final_url"] == "https://example.com/article"
    assert parsed["headers"]["retry-after"] == "0"
    assert parsed["body_preview"].startswith("<html>")


def test_resolve_browser_command_prefers_requested_browser() -> None:
    runtime_status = {
        "commands": {
            "chromium": "/usr/bin/chromium",
            "google-chrome": "/usr/bin/google-chrome",
        },
        "chromium_family": {
            "preferred": "chromium",
            "preferred_path": "/usr/bin/chromium",
        },
    }

    command, path = _resolve_browser_command(runtime_status, preferred_browser="google-chrome")

    assert command == "google-chrome"
    assert path == "/usr/bin/google-chrome"


def test_browser_recommendations_suggest_browser_escalation_when_available() -> None:
    recommendations = _browser_recommendations(
        {"classification": "challenge_page", "accessible": False},
        {"headless_dom_supported": True},
        browser_attempted=False,
        browser_accessible=False,
    )

    assert recommendations[0]["tool"] == "browser_fetch"
    assert any(item.get("action") == "stop_same_origin_http_retries" for item in recommendations)


def test_browser_recommendations_suggest_bootstrap_when_runtime_missing() -> None:
    recommendations = _browser_recommendations(
        {"classification": "challenge_page", "accessible": False},
        {"headless_dom_supported": False},
        browser_attempted=False,
        browser_accessible=False,
    )

    assert recommendations[0]["tool"] == "browser_bootstrap"


def test_retry_guidance_blocks_same_origin_retry_loops_for_challenge_pages() -> None:
    guidance = _retry_guidance(
        {"classification": "challenge_page", "accessible": False},
        {"headless_dom_supported": False},
        browser_attempted=False,
        browser_accessible=False,
    )

    assert guidance["should_stop"] is True
    assert guidance["same_origin_http_retry_allowed"] is False
    assert guidance["header_variation_allowed"] is False
    assert guidance["query_variant_allowed"] is False
    assert guidance["recommended_action"] == "report_blocked_access"


def test_retry_guidance_allows_single_browser_escalation_when_available() -> None:
    guidance = _retry_guidance(
        {"classification": "forbidden", "accessible": False},
        {"headless_dom_supported": True},
        browser_attempted=False,
        browser_accessible=False,
    )

    assert guidance["should_stop"] is False
    assert guidance["same_origin_http_retry_allowed"] is False
    assert guidance["browser_escalation_allowed"] is True
    assert guidance["recommended_action"] == "try_browser_fetch"


@pytest.mark.asyncio
async def test_http_probe_payload_surfaces_browser_followup_when_runtime_available(monkeypatch) -> None:
    async def fake_fetch_http_probe(**kwargs):
        return (
            {
                "transport": "curl",
                "transport_ok": True,
                "status_code": 403,
                "final_url": "https://example.com/article",
                "headers": {"content-type": "text/html"},
                "body_preview": "<html><title>Are you a robot?</title></html>",
                "transfer_error": None,
            },
            {"commands": {"curl": True}},
        )

    async def fake_runtime_status_snapshot(*, refresh: bool = False):
        assert refresh is False
        return (
            {"commands": {"curl": True, "chromium": True}},
            {
                "commands": {"chromium": "/usr/bin/chromium"},
                "chromium_family": {
                    "available": True,
                    "preferred": "chromium",
                    "preferred_path": "/usr/bin/chromium",
                    "candidates": [{"command": "chromium", "path": "/usr/bin/chromium"}],
                },
                "headless_dom_supported": True,
            },
        )

    monkeypatch.setattr("mcp_nexus.tools.network._fetch_http_probe", fake_fetch_http_probe)
    monkeypatch.setattr("mcp_nexus.tools.network._runtime_status_snapshot", fake_runtime_status_snapshot)

    payload, _ = await _http_probe_payload(
        url="https://example.com/article",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout_sec=20,
        max_body_chars=5000,
    )

    assert payload["runtime_status"]["headless_dom_supported"] is True
    assert payload["retry_guidance"]["should_stop"] is False
    assert payload["retry_guidance"]["browser_escalation_allowed"] is True
    assert payload["retry_guidance"]["recommended_action"] == "try_browser_fetch"
    assert payload["recommendations"][0]["tool"] == "browser_fetch"
    assert payload["error_code"] == "WEB_ACCESS_REQUIRES_BROWSER_ESCALATION"
    assert payload["error_stage"] == "continuation"
    assert payload["message"] == "Invoke browser_fetch next. Direct HTTP did not recover an accessible page state."
    assert payload["workflow_handoff"]["recommended_tool"] == "browser_fetch"
    assert payload["continuation"]["next_step"]["tool"] == "browser_fetch"
    assert payload["workflow_handoff"]["next_tools"][0]["call_template"]["url"] == "https://example.com/article"
    assert payload["response"]["interaction_capability"]["mode"] == "http_response_only"
    assert payload["response"]["surface_summary"]


@pytest.mark.asyncio
async def test_http_probe_payload_falls_back_to_capability_hint_when_runtime_probe_fails(monkeypatch) -> None:
    async def fake_fetch_http_probe(**kwargs):
        return (
            {
                "transport": "curl",
                "transport_ok": True,
                "status_code": 403,
                "final_url": "https://example.com/article",
                "headers": {"content-type": "text/html"},
                "body_preview": "<html><title>Are you a robot?</title></html>",
                "transfer_error": None,
            },
            {"commands": {"curl": True, "chromium": True}},
        )

    async def fake_runtime_status_snapshot(*, refresh: bool = False):
        raise RuntimeError("runtime probe unavailable")

    monkeypatch.setattr("mcp_nexus.tools.network._fetch_http_probe", fake_fetch_http_probe)
    monkeypatch.setattr("mcp_nexus.tools.network._runtime_status_snapshot", fake_runtime_status_snapshot)

    payload, _ = await _http_probe_payload(
        url="https://example.com/article",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout_sec=20,
        max_body_chars=5000,
    )

    assert payload["runtime_status"]["detection_source"] == "capability_probe"
    assert payload["runtime_status"]["headless_dom_supported"] is True
    assert payload["retry_guidance"]["browser_escalation_allowed"] is True
    assert payload["retry_guidance"]["recommended_action"] == "try_browser_fetch"
    assert payload["recommendations"][0]["tool"] == "browser_fetch"
    assert payload["error_code"] == "WEB_ACCESS_REQUIRES_BROWSER_ESCALATION"
    assert payload["workflow_handoff"]["recommended_tool"] == "browser_fetch"


@pytest.mark.asyncio
async def test_web_page_diagnosis_reports_browser_attempt_and_next_tool(monkeypatch) -> None:
    http_payload = {
        "ok": False,
        "error_code": "WEB_ACCESS_REQUIRES_BROWSER_ESCALATION",
        "error_stage": "continuation",
        "message": "Direct HTTP was classified as challenge_page. Invoke browser_fetch next instead of stopping at the HTTP challenge.",
        "request": {"url": "https://example.com/article", "method": "GET", "headers": {"User-Agent": "Mozilla/5.0"}},
        "response": {"transport": "curl", "status_code": 403, "transfer_error": None},
        "assessment": {"classification": "challenge_page", "accessible": False},
        "retry_guidance": {"recommended_action": "try_browser_fetch"},
        "workflow_handoff": {
            "recommended_tool": "browser_fetch",
            "next_tools": [{"tool": "browser_fetch", "call_template": {"url": "https://example.com/article"}}],
        },
        "continuation": {"state": "invoke_tool", "next_step": {"tool": "browser_fetch"}},
        "feedback_loop": {"attempt_trace": [{"tool": "http_fetch"}]},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    browser_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "transport": "browser_dom",
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "transfer_error": None,
            "dom_observation": {
                "interactive_elements": [{"tag": "input", "type": "checkbox", "label": None}],
                "visual_elements": [],
                "counts": {
                    "form": 1,
                    "button": 0,
                    "input": 1,
                    "checkbox": 1,
                    "iframe": 0,
                    "image": 0,
                    "canvas": 0,
                    "script": 1,
                },
                "provider_hosts": ["captcha.example"],
                "script_sources": ["https://captcha.example/widget.js"],
                "interactive_surface_detected": True,
                "visual_surface_detected": False,
            },
            "interaction_capability": {
                "mode": "read_only_dom_dump",
                "click_supported": False,
                "form_fill_supported": False,
                "captcha_completion_supported": False,
                "reason": (
                    "This browser path is a bounded read-only DOM capture. When continuation is returned, "
                    "use the indicated visual or interaction tool for grounded follow-up."
                ),
            },
            "surface_summary": (
                "Captured static DOM controls: 1 checkbox input. "
                "This browser path is a bounded read-only DOM capture. When continuation is returned, "
                "use the indicated visual or interaction tool for grounded follow-up."
            ),
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }

    async def fake_http_probe_payload(**kwargs):
        return http_payload, {}

    async def fake_runtime_status_snapshot(*, refresh: bool = False):
        return (
            {"commands": {"curl": True, "chromium": True}},
            {
                "commands": {"chromium": "/usr/bin/chromium"},
                "chromium_family": {
                    "available": True,
                    "preferred": "chromium",
                    "preferred_path": "/usr/bin/chromium",
                    "candidates": [{"command": "chromium", "path": "/usr/bin/chromium"}],
                },
                "headless_dom_supported": True,
                "automation": {
                    "visual_capture_supported": True,
                    "coordinate_click_supported": True,
                },
            },
        )

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, {
            "commands": {"chromium": "/usr/bin/chromium"},
            "chromium_family": {
                "available": True,
                "preferred": "chromium",
                "preferred_path": "/usr/bin/chromium",
                "candidates": [{"command": "chromium", "path": "/usr/bin/chromium"}],
            },
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        }

    async def fake_browser_screenshot_payload(**kwargs):
        return (
            {
                "ok": True,
                "error_code": None,
                "error_stage": None,
                "message": "Captured a browser screenshot and coordinate grid.",
                "request": {"url": "https://example.com/article"},
                "response": {
                    "browser": "chromium",
                    "browser_path": "/usr/bin/chromium",
                    "node_path": "/usr/bin/node",
                    "capture_backend": "node_cdp",
                    "final_url": "https://example.com/article",
                    "viewport_width": 1440,
                    "viewport_height": 2200,
                    "screenshot_available": True,
                    "grid_available": True,
                    "metadata": {"title": "Are you a robot?"},
                    "dom_observation": browser_payload["response"]["dom_observation"],
                    "interaction_targets": [
                        {
                            "tag": "input",
                            "kind": "checkbox",
                            "input_type": "checkbox",
                            "label": "I am human",
                            "selector_hint": "input#human-check",
                            "clickable": True,
                            "visible": True,
                            "in_viewport": True,
                            "disabled": False,
                            "pointer": False,
                            "checked": False,
                            "x": 420,
                            "y": 360,
                            "width": 28,
                            "height": 28,
                            "viewport_width": 1440,
                            "viewport_height": 2200,
                        }
                    ],
                    "interaction_target_summary": (
                        "Detected 1 visible browser interaction target with grounded viewport coordinates: checkbox."
                    ),
                    "auto_interaction": {
                        "eligible": False,
                        "reason": "No visible clickable browser target was grounded well enough for an automatic click.",
                        "selected_target": None,
                        "click_request": None,
                        "requires_visual_review": True,
                    },
                    "surface_summary": (
                        "Captured static DOM controls: 1 checkbox input. "
                        "This tool captures a screenshot and grid overlay for visual inspection; "
                        "use browser_coordinate_click for deliberate coordinate-based interaction. "
                        "Detected 1 visible browser interaction target with grounded viewport coordinates: checkbox."
                    ),
                    "interaction_capability": {
                        "mode": "visual_capture_only",
                        "click_supported": False,
                        "reason": (
                            "This tool captures a screenshot and grid overlay for visual inspection; "
                            "use browser_coordinate_click for deliberate coordinate-based interaction."
                        ),
                    },
                    "capture_stderr": "",
                    "capture_exit_code": 0,
                },
                "assessment": {"classification": "challenge_page", "accessible": False},
                "runtime_status": {
                    "headless_dom_supported": True,
                    "automation": {
                        "visual_capture_supported": True,
                        "coordinate_click_supported": True,
                    },
                },
                "capabilities": {"python_command": "python3"},
                "artifacts": [],
                "duration_ms": 12.0,
                "body_preview": "<html><title>Are you a robot?</title></html>",
            },
            [],
        )

    monkeypatch.setattr("mcp_nexus.tools.network._http_probe_payload", fake_http_probe_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._runtime_status_snapshot", fake_runtime_status_snapshot)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_screenshot_payload", fake_browser_screenshot_payload)

    payload = await _web_page_diagnosis_payload(
        url="https://example.com/article",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout_sec=20,
        max_body_chars=5000,
        browser_profile=True,
        try_browser=True,
        wait_ms=1000,
        preferred_browser="",
    )

    assert payload["error_code"] == "WEB_ACCESS_CONTINUATION_REQUIRED"
    assert payload["error_stage"] == "continuation"
    assert payload["message"].startswith(
        "Continue with browser_fetch. Visual browser capture completed and the page still needs grounded follow-up."
    )
    assert "Detected 1 visible browser interaction target" in payload["message"]
    assert payload["feedback_loop"]["attempt_trace"][1]["browser"] == "chromium"
    assert payload["feedback_loop"]["attempt_trace"][1]["click_supported"] is False
    assert payload["feedback_loop"]["attempt_trace"][2]["tool"] == "browser_screenshot"
    assert payload["feedback_loop"]["attempt_trace"][2]["interaction_target_count"] == 1
    assert payload["workflow_handoff"]["recommended_tool"] == "browser_fetch"
    assert payload["workflow_handoff"]["next_tools"][0]["tool"] == "browser_fetch"
    assert payload["workflow_handoff"]["next_tools"][0]["alternate_tool"] == "browser_coordinate_click"
    assert payload["continuation"]["state"] == "invoke_tool"
    assert payload["continuation"]["next_step"]["tool"] == "browser_fetch"
    assert payload["continuation"]["next_step"]["alternate_tool"] == "browser_coordinate_click"
    assert payload["continuation"]["next_step"]["call_template"]["manual_click_x"] == "<grid_x>"
    assert payload["continuation"]["next_step"]["call_template"]["manual_click_y"] == "<grid_y>"


@pytest.mark.asyncio
async def test_browser_fetch_embeds_visual_followup_and_skips_screenshot_handoff(monkeypatch) -> None:
    settings = Settings()
    settings.intelligence_enabled = False
    server = create_server(settings)
    tool = server._tool_manager._tools["browser_fetch"]
    browser_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "transport": "browser_dom",
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "transfer_error": None,
            "surface_summary": "Captured no static button, input, or iframe controls in the DOM dump.",
            "interaction_capability": {"mode": "read_only_dom_dump", "click_supported": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "body_preview": "<html><title>Are you a robot?</title></html>",
        "duration_ms": 12.0,
    }
    screenshot_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Captured a browser screenshot and coordinate grid.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "viewport_width": 1440,
            "viewport_height": 2200,
            "surface_summary": (
                "Captured static DOM controls: 1 checkbox input. "
                "Detected 1 visible browser interaction target with grounded viewport coordinates: checkbox."
            ),
            "interaction_targets": [
                {
                    "type": "checkbox",
                    "label": "I am human",
                    "x": 512,
                    "y": 448,
                    "visible": True,
                }
            ],
            "auto_interaction": {
                "eligible": False,
                "reason": "Manual visual confirmation is still required.",
                "selected_target": None,
                "click_request": None,
                "requires_visual_review": True,
            },
            "interaction_capability": {
                "mode": "visual_capture_only",
                "click_supported": False,
            },
            "capture_stderr": "",
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "artifacts": [],
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, browser_payload["runtime_status"]

    async def fake_browser_screenshot_payload(**kwargs):
        return screenshot_payload, []

    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_screenshot_payload", fake_browser_screenshot_payload)

    result = await tool.fn(url="https://example.com/article")

    assert result.error_code == "WEB_ACCESS_CONTINUATION_REQUIRED"
    assert result.error_stage == "continuation"
    assert result.message.startswith(
        "Continue with browser_fetch. Visual browser capture completed and the page still needs grounded follow-up."
    )
    assert result.data["strategy"] == "browser_visual_capture"
    assert result.data["response"]["interaction_targets"][0]["type"] == "checkbox"
    assert result.data["screenshot_attempt"]["ok"] is True
    assert result.data["continuation"]["state"] == "invoke_tool"
    assert result.data["workflow_handoff"]["recommended_tool"] == "browser_fetch"
    assert result.data["workflow_handoff"]["next_tools"][0]["tool"] == "browser_fetch"
    assert result.data["workflow_handoff"]["next_tools"][0]["alternate_tool"] == "browser_coordinate_click"
    assert result.data["continuation"]["next_step"]["tool"] == "browser_fetch"
    assert result.data["continuation"]["next_step"]["alternate_tool"] == "browser_coordinate_click"
    assert result.data["feedback_loop"]["attempt_trace"][1]["tool"] == "browser_screenshot"
    assert result.data["continuation"]["surface_verification"]["surface_scope"] == "server_registry_snapshot"


@pytest.mark.asyncio
async def test_browser_fetch_manual_click_path_works_without_screenshot_tool(monkeypatch) -> None:
    settings = Settings()
    settings.intelligence_enabled = False
    server = create_server(settings)
    tool = server._tool_manager._tools["browser_fetch"]
    browser_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "transport": "browser_dom",
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "transfer_error": None,
            "surface_summary": "Captured no static button, input, or iframe controls in the DOM dump.",
            "interaction_capability": {"mode": "read_only_dom_dump", "click_supported": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "body_preview": "<html><title>Are you a robot?</title></html>",
        "duration_ms": 12.0,
    }
    click_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Performed a coordinate-based browser click and captured the post-click state.",
        "request": {"url": "https://example.com/article", "x": 512, "y": 448},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "coordinate_space": "viewport_pixels",
            "click_performed": True,
            "final_url": "https://example.com/article",
            "interaction_targets": [],
            "surface_summary": "Performed one grounded coordinate click.",
            "capture_stderr": "",
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "artifacts": [
            {"kind": "image/png", "path": "/tmp/challenge-final.png", "size_bytes": 1024},
            {"kind": "image/svg+xml", "path": "/tmp/challenge-final-grid.svg", "size_bytes": 2048},
        ],
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    screenshot_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Captured a browser screenshot and coordinate grid.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "viewport_width": 1440,
            "viewport_height": 2200,
            "interaction_targets": [],
            "surface_summary": "Detected no visible browser interaction targets with grounded viewport coordinates.",
            "capture_stderr": "",
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "artifacts": [],
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, browser_payload["runtime_status"]

    async def fake_browser_coordinate_click_payload(**kwargs):
        return click_payload, []

    async def fake_browser_screenshot_payload(**kwargs):
        return screenshot_payload, []

    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_coordinate_click_payload", fake_browser_coordinate_click_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_screenshot_payload", fake_browser_screenshot_payload)

    result = await tool.fn(
        url="https://example.com/article",
        manual_click_x=512,
        manual_click_y=448,
    )

    assert result.data["strategy"] == "browser_coordinate_click"
    assert result.data["manual_click_request"]["requested"] is True
    assert result.data["manual_click_request"]["x"] == 512
    assert result.data["manual_click_request"]["y"] == 448
    assert result.data["screenshot_attempt"] is not None
    assert result.data["interactive_attempt"]["ok"] is True
    assert result.data["continuation"]["state"] == "stop"
    assert result.error_code == "WEB_ACCESS_BLOCKED_AFTER_BROWSER_ATTEMPT"
    assert "Please indicate which visible control should be clicked next" in result.message
    assert len(result.data["interaction_attempts"]) == 1
    assert result.data["interaction_attempts"][0]["x"] == 512
    assert result.data["interaction_attempts"][0]["y"] == 448
    assert result.data["challenge_diagnostics_history"]
    assert result.data["final_visual_evidence"]["source"] == "browser_coordinate_click"
    assert result.data["final_visual_evidence"]["screenshot_path"] == "/tmp/challenge-final.png"
    assert result.data["response"]["click_performed"] is True
    assert result.data["challenge_diagnostics"]["blocked_after_click"] is True


@pytest.mark.asyncio
async def test_browser_fetch_manual_click_progresses_through_additional_grounded_candidates(monkeypatch) -> None:
    settings = Settings()
    settings.intelligence_enabled = False
    server = create_server(settings)
    tool = server._tool_manager._tools["browser_fetch"]
    browser_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "transport": "browser_dom",
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "transfer_error": None,
            "surface_summary": "Captured no static button, input, or iframe controls in the DOM dump.",
            "interaction_capability": {"mode": "read_only_dom_dump", "click_supported": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "body_preview": "<html><title>Are you a robot?</title></html>",
        "duration_ms": 12.0,
    }
    first_click_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Performed a coordinate-based browser click and captured the post-click state.",
        "request": {"url": "https://example.com/article", "x": 512, "y": 448},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "coordinate_space": "viewport_pixels",
            "click_performed": True,
            "final_url": "https://example.com/article",
            "interaction_targets": [],
            "auto_interaction": {
                "eligible": False,
                "suggested_click_request": {"x": 700, "y": 500},
                "candidate_ranking": [{"x": 700, "y": 500, "score": 0.87, "kind": "checkbox"}],
            },
            "surface_summary": "First grounded click executed; additional challenge controls remain.",
            "capture_stderr": "",
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "artifacts": [],
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    second_click_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Performed a coordinate-based browser click and captured the post-click state.",
        "request": {"url": "https://example.com/article", "x": 700, "y": 500},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "coordinate_space": "viewport_pixels",
            "click_performed": True,
            "final_url": "https://example.com/article",
            "interaction_targets": [],
            "auto_interaction": {
                "eligible": False,
                "suggested_click_request": None,
                "candidate_ranking": [],
            },
            "surface_summary": "Recovered article body.",
            "capture_stderr": "",
        },
        "assessment": {"classification": "ok", "accessible": True},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "artifacts": [],
        "body_preview": "<html><title>Recovered</title><body>Recovered article body</body></html>",
    }
    screenshot_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Captured a browser screenshot and coordinate grid.",
        "request": {"url": "https://example.com/article"},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "viewport_width": 1440,
            "viewport_height": 2200,
            "interaction_targets": [],
            "surface_summary": "Detected no visible browser interaction targets with grounded viewport coordinates.",
            "capture_stderr": "",
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {
                "visual_capture_supported": True,
                "coordinate_click_supported": True,
            },
        },
        "artifacts": [],
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }

    click_calls: list[tuple[int, int]] = []

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, browser_payload["runtime_status"]

    async def fake_browser_coordinate_click_payload(**kwargs):
        click_calls.append((int(kwargs["x"]), int(kwargs["y"])))
        if int(kwargs["x"]) == 512 and int(kwargs["y"]) == 448:
            return first_click_payload, []
        if int(kwargs["x"]) == 700 and int(kwargs["y"]) == 500:
            return second_click_payload, []
        raise AssertionError(f"Unexpected click coordinate: {(kwargs['x'], kwargs['y'])}")

    async def fake_browser_screenshot_payload(**kwargs):
        return screenshot_payload, []

    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_coordinate_click_payload", fake_browser_coordinate_click_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_screenshot_payload", fake_browser_screenshot_payload)

    result = await tool.fn(
        url="https://example.com/article",
        manual_click_x=512,
        manual_click_y=448,
    )

    assert click_calls == [(512, 448), (700, 500)]
    assert result.data["strategy"] == "browser_coordinate_click"
    assert result.data["assessment"]["accessible"] is True
    assert len(result.data["interaction_attempts"]) == 2
    assert result.data["interaction_attempts"][0]["x"] == 512
    assert result.data["interaction_attempts"][1]["x"] == 700
    assert result.data["interactive_attempt"]["assessment"]["accessible"] is True
    assert result.data["final_visual_evidence"] is None


@pytest.mark.asyncio
async def test_browser_fetch_manual_click_requires_both_coordinates(monkeypatch) -> None:
    settings = Settings()
    settings.intelligence_enabled = False
    server = create_server(settings)
    tool = server._tool_manager._tools["browser_fetch"]

    async def fail_browser_fetch_payload(**kwargs):
        raise AssertionError("browser_fetch should not run when click arguments are invalid")

    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fail_browser_fetch_payload)

    result = await tool.fn(url="https://example.com/article", manual_click_x=512)

    assert result.ok is False
    assert result.error_code == "INVALID_ARGUMENT"
    assert result.error_stage == "input_validation"
    assert result.data["request"]["manual_click_x"] == 512
    assert result.data["request"]["manual_click_y"] is None


@pytest.mark.asyncio
async def test_web_retrieval_auto_clicks_single_grounded_target(monkeypatch) -> None:
    http_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com"},
        "response": {"transport": "curl", "transfer_error": None},
        "assessment": {"classification": "challenge_page", "accessible": False},
        "retry_guidance": {"recommended_action": "try_browser_fetch"},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    browser_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com"},
        "response": {
            "transport": "browser_dom",
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "transfer_error": None,
            "surface_summary": "Captured no static button, input, or iframe controls in the DOM dump.",
            "interaction_capability": {"mode": "read_only_dom_dump", "click_supported": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    screenshot_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Captured a browser screenshot and coordinate grid.",
        "request": {"url": "https://example.com"},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "node_path": "/usr/bin/node",
            "viewport_width": 1440,
            "viewport_height": 2200,
            "metadata": {"title": "Are you a robot?"},
            "dom_observation": {"counts": {}},
            "interaction_targets": [
                {
                    "tag": "input",
                    "kind": "checkbox",
                    "input_type": "checkbox",
                    "label": "I am human",
                    "selector_hint": "input#human-check",
                    "clickable": True,
                    "visible": True,
                    "in_viewport": True,
                    "disabled": False,
                    "pointer": False,
                    "checked": False,
                    "x": 512,
                    "y": 448,
                    "width": 28,
                    "height": 28,
                    "viewport_width": 1440,
                    "viewport_height": 2200,
                }
            ],
            "interaction_target_summary": (
                "Detected 1 visible browser interaction target with grounded viewport coordinates: checkbox."
            ),
            "auto_interaction": {
                "eligible": True,
                "reason": "Exactly one high-confidence visible interaction target was detected on the blocked page.",
                "selected_target": {"kind": "checkbox", "x": 512, "y": 448},
                "click_request": {"x": 512, "y": 448},
                "requires_visual_review": False,
            },
            "surface_summary": "Detected 1 visible browser interaction target with grounded viewport coordinates: checkbox.",
            "interaction_capability": {"mode": "visual_capture_only", "click_supported": False},
        },
        "assessment": {"classification": "challenge_page", "accessible": False},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {"visual_capture_supported": True, "coordinate_click_supported": True},
        },
        "capabilities": {"python_command": "python3"},
        "artifacts": [],
        "duration_ms": 10.0,
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    click_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": "Performed a coordinate-based browser click and captured the post-click state.",
        "request": {"url": "https://example.com", "x": 512, "y": 448},
        "response": {
            "browser": "chromium",
            "browser_path": "/usr/bin/chromium",
            "node_path": "/usr/bin/node",
            "coordinate_space": "viewport_pixels",
            "click_performed": True,
            "final_url": "https://example.com/article",
            "metadata": {"title": "Recovered"},
            "dom_observation": {"counts": {}},
            "interaction_targets": [],
            "interaction_target_summary": (
                "Detected no visible browser interaction targets with grounded viewport coordinates."
            ),
            "auto_interaction": {
                "eligible": False,
                "reason": "Automatic browser interaction is reserved for blocked or challenge page states.",
                "selected_target": None,
                "click_request": None,
                "requires_visual_review": False,
            },
            "surface_summary": "Recovered article body.",
            "interaction_capability": {"mode": "coordinate_click", "click_supported": True},
            "capture_stderr": "",
        },
        "assessment": {"classification": "ok", "accessible": True},
        "runtime_status": {
            "headless_dom_supported": True,
            "automation": {"visual_capture_supported": True, "coordinate_click_supported": True},
        },
        "capabilities": {"commands": {"node": "/usr/bin/node"}},
        "artifacts": [],
        "duration_ms": 9.0,
        "body_preview": "<html><title>Recovered</title><body>Recovered article body</body></html>",
    }

    async def fake_http_probe_payload(**kwargs):
        return http_payload, {}

    async def fake_runtime_status_snapshot(*, refresh: bool = False):
        return (
            {"commands": {"curl": True, "chromium": True, "node": True}},
            {
                "commands": {"chromium": "/usr/bin/chromium", "node": "/usr/bin/node"},
                "chromium_family": {
                    "available": True,
                    "preferred": "chromium",
                    "preferred_path": "/usr/bin/chromium",
                    "candidates": [{"command": "chromium", "path": "/usr/bin/chromium"}],
                },
                "headless_dom_supported": True,
                "automation": {"visual_capture_supported": True, "coordinate_click_supported": True},
            },
        )

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, {
            "commands": {"chromium": "/usr/bin/chromium", "node": "/usr/bin/node"},
            "chromium_family": {
                "available": True,
                "preferred": "chromium",
                "preferred_path": "/usr/bin/chromium",
                "candidates": [{"command": "chromium", "path": "/usr/bin/chromium"}],
            },
            "headless_dom_supported": True,
            "automation": {"visual_capture_supported": True, "coordinate_click_supported": True},
        }

    async def fake_browser_screenshot_payload(**kwargs):
        return screenshot_payload, []

    async def fake_browser_coordinate_click_payload(**kwargs):
        assert kwargs["x"] == 512
        assert kwargs["y"] == 448
        return click_payload, []

    monkeypatch.setattr("mcp_nexus.tools.network._http_probe_payload", fake_http_probe_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._runtime_status_snapshot", fake_runtime_status_snapshot)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_screenshot_payload", fake_browser_screenshot_payload)
    monkeypatch.setattr(
        "mcp_nexus.tools.network._browser_coordinate_click_payload",
        fake_browser_coordinate_click_payload,
    )

    payload = await _web_retrieval_payload(
        url="https://example.com",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout_sec=20,
        max_body_chars=5000,
        browser_profile=True,
        try_browser=True,
        wait_ms=1000,
        preferred_browser="",
        allow_bootstrap=False,
        bootstrap_target="chromium",
        bootstrap_timeout_sec=900,
    )

    assert payload["strategy"] == "browser_coordinate_click"
    assert payload["interactive_attempt"]["assessment"]["accessible"] is True
    assert len(payload["interaction_attempts"]) == 1
    assert payload["interaction_attempts"][0]["x"] == 512
    assert payload["final_assessment"]["accessible"] is True
    assert payload["continuation"]["state"] == "stop"
    assert payload["feedback_loop"]["attempt_trace"][-1]["tool"] == "browser_coordinate_click"
    assert "grounded target" in payload["message"]


def test_browser_bootstrap_plan_builds_supported_apt_command() -> None:
    plan = _browser_bootstrap_plan("apt-get", target="chromium")

    assert plan is not None
    assert plan["package_manager"] == "apt-get"
    assert "apt-get install" in plan["command"]


@pytest.mark.asyncio
async def test_web_retrieval_bootstraps_and_uses_browser_when_runtime_missing(monkeypatch) -> None:
    http_payload = {
        "ok": False,
        "error_code": "HTTP_CHALLENGE_DETECTED",
        "error_stage": "access",
        "message": "Target returned a challenge page instead of the requested content.",
        "request": {"url": "https://example.com"},
        "response": {"transport": "curl", "transfer_error": None},
        "assessment": {"classification": "challenge_page", "accessible": False},
        "retry_guidance": {"recommended_action": "report_blocked_access"},
        "body_preview": "<html><title>Are you a robot?</title></html>",
    }
    browser_payload = {
        "ok": True,
        "error_code": None,
        "error_stage": None,
        "message": None,
        "request": {"url": "https://example.com"},
        "response": {"transport": "browser_dom", "transfer_error": None},
        "assessment": {"classification": "ok", "accessible": True},
        "body_preview": "<html><title>Article</title><body>Recovered content</body></html>",
    }

    async def fake_http_probe_payload(**kwargs):
        return http_payload, {}

    async def fake_runtime_status_snapshot(*, refresh: bool = False):
        assert refresh is False
        return {"python_command": "python3"}, {"headless_dom_supported": False}

    async def fake_bootstrap_browser_runtime(*, target: str, timeout_sec: int, refresh: bool = True):
        assert target == "chromium"
        assert refresh is True
        return {
            "ok": True,
            "error_code": None,
            "error_stage": None,
            "message": "Installed a headless browser runtime.",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "target": target,
            "already_available": False,
            "installed": True,
            "install_plan": {"target": target, "package_manager": "apt-get"},
            "runtime_status_before": {"headless_dom_supported": False},
            "runtime_status": {"headless_dom_supported": True},
            "capabilities": {"package_manager": "apt-get"},
            "duration_ms": 10.0,
        }

    async def fake_browser_fetch_payload(**kwargs):
        return browser_payload, {"headless_dom_supported": True}

    monkeypatch.setattr("mcp_nexus.tools.network._http_probe_payload", fake_http_probe_payload)
    monkeypatch.setattr("mcp_nexus.tools.network._runtime_status_snapshot", fake_runtime_status_snapshot)
    monkeypatch.setattr("mcp_nexus.tools.network._bootstrap_browser_runtime", fake_bootstrap_browser_runtime)
    monkeypatch.setattr("mcp_nexus.tools.network._browser_fetch_payload", fake_browser_fetch_payload)

    payload = await _web_retrieval_payload(
        url="https://example.com",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout_sec=20,
        max_body_chars=5000,
        browser_profile=True,
        try_browser=True,
        wait_ms=1000,
        preferred_browser="",
        allow_bootstrap=True,
        bootstrap_target="chromium",
        bootstrap_timeout_sec=900,
    )

    assert payload["strategy"] == "browser_dom_after_bootstrap"
    assert payload["bootstrap_attempt"]["installed"] is True
    assert payload["browser_attempt"]["assessment"]["accessible"] is True
    assert payload["final_assessment"]["accessible"] is True
