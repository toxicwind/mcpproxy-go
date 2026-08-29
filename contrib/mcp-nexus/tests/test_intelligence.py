"""Tests for the intelligence / memory engine."""

import pytest

from mcp_nexus.intelligence.memory import MemoryEngine


@pytest.fixture
def memory(tmp_path):
    engine = MemoryEngine(data_dir=str(tmp_path))
    engine.open()
    yield engine
    engine.close()


def test_init_creates_db(tmp_path):
    engine = MemoryEngine(data_dir=str(tmp_path))
    engine.open()
    assert (tmp_path / "memory.db").exists()
    engine.close()


@pytest.mark.asyncio
async def test_record_interaction(memory):
    await memory.record("read_file", {"path": "/etc/hosts"}, True, 42.0)
    ctx = await memory.get_context()
    assert ctx["recent_actions"][0]["tool"] == "read_file"
    assert ctx["recent_actions"][0]["ok"] is True
    assert ctx["recent_actions"][0]["after"]["ok"] is True


@pytest.mark.asyncio
async def test_session_tracking(memory):
    await memory.record("git_status", {"repo_path": "/app"}, True, 10.0)
    await memory.record("git_diff", {"repo_path": "/app"}, True, 15.0)

    ctx = await memory.get_context()
    assert ctx["current_session"]["tools_used"] == 2
    assert ctx["current_session"]["active"] is True


@pytest.mark.asyncio
async def test_preference_learning(memory):
    # Repeatedly use the same repo path
    for _ in range(5):
        await memory.record("git_status", {"repo_path": "/my/repo"}, True, 10.0)

    prefs = await memory.get_preferences()
    assert "arg:repo_path" in prefs
    assert prefs["arg:repo_path"]["value"] == "/my/repo"
    assert prefs["arg:repo_path"]["confidence"] >= 0.9


@pytest.mark.asyncio
async def test_tool_sequences(memory):
    await memory.record("git_status", {}, True, 5.0)
    await memory.record("git_diff", {}, True, 5.0)
    await memory.record("git_commit", {}, True, 5.0)

    suggestions = await memory.suggest_next("git_status")
    assert len(suggestions) >= 1
    assert suggestions[0]["tool"] == "git_diff"


@pytest.mark.asyncio
async def test_insights(memory):
    await memory.record("read_file", {"path": "/a"}, True, 10.0)
    await memory.record("read_file", {"path": "/b"}, True, 12.0)
    await memory.record("execute_command", {"command": "ls"}, True, 5.0)
    await memory.record("git_status", {}, False, 100.0)

    insights = await memory.get_insights()
    assert insights["totals"]["interactions"] == 4
    assert insights["totals"]["errors"] == 1
    assert "read_file" in insights["top_tools"]
    assert insights["top_tools"]["read_file"] == 2
    assert insights["learning"]["model"]["type"] == "online_softmax_ranker"


@pytest.mark.asyncio
async def test_manual_preference(memory):
    await memory.set_preference("default_repo", "/my/custom/repo")
    prefs = await memory.get_preferences()
    assert prefs["default_repo"]["value"] == "/my/custom/repo"
    assert prefs["default_repo"]["confidence"] == 1.0


@pytest.mark.asyncio
async def test_clear_memory(memory):
    await memory.record("read_file", {"path": "/x"}, True, 5.0)
    await memory.clear()

    ctx = await memory.get_context()
    assert ctx.get("recent_actions") is None or len(ctx.get("recent_actions", [])) == 0
    insights = await memory.get_insights()
    assert insights.get("totals", {}).get("interactions", 0) == 0


@pytest.mark.asyncio
async def test_error_tracking(memory):
    await memory.record("db_query", {"query": "SELECT 1"}, False, 500.0)
    ctx = await memory.get_context()
    assert len(ctx["recent_errors"]) == 1
    assert ctx["recent_errors"][0]["tool"] == "db_query"


@pytest.mark.asyncio
async def test_context_exposes_short_and_long_term_memory(memory):
    await memory.record("git_status", {"repo_path": "/srv/app"}, True, 11.0)
    await memory.record("git_diff", {"repo_path": "/srv/app"}, True, 9.0)

    ctx = await memory.get_context()
    assert ctx["short_term_memory"]["recent_actions"][0]["tool"] == "git_diff"
    assert ctx["short_term_memory"]["recent_actions"][0]["before"]["previous_tool"] == "git_status"
    assert "arg:repo_path" in ctx["long_term_memory"]["preferences"]
    assert ctx["long_term_memory"]["learning"]["model"]["type"] == "online_softmax_ranker"


@pytest.mark.asyncio
async def test_suggestions_downrank_unreliable_transitions(memory):
    for _ in range(4):
        await memory.record("git_status", {}, True, 5.0)
        await memory.record("git_diff", {}, True, 5.0)
        await memory.record("git_status", {}, True, 5.0)
        await memory.record("git_push", {}, False, 5.0)

    suggestions = await memory.suggest_next("git_status")
    assert suggestions[0]["tool"] == "git_diff"
    by_tool = {item["tool"]: item for item in suggestions}
    assert by_tool["git_diff"]["expected_success_rate"] > by_tool["git_push"]["expected_success_rate"]


@pytest.mark.asyncio
async def test_workflows(memory):
    # Build up a consistent pattern
    for _ in range(4):
        await memory.record("git_status", {}, True, 5.0)
        await memory.record("git_diff", {}, True, 5.0)
        await memory.record("git_commit", {}, True, 5.0)

    workflows = await memory.get_workflows()
    assert len(workflows) >= 1
    # Should detect git_status -> git_diff -> git_commit chain
    chains = [w["chain"] for w in workflows]
    assert any("git_status" in c and "git_diff" in c for c in chains)
