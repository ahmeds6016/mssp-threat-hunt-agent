"""Tests for V7 BudgetTracker and ContextManager."""

from __future__ import annotations

import time

import pytest

from mssp_hunt_agent.hunter.budget import BudgetExhausted, BudgetTracker
from mssp_hunt_agent.hunter.context import ContextManager
from mssp_hunt_agent.hunter.models.campaign import CampaignConfig


# ── Budget Tracker Tests ───────────────────────────────────────────


@pytest.fixture
def budget_config() -> CampaignConfig:
    return CampaignConfig(
        client_name="TestCorp",
        max_total_queries=10,
        max_llm_tokens=50_000,
        max_duration_minutes=1,  # 60 seconds
    )


@pytest.fixture
def budget(budget_config: CampaignConfig) -> BudgetTracker:
    return BudgetTracker(budget_config)


class TestBudgetTracker:
    def test_initial_state(self, budget: BudgetTracker):
        assert budget.queries_remaining == 10
        assert budget.tokens_remaining == 50_000
        assert budget.can_query() is True
        assert budget.can_call_llm() is True

    def test_record_query(self, budget: BudgetTracker):
        budget.record_query(3)
        assert budget.queries_remaining == 7

    def test_record_llm_tokens(self, budget: BudgetTracker):
        budget.record_llm_tokens(20_000)
        assert budget.tokens_remaining == 30_000

    def test_record_tool_call(self, budget: BudgetTracker):
        budget.record_tool_call(5)
        snap = budget.snapshot()
        assert snap["tool_calls"] == 5

    def test_query_budget_exhaustion(self, budget: BudgetTracker):
        budget.record_query(10)
        assert budget.can_query() is False
        assert budget.queries_remaining == 0

    def test_token_budget_exhaustion(self, budget: BudgetTracker):
        budget.record_llm_tokens(50_000)
        assert budget.can_call_llm() is False

    def test_can_call_llm_with_estimate(self, budget: BudgetTracker):
        budget.record_llm_tokens(48_000)
        assert budget.can_call_llm(estimated_tokens=1000) is True
        assert budget.can_call_llm(estimated_tokens=5000) is False

    def test_check_or_raise_queries(self, budget: BudgetTracker):
        budget.record_query(10)
        with pytest.raises(BudgetExhausted, match="Query budget"):
            budget.check_or_raise()

    def test_check_or_raise_tokens(self, budget: BudgetTracker):
        budget.record_llm_tokens(50_000)
        with pytest.raises(BudgetExhausted, match="Token budget"):
            budget.check_or_raise()

    def test_check_or_raise_ok(self, budget: BudgetTracker):
        budget.record_query(5)
        budget.record_llm_tokens(25_000)
        budget.check_or_raise()  # Should not raise

    def test_snapshot(self, budget: BudgetTracker):
        budget.record_query(3)
        budget.record_llm_tokens(10_000)
        budget.record_tool_call(7)
        snap = budget.snapshot()
        assert snap["queries_used"] == 3
        assert snap["queries_remaining"] == 7
        assert snap["tokens_used"] == 10_000
        assert snap["tokens_remaining"] == 40_000
        assert snap["tool_calls"] == 7
        assert snap["elapsed_seconds"] >= 0

    def test_time_budget_immediate(self):
        """With 0-minute budget, time should expire quickly."""
        config = CampaignConfig(client_name="X", max_duration_minutes=0)
        b = BudgetTracker(config)
        assert b.is_time_expired is True
        assert b.can_query() is False

    def test_elapsed_seconds(self, budget: BudgetTracker):
        assert budget.elapsed_seconds >= 0
        assert budget.elapsed_seconds < 5  # Should be nearly instant


# ── Context Manager Tests ──────────────────────────────────────────


@pytest.fixture
def ctx() -> ContextManager:
    return ContextManager(max_tokens=100_000, compression_threshold=200, keep_recent=3)


class TestContextManager:
    def test_estimate_tokens_empty(self, ctx: ContextManager):
        assert ctx.estimate_tokens([]) == 0

    def test_estimate_tokens_content(self, ctx: ContextManager):
        msgs = [{"role": "user", "content": "a" * 400}]
        tokens = ctx.estimate_tokens(msgs)
        assert tokens == 100  # 400 chars / 4

    def test_estimate_tokens_with_tool_calls(self, ctx: ContextManager):
        msgs = [
            {"role": "assistant", "content": "thinking", "tool_calls": [{"function": {"name": "test", "arguments": "{}"}}]},
        ]
        tokens = ctx.estimate_tokens(msgs)
        assert tokens > 0

    def test_should_compress_false(self, ctx: ContextManager):
        msgs = [{"role": "user", "content": "short"}]
        assert ctx.should_compress(msgs) is False

    def test_should_compress_true(self, ctx: ContextManager):
        # 200 token threshold = 800 chars
        msgs = [{"role": "user", "content": "x" * 1000}]
        assert ctx.should_compress(msgs) is True

    def test_compress_keeps_system_prompt(self, ctx: ContextManager):
        messages = [
            {"role": "system", "content": "You are a hunter."},
            {"role": "user", "content": "Start hunt"},
            {"role": "assistant", "content": "Calling tool..."},
            {"role": "tool", "tool_call_id": "1", "content": "result1"},
            {"role": "assistant", "content": "Analyzing..."},
            {"role": "tool", "tool_call_id": "2", "content": "result2"},
            {"role": "assistant", "content": "Found something"},
            {"role": "user", "content": "Continue"},
        ]
        compressed = ctx.compress(messages, "Summary of observations")
        # System prompt + compression summary + recent (extended to avoid orphaned tool msgs)
        assert compressed[0]["role"] == "system"
        assert compressed[0]["content"] == "You are a hunter."
        assert "COMPRESSED CONTEXT" in compressed[1]["content"]
        # The split extends backward past orphaned tool messages, so recent count may be >3
        assert len(compressed) >= 5
        # Last message should always be the most recent
        assert compressed[-1]["content"] == "Continue"

    def test_compress_short_messages_unchanged(self, ctx: ContextManager):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "hello"},
        ]
        compressed = ctx.compress(messages, "summary")
        assert compressed == messages  # Too few messages to compress

    def test_compress_preserves_recent(self, ctx: ContextManager):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "old msg 1"},
            {"role": "assistant", "content": "old reply"},
            {"role": "user", "content": "old msg 2"},
            {"role": "assistant", "content": "old reply 2"},
            {"role": "user", "content": "recent 1"},
            {"role": "assistant", "content": "recent 2"},
            {"role": "user", "content": "recent 3"},
        ]
        compressed = ctx.compress(messages, "summary")
        recent_contents = [m["content"] for m in compressed[-3:]]
        assert "recent 1" in recent_contents
        assert "recent 3" in recent_contents

    def test_compress_avoids_orphaned_tool_messages(self, ctx: ContextManager):
        """Compression must not start with a tool message (no preceding assistant+tool_calls)."""
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "start"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "tc1", "function": {"name": "search_mitre", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "tc1", "content": "mitre result"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "tc2", "function": {"name": "run_kql", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "tc2", "content": "kql result"},
            {"role": "assistant", "content": "Final analysis"},
        ]
        compressed = ctx.compress(messages, "summary")
        # The first non-system message after the summary must NOT be a tool message
        non_system = [m for m in compressed if m["role"] not in ("system",)]
        if non_system:
            assert non_system[0]["role"] != "tool", "First kept message after system should not be orphaned tool"

    def test_build_compression_prompt(self, ctx: ContextManager):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "tool", "content": "SigninLogs returned 42 results"},
            {"role": "assistant", "content": "I see suspicious activity from IP 1.2.3.4"},
            {"role": "tool", "content": "SecurityEvent returned 0 results"},
        ]
        prompt = ctx.build_compression_prompt(messages)
        assert "Summarize" in prompt
        assert "42 results" in prompt
        assert "suspicious activity" in prompt

    def test_build_compression_prompt_truncates_long_tool_results(self, ctx: ContextManager):
        messages = [
            {"role": "tool", "content": "x" * 1000},
        ]
        prompt = ctx.build_compression_prompt(messages)
        assert "..." in prompt

    def test_compression_reduces_tokens(self, ctx: ContextManager):
        messages = [
            {"role": "system", "content": "system prompt"},
        ]
        # Add many tool results
        for i in range(20):
            messages.append({"role": "assistant", "content": f"Calling tool {i}"})
            messages.append({"role": "tool", "content": f"Result {i}: " + "data " * 50})

        before = ctx.estimate_tokens(messages)
        compressed = ctx.compress(messages, "Summary of 20 tool calls")
        after = ctx.estimate_tokens(compressed)
        assert after < before
