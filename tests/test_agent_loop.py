"""Tests for the agentic tool-calling loop (V6)."""

import pytest

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
from mssp_hunt_agent.agent.agent_loop import AgentLoop, AgentLoopResult, ToolCallRecord
from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS, ToolExecutor
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="TestClient",
        agent_loop_max_iterations=5,
        agent_loop_timeout_seconds=120,
    )


@pytest.fixture
def llm() -> MockLLMAdapter:
    return MockLLMAdapter()


@pytest.fixture
def executor(config: HuntAgentConfig) -> ToolExecutor:
    return ToolExecutor(config)


@pytest.fixture
def loop(config: HuntAgentConfig, llm: MockLLMAdapter, executor: ToolExecutor) -> AgentLoop:
    return AgentLoop(
        config=config,
        llm=llm,
        tool_executor=executor,
        system_prompt="You are a test agent.",
    )


# ── Basic loop execution ────────────────────────────────────────────


class TestAgentLoopBasics:
    def test_returns_agent_loop_result(self, loop: AgentLoop) -> None:
        result = loop.run("Hello, what can you do?")
        assert isinstance(result, AgentLoopResult)
        assert result.response_text
        assert result.total_iterations >= 1

    def test_general_message_no_tools(self, loop: AgentLoop) -> None:
        """A general message should get a direct response without tool calls."""
        result = loop.run("What is the meaning of life?")
        assert result.response_text
        # No tool-matching keywords → no tool calls
        assert len(result.tool_calls_made) == 0

    def test_cve_triggers_tool_call(self, loop: AgentLoop) -> None:
        """A CVE question should trigger lookup_cve tool."""
        result = loop.run("Are we vulnerable to CVE-2024-3400?")
        assert len(result.tool_calls_made) >= 1
        tool_names = [tc.tool_name for tc in result.tool_calls_made]
        assert "lookup_cve" in tool_names

    def test_hunt_triggers_kql_query(self, loop: AgentLoop) -> None:
        """A hunt request should trigger run_kql_query."""
        result = loop.run("Hunt for failed logins in the last 7 days")
        assert len(result.tool_calls_made) >= 1
        tool_names = [tc.tool_name for tc in result.tool_calls_made]
        assert "run_kql_query" in tool_names

    def test_detection_triggers_mitre_search(self, loop: AgentLoop) -> None:
        """A detection request should trigger search_mitre."""
        result = loop.run("Create a detection rule for T1059")
        assert len(result.tool_calls_made) >= 1
        tool_names = [tc.tool_name for tc in result.tool_calls_made]
        assert "search_mitre" in tool_names

    def test_risk_triggers_assess_risk(self, loop: AgentLoop) -> None:
        """A risk question should trigger assess_risk."""
        result = loop.run("What if we lose EDR?")
        assert len(result.tool_calls_made) >= 1
        tool_names = [tc.tool_name for tc in result.tool_calls_made]
        assert "assess_risk" in tool_names

    def test_landscape_triggers_check(self, loop: AgentLoop) -> None:
        """A threat landscape query should trigger check_landscape."""
        result = loop.run("What active threats can't we detect?")
        assert len(result.tool_calls_made) >= 1
        tool_names = [tc.tool_name for tc in result.tool_calls_made]
        assert "check_landscape" in tool_names


# ── Reasoning steps ─────────────────────────────────────────────────


class TestReasoningSteps:
    def test_has_reasoning_steps(self, loop: AgentLoop) -> None:
        result = loop.run("Hunt for lateral movement")
        assert len(result.reasoning_steps) > 0

    def test_tool_call_step_recorded(self, loop: AgentLoop) -> None:
        result = loop.run("Are we vulnerable to CVE-2024-3400?")
        tool_steps = [s for s in result.reasoning_steps if s.step_type == "tool_call"]
        assert len(tool_steps) >= 1

    def test_synthesizing_step_recorded(self, loop: AgentLoop) -> None:
        result = loop.run("Hello")
        synth_steps = [s for s in result.reasoning_steps if s.step_type == "synthesizing"]
        assert len(synth_steps) >= 1


# ── Tool call records ───────────────────────────────────────────────


class TestToolCallRecords:
    def test_tool_call_record_fields(self, loop: AgentLoop) -> None:
        result = loop.run("Are we vulnerable to CVE-2024-3400?")
        assert len(result.tool_calls_made) >= 1
        tc = result.tool_calls_made[0]
        assert isinstance(tc, ToolCallRecord)
        assert tc.tool_name
        assert isinstance(tc.arguments, dict)
        assert tc.duration_ms >= 0

    def test_result_preview_truncated(self, loop: AgentLoop) -> None:
        result = loop.run("Hunt for suspicious activity")
        for tc in result.tool_calls_made:
            assert len(tc.result_preview) <= 200


# ── Iteration and timeout ──────────────────────────────────────────


class TestIterationLimits:
    def test_max_iterations_respected(self, config: HuntAgentConfig) -> None:
        config.agent_loop_max_iterations = 2
        llm = MockLLMAdapter()
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=llm, tool_executor=executor,
            system_prompt="Test",
        )
        result = loop.run("Hunt for lateral movement")
        assert result.total_iterations <= 2

    def test_timeout_produces_result(self, config: HuntAgentConfig) -> None:
        config.agent_loop_timeout_seconds = 0  # Immediate timeout
        llm = MockLLMAdapter()
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=llm, tool_executor=executor,
            system_prompt="Test",
        )
        result = loop.run("Hunt for something")
        # Should still produce a result even after timeout
        assert result.response_text


# ── Error handling ──────────────────────────────────────────────────


class TestErrorHandling:
    def test_llm_failure_produces_error_step(self, config: HuntAgentConfig) -> None:
        failing_llm = MockLLMAdapter(should_fail=True)
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=failing_llm, tool_executor=executor,
            system_prompt="Test",
        )
        result = loop.run("Hunt for something")
        error_steps = [s for s in result.reasoning_steps if s.step_type == "error"]
        assert len(error_steps) >= 1

    def test_llm_failure_still_returns_text(self, config: HuntAgentConfig) -> None:
        failing_llm = MockLLMAdapter(should_fail=True)
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=failing_llm, tool_executor=executor,
            system_prompt="Test",
        )
        result = loop.run("What happened?")
        assert result.response_text  # Should have fallback text


# ── System prompt ───────────────────────────────────────────────────


class TestSystemPrompt:
    def test_system_prompt_included(self, config: HuntAgentConfig) -> None:
        llm = MockLLMAdapter()
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=llm, tool_executor=executor,
            system_prompt="You are a security expert for ACME Corp.",
        )
        result = loop.run("Hello")
        # The loop should work with a system prompt
        assert result.response_text

    def test_empty_system_prompt(self, config: HuntAgentConfig) -> None:
        llm = MockLLMAdapter()
        executor = ToolExecutor(config)
        loop = AgentLoop(
            config=config, llm=llm, tool_executor=executor,
            system_prompt="",
        )
        result = loop.run("Hello")
        assert result.response_text
