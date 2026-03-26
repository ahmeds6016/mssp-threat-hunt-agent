"""Tests for chain-of-thought reasoning and LLM-enhanced agent."""

import pytest

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
from mssp_hunt_agent.agent.chain_of_thought import ReasoningChain
from mssp_hunt_agent.agent.controller import AgentController
from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse
from mssp_hunt_agent.agent.response_formatter import format_response
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="PurpleStratus",
        agent_enabled=True,
        agent_thinking_visible=True,
        agent_max_chain_steps=10,
        agent_llm_fallback=True,
        llm_enabled=False,
        persist=False,
    )


@pytest.fixture
def mock_llm() -> MockLLMAdapter:
    return MockLLMAdapter()


@pytest.fixture
def failing_llm() -> MockLLMAdapter:
    return MockLLMAdapter(should_fail=True)


# ── ReasoningChain tests ─────────────────────────────────────────────


class TestReasoningChain:
    def test_process_returns_response(self, config: HuntAgentConfig, mock_llm: MockLLMAdapter) -> None:
        chain = ReasoningChain(config=config, llm=mock_llm)
        response = chain.process("Hunt for lateral movement")
        assert isinstance(response, AgentResponse)
        assert response.intent == AgentIntent.RUN_HUNT

    def test_thinking_trace_has_steps(self, config: HuntAgentConfig, mock_llm: MockLLMAdapter) -> None:
        chain = ReasoningChain(config=config, llm=mock_llm)
        response = chain.process("Hunt for lateral movement")
        assert len(response.thinking_trace) >= 2
        step_types = [s.step_type for s in response.thinking_trace]
        assert "planning" in step_types

    def test_llm_enhances_response(self, config: HuntAgentConfig, mock_llm: MockLLMAdapter) -> None:
        chain = ReasoningChain(config=config, llm=mock_llm)
        response = chain.process("Are we vulnerable to CVE-2025-55182?")
        # LLM should enhance the summary
        assert "analysis" in response.summary.lower() or "evidence" in response.summary.lower()

    def test_works_without_llm(self, config: HuntAgentConfig) -> None:
        chain = ReasoningChain(config=config, llm=None)
        response = chain.process("Hunt for privilege escalation")
        assert response.intent == AgentIntent.RUN_HUNT
        assert response.run_id.startswith("RUN-")

    def test_max_steps_limit(self, config: HuntAgentConfig, mock_llm: MockLLMAdapter) -> None:
        config.agent_max_chain_steps = 2
        chain = ReasoningChain(config=config, llm=mock_llm)
        response = chain.process("Hunt for lateral movement")
        # Steps should be limited
        chain_steps = [s for s in response.thinking_trace if s.step_type in ("planning", "result")]
        assert len(chain_steps) <= 4  # 2 from chain + possible action steps

    def test_llm_fallback_on_failure(self, config: HuntAgentConfig, failing_llm: MockLLMAdapter) -> None:
        chain = ReasoningChain(config=config, llm=failing_llm)
        # Should still return a valid response (rule-based fallback)
        response = chain.process("Hunt for lateral movement")
        assert isinstance(response, AgentResponse)
        # Error step should be in thinking trace
        error_steps = [s for s in response.thinking_trace if s.step_type == "error"]
        assert len(error_steps) > 0


# ── Controller with LLM tests ───────────────────────────────────────


class TestControllerWithLLM:
    def test_controller_uses_chain_when_llm_provided(
        self, config: HuntAgentConfig, mock_llm: MockLLMAdapter
    ) -> None:
        controller = AgentController(config=config, llm=mock_llm)
        response = controller.process("Hunt for lateral movement")
        assert isinstance(response, AgentResponse)
        # Should have chain-of-thought steps
        assert len(response.thinking_trace) >= 2

    def test_controller_falls_back_without_llm(self, config: HuntAgentConfig) -> None:
        controller = AgentController(config=config, llm=None)
        response = controller.process("Hunt for lateral movement")
        assert isinstance(response, AgentResponse)
        assert response.run_id.startswith("RUN-")

    def test_controller_auto_builds_mock_llm(self, config: HuntAgentConfig) -> None:
        config.llm_enabled = True
        config.adapter_mode = "mock"
        controller = AgentController(config=config)
        assert controller.llm is not None

    def test_controller_no_llm_when_disabled(self, config: HuntAgentConfig) -> None:
        config.llm_enabled = False
        controller = AgentController(config=config)
        assert controller.llm is None


# ── Response formatter tests ─────────────────────────────────────────


class TestResponseFormatter:
    def test_format_basic_response(self) -> None:
        response = AgentResponse(
            summary="Hunt started.",
            intent=AgentIntent.RUN_HUNT,
            confidence=0.9,
            run_id="RUN-abc123",
        )
        text = format_response(response)
        assert "Hunt started" in text

    def test_format_cve_response(self) -> None:
        response = AgentResponse(
            summary="PARTIALLY VULNERABLE",
            intent=AgentIntent.CVE_CHECK,
            confidence=0.9,
            details={
                "verdict": "PARTIALLY VULNERABLE",
                "in_cisa_kev": True,
                "coverage": {"T1190": "covered", "T1059.001": "gap"},
                "gaps": ["T1059.001"],
                "recommendations": ["Add detection for T1059.001"],
            },
        )
        text = format_response(response)
        assert "PARTIALLY VULNERABLE" in text
        assert "ACTIVELY EXPLOITED" in text
        assert "T1059.001" in text

    def test_format_with_follow_ups(self) -> None:
        response = AgentResponse(
            summary="Profile started.",
            intent=AgentIntent.TELEMETRY_PROFILE,
            follow_up_suggestions=["Check status", "Generate report"],
        )
        text = format_response(response)
        assert "You can also try" in text
        assert "Check status" in text

    def test_format_risk_response(self) -> None:
        response = AgentResponse(
            summary="Risk assessment complete.",
            intent=AgentIntent.RISK_ASSESSMENT,
            details={
                "risk_rating": "high",
                "blind_spots": ["T1059", "T1021"],
                "recommendations": ["Enable process logging"],
            },
        )
        text = format_response(response)
        assert "HIGH" in text
        assert "T1059" in text
