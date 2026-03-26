"""Tests for the agent controller and action router."""

import pytest

from mssp_hunt_agent.agent.controller import AgentController
from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="PurpleStratus",
        agent_enabled=True,
        agent_thinking_visible=True,
        persist=False,
    )


@pytest.fixture
def controller(config: HuntAgentConfig) -> AgentController:
    return AgentController(config=config)


# ── Basic controller tests ───────────────────────────────────────────


class TestControllerBasics:
    def test_empty_message(self, controller: AgentController) -> None:
        response = controller.process("")
        assert response.error == "empty_message"

    def test_returns_agent_response(self, controller: AgentController) -> None:
        response = controller.process("Hello")
        assert isinstance(response, AgentResponse)

    def test_general_question_fallback(self, controller: AgentController) -> None:
        response = controller.process("What is the meaning of life?")
        assert response.intent == AgentIntent.GENERAL_QUESTION

    def test_thinking_trace_present(self, controller: AgentController) -> None:
        response = controller.process("Hunt for lateral movement")
        assert len(response.thinking_trace) > 0
        assert response.thinking_trace[0].step_type == "planning"

    def test_thinking_hidden_when_disabled(self, config: HuntAgentConfig) -> None:
        config.agent_thinking_visible = False
        ctrl = AgentController(config=config)
        response = ctrl.process("Hunt for lateral movement")
        # Thinking trace from controller's planning step should not be present
        # (only action router's own traces may remain)
        planning_steps = [s for s in response.thinking_trace if s.description.startswith("Classified")]
        assert len(planning_steps) == 0


# ── Hunt action tests ────────────────────────────────────────────────


class TestHuntAction:
    def test_hunt_returns_run_id(self, controller: AgentController) -> None:
        response = controller.process("Hunt for lateral movement")
        assert response.intent == AgentIntent.RUN_HUNT
        assert response.run_id.startswith("RUN-")

    def test_hunt_uses_default_client(self, controller: AgentController) -> None:
        response = controller.process("Hunt for privilege escalation")
        assert "PurpleStratus" in response.details.get("client", "")

    def test_hunt_has_follow_ups(self, controller: AgentController) -> None:
        response = controller.process("Investigate suspicious authentication")
        assert len(response.follow_up_suggestions) > 0


# ── IOC sweep action tests ──────────────────────────────────────────


class TestIOCSweepAction:
    def test_ip_sweep(self, controller: AgentController) -> None:
        response = controller.process("Check if 203.0.113.77 is in our logs")
        assert response.intent == AgentIntent.IOC_SWEEP
        assert response.run_id.startswith("RUN-IOC")

    def test_no_iocs_error(self, controller: AgentController) -> None:
        response = controller.process("Run an IOC sweep")
        assert response.error == "no_iocs"

    def test_sweep_count_in_details(self, controller: AgentController) -> None:
        response = controller.process("Sweep for 1.2.3.4 and 5.6.7.8")
        assert response.details.get("ioc_count", 0) >= 2


# ── CVE check action tests ──────────────────────────────────────────


class TestCVECheckAction:
    def test_cve_assessment(self, controller: AgentController) -> None:
        response = controller.process("Are we vulnerable to CVE-2025-55182?")
        assert response.intent == AgentIntent.CVE_CHECK
        assert "CVE-2025-55182" in response.details.get("cve_id", "")

    def test_cve_has_verdict(self, controller: AgentController) -> None:
        response = controller.process("Are we vulnerable to CVE-2025-55182?")
        assert response.details.get("verdict") in (
            "COVERED", "PARTIALLY VULNERABLE", "ASSESSMENT INCOMPLETE"
        )

    def test_cve_no_id_error(self, controller: AgentController) -> None:
        response = controller.process("Are we vulnerable to the latest exploit?")
        # Should still match CVE_CHECK intent but may not have a CVE entity
        # depending on patterns; if no CVE found, error is returned
        if response.intent == AgentIntent.CVE_CHECK:
            assert response.error == "no_cve" or response.details.get("cve_id")

    def test_cve_thinking_trace(self, controller: AgentController) -> None:
        response = controller.process("Check CVE-2025-55182")
        step_types = [s.step_type for s in response.thinking_trace]
        assert "planning" in step_types


# ── Telemetry profile action tests ───────────────────────────────────


class TestTelemetryProfileAction:
    def test_profile_started(self, controller: AgentController) -> None:
        response = controller.process("What telemetry do we have?")
        assert response.intent == AgentIntent.TELEMETRY_PROFILE
        assert response.run_id.startswith("RUN-PROF")


# ── Threat model action tests ───────────────────────────────────────


class TestThreatModelAction:
    def test_attack_paths(self, controller: AgentController) -> None:
        response = controller.process("What are our attack paths?")
        assert response.intent == AgentIntent.THREAT_MODEL
        assert response.details.get("path_count", 0) > 0


# ── Risk assessment action tests ─────────────────────────────────────


class TestRiskAssessmentAction:
    def test_risk_if_lose_edr(self, controller: AgentController) -> None:
        response = controller.process("What if we lose EDR?")
        assert response.intent == AgentIntent.RISK_ASSESSMENT
        assert "risk_rating" in response.details


# ── Detection rule action tests ──────────────────────────────────────


class TestDetectionRuleAction:
    def test_generate_detection(self, controller: AgentController) -> None:
        response = controller.process("Create a detection for T1059")
        assert response.intent == AgentIntent.DETECTION_RULE
        assert "kql_query" in response.details


# ── Landscape check action tests ────────────────────────────────────


class TestLandscapeCheckAction:
    def test_active_threats(self, controller: AgentController) -> None:
        response = controller.process("Any active threats we can't detect?")
        assert response.intent == AgentIntent.LANDSCAPE_CHECK


# ── Status / report action tests ────────────────────────────────────


class TestStatusAction:
    def test_status_no_run_id(self, controller: AgentController) -> None:
        response = controller.process("How is the hunt going?")
        # Without a run ID, should still try to handle
        assert response.intent in (AgentIntent.HUNT_STATUS, AgentIntent.GENERAL_QUESTION)

    def test_status_not_found(self, controller: AgentController) -> None:
        response = controller.process("What's the status of RUN-doesnotexist?")
        assert response.intent == AgentIntent.HUNT_STATUS
        assert "not_found" in response.error or "not found" in response.summary.lower()


class TestReportAction:
    def test_report_no_run_id(self, controller: AgentController) -> None:
        response = controller.process("Give me an executive summary")
        assert response.intent == AgentIntent.GENERATE_REPORT
