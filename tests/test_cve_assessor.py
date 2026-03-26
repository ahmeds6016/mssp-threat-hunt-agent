"""Tests for the CVE assessor and CVE lookup modules."""

import pytest

from mssp_hunt_agent.agent.cve_assessor import CVEAssessor
from mssp_hunt_agent.agent.models import AgentIntent
from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.intel.cve_lookup import CVEDetail, CVELookup


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="PurpleStratus",
        persist=False,
    )


# ── CVE Lookup tests ─────────────────────────────────────────────────


class TestCVELookup:
    def test_known_cve(self) -> None:
        lookup = CVELookup(use_mock=True)
        cve = lookup.fetch("CVE-2025-55182")
        assert cve.cve_id == "CVE-2025-55182"
        assert cve.severity == "critical"
        assert cve.cvss_score == 9.8
        assert "T1190" in cve.techniques
        assert cve.actively_exploited is True

    def test_unknown_cve_returns_default(self) -> None:
        lookup = CVELookup(use_mock=True)
        cve = lookup.fetch("CVE-9999-99999")
        assert cve.cve_id == "CVE-9999-99999"
        assert cve.severity == "medium"
        assert cve.cvss_score > 0

    def test_case_insensitive(self) -> None:
        lookup = CVELookup(use_mock=True)
        cve = lookup.fetch("cve-2025-55182")
        assert cve.severity == "critical"

    def test_palo_alto_cve(self) -> None:
        lookup = CVELookup(use_mock=True)
        cve = lookup.fetch("CVE-2024-3400")
        assert cve.cvss_score == 10.0
        assert "T1190" in cve.techniques
        assert cve.actively_exploited is True

    def test_cve_detail_model(self) -> None:
        cve = CVEDetail(
            cve_id="CVE-2024-0001",
            description="Test vuln",
            severity="high",
            cvss_score=8.0,
            techniques=["T1190"],
        )
        assert cve.cve_id == "CVE-2024-0001"
        data = cve.model_dump()
        assert "techniques" in data


# ── CVE Assessor tests ───────────────────────────────────────────────


class TestCVEAssessor:
    def test_assess_known_cve(self, config: HuntAgentConfig) -> None:
        assessor = CVEAssessor(config)
        response = assessor.assess("CVE-2025-55182")
        assert response.intent == AgentIntent.CVE_CHECK
        assert response.details["cve_id"] == "CVE-2025-55182"
        assert response.details["severity"] == "critical"
        assert response.details["cvss_score"] == 9.8

    def test_assess_returns_verdict(self, config: HuntAgentConfig) -> None:
        assessor = CVEAssessor(config)
        response = assessor.assess("CVE-2025-55182")
        assert response.details["verdict"] in (
            "COVERED", "PARTIALLY VULNERABLE", "ASSESSMENT INCOMPLETE"
        )

    def test_assess_has_thinking_trace(self, config: HuntAgentConfig) -> None:
        assessor = CVEAssessor(config)
        response = assessor.assess("CVE-2025-55182")
        assert len(response.thinking_trace) >= 3
        step_types = [s.step_type for s in response.thinking_trace]
        assert "planning" in step_types
        assert "synthesizing" in step_types

    def test_assess_actively_exploited(self, config: HuntAgentConfig) -> None:
        assessor = CVEAssessor(config)
        response = assessor.assess("CVE-2025-55182")
        assert response.details["in_cisa_kev"] is True
        assert "ACTIVELY EXPLOITED" in response.summary

    def test_assess_has_follow_ups(self, config: HuntAgentConfig) -> None:
        assessor = CVEAssessor(config)
        response = assessor.assess("CVE-2025-55182")
        assert len(response.follow_up_suggestions) > 0
