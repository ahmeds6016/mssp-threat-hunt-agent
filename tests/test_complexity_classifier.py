"""Tests for complexity classifier — GPT-5.3 routing between chat and campaign."""

from __future__ import annotations

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
from mssp_hunt_agent.agent.complexity_classifier import (
    RoutingDecision,
    classify_complexity,
)


class TestClassifyComplexity:
    """Test that the classifier routes correctly via MockLLMAdapter."""

    def setup_method(self):
        self.llm = MockLLMAdapter()

    # -- Chat routes (simple queries) --

    def test_cve_lookup_routes_to_chat(self):
        result = classify_complexity(self.llm, "Are we vulnerable to CVE-2024-3400?")
        assert result.route == "chat"

    def test_single_hunt_routes_to_chat(self):
        result = classify_complexity(self.llm, "Check for failed logins in the last 7 days")
        assert result.route == "chat"

    def test_detection_rule_routes_to_chat(self):
        result = classify_complexity(self.llm, "Create a detection rule for brute force")
        assert result.route == "chat"

    def test_risk_assessment_routes_to_chat(self):
        result = classify_complexity(self.llm, "What if we lose our EDR?")
        assert result.route == "chat"

    def test_general_question_routes_to_chat(self):
        result = classify_complexity(self.llm, "What data sources do we have?")
        assert result.route == "chat"

    def test_mitre_question_routes_to_chat(self):
        result = classify_complexity(self.llm, "What is technique T1059?")
        assert result.route == "chat"

    # -- Campaign routes (complex investigations) --

    def test_full_threat_hunt_routes_to_campaign(self):
        result = classify_complexity(self.llm, "Run a full threat hunt on our environment")
        assert result.route == "campaign"

    def test_comprehensive_investigation_routes_to_campaign(self):
        result = classify_complexity(self.llm, "Do a comprehensive security assessment")
        assert result.route == "campaign"

    def test_deep_dive_routes_to_campaign(self):
        result = classify_complexity(self.llm, "Deep dive into our ransomware exposure")
        assert result.route == "campaign"

    def test_proactive_hunt_routes_to_campaign(self):
        result = classify_complexity(self.llm, "What threats are we missing?")
        assert result.route == "campaign"

    def test_autonomous_hunt_routes_to_campaign(self):
        result = classify_complexity(self.llm, "Start an autonomous hunt for lateral movement")
        assert result.route == "campaign"

    def test_full_hunt_routes_to_campaign(self):
        result = classify_complexity(self.llm, "Run a full hunt across all data sources")
        assert result.route == "campaign"

    # -- Focus area extraction --

    def test_extracts_ransomware_focus(self):
        result = classify_complexity(self.llm, "Run a full threat hunt focused on ransomware")
        assert result.route == "campaign"
        assert "ransomware" in result.focus_areas

    def test_extracts_lateral_movement_focus(self):
        result = classify_complexity(self.llm, "Comprehensive investigation into lateral movement")
        assert "lateral movement" in result.focus_areas

    def test_extracts_credential_focus(self):
        result = classify_complexity(self.llm, "Full hunt for credential theft indicators")
        assert "credential theft" in result.focus_areas

    def test_extracts_multiple_focus_areas(self):
        result = classify_complexity(
            self.llm,
            "Run a full threat hunt for ransomware and lateral movement"
        )
        assert "ransomware" in result.focus_areas
        assert "lateral movement" in result.focus_areas

    # -- Time range extraction --

    def test_extracts_7_day_range(self):
        result = classify_complexity(self.llm, "Full threat hunt over the last 7 days")
        assert result.time_range == "last 7 days"

    def test_extracts_90_day_range(self):
        result = classify_complexity(self.llm, "Comprehensive hunt over the last 90 days")
        assert result.time_range == "last 90 days"

    def test_defaults_to_30_days(self):
        result = classify_complexity(self.llm, "Run a full threat hunt")
        assert result.time_range == "last 30 days"

    # -- Edge cases --

    def test_empty_message_routes_to_chat(self):
        result = classify_complexity(self.llm, "")
        assert result.route == "chat"

    def test_returns_confidence(self):
        result = classify_complexity(self.llm, "Are we vulnerable to CVE-2024-3400?")
        assert 0.0 <= result.confidence <= 1.0

    def test_returns_reasoning(self):
        result = classify_complexity(self.llm, "Run a full threat hunt")
        assert result.reasoning

    def test_llm_failure_defaults_to_chat(self):
        llm = MockLLMAdapter(should_fail=True)
        result = classify_complexity(llm, "Run a full threat hunt")
        assert result.route == "chat"
        assert result.confidence == 0.5


class TestRoutingDecision:
    """Test the RoutingDecision model."""

    def test_defaults(self):
        rd = RoutingDecision()
        assert rd.route == "chat"
        assert rd.confidence == 0.8
        assert rd.focus_areas == []
        assert rd.time_range == "last 30 days"
        assert rd.max_hypotheses == 10

    def test_campaign_with_focus(self):
        rd = RoutingDecision(
            route="campaign",
            focus_areas=["ransomware", "lateral movement"],
            time_range="last 14 days",
        )
        assert rd.route == "campaign"
        assert len(rd.focus_areas) == 2


class TestMockClassifierIntegration:
    """Test that MockLLMAdapter handles classifier prompts correctly."""

    def setup_method(self):
        self.llm = MockLLMAdapter()

    def test_classifier_prompt_detected(self):
        """Verify the mock detects the routing classifier system prompt."""
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": "You are a routing classifier for an MSSP threat hunting platform."},
                {"role": "user", "content": "Are we vulnerable to CVE-2024-3400?"},
            ],
            tools=[],
        )
        assert response["content"] is not None
        assert response["tool_calls"] is None
        import json
        parsed = json.loads(response["content"])
        assert "route" in parsed
        assert parsed["route"] in ("chat", "campaign")

    def test_non_classifier_prompt_not_affected(self):
        """Regular agent loop prompts should NOT trigger classifier path."""
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": "You are an MSSP threat hunting agent."},
                {"role": "user", "content": "Are we vulnerable to CVE-2024-3400?"},
            ],
            tools=[
                {"function": {"name": "lookup_cve", "parameters": {}}},
            ],
        )
        assert response["tool_calls"] is not None
        assert response["tool_calls"][0]["function"]["name"] == "lookup_cve"
