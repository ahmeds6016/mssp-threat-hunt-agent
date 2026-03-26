"""Tests for prompt-aware MockLLMAdapter campaign phase behavior.

Validates that the mock:
1. Detects campaign phases from system prompt keywords
2. Returns structured JSON matching phase expectations
3. Simulates multi-iteration drill-down in execute phase
4. Preserves legacy 2-iteration behavior for agent loop tests
"""

from __future__ import annotations

import json
import re

import pytest

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter


# ── Helpers ──────────────────────────────────────────────────────────

SAMPLE_TOOLS = [
    {"function": {"name": "run_kql_query", "parameters": {}}},
    {"function": {"name": "validate_kql", "parameters": {}}},
    {"function": {"name": "search_mitre", "parameters": {}}},
    {"function": {"name": "check_landscape", "parameters": {}}},
    {"function": {"name": "lookup_cve", "parameters": {}}},
    {"function": {"name": "check_telemetry", "parameters": {}}},
    {"function": {"name": "assess_risk", "parameters": {}}},
]


def _msgs(system: str, user: str = "Go", tool_results: int = 0) -> list[dict]:
    """Build a messages list for testing."""
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    for i in range(tool_results):
        msgs.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": f"call_{i}", "function": {"name": "run_kql_query", "arguments": "{}"}}],
        })
        msgs.append({"role": "tool", "tool_call_id": f"call_{i}", "content": '{"result_count": 5}'})
    return msgs


def _extract_json(content: str) -> dict | list:
    """Extract JSON from markdown code block."""
    match = re.search(r"```json\n(.*?)\n```", content, re.DOTALL)
    assert match, f"No JSON block found in: {content[:200]}"
    return json.loads(match.group(1))


# ── Phase detection ─────────────────────────────────────────────────

class TestPhaseDetection:
    def setup_method(self):
        self.mock = MockLLMAdapter()

    def test_detects_hypothesize_phase(self):
        assert self.mock._detect_phase("Generate prioritized hunt hypotheses for Acme Corp") == "hypothesize"

    def test_detects_execute_phase(self):
        assert self.mock._detect_phase("Execute hypothesis H-001. Drill-down on suspicious findings.") == "execute"

    def test_detects_conclude_phase(self):
        assert self.mock._detect_phase("Conclude the investigation. Classify findings and triage.") == "conclude"

    def test_detects_deliver_phase(self):
        assert self.mock._detect_phase("Deliver the campaign report with executive summary.") == "deliver"

    def test_no_phase_for_agent_loop(self):
        assert self.mock._detect_phase("You are an MSSP threat hunting agent.") == ""

    def test_no_phase_for_empty(self):
        assert self.mock._detect_phase("") == ""


# ── Hypothesize phase ──────────────────────────────────────────────

class TestHypothesizePhase:
    def setup_method(self):
        self.mock = MockLLMAdapter()
        self.system = "Generate prioritized hunt hypotheses for Acme Corp based on environment."

    def test_first_call_triggers_tool(self):
        msgs = _msgs(self.system)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "search_mitre"

    def test_second_call_triggers_landscape(self):
        msgs = _msgs(self.system, tool_results=1)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "check_landscape"

    def test_third_call_triggers_telemetry_check(self):
        msgs = _msgs(self.system, tool_results=2)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "check_telemetry"

    def test_fourth_call_returns_structured_hypotheses(self):
        msgs = _msgs(self.system, tool_results=3)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None
        assert result["content"] is not None

        hypotheses = _extract_json(result["content"])
        assert isinstance(hypotheses, list)
        assert len(hypotheses) == 3

        h = hypotheses[0]
        assert "hypothesis_id" in h
        assert "title" in h
        assert "mitre_techniques" in h
        assert "required_tables" in h
        assert "kql_approach" in h
        assert 0 < h["threat_likelihood"] <= 1.0
        assert 0 < h["detection_feasibility"] <= 1.0

    def test_hypothesis_has_realistic_content(self):
        msgs = _msgs(self.system, tool_results=3)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        hypotheses = _extract_json(result["content"])

        # Check that hypotheses reference real techniques
        all_techniques = []
        for h in hypotheses:
            all_techniques.extend(h.get("mitre_techniques", []))
        assert any(t.startswith("T") for t in all_techniques)

        # Check that hypotheses reference real Sentinel tables
        all_tables = []
        for h in hypotheses:
            all_tables.extend(h.get("required_tables", []))
        assert "SigninLogs" in all_tables


# ── Execute phase ──────────────────────────────────────────────────

class TestExecutePhase:
    def setup_method(self):
        self.mock = MockLLMAdapter()
        self.system = "Execute hypothesis H-001. Drill-down and pivot on suspicious findings."

    def test_iteration_1_broad_query(self):
        msgs = _msgs(self.system)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        name = result["tool_calls"][0]["function"]["name"]
        assert name == "run_kql_query"
        args = json.loads(result["tool_calls"][0]["function"]["arguments"])
        assert "SigninLogs" in args["query"]

    def test_iteration_2_drilldown(self):
        msgs = _msgs(self.system, tool_results=1)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        args = json.loads(result["tool_calls"][0]["function"]["arguments"])
        # Should drill down on specific entity
        assert "svc-mailrelay" in args["query"]

    def test_iteration_3_pivot(self):
        msgs = _msgs(self.system, tool_results=2)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        args = json.loads(result["tool_calls"][0]["function"]["arguments"])
        # Should pivot to different table
        assert "AuditLogs" in args["query"]
        assert "svc-mailrelay" in args["query"]

    def test_iteration_4_validate_kql(self):
        msgs = _msgs(self.system, tool_results=3)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "validate_kql"

    def test_iteration_5_mitre_enrichment(self):
        msgs = _msgs(self.system, tool_results=4)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "search_mitre"

    def test_final_returns_structured_findings(self):
        msgs = _msgs(self.system, tool_results=5)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None
        assert result["content"] is not None

        findings = _extract_json(result["content"])
        assert isinstance(findings, list)
        assert len(findings) >= 1

        f = findings[0]
        assert "finding_id" in f
        assert "title" in f
        assert "severity" in f
        assert "classification" in f
        assert "affected_entities" in f
        assert "evidence_queries" in f
        assert "remediation" in f
        assert f["confidence"] > 0

    def test_execute_simulates_minimum_3_queries(self):
        """Verify execute phase runs at least 3 tool calls before concluding."""
        msgs = _msgs(self.system)
        tool_calls_made = 0
        for _ in range(10):  # safety cap
            result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
            if result["tool_calls"] is None:
                break
            tool_calls_made += 1
            # Simulate adding tool result to messages
            tc = result["tool_calls"][0]
            msgs.append({"role": "assistant", "content": None, "tool_calls": [tc]})
            msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": '{"result_count": 5}'})
        assert tool_calls_made >= 3, f"Execute phase only made {tool_calls_made} tool calls"


# ── Conclude phase ─────────────────────────────────────────────────

class TestConcludePhase:
    def setup_method(self):
        self.mock = MockLLMAdapter()
        self.system = "Conclude the investigation. Classify findings and assess evidence."

    def test_first_call_searches_mitre(self):
        msgs = _msgs(self.system)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "search_mitre"

    def test_returns_structured_conclusion(self):
        msgs = _msgs(self.system, tool_results=1)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None

        conclusion = _extract_json(result["content"])
        assert "findings_summary" in conclusion
        assert "overall_assessment" in conclusion
        assert "recommendations" in conclusion
        assert conclusion["overall_assessment"]["true_positives"] >= 0


# ── Deliver phase ──────────────────────────────────────────────────

class TestDeliverPhase:
    def setup_method(self):
        self.mock = MockLLMAdapter()
        self.system = "Deliver the campaign report with executive summary."

    def test_returns_report(self):
        msgs = _msgs(self.system)
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None

        report = _extract_json(result["content"])
        assert "executive_summary" in report
        assert "findings_count" in report
        assert "top_recommendations" in report


# ── Agent loop (legacy) ───────────────────────────────────────────

class TestAgentLoopLegacy:
    """Verify non-campaign behavior is unchanged."""

    def setup_method(self):
        self.mock = MockLLMAdapter()
        self.system = "You are an MSSP threat hunting agent for Acme Corp."

    def test_cve_query_triggers_lookup(self):
        msgs = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": "Are we vulnerable to CVE-2024-3400?"},
        ]
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "lookup_cve"
        args = json.loads(result["tool_calls"][0]["function"]["arguments"])
        assert args["cve_id"] == "CVE-2024-3400"

    def test_hunt_query_triggers_kql(self):
        msgs = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": "Hunt for suspicious logins"},
        ]
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["function"]["name"] == "run_kql_query"

    def test_tool_results_produce_final_text(self):
        msgs = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": "Hunt for lateral movement"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "function": {"name": "run_kql_query", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "{}"},
        ]
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None
        assert "analysis" in result["content"].lower()

    def test_general_query_no_tools(self):
        msgs = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": "Hello, what can you do?"},
        ]
        result = self.mock.chat_with_tools(msgs, SAMPLE_TOOLS)
        assert result["tool_calls"] is None
        assert result["content"] is not None


# ── Existing methods unchanged ─────────────────────────────────────

class TestExistingMethodsUnchanged:
    """Verify analyze(), classify_intent(), generate_response() still work."""

    def setup_method(self):
        self.mock = MockLLMAdapter()

    def test_analyze_returns_findings(self):
        result = self.mock.analyze("system", "user")
        assert "findings" in result
        assert result["findings"][0]["finding_id"].startswith("F-LLM-")
        assert result["findings"][0]["description"]

    def test_analyze_evidence_source(self):
        result = self.mock.analyze("system", "user")
        assert result["evidence_items"][0]["source"] == "llm_analysis"

    def test_classify_intent_cve(self):
        result = self.mock.classify_intent("check CVE-2024-1234", ["cve_check", "run_hunt"])
        assert result["intent"] == "cve_check"

    def test_generate_response(self):
        result = self.mock.generate_response("context", {})
        assert "analysis" in result.lower()

    def test_should_fail(self):
        mock = MockLLMAdapter(should_fail=True)
        with pytest.raises(RuntimeError):
            mock.chat_with_tools([], [])
        with pytest.raises(RuntimeError):
            mock.analyze("s", "u")
