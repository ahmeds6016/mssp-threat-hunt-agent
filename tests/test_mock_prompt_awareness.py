"""Tests for MockLLMAdapter prompt-awareness — verifies campaign phases
extract context from system prompts and produce grounded responses."""

from __future__ import annotations

import json
import re

import pytest

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter


class TestExecutePromptAwareness:
    """Execute phase should extract tables, entities, techniques from system prompt."""

    def setup_method(self):
        self.llm = MockLLMAdapter()
        self.tools = [
            {"function": {"name": "run_kql_query", "parameters": {}}},
            {"function": {"name": "validate_kql", "parameters": {}}},
            {"function": {"name": "search_mitre", "parameters": {}}},
        ]

    def _make_execute_prompt(self, tables=None, entity=None, techniques=None, time_range="30 days"):
        """Build a system prompt that looks like what the execute phase produces."""
        tables = tables or ["DeviceEvents", "DeviceProcessEvents"]
        entity = entity or "admin@testcorp.com"
        techniques = techniques or ["T1059", "T1059.001"]
        return (
            f"You are executing a hunt hypothesis. Drill-down and pivot on findings.\n"
            f"Minimum 3 queries before concluding.\n"
            f"Hypothesis: Suspicious process execution on endpoints\n"
            f'"required_tables": {json.dumps(tables)}\n'
            f'"mitre_techniques": {json.dumps(techniques)}\n'
            f"Admin user: {entity}\n"
            f"Time range: last {time_range}\n"
        )

    def test_extracts_primary_table(self):
        """First query should use the primary table from hypothesis."""
        prompt = self._make_execute_prompt(tables=["DeviceProcessEvents", "DeviceEvents"])
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": "Execute this hypothesis"},
            ],
            tools=self.tools,
        )
        assert response["tool_calls"] is not None
        query = json.loads(response["tool_calls"][0]["function"]["arguments"])["query"]
        assert "DeviceProcessEvents" in query

    def test_extracts_pivot_table(self):
        """Third query (pivot) should use secondary table."""
        prompt = self._make_execute_prompt(tables=["SigninLogs", "OfficeActivity"])
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Execute"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "function": {"name": "run_kql_query"}}]},
            {"role": "tool", "content": '{"results": [{"UserPrincipalName": "suspect@test.com"}]}', "tool_call_id": "1"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "2", "function": {"name": "run_kql_query"}}]},
            {"role": "tool", "content": '{"results": [{"IP": "10.0.0.5"}]}', "tool_call_id": "2"},
        ]
        response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
        assert response["tool_calls"] is not None
        query = json.loads(response["tool_calls"][0]["function"]["arguments"])["query"]
        assert "OfficeActivity" in query

    def test_extracts_time_range(self):
        """Query should use time range from the prompt."""
        prompt = self._make_execute_prompt(time_range="14 days")
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": "Execute"},
            ],
            tools=self.tools,
        )
        query = json.loads(response["tool_calls"][0]["function"]["arguments"])["query"]
        assert "ago(14d)" in query

    def test_extracts_entity_from_tool_results(self):
        """Second query should drill down on entity found in first query's results."""
        prompt = self._make_execute_prompt()
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Execute"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "function": {"name": "run_kql_query"}}]},
            {"role": "tool", "content": '{"results": [{"UserPrincipalName": "compromised@evil.com", "count_": 500}]}', "tool_call_id": "1"},
        ]
        response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
        query = json.loads(response["tool_calls"][0]["function"]["arguments"])["query"]
        assert "compromised@evil.com" in query

    def test_extracts_techniques(self):
        """Final findings should include techniques from the hypothesis."""
        prompt = self._make_execute_prompt(techniques=["T1059", "T1059.001", "T1569.002"])
        # Build 4+ iterations to reach the final findings JSON
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Execute"},
        ]
        # Simulate 4 tool call + result pairs
        for i in range(5):
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": str(i), "function": {"name": "run_kql_query"}}]})
            messages.append({"role": "tool", "content": '{"results": []}', "tool_call_id": str(i)})

        response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
        # Should return structured findings (not tool call)
        assert response["tool_calls"] is None
        assert response["content"] is not None
        findings = json.loads(response["content"].strip("`\njson "))
        assert findings[0]["mitre_techniques"][0] == "T1059"

    def test_minimum_queries_enforced(self):
        """Mock should produce at least 3 tool calls before final JSON (matching prompt rules)."""
        prompt = self._make_execute_prompt()
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Execute"},
        ]

        tool_call_count = 0
        for _ in range(10):
            response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
            if response["tool_calls"]:
                tool_call_count += 1
                tc = response["tool_calls"][0]
                messages.append({"role": "assistant", "content": None, "tool_calls": [tc]})
                messages.append({"role": "tool", "content": '{"results": []}', "tool_call_id": tc["id"]})
            else:
                break

        assert tool_call_count >= 3, f"Expected at least 3 queries, got {tool_call_count}"

    def test_final_findings_have_entity_and_tables(self):
        """Final structured findings should reference extracted tables and entities."""
        prompt = self._make_execute_prompt(
            tables=["OfficeActivity", "AzureActivity"],
            entity="attacker@badcorp.com",
        )
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Execute"},
        ]
        for i in range(6):
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": str(i), "function": {"name": "run_kql_query"}}]})
            messages.append({"role": "tool", "content": '{"results": []}', "tool_call_id": str(i)})

        response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
        content = response["content"]
        findings = json.loads(content.strip("`\njson "))
        finding = findings[0]
        assert "OfficeActivity" in finding["tables_queried"]
        assert "AzureActivity" in finding["tables_queried"]
        assert "attacker@badcorp.com" in finding["affected_entities"][0]["value"]


class TestHypothesizePromptAwareness:
    """Hypothesize phase should extract available tables and MITRE gaps."""

    def setup_method(self):
        self.llm = MockLLMAdapter()
        self.tools = [
            {"function": {"name": "search_mitre", "parameters": {}}},
            {"function": {"name": "check_landscape", "parameters": {}}},
            {"function": {"name": "check_telemetry", "parameters": {}}},
        ]

    def _make_hypothesize_prompt(self, tables=None, gaps=None):
        tables = tables or ["OfficeActivity", "AzureActivity", "DeviceEvents"]
        gaps = gaps or ["T1566", "T1566.001"]
        table_json = json.dumps([{"table": t, "row_count_7d": 1000} for t in tables])
        return (
            f"Generate prioritized hunt hypotheses.\n"
            f"Table profiles: {table_json}\n"
            f"MITRE gaps: {json.dumps(gaps)}\n"
        )

    def test_uses_mitre_gap_for_first_query(self):
        """First MITRE search should use a gap technique from the prompt."""
        prompt = self._make_hypothesize_prompt(gaps=["T1566", "T1190"])
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": "Generate hypotheses"},
            ],
            tools=self.tools,
        )
        assert response["tool_calls"] is not None
        args = json.loads(response["tool_calls"][0]["function"]["arguments"])
        assert args["query"] == "T1566"

    def test_hypotheses_use_extracted_tables(self):
        """Final hypotheses should reference tables from the environment."""
        prompt = self._make_hypothesize_prompt(tables=["EmailEvents", "CloudAppEvents", "DeviceNetworkEvents"])
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Generate"},
        ]
        # Simulate 3 tool iterations
        for i in range(3):
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": str(i), "function": {"name": "search_mitre"}}]})
            messages.append({"role": "tool", "content": '{"techniques": []}', "tool_call_id": str(i)})

        response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
        assert response["tool_calls"] is None
        hypotheses = json.loads(response["content"].strip("`\njson "))
        # First hypothesis should use EmailEvents as primary table
        assert "EmailEvents" in hypotheses[0]["required_tables"]

    def test_produces_three_tool_calls_before_final(self):
        """Hypothesize phase should call search_mitre, check_landscape, check_telemetry."""
        prompt = self._make_hypothesize_prompt()
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Generate"},
        ]
        tool_names_called = []
        for _ in range(5):
            response = self.llm.chat_with_tools(messages=messages, tools=self.tools)
            if response["tool_calls"]:
                name = response["tool_calls"][0]["function"]["name"]
                tool_names_called.append(name)
                tc = response["tool_calls"][0]
                messages.append({"role": "assistant", "content": None, "tool_calls": [tc]})
                messages.append({"role": "tool", "content": '{}', "tool_call_id": tc["id"]})
            else:
                break

        assert len(tool_names_called) >= 2
        assert "search_mitre" in tool_names_called


class TestConcludePromptAwareness:
    """Conclude phase should extract techniques for MITRE enrichment."""

    def setup_method(self):
        self.llm = MockLLMAdapter()
        self.tools = [
            {"function": {"name": "search_mitre", "parameters": {}}},
        ]

    def test_uses_technique_from_prompt(self):
        prompt = "Conclude and classify findings. Techniques investigated: T1547.001, T1053.005. Triage all findings."
        response = self.llm.chat_with_tools(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": "Conclude"},
            ],
            tools=self.tools,
        )
        assert response["tool_calls"] is not None
        args = json.loads(response["tool_calls"][0]["function"]["arguments"])
        assert args["query"] == "T1547.001"


class TestPhaseDetection:
    """Verify correct phase detection from system prompts."""

    def setup_method(self):
        self.llm = MockLLMAdapter()

    def test_execute_detected(self):
        assert self.llm._detect_phase("Execute this hypothesis with drill-down") == "execute"

    def test_hypothesize_detected(self):
        assert self.llm._detect_phase("Generate prioritized hunt hypotheses for this client") == "hypothesize"

    def test_conclude_detected(self):
        assert self.llm._detect_phase("Conclude and classify each finding with evidence assessment") == "conclude"

    def test_deliver_detected(self):
        assert self.llm._detect_phase("Deliver the campaign report with executive summary") == "deliver"

    def test_no_phase_detected(self):
        assert self.llm._detect_phase("You are an MSSP agent") == ""

    def test_execute_before_hypothesize(self):
        """Execute should be detected even if prompt also contains 'hypothesis' word."""
        prompt = "Execute the following hypothesis. Drill-down on hits. Pivot on suspicious results."
        assert self.llm._detect_phase(prompt) == "execute"
