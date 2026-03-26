"""Tests for agent tool definitions and executor."""

import json

import pytest

from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS, ToolExecutor
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="TestClient",
    )


@pytest.fixture
def executor(config: HuntAgentConfig) -> ToolExecutor:
    return ToolExecutor(config)


# ── Tool schema validation ──────────────────────────────────────────


class TestToolSchemas:
    def test_all_tools_have_type_function(self) -> None:
        for tool in AGENT_TOOLS:
            assert tool["type"] == "function"

    def test_all_tools_have_name(self) -> None:
        for tool in AGENT_TOOLS:
            assert "name" in tool["function"]
            assert tool["function"]["name"]

    def test_all_tools_have_description(self) -> None:
        for tool in AGENT_TOOLS:
            assert "description" in tool["function"]
            assert len(tool["function"]["description"]) > 10

    def test_all_tools_have_parameters(self) -> None:
        for tool in AGENT_TOOLS:
            assert "parameters" in tool["function"]
            params = tool["function"]["parameters"]
            assert params["type"] == "object"

    def test_tool_count(self) -> None:
        assert len(AGENT_TOOLS) == 12

    def test_expected_tool_names(self) -> None:
        names = {t["function"]["name"] for t in AGENT_TOOLS}
        expected = {
            "run_kql_query", "validate_kql", "lookup_cve",
            "search_mitre", "get_sentinel_rule_examples",
            "check_telemetry", "run_hunt", "assess_risk",
            "check_landscape", "identify_attack_paths",
            "enrich_ioc", "check_lolbas",
        }
        assert names == expected

    def test_required_params_present(self) -> None:
        """Tools with required params should list them."""
        for tool in AGENT_TOOLS:
            params = tool["function"]["parameters"]
            required = params.get("required", [])
            properties = params.get("properties", {})
            for req in required:
                assert req in properties, f"{tool['function']['name']} missing required param {req}"


# ── Tool executor ───────────────────────────────────────────────────


class TestToolExecutor:
    def test_unknown_tool_returns_error(self, executor: ToolExecutor) -> None:
        result = executor.execute("nonexistent_tool", {})
        data = json.loads(result)
        assert "error" in data
        assert "Unknown tool" in data["error"]

    def test_run_kql_query(self, executor: ToolExecutor) -> None:
        result = executor.execute("run_kql_query", {
            "query": "SecurityEvent | where TimeGenerated > ago(7d) | take 5",
        })
        data = json.loads(result)
        assert "total_events" in data
        assert "events" in data

    def test_validate_kql(self, executor: ToolExecutor) -> None:
        result = executor.execute("validate_kql", {
            "kql": "SecurityEvent | where TimeGenerated > ago(7d)",
        })
        data = json.loads(result)
        assert "is_valid" in data or "valid" in data or "errors" in data

    def test_lookup_cve(self, executor: ToolExecutor) -> None:
        result = executor.execute("lookup_cve", {"cve_id": "CVE-2024-3400"})
        data = json.loads(result)
        assert "cve_id" in data or "error" in data

    def test_search_mitre(self, executor: ToolExecutor) -> None:
        result = executor.execute("search_mitre", {"query": "T1059"})
        data = json.loads(result)
        assert "techniques" in data

    def test_check_telemetry(self, executor: ToolExecutor) -> None:
        result = executor.execute("check_telemetry", {})
        data = json.loads(result)
        assert "data_sources" in data

    def test_assess_risk(self, executor: ToolExecutor) -> None:
        result = executor.execute("assess_risk", {
            "change_type": "remove_source",
            "affected_source": "EDR",
        })
        data = json.loads(result)
        assert "risk_rating" in data or "error" not in data

    def test_check_landscape(self, executor: ToolExecutor) -> None:
        result = executor.execute("check_landscape", {})
        data = json.loads(result)
        assert "alerts" in data or "correlations" in data

    def test_identify_attack_paths(self, executor: ToolExecutor) -> None:
        result = executor.execute("identify_attack_paths", {})
        data = json.loads(result)
        assert "paths" in data or "path_count" in data

    def test_kql_max_results_capped(self, executor: ToolExecutor) -> None:
        result = executor.execute("run_kql_query", {
            "query": "SecurityEvent | take 1000",
            "max_results": 99999,
        })
        data = json.loads(result)
        # Should be capped by config.agent_loop_max_kql_results (200)
        assert data["events_returned"] <= 200

    def test_executor_handles_exception_gracefully(self, executor: ToolExecutor) -> None:
        """Even if a handler raises, executor should return JSON error."""
        # Force an error by passing invalid args to a strict handler
        result = executor.execute("validate_kql", {"kql": ""})
        data = json.loads(result)
        # Should either succeed or have an error key — not crash
        assert isinstance(data, dict)
