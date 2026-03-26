"""Tests for the V4.5 MCP Server — tools, resources, prompts."""

from __future__ import annotations

import json
import pytest


# ── Tool Registry ─────────────────────────────────────────────────────────

class TestToolRegistry:
    """Verify the tool registry structure and execute_tool dispatch."""

    def test_registry_has_expected_tools(self):
        from mssp_hunt_agent.mcp.tools import TOOL_REGISTRY

        expected = {
            "run_hunt", "run_ioc_sweep", "run_profile", "get_hunt_status",
            "ingest_feed", "deconflict_iocs", "auto_sweep",
            "get_client_kpis", "generate_rollup", "add_tuning_rule",
            "search_mitre", "generate_detection", "validate_kql",
            "simulate_detection", "map_assets", "identify_attack_paths",
            "simulate_risk", "portfolio_risk", "correlate_landscape",
            "chat", "assess_cve",
        }
        assert expected.issubset(set(TOOL_REGISTRY.keys()))

    def test_every_tool_has_required_keys(self):
        from mssp_hunt_agent.mcp.tools import TOOL_REGISTRY

        for name, meta in TOOL_REGISTRY.items():
            assert "description" in meta, f"{name} missing description"
            assert "input_schema" in meta, f"{name} missing input_schema"
            assert "handler" in meta, f"{name} missing handler"
            assert callable(meta["handler"]), f"{name} handler not callable"

    def test_execute_unknown_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("nonexistent_tool", {}))
        assert "error" in result
        assert "Unknown tool" in result["error"]

    def test_search_mitre(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("search_mitre", {"query": "lateral"}))
        assert "matches" in result
        # "lateral_movement" tactic should match
        assert len(result["matches"]) >= 1

    def test_generate_detection_by_technique(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("generate_detection", {"technique_id": "T1078"}))
        assert "rule_id" in result
        assert "kql_query" in result
        assert "T1078" in result.get("mitre_techniques", [])

    def test_validate_kql_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        kql = "SecurityEvent | where EventID == 4625 | limit 100"
        result = json.loads(execute_tool("validate_kql", {"kql": kql}))
        assert "valid" in result

    def test_map_assets_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("map_assets", {
            "client_name": "TestCorp",
            "data_sources": ["SecurityEvent", "SigninLogs"],
        }))
        assert "client_name" in result
        assert result["client_name"] == "TestCorp"

    def test_identify_attack_paths_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("identify_attack_paths", {
            "data_sources": ["SecurityEvent", "SigninLogs", "EmailEvents"],
        }))
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_simulate_risk_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("simulate_risk", {
            "client_name": "TestCorp",
            "change_type": "remove_source",
            "affected_source": "SecurityEvent",
            "current_data_sources": ["SecurityEvent", "SigninLogs", "DeviceProcessEvents"],
        }))
        assert "risk_rating" in result

    def test_portfolio_risk_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("portfolio_risk", {
            "client_sources": {
                "ClientA": ["SecurityEvent", "SigninLogs"],
                "ClientB": ["SecurityEvent"],
            },
        }))
        assert "highest_risk_client" in result

    def test_simulate_detection_tool(self):
        from mssp_hunt_agent.mcp.tools import execute_tool

        result = json.loads(execute_tool("simulate_detection", {
            "technique_id": "T1110",
        }))
        assert "rule" in result
        assert "quality_score" in result


# ── Resource Registry ─────────────────────────────────────────────────────

class TestResourceRegistry:
    """Verify resource URI routing and content."""

    def test_registry_has_expected_resources(self):
        from mssp_hunt_agent.mcp.resources import RESOURCE_REGISTRY

        expected_prefixes = [
            "clients://", "hunts://", "intel://", "tuning://",
            "mitre://", "landscape://",
        ]
        keys = list(RESOURCE_REGISTRY.keys())
        for prefix in expected_prefixes:
            assert any(k.startswith(prefix) for k in keys), f"Missing resource: {prefix}"

    def test_read_mitre_tactics(self):
        from mssp_hunt_agent.mcp.resources import read_resource

        result = json.loads(read_resource("mitre://tactics"))
        assert isinstance(result, dict)
        # Should have ATT&CK tactics
        assert len(result) >= 5

    def test_read_intel_feeds(self):
        from mssp_hunt_agent.mcp.resources import read_resource

        result = json.loads(read_resource("intel://feeds"))
        assert "supported_formats" in result

    def test_read_landscape_alerts(self):
        from mssp_hunt_agent.mcp.resources import read_resource

        result = json.loads(read_resource("landscape://alerts"))
        assert "supported_feeds" in result

    def test_unknown_resource(self):
        from mssp_hunt_agent.mcp.resources import read_resource

        result = json.loads(read_resource("unknown://something"))
        assert "error" in result


# ── Prompt Registry ───────────────────────────────────────────────────────

class TestPromptRegistry:
    """Verify prompt templates and rendering."""

    def test_registry_has_expected_prompts(self):
        from mssp_hunt_agent.mcp.prompts import PROMPT_REGISTRY

        expected = {
            "threat_hunt_analysis", "ioc_triage", "executive_summary",
            "gap_analysis", "detection_review",
        }
        assert expected == set(PROMPT_REGISTRY.keys())

    def test_every_prompt_has_description_and_template(self):
        from mssp_hunt_agent.mcp.prompts import PROMPT_REGISTRY

        for name, meta in PROMPT_REGISTRY.items():
            assert "description" in meta, f"{name} missing description"
            assert "template" in meta, f"{name} missing template"
            assert len(meta["template"]) > 50, f"{name} template too short"

    def test_render_threat_hunt_analysis(self):
        from mssp_hunt_agent.mcp.prompts import render_prompt

        text = render_prompt("threat_hunt_analysis", {
            "client_name": "Contoso",
            "hypothesis": "Lateral movement via RDP",
            "time_range": "last 7 days",
            "data_sources": "SecurityEvent, SigninLogs",
        })
        assert "Contoso" in text
        assert "Lateral movement via RDP" in text
        assert "MITRE ATT&CK" in text

    def test_render_executive_summary(self):
        from mssp_hunt_agent.mcp.prompts import render_prompt

        text = render_prompt("executive_summary", {
            "client_name": "Acme Corp",
            "findings": "3 suspicious login attempts from unusual geolocations",
        })
        assert "Acme Corp" in text
        assert "suspicious login" in text

    def test_render_with_missing_args(self):
        from mssp_hunt_agent.mcp.prompts import render_prompt

        text = render_prompt("ioc_triage", {"client_name": "TestCo"})
        assert "TestCo" in text
        assert "(not provided)" in text

    def test_render_unknown_prompt(self):
        from mssp_hunt_agent.mcp.prompts import render_prompt

        result = render_prompt("nonexistent", {})
        assert "Unknown prompt" in result

    def test_render_detection_review(self):
        from mssp_hunt_agent.mcp.prompts import render_prompt

        text = render_prompt("detection_review", {
            "rule_name": "Brute Force Detection",
            "kql": "SecurityEvent | where EventID == 4625 | summarize count() by Account",
            "techniques": "T1110",
            "severity": "high",
        })
        assert "Brute Force Detection" in text
        assert "T1110" in text
        assert "quality" in text.lower() or "rate" in text.lower()


# ── MCP Server (if SDK available) ────────────────────────────────────────

class TestMCPServerCreation:
    """Test MCP server factory (skipped if MCP SDK not installed)."""

    def test_create_server_without_mcp_sdk(self):
        """If MCP SDK is not installed, create_server should raise ImportError."""
        try:
            from mcp.server import Server  # noqa: F401
            pytest.skip("MCP SDK is installed — this test checks the fallback")
        except ImportError:
            pass

        from mssp_hunt_agent.mcp.server import create_server, _MCP_AVAILABLE
        if _MCP_AVAILABLE:
            pytest.skip("MCP SDK is available")
        with pytest.raises(ImportError, match="MCP SDK not installed"):
            create_server()
