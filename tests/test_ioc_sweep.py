"""Tests for IOC sweep module."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssp_hunt_agent.intel.intel_processor import IntelEvent
from mssp_hunt_agent.intel.ioc_sweep import (
    IOCSweeper,
    _build_domain_queries,
    _build_hash_queries,
    _build_ip_queries,
    _build_package_queries,
)


def make_intel_event_with_iocs() -> IntelEvent:
    return IntelEvent(
        event_id="TEST-001",
        title="Test Supply Chain Attack",
        severity="high",
        category="supply_chain",
        summary="Test event with IOCs",
        article_count=1,
        sources=["Test"],
        relevance_score=0.9,
        iocs=[
            {"type": "ip", "value": "142.11.206.73", "context": "C2 server"},
            {"type": "domain", "value": "sfrclak.com", "context": "C2 domain"},
            {"type": "hash_sha256", "value": "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", "context": "Windows payload"},
            {"type": "filepath", "value": "/tmp/ld.py", "context": "Linux payload"},
        ],
        mitre_techniques=["T1195.002", "T1059.007"],
        affected_software=["axios 1.14.1", "plain-crypto-js"],
    )


class TestQueryBuilders:
    def test_ip_queries_cover_all_tables(self) -> None:
        queries = _build_ip_queries("142.11.206.73")
        tables = [t for t, _ in queries]
        assert "SigninLogs" in tables
        assert "SecurityEvent" in tables
        assert "DeviceNetworkEvents" in tables
        assert "Syslog" in tables

    def test_domain_queries_cover_all_tables(self) -> None:
        queries = _build_domain_queries("sfrclak.com")
        tables = [t for t, _ in queries]
        assert "DeviceNetworkEvents" in tables
        assert "DnsEvents" in tables

    def test_hash_queries(self) -> None:
        queries = _build_hash_queries("abc123", "hash_sha256")
        assert len(queries) >= 2
        assert any("DeviceFileEvents" in t for t, _ in queries)
        assert any("DeviceProcessEvents" in t for t, _ in queries)

    def test_package_queries(self) -> None:
        queries = _build_package_queries("axios 1.14.1")
        assert len(queries) >= 2
        assert any("DeviceProcessEvents" in t for t, _ in queries)

    def test_ip_value_in_query(self) -> None:
        queries = _build_ip_queries("1.2.3.4")
        for _, kql in queries:
            assert "1.2.3.4" in kql


class TestIOCSweeper:
    def test_sweep_with_hits(self) -> None:
        mock_adapter = MagicMock()
        mock_result = MagicMock()
        mock_result.result_count = 5
        mock_result.events = []
        mock_adapter.execute_query.return_value = mock_result

        sweeper = IOCSweeper(adapter=mock_adapter)
        event = make_intel_event_with_iocs()
        result = sweeper.run_sweep(event)

        assert result.total_queries > 0
        assert result.total_hits > 0
        assert result.sweep_id.startswith("SWEEP-")

    def test_sweep_with_no_hits(self) -> None:
        mock_adapter = MagicMock()
        mock_result = MagicMock()
        mock_result.result_count = 0
        mock_result.events = []
        mock_adapter.execute_query.return_value = mock_result

        sweeper = IOCSweeper(adapter=mock_adapter)
        event = make_intel_event_with_iocs()
        result = sweeper.run_sweep(event)

        assert result.total_queries > 0
        assert result.total_hits == 0
        assert result.total_misses > 0

    def test_sweep_handles_query_errors(self) -> None:
        mock_adapter = MagicMock()
        mock_adapter.execute_query.side_effect = Exception("Query failed")

        sweeper = IOCSweeper(adapter=mock_adapter)
        event = make_intel_event_with_iocs()
        result = sweeper.run_sweep(event)

        assert len(result.errors) > 0

    def test_sweep_includes_affected_software(self) -> None:
        mock_adapter = MagicMock()
        mock_result = MagicMock()
        mock_result.result_count = 0
        mock_result.events = []
        mock_adapter.execute_query.return_value = mock_result

        sweeper = IOCSweeper(adapter=mock_adapter)
        event = make_intel_event_with_iocs()
        result = sweeper.run_sweep(event)

        # Should have queries for both IOCs and affected software
        # Check that queries were made for the software packages
        call_count = mock_adapter.execute_query.call_count
        # 4 IOCs * ~4 tables each + 2 packages * 3 tables each = ~22+ queries
        assert call_count >= 20, f"Expected 20+ queries, got {call_count}"

    def test_sweep_empty_event(self) -> None:
        mock_adapter = MagicMock()
        sweeper = IOCSweeper(adapter=mock_adapter)
        event = IntelEvent(
            event_id="EMPTY", title="No IOCs", severity="low",
            category="general", summary="Nothing to sweep",
        )
        result = sweeper.run_sweep(event)
        assert result.total_queries == 0
        assert result.total_hits == 0

    def test_to_dict(self) -> None:
        mock_adapter = MagicMock()
        mock_result = MagicMock()
        mock_result.result_count = 0
        mock_result.events = []
        mock_adapter.execute_query.return_value = mock_result

        sweeper = IOCSweeper(adapter=mock_adapter)
        event = make_intel_event_with_iocs()
        result = sweeper.run_sweep(event)
        d = result.to_dict()
        assert "sweep_id" in d
        assert "total_queries" in d
        assert "hits" in d
        assert "misses" in d


class TestCampaignLauncherRouting:
    def test_routes_to_ioc_sweep_when_iocs_present(self) -> None:
        from mssp_hunt_agent.intel.intel_campaign import IntelCampaignLauncher
        config = MagicMock()
        config.default_client_name = "Test"
        config.adapter_mode = "mock"
        config.sentinel_workspace_id = ""
        llm = MagicMock()
        launcher = IntelCampaignLauncher(agent_config=config, llm=llm)
        event = make_intel_event_with_iocs()
        assert launcher._has_actionable_iocs(event) is True

    def test_routes_to_ttp_hunt_when_no_iocs(self) -> None:
        from mssp_hunt_agent.intel.intel_campaign import IntelCampaignLauncher
        config = MagicMock()
        config.default_client_name = "Test"
        llm = MagicMock()
        launcher = IntelCampaignLauncher(agent_config=config, llm=llm)
        event = IntelEvent(
            event_id="TTP-001", title="New Ransomware TTP", severity="high",
            category="apt", summary="New technique observed",
            mitre_techniques=["T1486", "T1490"],
        )
        assert launcher._has_actionable_iocs(event) is False
