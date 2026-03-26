"""Tests for V4.3 Executive Risk Simulator."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.risk.models import RiskScenario, ImpactAssessment, PortfolioRisk
from mssp_hunt_agent.risk.simulator import simulate_risk_scenario
from mssp_hunt_agent.risk.portfolio import portfolio_risk_summary


_FULL_SOURCES = [
    "SecurityEvent", "SigninLogs", "DeviceProcessEvents", "AuditLogs",
    "DeviceNetworkEvents", "DeviceFileEvents", "CommonSecurityLog",
    "DnsEvents", "OfficeActivity", "AzureActivity",
]


class TestSimulator:
    def test_remove_source_reduces_coverage(self):
        scenario = RiskScenario(client_name="Contoso", change_type="remove_source", affected_source="DeviceProcessEvents")
        result = simulate_risk_scenario(scenario, _FULL_SOURCES)
        assert result.overall_delta <= 0
        assert result.avg_coverage_after <= result.avg_coverage_before

    def test_add_source_improves_coverage(self):
        limited = ["SecurityEvent", "SigninLogs"]
        scenario = RiskScenario(client_name="Contoso", change_type="add_source", affected_source="DeviceProcessEvents")
        result = simulate_risk_scenario(scenario, limited)
        assert result.overall_delta >= 0
        assert result.avg_coverage_after >= result.avg_coverage_before

    def test_remove_critical_source_high_risk(self):
        scenario = RiskScenario(client_name="Contoso", change_type="remove_source", affected_source="SecurityEvent")
        result = simulate_risk_scenario(scenario, _FULL_SOURCES)
        assert result.risk_rating in ("medium", "high", "critical")

    def test_remove_nonexistent_source_no_change(self):
        scenario = RiskScenario(client_name="Contoso", change_type="remove_source", affected_source="FakeTable")
        result = simulate_risk_scenario(scenario, _FULL_SOURCES)
        assert result.overall_delta == 0.0

    def test_has_recommendations(self):
        scenario = RiskScenario(client_name="Contoso", change_type="remove_source", affected_source="DeviceProcessEvents")
        result = simulate_risk_scenario(scenario, _FULL_SOURCES)
        assert len(result.recommendations) > 0

    def test_changes_per_path(self):
        scenario = RiskScenario(client_name="Contoso", change_type="remove_source", affected_source="DeviceProcessEvents")
        result = simulate_risk_scenario(scenario, _FULL_SOURCES)
        assert len(result.changes) >= 4


class TestPortfolio:
    def test_portfolio_summary(self):
        clients = {
            "Contoso": _FULL_SOURCES,
            "Fabrikam": ["SecurityEvent", "SigninLogs"],
            "Woodgrove": ["SecurityEvent"],
        }
        result = portfolio_risk_summary(clients)
        assert result.total_clients == 3
        assert result.highest_risk_client in ("Fabrikam", "Woodgrove")
        assert result.avg_portfolio_coverage > 0

    def test_portfolio_with_scenario(self):
        clients = {
            "Contoso": _FULL_SOURCES,
            "Fabrikam": ["SecurityEvent", "SigninLogs", "DeviceProcessEvents"],
        }
        scenario = RiskScenario(client_name="", change_type="remove_source", affected_source="DeviceProcessEvents")
        result = portfolio_risk_summary(clients, scenario_template=scenario)
        assert len(result.assessments) == 2
        for a in result.assessments:
            assert a.overall_delta <= 0

    def test_empty_portfolio(self):
        result = portfolio_risk_summary({})
        assert result.total_clients == 0
        assert result.avg_portfolio_coverage == 0.0
