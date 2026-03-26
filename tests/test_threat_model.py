"""Tests for V4.2 Threat Modeling module."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.threat_model.models import AssetMap, AttackPath, BreachSimulation
from mssp_hunt_agent.threat_model.asset_mapper import map_assets
from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths
from mssp_hunt_agent.threat_model.breach_sim import simulate_breach


class TestAssetMapper:
    def test_maps_security_event_to_servers(self):
        result = map_assets("Contoso", ["SecurityEvent"])
        assert result.total_assets > 0
        names = [a.name for a in result.assets]
        assert "Windows Servers" in names

    def test_maps_signin_logs_to_identities(self):
        result = map_assets("Contoso", ["SigninLogs"])
        types = [a.asset_type for a in result.assets]
        assert "identity" in types

    def test_empty_sources(self):
        result = map_assets("Contoso", [])
        assert result.total_assets == 0

    def test_coverage_summary(self):
        result = map_assets("Contoso", ["SecurityEvent", "SigninLogs", "CommonSecurityLog"])
        assert "server" in result.coverage_summary
        assert "identity" in result.coverage_summary
        assert "network_device" in result.coverage_summary

    def test_deduplicates_assets(self):
        result = map_assets("Contoso", ["SecurityEvent", "SecurityEvent"])
        names = [a.name for a in result.assets]
        assert len(names) == len(set(names))


class TestAttackPaths:
    def test_full_coverage_paths(self):
        sources = ["SecurityEvent", "SigninLogs", "DeviceProcessEvents", "AuditLogs",
                    "DeviceNetworkEvents", "DeviceFileEvents", "CommonSecurityLog",
                    "DnsEvents", "OfficeActivity", "AzureActivity"]
        paths = identify_attack_paths(sources)
        assert len(paths) >= 4
        high_coverage = [p for p in paths if p.detection_coverage >= 0.8]
        assert len(high_coverage) >= 3

    def test_no_sources_all_gaps(self):
        paths = identify_attack_paths([])
        for path in paths:
            assert path.detection_coverage == 0.0
            assert path.risk_level == "high"
            assert len(path.gaps) > 0

    def test_partial_coverage(self):
        paths = identify_attack_paths(["SecurityEvent", "SigninLogs"])
        coverages = [p.detection_coverage for p in paths]
        assert any(0.0 < c < 1.0 for c in coverages)

    def test_path_has_techniques(self):
        paths = identify_attack_paths(["SecurityEvent"])
        for path in paths:
            assert len(path.techniques) > 0
            assert path.entry_point


class TestBreachSim:
    def test_simulate_with_good_coverage(self):
        paths = [AttackPath(path_id="AP1", entry_point="Phishing", techniques=["T1566"], detection_coverage=0.9, risk_level="low")]
        result = simulate_breach("Phishing scenario", paths)
        assert result.overall_detection_probability >= 0.8
        assert result.time_to_detect_estimate == "hours"

    def test_simulate_with_poor_coverage(self):
        paths = [AttackPath(path_id="AP1", entry_point="Supply chain", techniques=["T1195"], detection_coverage=0.1, risk_level="high")]
        result = simulate_breach("Supply chain", paths)
        assert result.overall_detection_probability <= 0.2
        assert "months" in result.time_to_detect_estimate or "weeks" in result.time_to_detect_estimate

    def test_simulate_empty_paths(self):
        result = simulate_breach("Empty", [])
        assert result.overall_detection_probability == 0.0

    def test_recommendations_for_gaps(self):
        paths = identify_attack_paths([])
        result = simulate_breach("Full gap analysis", paths)
        assert len(result.recommendations) > 0
