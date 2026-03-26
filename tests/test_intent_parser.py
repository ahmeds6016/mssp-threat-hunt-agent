"""Tests for the agent intent parser."""

import pytest

from mssp_hunt_agent.agent.intent_parser import IntentParser
from mssp_hunt_agent.agent.models import AgentIntent


@pytest.fixture
def parser() -> IntentParser:
    return IntentParser()


# ── Intent classification tests ──────────────────────────────────────


class TestCVECheck:
    def test_cve_by_id(self, parser: IntentParser) -> None:
        result = parser.parse("Are we vulnerable to CVE-2025-55182?")
        assert result.intent == AgentIntent.CVE_CHECK
        assert result.confidence >= 0.8

    def test_cve_entity_extracted(self, parser: IntentParser) -> None:
        result = parser.parse("Check if CVE-2024-12345 affects us")
        assert result.entities.get("cve") == "CVE-2024-12345"

    def test_cve_affected_by(self, parser: IntentParser) -> None:
        result = parser.parse("Are we affected by the new exploit?")
        assert result.intent == AgentIntent.CVE_CHECK

    def test_cve_multiple(self, parser: IntentParser) -> None:
        result = parser.parse("Check CVE-2025-1111 and CVE-2025-2222")
        assert result.intent == AgentIntent.CVE_CHECK
        cves = result.entities.get("cve")
        assert isinstance(cves, list)
        assert len(cves) == 2


class TestIOCSweep:
    def test_ip_address(self, parser: IntentParser) -> None:
        result = parser.parse("Check if 203.0.113.77 is in our logs")
        assert result.intent == AgentIntent.IOC_SWEEP
        assert result.entities.get("ip") == "203.0.113.77"

    def test_hash(self, parser: IntentParser) -> None:
        result = parser.parse("Sweep for e99a18c428cb38d5f260853678922e03")
        assert result.intent == AgentIntent.IOC_SWEEP
        assert "hash_md5" in result.entities

    def test_ioc_keyword(self, parser: IntentParser) -> None:
        result = parser.parse("Run an IOC sweep on these indicators")
        assert result.intent == AgentIntent.IOC_SWEEP

    def test_sha256(self, parser: IntentParser) -> None:
        sha = "a" * 64
        result = parser.parse(f"Check hash {sha}")
        assert result.intent == AgentIntent.IOC_SWEEP
        assert result.entities.get("hash_sha256") == sha


class TestRunHunt:
    def test_hunt_for(self, parser: IntentParser) -> None:
        result = parser.parse("Hunt for lateral movement in the last 7 days")
        assert result.intent == AgentIntent.RUN_HUNT

    def test_investigate(self, parser: IntentParser) -> None:
        result = parser.parse("Investigate suspicious PowerShell activity")
        assert result.intent == AgentIntent.RUN_HUNT

    def test_hypothesis_extracted(self, parser: IntentParser) -> None:
        result = parser.parse("Hunt for credential dumping via LSASS")
        assert "hypothesis" in result.entities
        assert "credential dumping" in result.entities["hypothesis"]

    def test_look_for(self, parser: IntentParser) -> None:
        result = parser.parse("Look for signs of exfiltration")
        assert result.intent == AgentIntent.RUN_HUNT


class TestDetectionRule:
    def test_create_detection(self, parser: IntentParser) -> None:
        result = parser.parse("Create a detection for T1059")
        assert result.intent == AgentIntent.DETECTION_RULE
        assert result.entities.get("technique") == "T1059"

    def test_generate_kql(self, parser: IntentParser) -> None:
        result = parser.parse("Generate a KQL rule for PowerShell execution")
        assert result.intent == AgentIntent.DETECTION_RULE

    def test_subtechnique(self, parser: IntentParser) -> None:
        result = parser.parse("Build a detection rule for T1059.001")
        assert result.intent == AgentIntent.DETECTION_RULE
        assert result.entities.get("technique") == "T1059.001"


class TestRiskAssessment:
    def test_what_if_lose(self, parser: IntentParser) -> None:
        result = parser.parse("What if we lose EDR?")
        assert result.intent == AgentIntent.RISK_ASSESSMENT

    def test_impact_without(self, parser: IntentParser) -> None:
        result = parser.parse("Impact of removing Syslog collection")
        assert result.intent == AgentIntent.RISK_ASSESSMENT


class TestLandscapeCheck:
    def test_active_threats(self, parser: IntentParser) -> None:
        result = parser.parse("Any active threats we can't detect?")
        assert result.intent == AgentIntent.LANDSCAPE_CHECK

    def test_blind_spots(self, parser: IntentParser) -> None:
        result = parser.parse("What are our blind spots?")
        assert result.intent == AgentIntent.LANDSCAPE_CHECK


class TestThreatModel:
    def test_attack_paths(self, parser: IntentParser) -> None:
        result = parser.parse("What are our attack paths?")
        assert result.intent == AgentIntent.THREAT_MODEL

    def test_breach_sim(self, parser: IntentParser) -> None:
        result = parser.parse("Simulate a breach scenario")
        assert result.intent == AgentIntent.THREAT_MODEL


class TestTelemetryProfile:
    def test_what_telemetry(self, parser: IntentParser) -> None:
        result = parser.parse("What telemetry do we have?")
        assert result.intent == AgentIntent.TELEMETRY_PROFILE

    def test_data_sources(self, parser: IntentParser) -> None:
        result = parser.parse("List our data sources")
        assert result.intent == AgentIntent.TELEMETRY_PROFILE


class TestHuntStatus:
    def test_status_with_run_id(self, parser: IntentParser) -> None:
        result = parser.parse("What's the status of RUN-abc123?")
        assert result.intent == AgentIntent.HUNT_STATUS
        assert result.entities.get("run_id") == "RUN-abc123"

    def test_bare_run_id(self, parser: IntentParser) -> None:
        result = parser.parse("RUN-xyz789")
        assert result.intent == AgentIntent.HUNT_STATUS


class TestGenerateReport:
    def test_generate_report(self, parser: IntentParser) -> None:
        result = parser.parse("Generate a report for RUN-abc123")
        assert result.intent == AgentIntent.GENERATE_REPORT
        assert result.entities.get("run_id") == "RUN-abc123"

    def test_executive_summary(self, parser: IntentParser) -> None:
        result = parser.parse("Give me an executive summary")
        assert result.intent == AgentIntent.GENERATE_REPORT


class TestGeneralQuestion:
    def test_empty_message(self, parser: IntentParser) -> None:
        result = parser.parse("")
        assert result.intent == AgentIntent.GENERAL_QUESTION
        assert result.confidence == 0.0

    def test_unrecognized(self, parser: IntentParser) -> None:
        result = parser.parse("Hello, how are you today?")
        assert result.intent == AgentIntent.GENERAL_QUESTION


# ── Entity extraction tests ──────────────────────────────────────────


class TestEntityExtraction:
    def test_time_range(self, parser: IntentParser) -> None:
        result = parser.parse("Hunt for lateral movement in the last 30 days")
        assert result.entities.get("time_range") == "30 days"

    def test_technique_id(self, parser: IntentParser) -> None:
        result = parser.parse("Investigate T1566.001 phishing activity")
        assert result.entities.get("technique") == "T1566.001"

    def test_url_extraction(self, parser: IntentParser) -> None:
        result = parser.parse("Check https://malicious.example.com/payload in logs")
        assert "url" in result.entities

    def test_email_extraction(self, parser: IntentParser) -> None:
        result = parser.parse("Check if attacker@evil.com sent any emails")
        assert result.entities.get("email") == "attacker@evil.com"

    def test_multiple_ips(self, parser: IntentParser) -> None:
        result = parser.parse("Sweep for 1.2.3.4 and 5.6.7.8")
        ips = result.entities.get("ip")
        assert isinstance(ips, list)
        assert len(ips) == 2


# ── V5.1: IP validation tests ────────────────────────────────────────


class TestIPValidation:
    def test_valid_ip_extracted(self, parser: IntentParser) -> None:
        result = parser.parse("Check 192.168.1.1 in logs")
        assert result.entities.get("ip") == "192.168.1.1"

    def test_invalid_ip_rejected(self, parser: IntentParser) -> None:
        """IPs with octets > 255 should not be extracted."""
        result = parser.parse("Check 999.999.999.999 in logs")
        assert "ip" not in result.entities

    def test_edge_ip_255(self, parser: IntentParser) -> None:
        result = parser.parse("Sweep for 255.255.255.255")
        assert result.entities.get("ip") == "255.255.255.255"

    def test_edge_ip_0(self, parser: IntentParser) -> None:
        result = parser.parse("Check 0.0.0.0")
        assert result.entities.get("ip") == "0.0.0.0"

    def test_partial_invalid_ip(self, parser: IntentParser) -> None:
        """256 in any octet should fail."""
        result = parser.parse("Check 10.0.256.1 in logs")
        assert "ip" not in result.entities


# ── V5.1: Scoring formula tests ──────────────────────────────────────


class TestScoringFormula:
    def test_single_match_below_0_5(self, parser: IntentParser) -> None:
        """A single pattern match should score 0.45, not 0.7."""
        result = parser.parse("check the IOC please")
        # "ioc" matches 1 pattern -> 0.25 + 0.2 = 0.45
        assert result.confidence <= 0.5

    def test_multiple_matches_moderate(self, parser: IntentParser) -> None:
        """Multiple pattern matches should produce moderate-to-high confidence."""
        result = parser.parse("run an IOC sweep")
        # "ioc" + "sweep" = 2 matches -> 0.25 + 0.4 = 0.65
        assert 0.6 <= result.confidence <= 0.95

    def test_entity_boost_overrides(self, parser: IntentParser) -> None:
        """Entity boosts should dominate for key intents."""
        result = parser.parse("Tell me about CVE-2024-12345")
        assert result.confidence >= 0.9


# ── V5.1: Clarification flag tests ───────────────────────────────────


class TestClarificationFlag:
    def test_low_confidence_needs_clarification(self, parser: IntentParser) -> None:
        result = parser.parse("Hello, how are you today?")
        assert result.needs_clarification is True
        assert len(result.clarification_reason) > 0

    def test_high_confidence_no_clarification(self, parser: IntentParser) -> None:
        result = parser.parse("Are we vulnerable to CVE-2025-55182?")
        assert result.needs_clarification is False
