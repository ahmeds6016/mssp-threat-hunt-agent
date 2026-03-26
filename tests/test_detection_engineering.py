"""Tests for the V4.1 Detection Engineering module."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.detection.models import DetectionRule, Severity, PerformanceRating, QualityScore
from mssp_hunt_agent.detection.generator import generate_detection_rule, list_available_techniques
from mssp_hunt_agent.detection.validator import validate_kql
from mssp_hunt_agent.detection.scorer import score_detection_quality


class TestDetectionModels:
    def test_detection_rule_defaults(self):
        rule = DetectionRule(rule_id="R1", name="Test", description="desc", kql_query="SecurityEvent")
        assert rule.severity == Severity.MEDIUM
        assert rule.created_by == "agent"
        assert rule.enabled is True

    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity("high") == Severity.HIGH


class TestGenerator:
    def test_generate_from_technique_id(self):
        rule = generate_detection_rule(technique_id="T1078")
        assert rule.rule_id.startswith("DET-")
        assert "T1078" in rule.mitre_techniques
        assert "SigninLogs" in rule.kql_query
        assert rule.severity == Severity.HIGH

    def test_generate_from_brute_force(self):
        rule = generate_detection_rule(technique_id="T1110")
        assert "4625" in rule.kql_query
        assert "SecurityEvent" in rule.data_sources

    def test_generate_from_powershell(self):
        rule = generate_detection_rule(technique_id="T1059.001")
        assert "powershell" in rule.kql_query.lower()
        assert rule.severity == Severity.HIGH

    def test_generate_from_description_logon(self):
        rule = generate_detection_rule(description="Detect suspicious logon activity")
        assert "SecurityEvent" in rule.kql_query
        assert "4624" in rule.kql_query or "4625" in rule.kql_query

    def test_generate_from_description_dns(self):
        rule = generate_detection_rule(description="DNS tunneling detection")
        assert "DnsEvents" in rule.kql_query

    def test_generate_from_description_lateral(self):
        rule = generate_detection_rule(description="Lateral movement via RDP")
        assert "SecurityEvent" in rule.kql_query

    def test_generate_unknown_technique_with_description(self):
        rule = generate_detection_rule(technique_id="T9999", description="Custom rule for testing")
        assert rule.rule_id.startswith("DET-")
        assert "T9999" in rule.mitre_techniques

    def test_generate_fallback(self):
        rule = generate_detection_rule(description="something unusual")
        assert "SecurityEvent" in rule.kql_query

    def test_list_available_techniques(self):
        techniques = list_available_techniques()
        assert "T1078" in techniques
        assert "T1110" in techniques
        assert len(techniques) >= 8

    def test_credential_dumping_rule(self):
        rule = generate_detection_rule(technique_id="T1003")
        assert rule.severity == Severity.CRITICAL
        assert "lsass" in rule.kql_query.lower() or "mimikatz" in rule.kql_query.lower()

    # ── V5.1: Expanded template tests ─────────────────────────────

    def test_t1098_uses_auditlogs(self):
        """T1098 should query AuditLogs, not SecurityEvent."""
        rule = generate_detection_rule(technique_id="T1098")
        assert "AuditLogs" in rule.kql_query
        assert "SecurityEvent" not in rule.kql_query

    def test_t1059_differs_from_t1059_001(self):
        """Parent technique T1059 and T1059.001 should produce different KQL."""
        rule_parent = generate_detection_rule(technique_id="T1059")
        rule_child = generate_detection_rule(technique_id="T1059.001")
        assert rule_parent.kql_query != rule_child.kql_query

    def test_t1110_003_password_spraying(self):
        rule = generate_detection_rule(technique_id="T1110.003")
        assert "SigninLogs" in rule.kql_query

    def test_t1486_ransomware(self):
        rule = generate_detection_rule(technique_id="T1486")
        assert rule.severity == Severity.CRITICAL

    def test_t1547_001_registry_run_keys(self):
        rule = generate_detection_rule(technique_id="T1547.001")
        assert "Registry" in rule.kql_query or "registry" in rule.kql_query.lower()

    def test_false_positive_guidance_present(self):
        """All template-generated rules should include false_positive_guidance."""
        rule = generate_detection_rule(technique_id="T1078")
        assert rule.false_positive_guidance
        assert len(rule.false_positive_guidance) > 10

    def test_expanded_technique_count(self):
        techniques = list_available_techniques()
        assert len(techniques) >= 30

    def test_description_keyword_account(self):
        """Description with 'account' keyword should produce account-specific KQL."""
        rule = generate_detection_rule(description="Detect suspicious account creation")
        assert "AuditLogs" in rule.kql_query or "SecurityEvent" in rule.kql_query

    def test_description_keyword_ransomware(self):
        rule = generate_detection_rule(description="Detect ransomware encryption activity")
        assert "encrypt" in rule.kql_query.lower() or "ransom" in rule.kql_query.lower() or "vssadmin" in rule.kql_query.lower()


class TestValidator:
    def test_valid_simple_query(self):
        result = validate_kql("SecurityEvent\n| where EventID == 4625\n| where TimeGenerated > ago(7d)")
        assert result.valid is True
        assert "SecurityEvent" in result.tables_referenced

    def test_empty_query_invalid(self):
        result = validate_kql("")
        assert result.valid is False
        assert "Empty query" in result.errors

    def test_dangerous_search_star(self):
        result = validate_kql("search * | where foo == 'bar'")
        assert result.valid is False
        assert any("search *" in e for e in result.errors)

    def test_unknown_table_warning(self):
        result = validate_kql("FooBarTable\n| where x == 1")
        assert any("Unknown table" in w for w in result.warnings)

    def test_no_time_filter_warning(self):
        result = validate_kql("SecurityEvent\n| where EventID == 4625")
        assert any("time filter" in w.lower() for w in result.warnings)

    def test_time_range_detection(self):
        result = validate_kql("SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4625")
        assert result.time_range_detected == "24h"

    def test_unbalanced_parens(self):
        result = validate_kql("SecurityEvent\n| where (EventID == 4625")
        assert result.valid is False
        assert any("parentheses" in e.lower() for e in result.errors)

    def test_cost_estimation_join(self):
        result = validate_kql("SecurityEvent\n| join (SigninLogs) on UserPrincipalName\n| where TimeGenerated > ago(1d)")
        assert result.estimated_cost == "high"

    def test_multiple_tables(self):
        result = validate_kql("SecurityEvent\n| join kind=inner (SigninLogs | where ResultType == 0) on $left.Account == $right.UserPrincipalName")
        assert "SecurityEvent" in result.tables_referenced
        assert "SigninLogs" in result.tables_referenced


class TestScorer:
    def _make_rule(self, **kw) -> DetectionRule:
        defaults = dict(
            rule_id="R-test",
            name="Test Rule",
            description="A test detection rule for scoring",
            kql_query="SecurityEvent\n| where TimeGenerated > ago(7d)\n| where EventID == 4625\n| summarize Count=count() by Account\n| where Count > 10",
            mitre_techniques=["T1110"],
            data_sources=["SecurityEvent"],
        )
        defaults.update(kw)
        return DetectionRule(**defaults)

    def test_well_formed_rule_scores_high(self):
        rule = self._make_rule()
        score = score_detection_quality(rule)
        assert score.overall_grade in ("A", "B")
        assert score.precision_estimate >= 0.7

    def test_no_mitre_lowers_coverage(self):
        rule = self._make_rule(mitre_techniques=[])
        score = score_detection_quality(rule)
        assert score.coverage_score == 0.0
        assert any("ATT&CK" in r for r in score.recommendations)

    def test_no_time_filter_lowers_score(self):
        rule = self._make_rule(kql_query="SecurityEvent\n| where EventID == 4625")
        score = score_detection_quality(rule)
        assert score.has_time_filter is False
        assert any("time filter" in r.lower() for r in score.recommendations)

    def test_join_marks_slow(self):
        rule = self._make_rule(
            kql_query="SecurityEvent\n| where TimeGenerated > ago(7d)\n| join (SigninLogs) on Account"
        )
        score = score_detection_quality(rule)
        assert score.performance_rating == PerformanceRating.SLOW

    def test_aggregation_detected(self):
        rule = self._make_rule()
        score = score_detection_quality(rule)
        assert score.uses_aggregation is True
