"""Tests for the Azure Sentinel community rules client."""

import pytest

from mssp_hunt_agent.intel.sentinel_rules import SentinelRule, _parse_yaml_rule


# ── YAML parsing ────────────────────────────────────────────────────


SAMPLE_YAML = """id: abc123
name: Failed Logon Brute Force on MFA
description: Detects accounts with multiple failed logon attempts followed by MFA.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
  - InitialAccess
relevantTechniques:
  - T1110
  - T1078
query: |
  SigninLogs
  | where TimeGenerated > ago(1d)
  | where ResultType == "50126"
  | summarize FailedCount=count() by UserPrincipalName, IPAddress
  | where FailedCount > 10
"""


class TestYAMLParsing:
    def test_parse_name(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML)
        assert rule is not None
        assert rule.name == "Failed Logon Brute Force on MFA"

    def test_parse_severity(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML)
        assert rule is not None
        assert rule.severity == "high"

    def test_parse_tactics(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML)
        assert rule is not None
        assert "CredentialAccess" in rule.tactics
        assert "InitialAccess" in rule.tactics

    def test_parse_techniques(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML)
        assert rule is not None
        assert "T1110" in rule.techniques
        assert "T1078" in rule.techniques

    def test_parse_kql_query(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML)
        assert rule is not None
        assert "SigninLogs" in rule.kql_query
        assert "ResultType" in rule.kql_query

    def test_parse_source_url(self) -> None:
        rule = _parse_yaml_rule(SAMPLE_YAML, source_url="https://example.com/rule.yaml")
        assert rule is not None
        assert rule.source_url == "https://example.com/rule.yaml"

    def test_empty_yaml_returns_none(self) -> None:
        rule = _parse_yaml_rule("")
        assert rule is None

    def test_no_name_no_query_returns_none(self) -> None:
        rule = _parse_yaml_rule("id: abc\nstatus: Available")
        assert rule is None


# ── SentinelRule model ──────────────────────────────────────────────


class TestSentinelRuleModel:
    def test_create_rule(self) -> None:
        rule = SentinelRule(
            name="Test Rule",
            severity="medium",
            kql_query="SecurityEvent | take 10",
            tactics=["Execution"],
            techniques=["T1059"],
        )
        assert rule.name == "Test Rule"
        assert rule.severity == "medium"

    def test_rule_defaults(self) -> None:
        rule = SentinelRule()
        assert rule.name == ""
        assert rule.tactics == []
        assert rule.kql_query == ""
