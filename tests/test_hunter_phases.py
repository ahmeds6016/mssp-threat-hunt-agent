"""Tests for V7 phase runners and campaign orchestrator."""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.hunter.budget import BudgetExhausted, BudgetTracker
from mssp_hunt_agent.hunter.context import ContextManager
from mssp_hunt_agent.hunter.models.campaign import (
    CampaignConfig,
    CampaignPhase,
    CampaignState,
    PhaseResult,
)
from mssp_hunt_agent.hunter.models.environment import (
    EnvironmentIndex,
    IdentityIndex,
    IndexMetadata,
    TableProfile,
    TelemetryIndex,
)
from mssp_hunt_agent.hunter.models.finding import (
    FindingClassification,
    FindingSeverity,
    HuntFinding,
    EvidenceChain,
)
from mssp_hunt_agent.hunter.models.hypothesis import (
    AutonomousHypothesis,
    HypothesisPriority,
    HypothesisSource,
)
from mssp_hunt_agent.hunter.phases.hypothesize import (
    HypothesizePhaseRunner,
    _parse_hypotheses_from_text,
)
from mssp_hunt_agent.hunter.phases.execute import (
    ExecutePhaseRunner,
    _extract_findings_from_response,
)
from mssp_hunt_agent.hunter.phases.conclude import ConcludePhaseRunner
from mssp_hunt_agent.hunter.phases.deliver import DeliverPhaseRunner, _build_report
from mssp_hunt_agent.hunter.prompts.phase_prompts import (
    build_hypothesize_prompt,
    build_execute_prompt,
    build_conclude_prompt,
    build_deliver_prompt,
)


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def campaign_config() -> CampaignConfig:
    return CampaignConfig(
        client_name="TestCorp",
        max_hypotheses=3,
        max_total_queries=50,
        max_duration_minutes=10,
        max_llm_tokens=100_000,
    )


@pytest.fixture
def env_index() -> EnvironmentIndex:
    return EnvironmentIndex(
        metadata=IndexMetadata(client_id="test-client", workspace_id="ws-123"),
        telemetry=TelemetryIndex(
            tables=[
                TableProfile(table_name="SigninLogs", row_count_7d=1000, ingestion_healthy=True),
                TableProfile(table_name="SecurityEvent", row_count_7d=5000, ingestion_healthy=True),
                TableProfile(table_name="AuditLogs", row_count_7d=2000, ingestion_healthy=True),
            ],
        ),
        identity=IdentityIndex(total_users=10, admin_count=2),
    )


@pytest.fixture
def campaign_state(campaign_config: CampaignConfig, env_index: EnvironmentIndex) -> CampaignState:
    return CampaignState(
        campaign_id="CAMP-test",
        config=campaign_config,
        status="running",
        started_at="2026-03-10T00:00:00+00:00",
        environment_index=env_index,
    )


@pytest.fixture
def mock_llm() -> MagicMock:
    llm = MagicMock()
    llm.chat_with_tools.return_value = {
        "content": "Analysis complete.",
        "tool_calls": None,
        "finish_reason": "stop",
    }
    return llm


@pytest.fixture
def mock_executor() -> MagicMock:
    executor = MagicMock()
    executor.execute.return_value = '{"result": "mock tool result"}'
    return executor


@pytest.fixture
def budget(campaign_config: CampaignConfig) -> BudgetTracker:
    return BudgetTracker(campaign_config)


@pytest.fixture
def context_mgr() -> ContextManager:
    return ContextManager()


def _make_hypothesis(
    h_id: str = "H-001",
    title: str = "Test Hypothesis",
    score: float = 0.5,
) -> AutonomousHypothesis:
    return AutonomousHypothesis(
        hypothesis_id=h_id,
        title=title,
        description="Test hypothesis description",
        source=HypothesisSource.COVERAGE_GAP,
        priority_score=score,
        priority=HypothesisPriority.HIGH if score >= 0.4 else HypothesisPriority.MEDIUM,
        threat_likelihood=0.7,
        detection_feasibility=0.8,
        business_impact=0.6,
        required_tables=["SigninLogs"],
        available_tables=["SigninLogs"],
    )


# ── Phase Prompt Tests ─────────────────────────────────────────────


class TestPhasePrompts:
    def test_hypothesize_prompt_contains_client(self):
        prompt = build_hypothesize_prompt("AcmeCorp", {"tables": 5}, {"queries_remaining": 100})
        assert "AcmeCorp" in prompt
        assert "tables" in prompt

    def test_execute_prompt_contains_hypothesis(self):
        prompt = build_execute_prompt(
            "AcmeCorp",
            {"title": "Credential Stuffing", "mitre_techniques": ["T1078"]},
            {"tables": 5},
            {"queries_remaining": 50},
        )
        assert "Credential Stuffing" in prompt
        assert "T1078" in prompt

    def test_execute_prompt_prior_findings(self):
        prompt = build_execute_prompt(
            "AcmeCorp", {}, {}, {},
            prior_findings_summary="- [high] Legacy auth: true_positive",
        )
        assert "Prior Findings" in prompt
        assert "Legacy auth" in prompt

    def test_conclude_prompt_contains_findings(self):
        prompt = build_conclude_prompt(
            "AcmeCorp",
            [{"finding_id": "F-001", "title": "Bad thing"}],
            [{"hypothesis_id": "H-001", "title": "Hyp"}],
            {},
        )
        assert "F-001" in prompt
        assert "Classification Criteria" in prompt

    def test_deliver_prompt_report_structure(self):
        prompt = build_deliver_prompt(
            "AcmeCorp",
            {"total_findings": 3},
            [{"finding_id": "F-001"}],
            {},
        )
        assert "Executive Summary" in prompt
        assert "Detection Engineering" in prompt
        assert "Next Steps" in prompt


# ── Hypothesis Parsing Tests ───────────────────────────────────────


class TestHypothesisParsing:
    def test_parse_json_array(self, campaign_state: CampaignState):
        text = json.dumps([
            {
                "title": "Brute Force Attacks",
                "description": "Hunt for brute force patterns in SigninLogs",
                "source": "coverage_gap",
                "threat_likelihood": 0.8,
                "detection_feasibility": 0.9,
                "business_impact": 0.7,
                "required_tables": ["SigninLogs"],
                "mitre_techniques": ["T1110"],
            },
            {
                "title": "Persistence via Scheduled Tasks",
                "description": "Check for malicious scheduled tasks",
                "source": "threat_landscape",
                "threat_likelihood": 0.6,
                "detection_feasibility": 0.5,
                "business_impact": 0.6,
                "required_tables": ["SecurityEvent"],
            },
        ])
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert len(hypotheses) == 2
        assert hypotheses[0].title == "Brute Force Attacks"
        assert hypotheses[0].priority_score > 0

    def test_parse_json_in_code_block(self, campaign_state: CampaignState):
        text = "Here are my hypotheses:\n```json\n" + json.dumps([
            {"title": "Test", "description": "Test hypothesis", "source": "analyst_input",
             "threat_likelihood": 0.5, "detection_feasibility": 0.5, "business_impact": 0.5,
             "required_tables": ["SigninLogs"]}
        ]) + "\n```"
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert len(hypotheses) == 1
        assert hypotheses[0].title == "Test"

    def test_parse_fallback_natural_language(self, campaign_state: CampaignState):
        text = "I recommend hunting for lateral movement using SigninLogs."
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert len(hypotheses) == 1
        assert hypotheses[0].source == HypothesisSource.COVERAGE_GAP

    def test_parse_available_tables_intersection(self, campaign_state: CampaignState):
        text = json.dumps([
            {"title": "Test", "description": "D", "source": "coverage_gap",
             "required_tables": ["SigninLogs", "NonExistentTable"],
             "threat_likelihood": 0.7, "detection_feasibility": 0.7, "business_impact": 0.7}
        ])
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert "SigninLogs" in hypotheses[0].available_tables
        assert "NonExistentTable" in hypotheses[0].missing_tables

    def test_parse_invalid_source_defaults(self, campaign_state: CampaignState):
        text = json.dumps([
            {"title": "Test", "description": "D", "source": "invalid_source",
             "required_tables": ["SigninLogs"]}
        ])
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert hypotheses[0].source == HypothesisSource.COVERAGE_GAP

    def test_parse_markdown_hypotheses(self, campaign_state: CampaignState):
        """Test parsing hypotheses from markdown format (real LLM output)."""
        text = """Here are 3 hypotheses:

---

Hypothesis 1 — Suspicious Azure AD Sign-ins
Description: Attackers may use stolen credentials to sign in from unusual locations.
Source: identity_risk
Required Tables: SigninLogs
MITRE Techniques: T1078, T1110
threat_likelihood: 0.85
detection_feasibility: 0.90
business_impact: 0.80

---

Hypothesis 2 — LSASS Credential Dumping
Description: Attackers may dump LSASS to obtain credentials.
Source: threat_landscape
Required Tables: SecurityEvent
MITRE Techniques: T1003
threat_likelihood: 0.7
detection_feasibility: 0.6
business_impact: 0.8

---

Hypothesis 3 — Persistence via Registry Run Keys
Description: Attackers may add registry run keys for persistence.
Required Tables: SecurityEvent
MITRE Techniques: T1547.001
threat_likelihood: 0.5
detection_feasibility: 0.5
business_impact: 0.5
"""
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert len(hypotheses) >= 2  # Should parse at least 2 meaningful sections
        # Check first hypothesis has expected attributes
        titles = [h.title for h in hypotheses]
        assert any("Sign-in" in t or "Credential" in t or "Azure" in t for t in titles)
        # MITRE techniques should be extracted
        all_mitre = []
        for h in hypotheses:
            all_mitre.extend(h.mitre_techniques)
        assert "T1078" in all_mitre or "T1003" in all_mitre

    def test_parse_markdown_extracts_scores(self, campaign_state: CampaignState):
        text = """---
Hypothesis 1 — Test Hypothesis
Description: A test
threat_likelihood: 0.8
detection_feasibility: 0.9
business_impact: 0.7
MITRE: T1059
Required Tables: SigninLogs, SecurityEvent
---
"""
        hypotheses = _parse_hypotheses_from_text(text, campaign_state)
        assert len(hypotheses) >= 1
        h = hypotheses[0]
        assert h.threat_likelihood == pytest.approx(0.8, abs=0.01)
        assert h.priority_score > 0

    def test_parse_markdown_empty_index_uses_regex_tables(self):
        """When index has 0 tables, parser should regex-extract table names from text."""
        # State with empty telemetry index
        state = CampaignState(
            campaign_id="CAMP-empty",
            config=CampaignConfig(client_name="TestCorp"),
            status="running",
            started_at="2026-01-01T00:00:00Z",
            environment_index=EnvironmentIndex(
                metadata=IndexMetadata(client_id="test"),
                telemetry=TelemetryIndex(tables=[]),  # empty!
            ),
        )
        text = """---
Hypothesis 1 — Suspicious Sign-ins
Description: Hunt for compromised credentials using SigninLogs and AuditLogs.
threat_likelihood: 0.8
detection_feasibility: 0.9
business_impact: 0.7
MITRE: T1078
---
"""
        hypotheses = _parse_hypotheses_from_text(text, state)
        assert len(hypotheses) >= 1
        h = hypotheses[0]
        # Should have extracted SigninLogs and AuditLogs via regex
        assert "SigninLogs" in h.available_tables or "AuditLogs" in h.available_tables

    def test_parse_fallback_empty_index_uses_defaults(self):
        """Fallback hypothesis should use default tables when index is empty."""
        state = CampaignState(
            campaign_id="CAMP-empty",
            config=CampaignConfig(client_name="TestCorp"),
            status="running",
            started_at="2026-01-01T00:00:00Z",
            environment_index=EnvironmentIndex(
                metadata=IndexMetadata(client_id="test"),
                telemetry=TelemetryIndex(tables=[]),
            ),
        )
        text = "Hunt for threats in the environment."
        hypotheses = _parse_hypotheses_from_text(text, state)
        assert len(hypotheses) == 1
        # Should have fallback tables so is_feasible passes
        assert len(hypotheses[0].available_tables) > 0

    def test_extract_artifacts_empty_index_skips_feasibility(self):
        """When index has 0 tables, hypotheses should not be filtered by is_feasible."""
        state = CampaignState(
            campaign_id="CAMP-empty",
            config=CampaignConfig(client_name="TestCorp", priority_threshold=0.1),
            status="running",
            started_at="2026-01-01T00:00:00Z",
            environment_index=EnvironmentIndex(
                metadata=IndexMetadata(client_id="test"),
                telemetry=TelemetryIndex(tables=[]),
            ),
        )
        mock_llm = MagicMock()
        mock_executor = MagicMock()
        budget = BudgetTracker(state.config)
        ctx = ContextManager()
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=ctx,
        )
        # Even with empty available_tables, hypothesis should survive
        response = """---
Hypothesis 1 — Credential Attack
Description: Look for credential attacks.
threat_likelihood: 0.8
detection_feasibility: 0.9
business_impact: 0.7
---
"""
        artifacts = runner.extract_artifacts(response, state)
        assert artifacts["hypotheses_viable"] >= 1


# ── Finding Extraction Tests ──────────────────────────────────────


class TestFindingExtraction:
    def test_extract_true_positive(self):
        hyp = _make_hypothesis()
        findings = _extract_findings_from_response(
            "This is a true_positive finding with critical severity. Confidence: 0.9",
            hyp, "CAMP-test",
        )
        assert len(findings) == 1
        assert findings[0].classification == FindingClassification.TRUE_POSITIVE
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_extract_false_positive(self):
        hyp = _make_hypothesis()
        findings = _extract_findings_from_response(
            "This is a false_positive finding. No malicious activity detected.",
            hyp, "CAMP-test",
        )
        # FPs with "finding" keyword still generate an entry
        assert len(findings) == 1
        assert findings[0].classification == FindingClassification.FALSE_POSITIVE

    def test_extract_inconclusive(self):
        hyp = _make_hypothesis()
        findings = _extract_findings_from_response(
            "Not enough data to determine. No clear evidence of malicious activity.",
            hyp, "CAMP-test",
        )
        assert len(findings) == 1
        assert findings[0].classification == FindingClassification.INCONCLUSIVE

    def test_extract_escalation(self):
        hyp = _make_hypothesis()
        findings = _extract_findings_from_response(
            "This requires escalation to the SOC team for further investigation.",
            hyp, "CAMP-test",
        )
        assert len(findings) == 1
        assert findings[0].classification == FindingClassification.REQUIRES_ESCALATION

    def test_extract_confidence_from_text(self):
        hyp = _make_hypothesis()
        findings = _extract_findings_from_response(
            "True positive finding. Confidence: 0.85 based on evidence.",
            hyp, "CAMP-test",
        )
        assert findings[0].confidence == pytest.approx(0.85, abs=0.1)

    def test_extract_preserves_mitre(self):
        hyp = _make_hypothesis()
        hyp.mitre_techniques = ["T1078", "T1110"]
        hyp.mitre_tactics = ["initial-access"]
        findings = _extract_findings_from_response(
            "True_positive finding with high severity.", hyp, "CAMP-test",
        )
        assert "T1078" in findings[0].mitre_techniques
        assert "initial-access" in findings[0].mitre_tactics


# ── Phase Runner Tests ─────────────────────────────────────────────


class TestHypothesizePhaseRunner:
    def test_phase_name(self, mock_llm, mock_executor, budget, context_mgr):
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        assert runner.phase_name() == CampaignPhase.HYPOTHESIZE

    def test_get_tools_subset(self, mock_llm, mock_executor, budget, context_mgr):
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        tools = runner.get_tools()
        tool_names = {t["function"]["name"] for t in tools}
        assert "search_mitre" in tool_names
        assert "check_landscape" in tool_names
        assert "run_kql_query" not in tool_names  # Not allowed in hypothesize

    def test_run_returns_phase_result(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        # LLM returns hypotheses as JSON
        hyp_json = json.dumps([
            {"title": "H1", "description": "Desc1", "source": "coverage_gap",
             "required_tables": ["SigninLogs"], "threat_likelihood": 0.8,
             "detection_feasibility": 0.8, "business_impact": 0.7},
        ])
        mock_llm.chat_with_tools.return_value = {
            "content": hyp_json,
            "tool_calls": None,
        }
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert result.phase == CampaignPhase.HYPOTHESIZE
        assert result.status == "success"
        assert len(campaign_state.hypotheses) >= 1

    def test_initial_user_message_includes_focus(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        campaign_state.config.focus_areas = ["ransomware", "credential theft"]
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        msg = runner.get_initial_user_message(campaign_state)
        assert "ransomware" in msg
        assert "credential theft" in msg


class TestExecutePhaseRunner:
    def test_phase_name(self, mock_llm, mock_executor, budget, context_mgr):
        runner = ExecutePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        assert runner.phase_name() == CampaignPhase.EXECUTE

    def test_get_tools_includes_kql(self, mock_llm, mock_executor, budget, context_mgr):
        runner = ExecutePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        tool_names = {t["function"]["name"] for t in runner.get_tools()}
        assert "run_kql_query" in tool_names
        assert "validate_kql" in tool_names

    def test_run_with_hypotheses(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        campaign_state.hypotheses = [_make_hypothesis()]
        mock_llm.chat_with_tools.return_value = {
            "content": "Inconclusive. No clear evidence found.",
            "tool_calls": None,
        }
        runner = ExecutePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert result.phase == CampaignPhase.EXECUTE
        assert result.status in ("success", "partial")

    def test_run_with_tool_calls(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        campaign_state.hypotheses = [_make_hypothesis()]

        # First call: tool call. Second call: final text.
        mock_llm.chat_with_tools.side_effect = [
            {
                "content": None,
                "tool_calls": [{
                    "id": "tc1",
                    "function": {
                        "name": "run_kql_query",
                        "arguments": '{"kql": "SigninLogs | take 10"}',
                    },
                }],
            },
            {
                "content": "True positive. Confidence: 0.8. High severity found.",
                "tool_calls": None,
            },
        ]
        runner = ExecutePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert result.tool_calls >= 1
        assert result.kql_queries_run >= 1
        assert len(campaign_state.findings) >= 1


class TestConcludePhaseRunner:
    def test_phase_name(self, mock_llm, mock_executor, budget, context_mgr):
        runner = ConcludePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        assert runner.phase_name() == CampaignPhase.CONCLUDE

    def test_get_tools_subset(self, mock_llm, mock_executor, budget, context_mgr):
        runner = ConcludePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        tool_names = {t["function"]["name"] for t in runner.get_tools()}
        assert "search_mitre" in tool_names
        assert "run_kql_query" not in tool_names

    def test_extract_artifacts_counts(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        campaign_state.findings = [
            HuntFinding(
                finding_id="F-1", hypothesis_id="H-1", title="F1",
                description="TP finding", classification=FindingClassification.TRUE_POSITIVE,
                severity=FindingSeverity.HIGH,
            ),
            HuntFinding(
                finding_id="F-2", hypothesis_id="H-1", title="F2",
                description="FP finding", classification=FindingClassification.FALSE_POSITIVE,
                severity=FindingSeverity.LOW,
            ),
        ]
        runner = ConcludePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        artifacts = runner.extract_artifacts("Review complete.", campaign_state)
        assert artifacts["findings_reviewed"] == 2
        assert artifacts["true_positives"] == 1
        assert artifacts["false_positives"] == 1


class TestDeliverPhaseRunner:
    def test_phase_name(self, mock_llm, mock_executor, budget, context_mgr):
        runner = DeliverPhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        assert runner.phase_name() == CampaignPhase.DELIVER

    def test_get_tools_subset(self, mock_llm, mock_executor, budget, context_mgr):
        runner = DeliverPhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        tool_names = {t["function"]["name"] for t in runner.get_tools()}
        assert "search_mitre" in tool_names
        assert "get_sentinel_rule_examples" in tool_names
        assert "run_kql_query" not in tool_names

    def test_run_produces_report(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        campaign_state.hypotheses = [_make_hypothesis()]
        campaign_state.hypotheses[0].findings_count = 1
        campaign_state.findings = [
            HuntFinding(
                finding_id="F-1", hypothesis_id="H-001", title="Finding 1",
                description="A finding", classification=FindingClassification.TRUE_POSITIVE,
                severity=FindingSeverity.HIGH, mitre_techniques=["T1078"],
                recommendations=["Block legacy auth"],
            ),
        ]
        mock_llm.chat_with_tools.return_value = {
            "content": "# Threat Hunt Report\n\n## Executive Summary\nAll good.",
            "tool_calls": None,
        }
        runner = DeliverPhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert result.status == "success"
        assert campaign_state.report is not None
        assert campaign_state.report.total_findings == 1
        assert campaign_state.report.true_positives == 1


class TestBuildReport:
    def test_build_report_counts(self, campaign_state: CampaignState):
        campaign_state.hypotheses = [_make_hypothesis()]
        campaign_state.hypotheses[0].findings_count = 2
        campaign_state.findings = [
            HuntFinding(
                finding_id="F-1", hypothesis_id="H-001", title="TP Finding",
                description="True positive", classification=FindingClassification.TRUE_POSITIVE,
                severity=FindingSeverity.CRITICAL, mitre_techniques=["T1078"],
                mitre_tactics=["initial-access"],
                recommendations=["Fix it"],
            ),
            HuntFinding(
                finding_id="F-2", hypothesis_id="H-001", title="FP Finding",
                description="False positive", classification=FindingClassification.FALSE_POSITIVE,
                severity=FindingSeverity.LOW,
            ),
        ]
        report = _build_report("# Report markdown", campaign_state)
        assert report.campaign_id == "CAMP-test"
        assert report.client_name == "TestCorp"
        assert report.total_findings == 2
        assert report.true_positives == 1
        assert report.false_positives == 1
        assert report.critical_findings == 1
        assert "T1078" in report.mitre_techniques_hunted
        assert "initial-access" in report.mitre_tactics_covered
        assert "Fix it" in report.recommendations
        assert "# Report markdown" in report.markdown

    def test_build_report_detection_suggestions(self, campaign_state: CampaignState):
        campaign_state.hypotheses = [_make_hypothesis()]
        campaign_state.findings = [
            HuntFinding(
                finding_id="F-1", hypothesis_id="H-001", title="Finding with KQL",
                description="Has detection rule", classification=FindingClassification.TRUE_POSITIVE,
                severity=FindingSeverity.HIGH,
                detection_rule_kql="SigninLogs | where ResultType != 0",
            ),
        ]
        report = _build_report("Report", campaign_state)
        assert len(report.detection_suggestions) == 1
        assert "SigninLogs" in report.detection_suggestions[0].kql_query


# ── Base PhaseRunner Tests ─────────────────────────────────────────


class TestBasePhaseRunner:
    def test_max_iterations_reached(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        """When max iterations reached, runner should force a final response."""
        # Override config for minimal iterations
        campaign_state.config.phase_max_iterations["hypothesize"] = 2

        # LLM always returns tool calls (never a final text)
        mock_llm.chat_with_tools.side_effect = [
            # Iteration 1: tool call
            {"content": None, "tool_calls": [{"id": "tc1", "function": {"name": "search_mitre", "arguments": '{"query": "T1078"}'}}]},
            # Iteration 2: tool call
            {"content": None, "tool_calls": [{"id": "tc2", "function": {"name": "search_mitre", "arguments": '{"query": "T1110"}'}}]},
            # Forced final (from for-else)
            {"content": "Final forced response with hypotheses.", "tool_calls": None},
        ]

        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert result.status == "partial"  # Hit max iterations

    def test_empty_response_breaks_loop(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        """LLM returning empty response should break the loop."""
        mock_llm.chat_with_tools.return_value = {
            "content": None,
            "tool_calls": None,
        }
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert "empty response" in result.errors[0].lower()

    def test_llm_error_breaks_loop(self, mock_llm, mock_executor, budget, context_mgr, campaign_state):
        """LLM exception should break the loop with error."""
        mock_llm.chat_with_tools.side_effect = RuntimeError("LLM unavailable")
        runner = HypothesizePhaseRunner(
            llm=mock_llm, tool_executor=mock_executor,
            budget=budget, context_manager=context_mgr,
        )
        result = runner.run(campaign_state)
        assert any("LLM call failed" in e for e in result.errors)
