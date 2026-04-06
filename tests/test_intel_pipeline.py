"""Tests for intel campaign launcher, executive report builder, email delivery, and pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.intel.executive_report import ExecutiveReportBuilder, IntelReport
from mssp_hunt_agent.intel.intel_campaign import IntelCampaignLauncher
from mssp_hunt_agent.intel.intel_processor import IntelEvent
from mssp_hunt_agent.persistence.email_delivery import EmailSender


# ── Test Fixtures ─────────────────────────────────────────────────────

def make_intel_event() -> IntelEvent:
    return IntelEvent(
        event_id="INTEL-20260331-0001",
        title="North Korea Supply Chain Attack on axios NPM Package",
        severity="high",
        category="supply_chain",
        summary="UNC4899 compromised the axios npm package via maintainer account takeover.",
        articles=[{"title": "Article 1", "source": "Google TAG", "summary": "..."}],
        article_count=2,
        sources=["Google TAG", "CrowdStrike"],
        relevance_score=0.7,
        relevance_reasoning="Windows endpoints present",
        iocs=[
            {"type": "domain", "value": "evil.com", "context": "C2 server"},
            {"type": "hash_sha256", "value": "abc123def456", "context": "Malware payload"},
        ],
        mitre_techniques=["T1195.002", "T1059.007"],
        mitre_tactics=["Initial Access", "Execution"],
        cves=[],
        affected_software=["axios 1.14.1", "plain-crypto-js"],
        threat_actor="UNC4899",
        kill_chain_phases=["initial_access", "execution", "command_and_control"],
        recommended_queries=["DeviceProcessEvents | where ProcessCommandLine has 'axios'"],
    )


def make_mock_campaign_state():
    state = MagicMock()
    state.campaign_id = "INTEL-CAMP-abc123"
    state.status = "completed"
    state.total_kql_queries = 12
    state.hypotheses = [MagicMock(), MagicMock()]
    state.findings = []
    state.duration_minutes = 8.5
    state.errors = []
    return state


# ── Intel Campaign Launcher Tests ─────────────────────────────────────

class TestIntelCampaignLauncher:
    def test_build_focus_areas(self) -> None:
        config = MagicMock()
        config.default_client_name = "PurpleStratus"
        llm = MagicMock()
        launcher = IntelCampaignLauncher(agent_config=config, llm=llm)
        event = make_intel_event()
        areas = launcher._build_focus_areas(event)
        assert "Initial Access" in areas
        assert any("UNC4899" in a for a in areas)

    def test_build_intel_context(self) -> None:
        config = MagicMock()
        config.default_client_name = "PurpleStratus"
        llm = MagicMock()
        launcher = IntelCampaignLauncher(agent_config=config, llm=llm)
        event = make_intel_event()
        context = launcher._build_intel_context(event)
        assert "UNC4899" in context
        assert "T1195.002" in context
        assert "evil.com" in context
        assert "axios 1.14.1" in context


# ── Executive Report Builder Tests ────────────────────────────────────

class TestExecutiveReportBuilder:
    def test_build_report_no_findings(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        state.findings = []
        report = builder.build_report(event, state)
        assert report.verdict == "not_exposed"
        assert report.risk_level == "low"
        assert "No indicators" in report.verdict_summary

    def test_build_report_with_true_positive(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        finding = MagicMock()
        finding.classification.value = "true_positive"
        finding.severity.value = "high"
        finding.title = "Malicious axios package detected"
        finding.description = "Found axios 1.14.1 in process logs"
        state.findings = [finding]
        report = builder.build_report(event, state)
        assert report.verdict == "exposed"
        assert report.risk_level == "high"
        assert report.hunt_findings_count == 1

    def test_to_markdown(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        report = builder.build_report(event, state)
        md = builder.to_markdown(report)
        assert "# Threat Intelligence Assessment" in md
        assert "UNC4899" in md
        assert report.campaign_id in md

    def test_to_html(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        report = builder.build_report(event, state)
        html = builder.to_html(report)
        assert "<html" in html
        assert "THREAT INTELLIGENCE ASSESSMENT" in html
        assert report.campaign_id in html

    def test_recommendations_for_exposed(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        recs = builder._build_recommendations(event, state, "exposed")
        assert any("incident response" in r.lower() for r in recs)

    def test_recommendations_for_not_exposed(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        recs = builder._build_recommendations(event, state, "not_exposed")
        assert any("monitoring" in r.lower() for r in recs)

    def test_identify_gaps(self) -> None:
        builder = ExecutiveReportBuilder()
        event = make_intel_event()
        state = make_mock_campaign_state()
        gaps = builder._identify_gaps(event, state)
        assert len(gaps) > 0


# ── Email Delivery Tests ──────────────────────────────────────────────

class TestEmailSender:
    def test_send_report_success(self) -> None:
        sender = EmailSender(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            sender_email="agent@test.com",
        )
        sender._token = "fake-token"

        mock_resp = MagicMock()
        mock_resp.status_code = 202

        with patch("mssp_hunt_agent.persistence.email_delivery.httpx.post", return_value=mock_resp):
            result = sender.send_report(
                to=["analyst@test.com"],
                subject="Test Report",
                html_body="<p>Test</p>",
            )
            assert result is True

    def test_send_report_failure(self) -> None:
        sender = EmailSender(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            sender_email="agent@test.com",
        )
        sender._token = "fake-token"

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"

        with patch("mssp_hunt_agent.persistence.email_delivery.httpx.post", return_value=mock_resp):
            result = sender.send_report(
                to=["analyst@test.com"],
                subject="Test Report",
                html_body="<p>Test</p>",
            )
            assert result is False

    def test_send_intel_report_builds_subject(self) -> None:
        sender = EmailSender(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            sender_email="agent@test.com",
        )
        sender._token = "fake-token"

        mock_resp = MagicMock()
        mock_resp.status_code = 202

        report = MagicMock()
        report.intel_event_title = "Test Threat"
        report.verdict = "not_exposed"
        report.risk_level = "low"

        with patch("mssp_hunt_agent.persistence.email_delivery.httpx.post", return_value=mock_resp) as mock_post:
            sender.send_intel_report(to=["a@b.com"], report=report, html_body="<p>Test</p>")
            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert "[THREAT INTEL]" in payload["message"]["subject"]
            assert "NOT EXPOSED" in payload["message"]["subject"]
