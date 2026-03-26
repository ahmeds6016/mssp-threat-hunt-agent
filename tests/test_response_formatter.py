"""Tests for the V5.1 response formatter."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse
from mssp_hunt_agent.agent.response_formatter import format_response, _strip_markdown


class TestStripMarkdown:
    def test_removes_code_fences(self) -> None:
        text = "Here is the KQL:\n```kql\nSecurityEvent\n| where EventID == 4625\n```"
        result = _strip_markdown(text)
        assert "```" not in result
        assert "SecurityEvent" in result

    def test_removes_inline_backticks(self) -> None:
        text = "Run `Get-Process` to check"
        result = _strip_markdown(text)
        assert "`" not in result
        assert "Get-Process" in result

    def test_removes_bold(self) -> None:
        text = "This is **important** text"
        result = _strip_markdown(text)
        assert "**" not in result
        assert "important" in result

    def test_removes_italic(self) -> None:
        text = "This is *italic* text"
        result = _strip_markdown(text)
        assert result == "This is italic text"

    def test_plain_text_unchanged(self) -> None:
        text = "No markdown here"
        assert _strip_markdown(text) == text


class TestFormatResponse:
    def test_cve_response(self) -> None:
        response = AgentResponse(
            summary="CVE-2025-55182 assessment complete.",
            intent=AgentIntent.CVE_CHECK,
            confidence=0.9,
            details={
                "verdict": "Potentially affected",
                "in_cisa_kev": True,
                "gaps": ["T1566", "T1190"],
                "recommendations": ["Enable email filtering", "Patch immediately"],
            },
        )
        text = format_response(response)
        assert "CVE-2025-55182" in text
        assert "ACTIVELY EXPLOITED" in text
        assert "Potentially affected" in text
        assert "Enable email filtering" in text

    def test_detection_rule_response(self) -> None:
        response = AgentResponse(
            summary="Detection rule generated: 'Test Rule'\nSeverity: Medium\nKQL:\nSecurityEvent | where EventID == 4625",
            intent=AgentIntent.DETECTION_RULE,
            confidence=0.85,
            details={
                "severity": "Severity.MEDIUM",
                "mitre_techniques": ["T1110"],
                "data_sources": ["SecurityEvent"],
                "false_positive_guidance": "Failed logins from service accounts",
            },
        )
        text = format_response(response)
        assert "Medium" in text
        assert "Severity.MEDIUM" not in text or "Medium" in text
        assert "T1110" in text
        assert "False Positive Guidance" in text

    def test_risk_response(self) -> None:
        response = AgentResponse(
            summary="Risk assessment complete.",
            intent=AgentIntent.RISK_ASSESSMENT,
            confidence=0.8,
            details={
                "risk_rating": "high",
                "blind_spots": ["lateral movement", "credential access"],
                "recommendations": ["Deploy EDR", "Enable audit logging"],
            },
        )
        text = format_response(response)
        assert "HIGH" in text
        assert "lateral movement" in text

    def test_follow_up_suggestions(self) -> None:
        response = AgentResponse(
            summary="Done.",
            intent=AgentIntent.GENERAL_QUESTION,
            follow_up_suggestions=["Try this", "Or that"],
        )
        text = format_response(response)
        assert "You can also try:" in text
        assert "Try this" in text

    def test_strips_markdown_from_summary(self) -> None:
        response = AgentResponse(
            summary="Rule:\n```kql\nSecurityEvent\n```",
            intent=AgentIntent.GENERAL_QUESTION,
        )
        text = format_response(response)
        assert "```" not in text
        assert "SecurityEvent" in text

    def test_hunt_response(self) -> None:
        response = AgentResponse(
            summary="Threat hunt started.",
            intent=AgentIntent.RUN_HUNT,
            details={"client": "PurpleStratus", "status": "running"},
        )
        text = format_response(response)
        assert "PurpleStratus" in text

    def test_landscape_response(self) -> None:
        response = AgentResponse(
            summary="Threat landscape analysis.",
            intent=AgentIntent.LANDSCAPE_CHECK,
            details={"alerts": [{"msg": "a"}], "gaps": [{"msg": "b"}, {"msg": "c"}]},
        )
        text = format_response(response)
        assert "Coverage gaps: 2" in text
