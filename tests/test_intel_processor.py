"""Tests for intel processor — article correlation, relevance scoring, and extraction."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from mssp_hunt_agent.intel.intel_processor import IntelEvent, IntelProcessor


# ── Sample Data ───────────────────────────────────────────────────────

SAMPLE_ARTICLES = [
    {
        "article_id": "aaa111",
        "title": "North Korea Compromises axios NPM Package",
        "url": "https://blog.google/nk-axios",
        "published": "2026-03-31T14:00:00Z",
        "source": "Google TAG",
        "category": "apt",
        "summary": "UNC4899 compromised the axios npm package via maintainer account takeover.",
        "tags": ["APT", "Supply Chain"],
    },
    {
        "article_id": "bbb222",
        "title": "STARDUST CHOLLIMA Likely Compromises Axios npm Package",
        "url": "https://crowdstrike.com/axios-npm",
        "published": "2026-03-31T16:00:00Z",
        "source": "CrowdStrike Blog",
        "category": "apt",
        "summary": "CrowdStrike tracks the axios supply chain compromise to STARDUST CHOLLIMA.",
        "tags": ["Supply Chain"],
    },
    {
        "article_id": "ccc333",
        "title": "WhatsApp Malware Campaign Delivers VBScript Backdoors",
        "url": "https://microsoft.com/whatsapp-malware",
        "published": "2026-03-31T13:00:00Z",
        "source": "Microsoft Security Blog",
        "category": "general",
        "summary": "A new WhatsApp-based campaign delivers VBScript and MSI backdoors to targets.",
        "tags": ["Malware"],
    },
    {
        "article_id": "ddd444",
        "title": "Critical RCE in Apache Struts CVE-2026-1234",
        "url": "https://example.com/struts-rce",
        "published": "2026-03-30T10:00:00Z",
        "source": "BleepingComputer",
        "category": "vulnerability",
        "summary": "A critical remote code execution vulnerability in Apache Struts.",
        "tags": ["CVE", "RCE"],
    },
]

SAMPLE_ENV_SUMMARY = {
    "client_name": "PurpleStratus",
    "tables": ["SecurityEvent", "SigninLogs", "DeviceProcessEvents", "Syslog"],
    "assets": {"windows_servers": 2, "workstations": 2, "linux_servers": 1},
    "users": {"total": 10, "admins": 3, "mfa_enabled": 2},
}


# ── Mock LLM Responses ───────────────────────────────────────────────

def make_mock_llm():
    """Create a mock LLM adapter with realistic responses."""
    mock = MagicMock()

    import json

    # chat_with_tools returns {"content": "json_string"} format
    mock.chat_with_tools.side_effect = [
        # First call: correlation
        {"content": json.dumps({
            "events": [
                {
                    "title": "North Korea Supply Chain Attack on axios NPM Package",
                    "severity": "high",
                    "category": "supply_chain",
                    "summary": "North Korea-nexus threat actor compromised the axios npm package via maintainer account takeover.",
                    "article_indices": [0, 1],
                },
                {
                    "title": "WhatsApp VBScript Malware Campaign",
                    "severity": "medium",
                    "category": "malware",
                    "summary": "A WhatsApp-based social engineering campaign delivers VBScript backdoors.",
                    "article_indices": [2],
                },
                {
                    "title": "Apache Struts Critical RCE (CVE-2026-1234)",
                    "severity": "critical",
                    "category": "vulnerability",
                    "summary": "Remote code execution vulnerability in Apache Struts.",
                    "article_indices": [3],
                },
            ]
        })},
        # Second call: relevance for event 1
        {"content": json.dumps({"relevance_score": 0.3, "reasoning": "No npm activity in environment", "hunt_recommended": False, "priority_hunt_areas": []})},
        # Third call: relevance for event 2
        {"content": json.dumps({"relevance_score": 0.7, "reasoning": "Windows endpoints present, VBScript in sim data", "hunt_recommended": True, "priority_hunt_areas": ["VBScript execution"]})},
        # Fourth call: relevance for event 3
        {"content": json.dumps({"relevance_score": 0.2, "reasoning": "No Apache Struts in environment", "hunt_recommended": False, "priority_hunt_areas": []})},
        # Fifth call: extraction for event 2 (only one above threshold)
        {"content": json.dumps({
            "iocs": [{"type": "domain", "value": "evil-whatsapp.com", "context": "C2 server"}],
            "mitre_techniques": ["T1059.005", "T1204.002"],
            "mitre_tactics": ["Execution", "Initial Access"],
            "cves": [],
            "affected_software": ["WhatsApp Desktop"],
            "threat_actor": "",
            "kill_chain_phases": ["initial_access", "execution"],
            "recommended_queries": ["DeviceProcessEvents | where ProcessCommandLine has 'wscript'"],
        })},
    ]
    return mock


class TestIntelEvent:
    def test_to_dict(self) -> None:
        event = IntelEvent(
            event_id="INTEL-20260331-0001",
            title="Test Event",
            severity="high",
            category="apt",
            summary="Test summary",
            article_count=2,
            sources=["Source A", "Source B"],
        )
        d = event.to_dict()
        assert d["event_id"] == "INTEL-20260331-0001"
        assert d["article_count"] == 2
        assert "Source A" in d["sources"]


class TestCorrelation:
    def test_correlate_groups_related_articles(self) -> None:
        mock_llm = make_mock_llm()
        processor = IntelProcessor(llm=mock_llm)
        events = processor.correlate_articles(SAMPLE_ARTICLES)

        assert len(events) == 3
        # First event should have 2 articles (axios)
        axios_event = next(e for e in events if "axios" in e.title.lower() or "supply chain" in e.title.lower())
        assert axios_event.article_count == 2
        assert len(axios_event.sources) == 2

    def test_correlate_empty_input(self) -> None:
        mock_llm = MagicMock()
        processor = IntelProcessor(llm=mock_llm)
        events = processor.correlate_articles([])
        assert events == []

    def test_correlate_fallback_on_error(self) -> None:
        mock_llm = MagicMock()
        mock_llm.analyze.side_effect = Exception("LLM error")
        processor = IntelProcessor(llm=mock_llm)
        events = processor.correlate_articles(SAMPLE_ARTICLES)
        # Each article becomes its own event
        assert len(events) == 4


class TestRelevanceScoring:
    def test_score_returns_sorted_by_relevance(self) -> None:
        mock_llm = make_mock_llm()
        processor = IntelProcessor(llm=mock_llm)

        events = processor.correlate_articles(SAMPLE_ARTICLES)
        scored = processor.score_relevance(events, SAMPLE_ENV_SUMMARY)

        # Should be sorted highest first
        assert scored[0].relevance_score >= scored[-1].relevance_score
        # WhatsApp event should be highest (0.7)
        assert scored[0].relevance_score == 0.7

    def test_score_empty_events(self) -> None:
        mock_llm = MagicMock()
        processor = IntelProcessor(llm=mock_llm)
        assert processor.score_relevance([], {}) == []


class TestExtraction:
    def test_extract_populates_iocs(self) -> None:
        mock_llm = make_mock_llm()
        processor = IntelProcessor(llm=mock_llm)

        events = processor.correlate_articles(SAMPLE_ARTICLES)
        scored = processor.score_relevance(events, SAMPLE_ENV_SUMMARY)
        enriched = processor.extract_intel(scored, min_relevance=0.5)

        # Only the WhatsApp event (0.7) should have extraction
        whatsapp = next(e for e in enriched if e.relevance_score == 0.7)
        assert len(whatsapp.iocs) > 0
        assert "T1059.005" in whatsapp.mitre_techniques

        # Low relevance events should NOT have extraction
        low = [e for e in enriched if e.relevance_score < 0.5]
        for e in low:
            assert e.iocs == []

    def test_extract_skips_below_threshold(self) -> None:
        mock_llm = MagicMock()
        processor = IntelProcessor(llm=mock_llm)

        event = IntelEvent(
            event_id="TEST-001", title="Low relevance", severity="low",
            category="general", summary="Not relevant", relevance_score=0.2,
        )
        result = processor.extract_intel([event], min_relevance=0.5)
        # LLM should NOT have been called
        mock_llm.analyze.assert_not_called()
        assert result[0].iocs == []


class TestFullPipeline:
    def test_process_articles_end_to_end(self) -> None:
        mock_llm = make_mock_llm()
        processor = IntelProcessor(llm=mock_llm)

        results = processor.process_articles(
            SAMPLE_ARTICLES, SAMPLE_ENV_SUMMARY, relevance_threshold=0.5,
        )

        # Should return only events above threshold
        assert len(results) >= 1
        assert all(e.relevance_score >= 0.5 for e in results)


class TestJsonExtraction:
    def test_extract_json_from_findings(self) -> None:
        response = {"findings": {"key": "value"}}
        result = IntelProcessor._extract_json(response)
        assert result == {"key": "value"}

    def test_extract_json_from_code_fence(self) -> None:
        response = {"content": 'Here is the result:\n```json\n{"key": "value"}\n```'}
        result = IntelProcessor._extract_json(response)
        assert result == {"key": "value"}

    def test_extract_json_from_raw_text(self) -> None:
        response = {"content": '{"events": []}'}
        result = IntelProcessor._extract_json(response)
        assert result == {"events": []}

    def test_extract_json_returns_none_on_failure(self) -> None:
        response = {"content": "no json here at all"}
        result = IntelProcessor._extract_json(response)
        assert result is None
