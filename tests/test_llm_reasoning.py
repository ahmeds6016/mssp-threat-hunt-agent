"""Tests for the LLM reasoning pipeline and fallback logic."""

from __future__ import annotations

import uuid

import pytest

from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
from mssp_hunt_agent.models.input_models import HuntInput
from mssp_hunt_agent.models.result_models import (
    EnrichmentRecord,
    ExabeamEvent,
    QueryResult,
)
from mssp_hunt_agent.pipeline.intake import classify_telemetry
from mssp_hunt_agent.pipeline.planner import generate_plan
from mssp_hunt_agent.pipeline.llm_reasoning import (
    llm_analyse,
    _build_user_prompt,
    _parse_findings,
    _parse_evidence,
    _parse_confidence,
)


@pytest.fixture
def plan_and_data(identity_input: HuntInput):
    """Build a plan + query results + enrichments for testing."""
    telemetry = classify_telemetry(identity_input)
    plan = generate_plan(identity_input, telemetry)

    query_results = [
        QueryResult(
            query_id="Q-test-llm",
            query_text="src_ip = '185.220.101.34'",
            status="success",
            result_count=5,
            execution_time_ms=120,
            events=[
                ExabeamEvent(
                    timestamp="2024-11-15T03:22:41Z",
                    event_type="authentication-failure",
                    user="jsmith",
                    src_ip="185.220.101.34",
                )
                for _ in range(5)
            ],
        )
    ]

    enrichments = [
        EnrichmentRecord(
            entity_type="ip",
            entity_value="185.220.101.34",
            source="MockTI",
            verdict="malicious",
            confidence=0.85,
            labels=["known-bad", "c2-infra"],
        )
    ]

    return plan, query_results, enrichments


class TestLLMReasoning:
    """Tests for llm_analyse() with MockLLMAdapter."""

    def test_mock_adapter_produces_findings(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        adapter = MockLLMAdapter()
        findings, evidence, confidence = llm_analyse(plan, qr, enrich, adapter)

        assert len(findings) >= 1
        assert findings[0].title  # non-empty
        assert findings[0].confidence in ("low", "medium", "high")

    def test_mock_adapter_produces_evidence(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        adapter = MockLLMAdapter()
        findings, evidence, confidence = llm_analyse(plan, qr, enrich, adapter)

        assert len(evidence) >= 1
        assert evidence[0].source == "llm_analysis"

    def test_mock_adapter_produces_confidence(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        adapter = MockLLMAdapter()
        findings, evidence, confidence = llm_analyse(plan, qr, enrich, adapter)

        assert confidence.overall_confidence in ("low", "medium", "high")
        assert confidence.rationale

    def test_fallback_on_adapter_failure(self, plan_and_data) -> None:
        """When LLM fails, should fall back to rule-based reasoning."""
        plan, qr, enrich = plan_and_data
        adapter = MockLLMAdapter(should_fail=True)
        findings, evidence, confidence = llm_analyse(plan, qr, enrich, adapter)

        # Rule-based reasoning still produces results
        assert len(findings) >= 1
        assert confidence.overall_confidence in ("low", "medium", "high")

    def test_fallback_with_empty_data(self, minimal_input: HuntInput) -> None:
        """Fallback on failure still works with no results."""
        telemetry = classify_telemetry(minimal_input)
        plan = generate_plan(minimal_input, telemetry)
        adapter = MockLLMAdapter(should_fail=True)

        findings, evidence, confidence = llm_analyse(plan, [], [], adapter)

        assert len(findings) >= 1
        assert "No High-Confidence Threats" in findings[0].title

    def test_llm_result_structure(self, plan_and_data) -> None:
        """Verify full structure of LLM results."""
        plan, qr, enrich = plan_and_data
        adapter = MockLLMAdapter()
        findings, evidence, confidence = llm_analyse(plan, qr, enrich, adapter)

        for f in findings:
            assert f.finding_id.startswith("F-LLM-")
            assert f.description
            assert isinstance(f.benign_explanations, list)
            assert isinstance(f.what_would_increase_confidence, list)

        for e in evidence:
            assert e.evidence_id.startswith("E-LLM-")
            assert e.significance in (
                "informational", "suspicious", "high_confidence"
            )


class TestPromptConstruction:
    """Tests for _build_user_prompt."""

    def test_prompt_includes_hunt_context(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        prompt = _build_user_prompt(plan, qr, enrich)

        assert "Hunt Context" in prompt
        assert plan.client_name in prompt
        assert plan.objective in prompt

    def test_prompt_includes_query_results(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        prompt = _build_user_prompt(plan, qr, enrich)

        assert "Query Results" in prompt
        assert "Q-test-llm" in prompt
        assert "success" in prompt

    def test_prompt_includes_enrichments(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        prompt = _build_user_prompt(plan, qr, enrich)

        assert "Threat Intelligence Enrichments" in prompt
        assert "185.220.101.34" in prompt
        assert "malicious" in prompt

    def test_prompt_includes_telemetry_assessment(self, plan_and_data) -> None:
        plan, qr, enrich = plan_and_data
        prompt = _build_user_prompt(plan, qr, enrich)

        assert "Telemetry Assessment" in prompt
        assert "Readiness" in prompt

    def test_prompt_with_no_enrichments(self, plan_and_data) -> None:
        plan, qr, _ = plan_and_data
        prompt = _build_user_prompt(plan, qr, [])

        assert "No enrichments available" in prompt

    def test_prompt_with_error_query(self, plan_and_data) -> None:
        plan, _, enrich = plan_and_data
        error_qr = [
            QueryResult(
                query_id="Q-err",
                query_text="bad",
                status="error",
                error_message="timeout",
            )
        ]
        prompt = _build_user_prompt(plan, error_qr, enrich)
        assert "timeout" in prompt


class TestResponseParsing:
    """Tests for _parse_findings, _parse_evidence, _parse_confidence."""

    def test_parse_findings_basic(self) -> None:
        raw = [
            {
                "finding_id": "F-LLM-abc12345",
                "title": "Test Finding",
                "description": "A test finding",
                "confidence": "medium",
                "evidence_ids": ["E-1"],
                "benign_explanations": ["Could be normal"],
                "what_would_increase_confidence": ["More data"],
            }
        ]
        findings = _parse_findings(raw)

        assert len(findings) == 1
        assert findings[0].finding_id == "F-LLM-abc12345"
        assert findings[0].title == "Test Finding"
        assert findings[0].confidence == "medium"
        assert len(findings[0].benign_explanations) == 1
        assert len(findings[0].what_would_increase_confidence) == 1

    def test_parse_findings_missing_fields(self) -> None:
        raw = [{"title": "Partial"}]
        findings = _parse_findings(raw)

        assert len(findings) == 1
        assert findings[0].title == "Partial"
        assert findings[0].finding_id.startswith("F-LLM-")
        assert findings[0].confidence == "low"  # default

    def test_parse_evidence_basic(self) -> None:
        raw = [
            {
                "evidence_id": "E-LLM-abc12345",
                "source": "llm_analysis",
                "observation": "Something observed",
                "significance": "suspicious",
                "supporting_data": "data",
            }
        ]
        evidence = _parse_evidence(raw)

        assert len(evidence) == 1
        assert evidence[0].evidence_id == "E-LLM-abc12345"
        assert evidence[0].significance == "suspicious"

    def test_parse_evidence_defaults(self) -> None:
        raw = [{}]
        evidence = _parse_evidence(raw)

        assert len(evidence) == 1
        assert evidence[0].source == "llm_analysis"
        assert evidence[0].significance == "informational"

    def test_parse_confidence(self, plan_and_data) -> None:
        plan, _, _ = plan_and_data
        raw = {
            "overall_confidence": "high",
            "rationale": "Strong evidence",
            "limiting_factors": ["Factor A"],
            "telemetry_impact": "Good coverage",
        }
        confidence = _parse_confidence(raw, plan)

        assert confidence.overall_confidence == "high"
        assert confidence.rationale == "Strong evidence"
        assert "Factor A" in confidence.limiting_factors

    def test_parse_confidence_defaults(self, plan_and_data) -> None:
        plan, _, _ = plan_and_data
        confidence = _parse_confidence({}, plan)

        assert confidence.overall_confidence == "low"
        assert confidence.telemetry_impact == plan.telemetry_assessment.impact_on_hunt


class TestMockLLMAdapter:
    """Direct tests for MockLLMAdapter."""

    def test_analyze_returns_valid_structure(self) -> None:
        adapter = MockLLMAdapter()
        result = adapter.analyze("system", "user")

        assert "findings" in result
        assert "evidence_items" in result
        assert "confidence_assessment" in result
        assert len(result["findings"]) >= 1

    def test_analyze_fail_raises(self) -> None:
        adapter = MockLLMAdapter(should_fail=True)
        with pytest.raises(RuntimeError, match="configured to fail"):
            adapter.analyze("system", "user")

    def test_test_connection_healthy(self) -> None:
        assert MockLLMAdapter().test_connection() is True

    def test_test_connection_failing(self) -> None:
        assert MockLLMAdapter(should_fail=True).test_connection() is False

    def test_get_adapter_name(self) -> None:
        assert MockLLMAdapter().get_adapter_name() == "MockLLMAdapter"
