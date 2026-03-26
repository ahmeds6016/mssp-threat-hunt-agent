"""Tests for the reasoning / analysis stage."""

from __future__ import annotations

from mssp_hunt_agent.models.input_models import HuntInput
from mssp_hunt_agent.models.result_models import (
    EnrichmentRecord,
    ExabeamEvent,
    QueryResult,
)
from mssp_hunt_agent.pipeline.intake import classify_telemetry
from mssp_hunt_agent.pipeline.planner import generate_plan
from mssp_hunt_agent.pipeline.reasoning import analyse


class TestReasoning:
    def test_produces_findings_and_evidence(self, identity_input: HuntInput) -> None:
        telemetry = classify_telemetry(identity_input)
        plan = generate_plan(identity_input, telemetry)

        query_results = [
            QueryResult(
                query_id="Q-test",
                query_text="test",
                status="success",
                result_count=5,
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

        findings, evidence, confidence = analyse(plan, query_results, enrichments)

        assert len(findings) >= 1
        assert len(evidence) >= 1
        assert confidence.overall_confidence in ("low", "medium", "high")

    def test_no_results_produces_no_threat_finding(self, minimal_input: HuntInput) -> None:
        telemetry = classify_telemetry(minimal_input)
        plan = generate_plan(minimal_input, telemetry)

        findings, evidence, confidence = analyse(plan, [], [])

        assert len(findings) >= 1
        assert "No High-Confidence Threats" in findings[0].title

    def test_error_query_produces_evidence(self, minimal_input: HuntInput) -> None:
        telemetry = classify_telemetry(minimal_input)
        plan = generate_plan(minimal_input, telemetry)

        query_results = [
            QueryResult(
                query_id="Q-err",
                query_text="bad query",
                status="error",
                error_message="Connection timeout",
            )
        ]

        findings, evidence, confidence = analyse(plan, query_results, [])

        error_evidence = [e for e in evidence if "failed" in e.observation]
        assert len(error_evidence) >= 1
