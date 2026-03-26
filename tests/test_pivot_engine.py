"""Tests for the pivot engine — bounded follow-up query generation."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.models.hunt_models import (
    ExabeamQuery,
    HuntHypothesis,
    HuntPlan,
    HuntStep,
    QueryIntent,
    TelemetryAssessment,
    TelemetryReadiness,
)
from mssp_hunt_agent.models.result_models import EnrichmentRecord, ExabeamEvent, QueryResult
from mssp_hunt_agent.pipeline.pivot_engine import PivotEngine


def _make_plan(time_range: str = "2024-11-01 to 2024-11-30") -> HuntPlan:
    return HuntPlan(
        plan_id="HP-test",
        client_name="TestCorp",
        hunt_type="identity",
        objective="Test hunt",
        hypotheses=[
            HuntHypothesis(
                hypothesis_id="H-1",
                description="Test hypothesis",
                technique_source="inferred",
                confidence="medium",
                rationale="Test rationale",
            ),
        ],
        telemetry_assessment=TelemetryAssessment(
            readiness=TelemetryReadiness.GREEN,
            rationale="Adequate",
            impact_on_hunt="Minimal",
        ),
        hunt_steps=[
            HuntStep(
                step_number=1,
                description="Baseline",
                queries=[
                    ExabeamQuery(
                        query_id="Q-1",
                        intent=QueryIntent.BASELINE,
                        description="Baseline query",
                        query_text='user = "jsmith"',
                        time_range=time_range,
                        expected_signal="Auth events",
                    ),
                ],
                success_criteria="Events found",
                next_if_positive="Investigate",
                next_if_negative="Close",
            ),
        ],
        triage_checklist=["Check user"],
        escalation_criteria=["High confidence finding"],
        created_at="2024-12-01T00:00:00Z",
    )


def _make_query_results(
    users: list[str] | None = None,
    src_ips: list[str] | None = None,
) -> list[QueryResult]:
    events = []
    for user, ip in zip(users or ["jsmith"], src_ips or ["203.0.113.77"]):
        events.append(ExabeamEvent(
            timestamp="2024-11-15T10:00:00Z",
            event_type="auth",
            user=user,
            src_ip=ip,
        ))
    return [
        QueryResult(
            query_id="Q-1",
            query_text='user = "jsmith"',
            status="success",
            result_count=len(events),
            events=events,
        ),
    ]


def _make_enrichments(
    ips: list[tuple[str, str]] | None = None,
    hashes: list[tuple[str, str]] | None = None,
) -> list[EnrichmentRecord]:
    records = []
    for ip, verdict in (ips or []):
        records.append(EnrichmentRecord(
            entity_type="ip",
            entity_value=ip,
            source="TestTI",
            verdict=verdict,
            confidence=0.8,
        ))
    for h, verdict in (hashes or []):
        records.append(EnrichmentRecord(
            entity_type="hash",
            entity_value=h,
            source="TestTI",
            verdict=verdict,
            confidence=0.8,
        ))
    return records


class TestPivotEngine:
    def test_no_pivots_when_no_suspicious(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results()
        enrichments = _make_enrichments(ips=[("10.0.0.1", "benign")])

        pivots = engine.generate_pivots(plan, results, enrichments)

        assert len(pivots) == 0

    def test_ip_to_users_pivot(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results()
        enrichments = _make_enrichments(ips=[("203.0.113.77", "malicious")])

        pivots = engine.generate_pivots(plan, results, enrichments)

        assert len(pivots) >= 1
        ip_pivots = [p for p in pivots if "203.0.113.77" in p.query_text]
        assert len(ip_pivots) >= 1
        assert ip_pivots[0].is_pivot is True
        assert ip_pivots[0].intent == QueryIntent.PIVOT

    def test_user_to_hosts_pivot(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results(users=["jsmith"], src_ips=["203.0.113.77"])
        enrichments = _make_enrichments(ips=[("203.0.113.77", "suspicious")])

        pivots = engine.generate_pivots(plan, results, enrichments)

        user_pivots = [p for p in pivots if "jsmith" in p.query_text]
        assert len(user_pivots) >= 1

    def test_hash_to_hosts_pivot(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results()
        enrichments = _make_enrichments(
            hashes=[("e99a18c428cb38d5f260853678922e03", "malicious")]
        )

        pivots = engine.generate_pivots(plan, results, enrichments)

        hash_pivots = [p for p in pivots if "e99a18c428cb38d5" in p.query_text]
        assert len(hash_pivots) >= 1

    def test_max_pivots_respected(self) -> None:
        engine = PivotEngine(max_pivots=2)
        plan = _make_plan()
        results = _make_query_results(
            users=["u1", "u2", "u3"],
            src_ips=["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        )
        enrichments = _make_enrichments(ips=[
            ("1.1.1.1", "malicious"),
            ("2.2.2.2", "malicious"),
            ("3.3.3.3", "suspicious"),
        ])

        pivots = engine.generate_pivots(plan, results, enrichments)

        assert len(pivots) <= 2

    def test_empty_results_no_pivots(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()

        pivots = engine.generate_pivots(plan, [], [])

        assert len(pivots) == 0

    def test_pivot_ids_are_unique(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results(
            users=["u1", "u2"],
            src_ips=["1.1.1.1", "2.2.2.2"],
        )
        enrichments = _make_enrichments(ips=[
            ("1.1.1.1", "malicious"),
            ("2.2.2.2", "suspicious"),
        ])

        pivots = engine.generate_pivots(plan, results, enrichments)

        ids = [p.query_id for p in pivots]
        assert len(ids) == len(set(ids))

    def test_all_pivots_have_time_range(self) -> None:
        engine = PivotEngine()
        plan = _make_plan()
        results = _make_query_results()
        enrichments = _make_enrichments(ips=[("203.0.113.77", "malicious")])

        pivots = engine.generate_pivots(plan, results, enrichments)

        for p in pivots:
            assert p.time_range != ""


class TestPipelineWithPivots:
    """Integration-style test: full pipeline with allow_pivots=True in mock mode."""

    def test_pivots_in_mock_pipeline(self) -> None:
        """Verify that the pivot engine can be called after the main pipeline."""
        from mssp_hunt_agent.adapters.exabeam.mock import MockExabeamAdapter
        from mssp_hunt_agent.adapters.intel.mock import MockThreatIntelAdapter
        from mssp_hunt_agent.pipeline import enrichment as enrichment_mod
        from mssp_hunt_agent.pipeline import executor as executor_mod

        plan = _make_plan()
        # Auto-approve
        for step in plan.hunt_steps:
            for q in step.queries:
                q.approved = True

        adapter = MockExabeamAdapter()
        query_results = executor_mod.execute_approved_queries(plan, adapter)
        entities = enrichment_mod.extract_entities(query_results)
        enrichments = enrichment_mod.enrich_entities(entities, MockThreatIntelAdapter())

        engine = PivotEngine(max_pivots=3)
        pivots = engine.generate_pivots(plan, query_results, enrichments)

        # Pivots should be valid queries that can be executed
        for pq in pivots:
            assert pq.is_pivot is True
            assert pq.intent == QueryIntent.PIVOT
            assert pq.query_text != ""

        # Execute pivots
        if pivots:
            for pq in pivots:
                pq.approved = True
            from mssp_hunt_agent.models.hunt_models import HuntStep
            pivot_step = HuntStep(
                step_number=99,
                description="Pivot queries",
                queries=pivots,
                success_criteria="Pivot results",
                next_if_positive="Investigate",
                next_if_negative="Close",
            )
            pivot_plan = plan.model_copy(update={"hunt_steps": [pivot_step]})
            pivot_results = executor_mod.execute_approved_queries(pivot_plan, adapter)
            assert all(r.status in ("success", "no_results") for r in pivot_results)
