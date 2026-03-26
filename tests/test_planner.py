"""Tests for the hunt planner."""

from __future__ import annotations

from mssp_hunt_agent.models.input_models import HuntInput
from mssp_hunt_agent.pipeline.intake import classify_telemetry
from mssp_hunt_agent.pipeline.planner import generate_plan


class TestPlanner:
    def test_plan_has_required_fields(self, identity_input: HuntInput) -> None:
        telemetry = classify_telemetry(identity_input)
        plan = generate_plan(identity_input, telemetry)

        assert plan.plan_id.startswith("HP-")
        assert plan.client_name == "TestCorp"
        assert plan.hunt_type == "identity"
        assert plan.objective == identity_input.hunt_objective
        assert len(plan.hypotheses) >= 1
        assert plan.telemetry_assessment == telemetry
        assert len(plan.hunt_steps) >= 1
        assert len(plan.triage_checklist) >= 1
        assert len(plan.escalation_criteria) >= 1

    def test_analyst_provided_techniques_preserved(self, identity_input: HuntInput) -> None:
        telemetry = classify_telemetry(identity_input)
        plan = generate_plan(identity_input, telemetry)
        hyp = plan.hypotheses[0]

        assert hyp.technique_source == "analyst_provided"
        assert "T1078" in hyp.attack_techniques

    def test_inferred_techniques_when_none_provided(self, minimal_input: HuntInput) -> None:
        telemetry = classify_telemetry(minimal_input)
        plan = generate_plan(minimal_input, telemetry)
        hyp = plan.hypotheses[0]

        assert hyp.technique_source == "inferred"
        assert hyp.attack_techniques == []

    def test_queries_generated_for_identity_hunt(self, identity_input: HuntInput) -> None:
        telemetry = classify_telemetry(identity_input)
        plan = generate_plan(identity_input, telemetry)

        all_queries = [q for step in plan.hunt_steps for q in step.queries]
        assert len(all_queries) >= 2  # at least baseline + anomaly

    def test_queries_generated_for_endpoint_hunt(self, endpoint_input: HuntInput) -> None:
        telemetry = classify_telemetry(endpoint_input)
        plan = generate_plan(endpoint_input, telemetry)

        all_queries = [q for step in plan.hunt_steps for q in step.queries]
        assert len(all_queries) >= 2

    def test_fallback_queries_when_no_playbook_match(self) -> None:
        """When data sources don't match any playbook queries, fallback queries appear."""
        from mssp_hunt_agent.models.input_models import HuntType

        hi = HuntInput(
            client_name="NoMatch",
            hunt_objective="Hunt for something",
            hunt_hypothesis="Unknown threat",
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=["Obscure proprietary logs"],
            hunt_type=HuntType.IDENTITY,
        )
        telemetry = classify_telemetry(hi)
        plan = generate_plan(hi, telemetry)
        all_queries = [q for step in plan.hunt_steps for q in step.queries]
        assert len(all_queries) >= 1  # at least the fallback set
