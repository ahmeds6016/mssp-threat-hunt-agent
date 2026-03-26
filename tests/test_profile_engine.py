"""Tests for the profile engine — query generation, mock builder, classification."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.models.hunt_models import TelemetryReadiness
from mssp_hunt_agent.models.input_models import HuntType
from mssp_hunt_agent.models.profile_models import (
    DataSourceProfile,
    HuntCapability,
    ParsedFieldInfo,
    ProfileInput,
)
from mssp_hunt_agent.pipeline.profile_engine import (
    build_profile,
    classify_capabilities,
    generate_profile_plan,
    mock_build_profiles,
)


class TestProfilePlanGeneration:
    def test_plan_has_required_structure(self, profile_input: ProfileInput) -> None:
        plan = generate_profile_plan(profile_input)

        assert plan.plan_id.startswith("HP-PROF-")
        assert plan.hunt_type == "profile"
        assert plan.client_name == "TestCorp"
        assert len(plan.hunt_steps) >= 2  # at least discovery + field pop
        assert len(plan.hypotheses) == 1
        assert plan.hypotheses[0].technique_source == "profile_mode"

    def test_plan_queries_have_time_range(self, profile_input: ProfileInput) -> None:
        plan = generate_profile_plan(profile_input)

        for step in plan.hunt_steps:
            for q in step.queries:
                assert profile_input.time_range in q.query_text
                assert q.time_range == profile_input.time_range

    def test_plan_queries_are_baseline_intent(self, profile_input: ProfileInput) -> None:
        plan = generate_profile_plan(profile_input)

        for step in plan.hunt_steps:
            for q in step.queries:
                assert q.intent.value == "baseline"

    def test_plan_query_ids_unique(self, profile_input: ProfileInput) -> None:
        plan = generate_profile_plan(profile_input)

        ids = [q.query_id for step in plan.hunt_steps for q in step.queries]
        assert len(ids) == len(set(ids))


class TestMockProfileBuilder:
    def test_mock_produces_sources(self, profile_input: ProfileInput) -> None:
        profiles = mock_build_profiles(profile_input)
        assert 5 <= len(profiles) <= 8

    def test_mock_deterministic(self, profile_input: ProfileInput) -> None:
        a = mock_build_profiles(profile_input)
        b = mock_build_profiles(profile_input)

        assert len(a) == len(b)
        for pa, pb in zip(a, b):
            assert pa.source_name == pb.source_name
            assert pa.event_count == pb.event_count

    def test_mock_sources_marked_simulated(self, profile_input: ProfileInput) -> None:
        profiles = mock_build_profiles(profile_input)
        for ds in profiles:
            assert ds.is_simulated is True

    def test_mock_field_population_ranges(self, profile_input: ProfileInput) -> None:
        profiles = mock_build_profiles(profile_input)
        for ds in profiles:
            for pf in ds.parsed_fields:
                assert 0.0 <= pf.population_pct <= 100.0
                assert 0.0 <= pf.null_pct <= 100.0

    def test_mock_event_counts_positive(self, profile_input: ProfileInput) -> None:
        profiles = mock_build_profiles(profile_input)
        for ds in profiles:
            assert ds.event_count > 0


class TestCapabilityClassification:
    def _make_sources(self, names: list[tuple[str, HuntType]]) -> list[DataSourceProfile]:
        return [
            DataSourceProfile(
                source_name=name,
                category=cat,
                event_count=10_000,
                parsed_fields=[
                    ParsedFieldInfo(
                        field_name="user", population_pct=90.0,
                        null_pct=10.0, sample_values=["test"],
                    ),
                ],
            )
            for name, cat in names
        ]

    def test_green_classification(self) -> None:
        sources = self._make_sources([
            ("Azure AD sign-in logs", HuntType.IDENTITY),
            ("VPN logs", HuntType.IDENTITY),
            ("MFA logs", HuntType.IDENTITY),
            ("Active Directory event logs", HuntType.IDENTITY),
        ])
        caps = classify_capabilities(sources, [HuntType.IDENTITY])
        assert len(caps) == 1
        assert caps[0].readiness == TelemetryReadiness.GREEN

    def test_yellow_classification(self) -> None:
        sources = self._make_sources([
            ("Azure AD sign-in logs", HuntType.IDENTITY),
            ("VPN logs", HuntType.IDENTITY),
        ])
        caps = classify_capabilities(sources, [HuntType.IDENTITY])
        assert caps[0].readiness == TelemetryReadiness.YELLOW

    def test_red_classification(self) -> None:
        sources = self._make_sources([
            ("Some random source", HuntType.IDENTITY),
        ])
        caps = classify_capabilities(sources, [HuntType.IDENTITY])
        assert caps[0].readiness == TelemetryReadiness.RED

    def test_green_downgraded_on_low_field_quality(self) -> None:
        sources = [
            DataSourceProfile(
                source_name="Azure AD sign-in logs",
                category=HuntType.IDENTITY,
                event_count=10_000,
                parsed_fields=[
                    ParsedFieldInfo(
                        field_name="user", population_pct=10.0,
                        null_pct=90.0, sample_values=["test"],
                    ),
                ],
            ),
            DataSourceProfile(
                source_name="VPN logs", category=HuntType.IDENTITY,
                event_count=5_000,
            ),
            DataSourceProfile(
                source_name="MFA logs", category=HuntType.IDENTITY,
                event_count=3_000,
            ),
            DataSourceProfile(
                source_name="Active Directory event logs",
                category=HuntType.IDENTITY, event_count=8_000,
            ),
        ]
        caps = classify_capabilities(sources, [HuntType.IDENTITY])
        assert caps[0].readiness == TelemetryReadiness.YELLOW
        assert len(caps[0].field_quality_notes) > 0

    def test_all_hunt_types_assessed(self) -> None:
        sources = self._make_sources([
            ("Azure AD sign-in logs", HuntType.IDENTITY),
        ])
        caps = classify_capabilities(sources)
        assert len(caps) == 4
        types_covered = {c.hunt_type for c in caps}
        assert types_covered == set(HuntType)

    def test_missing_sources_listed(self) -> None:
        sources = self._make_sources([
            ("Azure AD sign-in logs", HuntType.IDENTITY),
        ])
        caps = classify_capabilities(sources, [HuntType.IDENTITY])
        assert len(caps[0].missing_sources) > 0


class TestProfileAssembly:
    def test_build_profile_complete(self, profile_input: ProfileInput) -> None:
        sources = mock_build_profiles(profile_input)
        caps = classify_capabilities(sources, profile_input.hunt_types_of_interest)
        profile = build_profile(profile_input, sources, caps, "mock")

        assert profile.profile_id.startswith("PROF-")
        assert profile.client_name == "TestCorp"
        assert profile.source_count == len(sources)
        assert profile.total_event_count > 0
        assert profile.is_simulated is True
        assert len(profile.capabilities) == 4

    def test_declared_vs_discovered_gaps(self) -> None:
        pi = ProfileInput(
            client_name="GapCorp",
            time_range="2024-01-01 to 2024-01-31",
            declared_data_sources=["Non-existent source", "Another missing"],
        )
        sources = [
            DataSourceProfile(source_name="Real source", event_count=100),
        ]
        caps = classify_capabilities(sources)
        profile = build_profile(pi, sources, caps, "mock")

        assert "Non-existent source" in profile.declared_vs_discovered_gaps
        assert "Another missing" in profile.declared_vs_discovered_gaps

    def test_mock_caveat_added(self, profile_input: ProfileInput) -> None:
        sources = mock_build_profiles(profile_input)
        caps = classify_capabilities(sources)
        profile = build_profile(profile_input, sources, caps, "mock")

        assert any("SIMULATED" in c for c in profile.caveats)

    def test_no_caveat_in_live_mode(self, profile_input: ProfileInput) -> None:
        sources = mock_build_profiles(profile_input)
        caps = classify_capabilities(sources)
        profile = build_profile(profile_input, sources, caps, "live")

        assert not any("SIMULATED" in c for c in profile.caveats)
