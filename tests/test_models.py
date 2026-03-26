"""Tests for Pydantic model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mssp_hunt_agent.models.input_models import HuntInput, HuntType, Priority


class TestHuntInputValidation:
    def test_valid_full_input(self, identity_input: HuntInput) -> None:
        assert identity_input.client_name == "TestCorp"
        assert identity_input.hunt_type == HuntType.IDENTITY
        assert identity_input.priority == Priority.HIGH
        assert len(identity_input.attack_techniques) == 2

    def test_valid_minimal_input(self, minimal_input: HuntInput) -> None:
        assert minimal_input.client_name == "MinimalCo"
        assert minimal_input.industry == "Not provided"
        assert minimal_input.analyst_notes == "Not provided"
        assert minimal_input.telemetry_gaps == []
        assert minimal_input.attack_techniques == []

    def test_missing_client_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            HuntInput(
                client_name="",
                hunt_objective="test",
                hunt_hypothesis="test",
                time_range="2024-01-01 to 2024-01-31",
                available_data_sources=["logs"],
            )

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            HuntInput(
                client_name="Test",
                # hunt_objective missing
                hunt_hypothesis="test",
                time_range="2024-01-01 to 2024-01-31",
                available_data_sources=["logs"],
            )

    def test_empty_data_sources_raises(self) -> None:
        with pytest.raises(ValidationError):
            HuntInput(
                client_name="Test",
                hunt_objective="test",
                hunt_hypothesis="test",
                time_range="2024-01-01 to 2024-01-31",
                available_data_sources=[],
            )

    def test_optional_fields_default(self) -> None:
        hi = HuntInput(
            client_name="X",
            hunt_objective="Y",
            hunt_hypothesis="Z",
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=["something"],
        )
        assert hi.hunt_type == HuntType.IDENTITY
        assert hi.priority == Priority.MEDIUM
        assert hi.key_assets == []
        assert hi.constraints == []
