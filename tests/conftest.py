"""Shared fixtures for the test suite."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.models.input_models import HuntInput, HuntType, Priority
from mssp_hunt_agent.models.profile_models import ProfileInput


@pytest.fixture
def identity_input() -> HuntInput:
    """Fully-populated identity hunt input."""
    return HuntInput(
        client_name="TestCorp",
        hunt_objective="Detect credential abuse from foreign IPs",
        hunt_hypothesis="Compromised VPN credentials used from Eastern European IP ranges",
        time_range="2024-11-01 to 2024-11-30",
        available_data_sources=[
            "Azure AD sign-in logs",
            "VPN logs",
            "MFA logs",
            "Active Directory event logs",
        ],
        telemetry_gaps=["CASB logs not available"],
        hunt_type=HuntType.IDENTITY,
        industry="Financial Services",
        key_assets=["Domain Controllers", "Exchange Online"],
        priority=Priority.HIGH,
        attack_techniques=["T1078", "T1110.003"],
        known_benign_patterns=["IT admin VPN from US"],
        exclusions=["svc_backup@test.com"],
        analyst_notes="Client reported suspicious MFA prompts.",
        constraints=["48-hour SLA"],
    )


@pytest.fixture
def minimal_input() -> HuntInput:
    """Bare minimum required fields only."""
    return HuntInput(
        client_name="MinimalCo",
        hunt_objective="General threat hunt",
        hunt_hypothesis="Unknown threat activity",
        time_range="2024-12-01 to 2024-12-31",
        available_data_sources=["Firewall logs"],
    )


@pytest.fixture
def endpoint_input() -> HuntInput:
    return HuntInput(
        client_name="Acme Manufacturing",
        hunt_objective="Identify LOLBin abuse on critical endpoints",
        hunt_hypothesis="Attacker using LOLBins to execute second-stage payloads",
        time_range="2024-12-01 to 2024-12-15",
        available_data_sources=[
            "EDR telemetry",
            "Windows event logs",
            "Sysmon logs",
            "PowerShell script-block logs",
        ],
        telemetry_gaps=["Antivirus logs not centralized"],
        hunt_type=HuntType.ENDPOINT,
        attack_techniques=["T1059.001", "T1218.005"],
    )


@pytest.fixture
def profile_input() -> ProfileInput:
    """Standard profiling input for tests."""
    return ProfileInput(
        client_name="TestCorp",
        time_range="2024-11-01 to 2024-11-30",
        declared_data_sources=[
            "Azure AD sign-in logs",
            "VPN logs",
            "EDR telemetry",
            "Firewall logs",
        ],
        hunt_types_of_interest=list(HuntType),
        analyst_notes="Pre-engagement profiling.",
    )


@pytest.fixture
def minimal_profile_input() -> ProfileInput:
    """Bare minimum profiling input."""
    return ProfileInput(
        client_name="MinimalCo",
        time_range="2024-12-01 to 2024-12-31",
    )
