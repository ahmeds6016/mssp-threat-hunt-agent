"""Intake stage — validate inputs and classify telemetry readiness."""

from __future__ import annotations

from mssp_hunt_agent.models.input_models import HuntInput, HuntType
from mssp_hunt_agent.models.hunt_models import TelemetryAssessment, TelemetryReadiness

# Minimum data‑source expectations per hunt type.
# If ≥80% present → Green, ≥40% → Yellow, else → Red.
EXPECTED_SOURCES: dict[HuntType, list[str]] = {
    HuntType.IDENTITY: [
        "Azure AD sign-in logs",
        "VPN logs",
        "MFA logs",
        "Active Directory event logs",
        "CASB logs",
    ],
    HuntType.ENDPOINT: [
        "EDR telemetry",
        "Windows event logs",
        "Sysmon logs",
        "PowerShell script-block logs",
        "Antivirus logs",
    ],
    HuntType.NETWORK: [
        "Firewall logs",
        "DNS logs",
        "Proxy / web-filter logs",
        "NetFlow / IPFIX",
        "IDS/IPS alerts",
    ],
    HuntType.CLOUD: [
        "Cloud audit logs",
        "CloudTrail / Activity Log",
        "VPC flow logs",
        "Cloud IAM logs",
        "Container runtime logs",
    ],
}


def classify_telemetry(hunt_input: HuntInput) -> TelemetryAssessment:
    """Compare available sources against expected sources for the hunt type."""
    expected = EXPECTED_SOURCES.get(hunt_input.hunt_type, [])
    available_lower = {s.lower() for s in hunt_input.available_data_sources}

    present = [s for s in expected if s.lower() in available_lower]
    missing = [s for s in expected if s.lower() not in available_lower]

    # Also include analyst‑declared gaps
    all_missing = list(set(missing) | set(hunt_input.telemetry_gaps))

    coverage = len(present) / max(len(expected), 1)
    gap_penalty = len(hunt_input.telemetry_gaps) > 2

    if coverage >= 0.8 and not gap_penalty:
        readiness = TelemetryReadiness.GREEN
        rationale = (
            f"{len(present)}/{len(expected)} expected sources available. "
            "Sufficient telemetry for meaningful hunt execution."
        )
        impact = "Hunt can proceed with high confidence in data coverage."
    elif coverage >= 0.4:
        readiness = TelemetryReadiness.YELLOW
        rationale = (
            f"{len(present)}/{len(expected)} expected sources available. "
            "Partial telemetry — hunt is possible but limited."
        )
        impact = (
            "Some hunt checks will be impossible or low-confidence. "
            f"Missing: {', '.join(missing[:3])}."
        )
    else:
        readiness = TelemetryReadiness.RED
        rationale = (
            f"Only {len(present)}/{len(expected)} expected sources available. "
            "Major telemetry gaps significantly limit hunt effectiveness."
        )
        impact = (
            "Critical data sources are absent. Hunt will produce incomplete results "
            "and should be scoped down or preceded by a telemetry onboarding effort."
        )

    return TelemetryAssessment(
        readiness=readiness,
        rationale=rationale,
        available_sources=list(hunt_input.available_data_sources),
        missing_sources=all_missing,
        impact_on_hunt=impact,
    )


def validate_and_normalise(hunt_input: HuntInput) -> HuntInput:
    """Light normalisation pass (Pydantic handles hard validation)."""
    # Strip whitespace from list items
    hunt_input.available_data_sources = [
        s.strip() for s in hunt_input.available_data_sources if s.strip()
    ]
    hunt_input.telemetry_gaps = [
        s.strip() for s in hunt_input.telemetry_gaps if s.strip()
    ]
    hunt_input.attack_techniques = [
        t.strip().upper() for t in hunt_input.attack_techniques if t.strip()
    ]
    return hunt_input
