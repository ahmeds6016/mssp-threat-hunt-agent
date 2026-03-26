"""Correlate active threats to client detection capabilities."""

from __future__ import annotations

import uuid

from mssp_hunt_agent.intel.cisa_kev import infer_detection_sources
from mssp_hunt_agent.intel.landscape_models import (
    KEVEntry,
    LandscapeAlert,
    LandscapeReport,
    ThreatCorrelation,
)


def correlate_threats_to_clients(
    threats: list[KEVEntry],
    client_sources: dict[str, list[str]],
) -> list[ThreatCorrelation]:
    """For each threat, check which clients can/can't detect it."""
    correlations: list[ThreatCorrelation] = []

    for threat in threats:
        required_sources = infer_detection_sources(threat)

        for client_name, available in client_sources.items():
            available_set = set(available)
            have = [s for s in required_sources if s in available_set]
            missing = [s for s in required_sources if s not in available_set]
            coverage = len(have) / len(required_sources) if required_sources else 0.0

            correlations.append(ThreatCorrelation(
                threat_id=threat.cve_id,
                threat_name=f"{threat.vendor} {threat.product}: {threat.vulnerability_name}",
                client_name=client_name,
                can_detect=coverage >= 0.5,
                detection_sources=have,
                missing_sources=missing,
                coverage_score=round(coverage, 2),
                mitre_techniques=threat.mitre_techniques,
            ))

    return correlations


def generate_alerts(
    correlations: list[ThreatCorrelation],
    min_severity: str = "high",
) -> list[LandscapeAlert]:
    """Produce actionable alerts for clients blind to active threats."""
    alerts: list[LandscapeAlert] = []

    for corr in correlations:
        if corr.can_detect:
            continue  # Client can detect this — no alert needed

        alert = LandscapeAlert(
            alert_id=f"LA-{uuid.uuid4().hex[:8].upper()}",
            severity="critical" if corr.coverage_score == 0.0 else "high",
            threat_id=corr.threat_id,
            threat_name=corr.threat_name,
            client_name=corr.client_name,
            message=f"{corr.client_name} cannot detect '{corr.threat_name}' ({corr.threat_id}) — {corr.coverage_score:.0%} coverage",
            missing_sources=corr.missing_sources,
            recommended_actions=[
                f"Deploy {src} for {corr.client_name}" for src in corr.missing_sources[:3]
            ],
        )
        alerts.append(alert)

    return alerts


def build_landscape_report(
    threats: list[KEVEntry],
    client_sources: dict[str, list[str]],
) -> LandscapeReport:
    """Build a complete threat landscape correlation report."""
    correlations = correlate_threats_to_clients(threats, client_sources)
    alerts = generate_alerts(correlations)

    clients_at_risk = sorted(set(a.client_name for a in alerts))

    return LandscapeReport(
        total_threats_analyzed=len(threats),
        total_correlations=len(correlations),
        alerts=alerts,
        correlations=correlations,
        clients_at_risk=clients_at_risk,
    )
