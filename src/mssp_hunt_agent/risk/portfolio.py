"""Portfolio-level risk aggregation across multiple clients."""

from __future__ import annotations

from mssp_hunt_agent.risk.models import ImpactAssessment, PortfolioRisk, RiskScenario
from mssp_hunt_agent.risk.simulator import simulate_risk_scenario


def portfolio_risk_summary(
    client_sources: dict[str, list[str]],
    scenario_template: RiskScenario | None = None,
) -> PortfolioRisk:
    """Aggregate risk across all clients in the portfolio.

    If scenario_template is provided, simulates that scenario across all clients.
    Otherwise, just computes baseline risk for each client.
    """
    assessments: list[ImpactAssessment] = []
    highest_risk_client = ""
    worst_coverage = 1.0

    for client_name, sources in client_sources.items():
        if scenario_template:
            scenario = RiskScenario(
                client_name=client_name,
                change_type=scenario_template.change_type,
                affected_source=scenario_template.affected_source,
                description=scenario_template.description,
            )
        else:
            # Baseline assessment: what's the current risk?
            scenario = RiskScenario(
                client_name=client_name,
                change_type="remove_source",
                affected_source="__none__",
                description="Baseline risk assessment",
            )

        assessment = simulate_risk_scenario(scenario, sources)
        assessment.scenario.client_name = client_name
        assessments.append(assessment)

        if assessment.avg_coverage_after < worst_coverage:
            worst_coverage = assessment.avg_coverage_after
            highest_risk_client = client_name

    avg_coverage = sum(a.avg_coverage_after for a in assessments) / len(assessments) if assessments else 0.0

    critical_gaps: list[str] = []
    for a in assessments:
        for bs in a.blind_spots[:2]:
            critical_gaps.append(f"{a.scenario.client_name}: {bs}")

    return PortfolioRisk(
        total_clients=len(client_sources),
        assessments=assessments,
        highest_risk_client=highest_risk_client,
        avg_portfolio_coverage=round(avg_coverage, 2),
        critical_gaps=critical_gaps[:10],
    )
