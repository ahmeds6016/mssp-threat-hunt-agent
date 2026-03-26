"""Risk scenario simulator — compute coverage impact when data sources change."""

from __future__ import annotations

from mssp_hunt_agent.risk.models import CoverageChange, ImpactAssessment, RiskScenario
from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths


def simulate_risk_scenario(
    scenario: RiskScenario,
    current_data_sources: list[str],
) -> ImpactAssessment:
    """Simulate the impact of adding/removing a data source on detection coverage."""
    # Compute before
    paths_before = identify_attack_paths(current_data_sources)

    # Build modified source list
    if scenario.change_type == "remove_source":
        modified = [s for s in current_data_sources if s != scenario.affected_source]
    elif scenario.change_type == "add_source":
        modified = list(current_data_sources) + [scenario.affected_source]
    elif scenario.change_type == "degrade_source":
        modified = [s for s in current_data_sources if s != scenario.affected_source]
    else:
        modified = list(current_data_sources)

    # Compute after
    paths_after = identify_attack_paths(modified)

    # Build per-path comparison
    changes: list[CoverageChange] = []
    before_map = {p.entry_point: p for p in paths_before}
    after_map = {p.entry_point: p for p in paths_after}

    all_names = set(list(before_map.keys()) + list(after_map.keys()))
    for name in sorted(all_names):
        b = before_map.get(name)
        a = after_map.get(name)
        cov_before = b.detection_coverage if b else 0.0
        cov_after = a.detection_coverage if a else 0.0
        risk_before = b.risk_level if b else "unknown"
        risk_after = a.risk_level if a else "unknown"
        changes.append(CoverageChange(
            path_name=name,
            coverage_before=round(cov_before, 2),
            coverage_after=round(cov_after, 2),
            delta=round(cov_after - cov_before, 2),
            risk_before=risk_before,
            risk_after=risk_after,
        ))

    # Aggregate
    avg_before = sum(c.coverage_before for c in changes) / len(changes) if changes else 0.0
    avg_after = sum(c.coverage_after for c in changes) / len(changes) if changes else 0.0
    overall_delta = round(avg_after - avg_before, 2)

    # Blind spots: paths that dropped below 50%
    blind_spots = [c.path_name for c in changes if c.coverage_after < 0.5 and c.coverage_before >= 0.5]

    # New gaps from after paths
    new_gaps: list[str] = []
    for p in paths_after:
        if p.detection_coverage < 0.5:
            new_gaps.extend(p.gaps[:2])

    # Risk rating
    if overall_delta <= -0.3 or avg_after < 0.3:
        risk = "critical"
    elif overall_delta <= -0.15 or avg_after < 0.5:
        risk = "high"
    elif overall_delta < 0:
        risk = "medium"
    else:
        risk = "low"

    # Recommendations
    recs: list[str] = []
    if scenario.change_type == "remove_source":
        recs.append(f"Removing '{scenario.affected_source}' reduces average coverage by {abs(overall_delta):.0%}")
        if blind_spots:
            recs.append(f"Creates blind spots in: {', '.join(blind_spots)}")
        if risk in ("high", "critical"):
            recs.append(f"STRONGLY ADVISE against removing '{scenario.affected_source}' — risk is {risk}")
    elif scenario.change_type == "add_source":
        recs.append(f"Adding '{scenario.affected_source}' improves average coverage by {overall_delta:.0%}")
        improved = [c.path_name for c in changes if c.delta > 0]
        if improved:
            recs.append(f"Improves detection for: {', '.join(improved)}")

    return ImpactAssessment(
        scenario=scenario,
        changes=changes,
        avg_coverage_before=round(avg_before, 2),
        avg_coverage_after=round(avg_after, 2),
        overall_delta=overall_delta,
        blind_spots=blind_spots + new_gaps[:5],
        risk_rating=risk,
        recommendations=recs,
    )
