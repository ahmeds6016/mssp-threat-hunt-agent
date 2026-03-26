"""Breach simulation — model impact of attack scenarios on a client."""

from __future__ import annotations

from mssp_hunt_agent.threat_model.models import AttackPath, BreachSimulation


def simulate_breach(
    scenario: str,
    attack_paths: list[AttackPath],
) -> BreachSimulation:
    """Simulate a breach scenario using identified attack paths."""
    if not attack_paths:
        return BreachSimulation(
            scenario=scenario,
            overall_detection_probability=0.0,
            time_to_detect_estimate="unknown",
            recommendations=["No attack paths analyzed — provide data sources for assessment"],
        )

    # Overall detection probability = weighted average of path coverages
    # Higher-risk paths get more weight
    weight_map = {"high": 3, "medium": 2, "low": 1}
    total_weight = 0
    weighted_coverage = 0.0

    for path in attack_paths:
        w = weight_map.get(path.risk_level, 1)
        total_weight += w
        weighted_coverage += path.detection_coverage * w

    overall_prob = weighted_coverage / total_weight if total_weight > 0 else 0.0

    # Time to detect estimate
    if overall_prob >= 0.8:
        ttd = "hours"
    elif overall_prob >= 0.5:
        ttd = "days"
    elif overall_prob >= 0.2:
        ttd = "weeks"
    else:
        ttd = "months or never"

    # Recommendations
    recs: list[str] = []
    high_risk = [p for p in attack_paths if p.risk_level == "high"]
    if high_risk:
        for p in high_risk:
            recs.append(f"HIGH RISK: '{p.entry_point}' path has {p.detection_coverage:.0%} coverage — address gaps: {', '.join(p.gaps[:3])}")

    all_gaps: list[str] = []
    for p in attack_paths:
        all_gaps.extend(p.gaps)

    # Find most common missing data sources
    missing_sources: dict[str, int] = {}
    for gap in all_gaps:
        if "needs:" in gap:
            sources = gap.split("needs:")[1].strip().rstrip(")")
            for src in sources.split(","):
                src = src.strip()
                missing_sources[src] = missing_sources.get(src, 0) + 1

    for src, count in sorted(missing_sources.items(), key=lambda x: -x[1])[:3]:
        recs.append(f"Deploy '{src}' to close {count} detection gap(s)")

    if overall_prob < 0.5:
        recs.append("Overall detection probability is below 50% — significant blind spots exist")

    return BreachSimulation(
        scenario=scenario,
        attack_paths=attack_paths,
        overall_detection_probability=round(overall_prob, 2),
        time_to_detect_estimate=ttd,
        recommendations=recs,
    )
