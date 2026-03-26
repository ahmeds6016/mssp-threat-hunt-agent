"""Quality scoring for detection rules."""

from __future__ import annotations

import re

from mssp_hunt_agent.detection.models import DetectionRule, PerformanceRating, QualityScore


def score_detection_quality(rule: DetectionRule) -> QualityScore:
    """Score a detection rule on coverage, precision, noise, and performance."""
    recommendations: list[str] = []
    kql = rule.kql_query

    # Coverage: based on ATT&CK technique mapping
    coverage = min(len(rule.mitre_techniques) * 0.3, 1.0) if rule.mitre_techniques else 0.0
    if not rule.mitre_techniques:
        recommendations.append("Map rule to ATT&CK technique(s) for coverage tracking")

    # Precision estimate: based on filter specificity
    precision = 0.5
    filter_count = kql.lower().count("where")
    if filter_count >= 3:
        precision = 0.8
    elif filter_count >= 2:
        precision = 0.7
    elif filter_count >= 1:
        precision = 0.6
    else:
        precision = 0.3
        recommendations.append("Add 'where' filters to reduce false positives")

    # Check for aggregation (summarize) which improves precision
    uses_aggregation = "summarize" in kql.lower()
    if uses_aggregation:
        precision = min(precision + 0.1, 1.0)

    # Check for threshold (where Count > N)
    has_threshold = bool(re.search(r"where\s+\w+\s*>\s*\d+", kql, re.IGNORECASE))
    if has_threshold:
        precision = min(precision + 0.1, 1.0)
    else:
        if uses_aggregation:
            recommendations.append("Add a threshold filter after summarize to reduce noise")

    # Noise estimate (inverse of precision)
    noise = round(1.0 - precision, 2)

    # Time filter check
    has_time_filter = bool(re.search(r"TimeGenerated|ago\(|between\(", kql, re.IGNORECASE))
    if not has_time_filter:
        recommendations.append("Add a time filter (e.g., 'where TimeGenerated > ago(7d)')")
        noise = min(noise + 0.2, 1.0)

    # Field filter check
    has_field_filters = filter_count > 0

    # Performance rating
    perf = PerformanceRating.FAST
    if "join" in kql.lower():
        perf = PerformanceRating.SLOW
        recommendations.append("Join operations are expensive — consider alternatives")
    elif "union" in kql.lower() and "*" in kql:
        perf = PerformanceRating.SLOW
    elif not has_time_filter:
        perf = PerformanceRating.SLOW
    elif uses_aggregation:
        perf = PerformanceRating.MODERATE

    # Data source check
    if not rule.data_sources:
        recommendations.append("Specify required data sources for deployment validation")

    # Description quality
    if len(rule.description) < 20:
        recommendations.append("Add a detailed description for analyst context")

    if not rule.false_positive_guidance:
        recommendations.append("Add false positive guidance for analysts")

    # Overall grade
    score = (coverage * 0.25 + precision * 0.35 + (1 - noise) * 0.25 + (1.0 if perf == PerformanceRating.FAST else 0.7 if perf == PerformanceRating.MODERATE else 0.3) * 0.15)
    if score >= 0.85:
        grade = "A"
    elif score >= 0.70:
        grade = "B"
    elif score >= 0.55:
        grade = "C"
    elif score >= 0.40:
        grade = "D"
    else:
        grade = "F"

    return QualityScore(
        rule_id=rule.rule_id,
        coverage_score=round(coverage, 2),
        precision_estimate=round(precision, 2),
        noise_estimate=round(noise, 2),
        performance_rating=perf,
        has_time_filter=has_time_filter,
        has_field_filters=has_field_filters,
        uses_aggregation=uses_aggregation,
        recommendations=recommendations,
        overall_grade=grade,
    )
