"""Response formatter — converts pipeline results into clean text for Copilot Studio."""

from __future__ import annotations

import re
from typing import Any

from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse


def format_response(response: AgentResponse) -> str:
    """Format an AgentResponse for Copilot Studio / Teams (markdown preserved)."""
    parts: list[str] = []

    # Preserve markdown — Teams and Copilot Studio render it properly
    parts.append(response.summary)

    # Add structured details for certain intents
    formatter = _FORMATTERS.get(response.intent)
    if formatter:
        extra = formatter(response)
        if extra:
            parts.append(extra)

    # Follow-up suggestions
    if response.follow_up_suggestions:
        parts.append("\nYou can also try:")
        for suggestion in response.follow_up_suggestions[:3]:
            parts.append(f"  - {suggestion}")

    return "\n".join(parts)


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting that doesn't render in Copilot Studio."""
    # Remove code fences (```kql ... ```, ```json ... ```, etc.)
    text = re.sub(r"```\w*\n?", "", text)
    # Remove inline backticks
    text = re.sub(r"`([^`]+)`", r"\1", text)
    # Remove bold/italic markers
    text = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", text)
    text = re.sub(r"_{1,3}([^_]+)_{1,3}", r"\1", text)
    return text.strip()


# ── Intent-specific formatters ────────────────────────────────────


def _format_cve_details(response: AgentResponse) -> str:
    """Format CVE assessment details."""
    details = response.details
    lines: list[str] = []

    verdict = details.get("verdict", "")
    if verdict:
        lines.append(f"\nVerdict: {verdict}")

    if details.get("in_cisa_kev"):
        lines.append("CISA KEV: ACTIVELY EXPLOITED")

    coverage = details.get("coverage", {})
    if coverage:
        lines.append("\nTechnique Coverage:")
        for tech, status in coverage.items():
            icon = "[OK]" if status == "covered" else "[GAP]"
            lines.append(f"  {icon} {tech}: {status}")

    gaps = details.get("gaps", [])
    if gaps:
        lines.append(f"\nDetection Gaps: {', '.join(gaps)}")

    recs = details.get("recommendations", [])
    if recs:
        lines.append("\nRecommendations:")
        for rec in recs:
            lines.append(f"  - {rec}")

    return "\n".join(lines)


def _format_risk_details(response: AgentResponse) -> str:
    """Format risk assessment details."""
    details = response.details
    lines: list[str] = []

    rating = details.get("risk_rating", "")
    if rating:
        lines.append(f"\nRisk Rating: {rating.upper()}")

    blind = details.get("blind_spots", [])
    if blind:
        lines.append(f"Blind Spots: {', '.join(blind[:5])}")

    recs = details.get("recommendations", [])
    if recs:
        lines.append("\nRecommendations:")
        for rec in recs[:5]:
            lines.append(f"  - {rec}")

    return "\n".join(lines)


def _format_detection_details(response: AgentResponse) -> str:
    """Format detection rule details."""
    details = response.details
    lines: list[str] = []

    severity = details.get("severity", "")
    if severity:
        # Handle enum values like "Severity.MEDIUM" or plain strings
        sev_str = str(severity)
        if "." in sev_str:
            sev_str = sev_str.split(".")[-1]
        lines.append(f"\nSeverity: {sev_str.title()}")

    techniques = details.get("mitre_techniques", [])
    if techniques:
        lines.append(f"MITRE Techniques: {', '.join(techniques)}")

    sources = details.get("data_sources", [])
    if sources:
        lines.append(f"Data Sources: {', '.join(sources)}")

    fp_guidance = details.get("false_positive_guidance", "")
    if fp_guidance:
        lines.append(f"\nFalse Positive Guidance: {fp_guidance}")

    return "\n".join(lines)


def _format_hunt_details(response: AgentResponse) -> str:
    """Format hunt initiation details."""
    details = response.details
    lines: list[str] = []

    if details.get("client"):
        lines.append(f"\nClient: {details['client']}")
    if details.get("status"):
        lines.append(f"Status: {details['status']}")

    return "\n".join(lines)


def _format_ioc_sweep_details(response: AgentResponse) -> str:
    """Format IOC sweep details."""
    details = response.details
    lines: list[str] = []

    count = details.get("ioc_count", 0)
    if count:
        lines.append(f"\nIOCs submitted: {count}")
    if details.get("status"):
        lines.append(f"Status: {details['status']}")

    return "\n".join(lines)


def _format_telemetry_details(response: AgentResponse) -> str:
    """Format telemetry profile details."""
    details = response.details
    lines: list[str] = []

    if details.get("status"):
        lines.append(f"\nStatus: {details['status']}")

    return "\n".join(lines)


def _format_threat_model_details(response: AgentResponse) -> str:
    """Format threat model details."""
    details = response.details
    lines: list[str] = []

    count = details.get("path_count", 0)
    if count:
        lines.append(f"\nTotal attack paths identified: {count}")

    return "\n".join(lines)


def _format_landscape_details(response: AgentResponse) -> str:
    """Format threat landscape details."""
    details = response.details
    lines: list[str] = []

    alerts = details.get("alerts", [])
    gaps = details.get("gaps", [])
    if alerts:
        lines.append(f"\nTotal alerts: {len(alerts)}")
    if gaps:
        lines.append(f"Coverage gaps: {len(gaps)}")

    return "\n".join(lines)


def _format_hunt_status_details(response: AgentResponse) -> str:
    """Format hunt status details."""
    details = response.details
    lines: list[str] = []

    if details.get("findings_count"):
        lines.append(f"\nFindings: {details['findings_count']}")
    if details.get("total_events"):
        lines.append(f"Events analyzed: {details['total_events']}")

    return "\n".join(lines)


def _format_report_details(response: AgentResponse) -> str:
    """Format report details."""
    details = response.details
    lines: list[str] = []

    if details.get("format"):
        lines.append(f"\nReport format: {details['format']}")
    if details.get("status"):
        lines.append(f"Hunt status: {details['status']}")

    return "\n".join(lines)


def _format_playbook_details(response: AgentResponse) -> str:
    """Format playbook execution details."""
    details = response.details
    lines: list[str] = []

    if details.get("playbook_name"):
        lines.append(f"\nPlaybook: {details['playbook_name']}")
    if details.get("steps_completed"):
        lines.append(f"Steps completed: {details['steps_completed']}")

    return "\n".join(lines)


def _format_general_details(response: AgentResponse) -> str:
    """Format general question details — no extra formatting needed."""
    return ""


_FORMATTERS: dict[AgentIntent, Any] = {
    AgentIntent.CVE_CHECK: _format_cve_details,
    AgentIntent.RISK_ASSESSMENT: _format_risk_details,
    AgentIntent.DETECTION_RULE: _format_detection_details,
    AgentIntent.RUN_HUNT: _format_hunt_details,
    AgentIntent.IOC_SWEEP: _format_ioc_sweep_details,
    AgentIntent.TELEMETRY_PROFILE: _format_telemetry_details,
    AgentIntent.THREAT_MODEL: _format_threat_model_details,
    AgentIntent.LANDSCAPE_CHECK: _format_landscape_details,
    AgentIntent.HUNT_STATUS: _format_hunt_status_details,
    AgentIntent.GENERATE_REPORT: _format_report_details,
    AgentIntent.RUN_PLAYBOOK: _format_playbook_details,
    AgentIntent.GENERAL_QUESTION: _format_general_details,
}
