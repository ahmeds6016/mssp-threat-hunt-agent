"""Phase 2: Hypothesis Generation — generates prioritized hunt hypotheses from the environment index."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS
from mssp_hunt_agent.hunter.models.campaign import CampaignPhase, CampaignState
from mssp_hunt_agent.hunter.models.hypothesis import (
    AutonomousHypothesis,
    HypothesisPriority,
    HypothesisSource,
)
from mssp_hunt_agent.hunter.phases.base import PhaseRunner
from mssp_hunt_agent.hunter.prompts.phase_prompts import build_hypothesize_prompt


# Common Sentinel tables used when the index has no table data.
# This ensures hypotheses can still be generated and executed.
_FALLBACK_TABLES: list[str] = [
    "SigninLogs", "AuditLogs", "SecurityEvent", "SecurityAlert",
    "SecurityIncident", "Syslog", "CommonSecurityLog",
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceLogonEvents", "OfficeActivity", "AzureActivity",
    "Heartbeat", "IdentityInfo",
]

# Regex for extracting table names from LLM text when index has no tables
_TABLE_NAME_PATTERN = re.compile(
    r'\b(' + '|'.join([
        'SigninLogs', 'AuditLogs', 'SecurityEvent', 'SecurityAlert',
        'SecurityIncident', 'Syslog', 'CommonSecurityLog',
        'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
        'DeviceLogonEvents', 'DeviceRegistryEvents', 'DeviceImageLoadEvents',
        'AADNonInteractiveUserSignInLogs', 'OfficeActivity', 'AzureActivity',
        'ThreatIntelligenceIndicator', 'Heartbeat', 'IdentityInfo',
        'BehaviorAnalytics', 'AzureDiagnostics', 'W3CIISLog',
        'EmailEvents', 'EmailAttachmentInfo', 'EmailUrlInfo',
        'IdentityLogonEvents', 'IdentityQueryEvents',
    ]) + r')\b'
)


class HypothesizePhaseRunner(PhaseRunner):
    """Generate prioritized threat hunt hypotheses from the environment index."""

    def phase_name(self) -> CampaignPhase:
        return CampaignPhase.HYPOTHESIZE

    def build_system_prompt(self, state: CampaignState) -> str:
        env_summary = state.environment_index.rich_summary() if state.environment_index else {}
        return build_hypothesize_prompt(
            client_name=state.config.client_name,
            env_summary=env_summary,
            budget=self.budget.snapshot(),
            learning_context=state.learning_context or None,
        )

    def get_tools(self) -> list[dict[str, Any]]:
        allowed = {"search_mitre", "check_landscape", "lookup_cve", "check_telemetry"}
        return [t for t in AGENT_TOOLS if t["function"]["name"] in allowed]

    def get_max_iterations(self, state: CampaignState) -> int:
        return state.config.phase_max_iterations.get("hypothesize", 15)

    def get_initial_user_message(self, state: CampaignState) -> str:
        if state.config.focus_areas:
            areas = ', '.join(state.config.focus_areas)
            return (
                f"Generate {state.config.max_hypotheses} prioritized threat hunt hypotheses "
                f"for {state.config.client_name}.\n\n"
                f"CRITICAL CONSTRAINT: ALL hypotheses MUST focus specifically on: {areas}. "
                f"Do NOT generate hypotheses outside these focus areas. Every hypothesis must "
                f"directly relate to {areas}.\n\n"
                f"Use the available tools to research these specific threats, check MITRE coverage "
                f"for these attack vectors, and assess the threat landscape before generating hypotheses."
            )
        return (
            f"Generate {state.config.max_hypotheses} prioritized threat hunt hypotheses "
            f"for {state.config.client_name} based on the environment profile. "
            f"Use the available tools to research threats, check MITRE coverage, "
            f"and assess the threat landscape before generating hypotheses."
        )

    def extract_artifacts(self, response_text: str, state: CampaignState) -> dict[str, Any]:
        """Parse hypotheses from the LLM's response.

        The LLM may return structured JSON or natural language.
        We try to extract structured hypotheses; if that fails,
        we create a single hypothesis from the text.
        """
        hypotheses = _parse_hypotheses_from_text(response_text, state)
        # Filter by feasibility and priority threshold.
        # If the index has 0 tables (discovery failed), skip feasibility check
        # so hypotheses still proceed — the execute phase will query real tables.
        index_has_tables = bool(
            state.environment_index and state.environment_index.telemetry.tables
        )
        threshold = state.config.priority_threshold
        viable = [
            h for h in hypotheses
            if h.priority_score >= threshold and (h.is_feasible or not index_has_tables)
        ]
        # Sort by priority score descending
        viable.sort(key=lambda h: h.priority_score, reverse=True)
        # Cap at max_hypotheses
        viable = viable[:state.config.max_hypotheses]

        # Store on campaign state
        state.hypotheses = viable

        return {
            "hypotheses_generated": len(hypotheses),
            "hypotheses_viable": len(viable),
            "hypotheses": [h.model_dump() for h in viable],
        }


def _parse_hypotheses_from_text(
    text: str,
    state: CampaignState,
) -> list[AutonomousHypothesis]:
    """Best-effort extraction of hypotheses from LLM text.

    Tries JSON parsing first, falls back to creating hypotheses
    from the raw text analysis.
    """
    # Try to find JSON array in the response
    hypotheses: list[AutonomousHypothesis] = []

    # Look for JSON blocks
    for marker in ["```json", "```"]:
        if marker in text:
            try:
                start = text.index(marker) + len(marker)
                end = text.index("```", start)
                json_str = text[start:end].strip()
                data = json.loads(json_str)
                if isinstance(data, list):
                    for item in data:
                        hypotheses.append(_dict_to_hypothesis(item, state))
                    return hypotheses
            except (ValueError, json.JSONDecodeError):
                pass

    # Try parsing the whole response as JSON
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                hypotheses.append(_dict_to_hypothesis(item, state))
            return hypotheses
    except json.JSONDecodeError:
        pass

    # Try to extract multiple hypotheses from markdown sections
    # Look for patterns like "Hypothesis 1", "Hypothesis 2", etc.
    sections = re.split(
        r'(?:^|\n)---+\s*\n'
        r'|(?:^|\n)#+\s*hypothesis\s+\d'
        r'|(?:^|\n)hypothesis\s+\d\s*[—\-–:.]',
        text,
        flags=re.IGNORECASE,
    )

    all_tables = []
    if state.environment_index:
        all_tables = state.environment_index.telemetry.table_names

    if len(sections) > 1:
        for idx, section in enumerate(sections):
            if len(section.strip()) < 50:
                continue  # Skip preamble / separators
            h = _parse_markdown_hypothesis(section, idx + 1, all_tables, state)
            if h:
                hypotheses.append(h)
        if hypotheses:
            return hypotheses

    # Fallback: create a single hypothesis from the text.
    # Use known tables if available, otherwise use well-known defaults
    # so the hypothesis passes is_feasible.
    available_tables = all_tables if all_tables else list(_FALLBACK_TABLES)

    hypotheses.append(AutonomousHypothesis(
        hypothesis_id=f"H-{uuid.uuid4().hex[:8]}",
        title="General threat hunt based on environment analysis",
        description=text[:1000],
        source=HypothesisSource.COVERAGE_GAP,
        priority_score=0.6,
        priority=HypothesisPriority.HIGH,
        threat_likelihood=0.7,
        detection_feasibility=0.8,
        business_impact=0.7,
        available_tables=available_tables,
        required_tables=available_tables,
    ))
    return hypotheses


def _parse_markdown_hypothesis(
    section: str,
    idx: int,
    all_tables: list[str],
    state: CampaignState,
) -> AutonomousHypothesis | None:
    """Extract a hypothesis from a markdown section."""
    lines = section.strip().split("\n")
    if not lines:
        return None

    # Extract title from first meaningful line
    title = ""
    for line in lines:
        cleaned = line.strip().lstrip("#-—*•").strip()
        if len(cleaned) > 10:
            title = cleaned[:200]
            break
    if not title:
        return None

    section_lower = section.lower()

    # Extract priority scores from text — try numeric first, then qualitative
    def _extract_float(label: str) -> float:
        # Try exact "label: 0.8" format
        pattern = rf'{label}\s*[:=]\s*([\d.]+)'
        m = re.search(pattern, section_lower)
        if m:
            try:
                return min(1.0, float(m.group(1)))
            except ValueError:
                pass
        return -1.0  # sentinel — not found

    def _infer_score_from_text(section_text: str) -> float:
        """Infer a composite score from qualitative keywords in the section."""
        high_keywords = ["critical", "high priority", "high likelihood", "high impact",
                         "actively exploited", "immediate", "urgent", "severe"]
        medium_keywords = ["medium", "moderate", "notable", "elevated"]
        low_keywords = ["low priority", "low likelihood", "informational", "unlikely"]

        text_lower = section_text.lower()
        high_count = sum(1 for kw in high_keywords if kw in text_lower)
        medium_count = sum(1 for kw in medium_keywords if kw in text_lower)
        low_count = sum(1 for kw in low_keywords if kw in text_lower)

        if high_count >= 2:
            return 0.85
        elif high_count >= 1:
            return 0.75
        elif medium_count >= 1:
            return 0.6
        elif low_count >= 1:
            return 0.35
        return 0.6  # default to medium-high — hypotheses worth investigating

    threat_likelihood = _extract_float("threat_likelihood")
    detection_feasibility = _extract_float("detection_feasibility")
    business_impact = _extract_float("business_impact")

    # If numeric extraction failed for any score, infer from qualitative text
    if threat_likelihood < 0 or detection_feasibility < 0 or business_impact < 0:
        inferred = _infer_score_from_text(section)
        if threat_likelihood < 0:
            threat_likelihood = inferred
        if detection_feasibility < 0:
            detection_feasibility = max(inferred, 0.6)  # if we have tables, feasibility is decent
        if business_impact < 0:
            business_impact = inferred

    # Extract MITRE techniques
    mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', section)
    mitre_techniques = list(dict.fromkeys(mitre_techniques))  # dedupe

    # Extract required tables — match known table names mentioned in section.
    # If all_tables is populated (from index), match against those.
    # If all_tables is empty (index discovery failed), regex-extract well-known names.
    if all_tables:
        mentioned_tables = [t for t in all_tables if t.lower() in section_lower]
    else:
        mentioned_tables = list(dict.fromkeys(_TABLE_NAME_PATTERN.findall(section)))
    available = mentioned_tables if mentioned_tables else (all_tables[:5] or list(_FALLBACK_TABLES[:5]))

    # Extract source type
    source = HypothesisSource.COVERAGE_GAP
    source_map = {
        "threat_landscape": HypothesisSource.THREAT_LANDSCAPE,
        "industry_threat": HypothesisSource.INDUSTRY_THREAT,
        "behavioral_anomaly": HypothesisSource.BEHAVIORAL_ANOMALY,
        "posture_weakness": HypothesisSource.POSTURE_WEAKNESS,
        "cisa_kev": HypothesisSource.CISA_KEV,
        "identity_risk": HypothesisSource.POSTURE_WEAKNESS,
    }
    for key, val in source_map.items():
        if key in section_lower:
            source = val
            break

    h = AutonomousHypothesis(
        hypothesis_id=f"H-{uuid.uuid4().hex[:8]}",
        title=title,
        description=section[:1000],
        source=source,
        threat_likelihood=threat_likelihood,
        detection_feasibility=detection_feasibility,
        business_impact=business_impact,
        mitre_techniques=mitre_techniques,
        required_tables=mentioned_tables,
        available_tables=available,
        missing_tables=[t for t in mentioned_tables if t not in all_tables],
    )
    h.compute_priority_score()
    return h


def _dict_to_hypothesis(data: dict, state: CampaignState) -> AutonomousHypothesis:
    """Convert a dict (from LLM JSON) to an AutonomousHypothesis."""
    available_tables = []
    if state.environment_index:
        all_tables = state.environment_index.telemetry.table_names
        required = data.get("required_tables", [])
        available_tables = [t for t in required if t in all_tables]

    source_str = data.get("source", "coverage_gap")
    try:
        source = HypothesisSource(source_str)
    except ValueError:
        source = HypothesisSource.COVERAGE_GAP

    h = AutonomousHypothesis(
        hypothesis_id=data.get("hypothesis_id", f"H-{uuid.uuid4().hex[:8]}"),
        title=data.get("title", "Untitled Hypothesis"),
        description=data.get("description", ""),
        source=source,
        threat_likelihood=float(data.get("threat_likelihood", 0.5)),
        detection_feasibility=float(data.get("detection_feasibility", 0.5)),
        business_impact=float(data.get("business_impact", 0.5)),
        mitre_techniques=data.get("mitre_techniques", []),
        mitre_tactics=data.get("mitre_tactics", []),
        required_tables=data.get("required_tables", []),
        available_tables=available_tables,
        missing_tables=[t for t in data.get("required_tables", []) if t not in available_tables],
        kql_approach=data.get("kql_approach", ""),
        expected_indicators=data.get("expected_indicators", []),
        false_positive_notes=data.get("false_positive_notes", ""),
        time_range=data.get("time_range", "last 30 days"),
    )
    h.compute_priority_score()
    return h
