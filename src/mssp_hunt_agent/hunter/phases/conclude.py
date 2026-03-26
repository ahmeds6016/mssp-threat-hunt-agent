"""Phase 4: Conclusion — classify findings, build evidence chains, assign severity."""

from __future__ import annotations

import json
from typing import Any

from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS
from mssp_hunt_agent.hunter.models.campaign import CampaignPhase, CampaignState
from mssp_hunt_agent.hunter.models.finding import FindingClassification, FindingSeverity
from mssp_hunt_agent.hunter.phases.base import PhaseRunner
from mssp_hunt_agent.hunter.prompts.phase_prompts import build_conclude_prompt


class ConcludePhaseRunner(PhaseRunner):
    """Review and classify findings from the execute phase."""

    def phase_name(self) -> CampaignPhase:
        return CampaignPhase.CONCLUDE

    def build_system_prompt(self, state: CampaignState) -> str:
        findings_data = [f.model_dump(mode="json") for f in state.findings]
        hypotheses_data = [
            {"hypothesis_id": h.hypothesis_id, "title": h.title,
             "description": h.description, "status": h.status,
             "mitre_techniques": h.mitre_techniques}
            for h in state.hypotheses
        ]
        env_summary = state.environment_index.rich_summary() if state.environment_index else {}
        return build_conclude_prompt(
            client_name=state.config.client_name,
            findings_data=findings_data,
            hypotheses_data=hypotheses_data,
            env_summary=env_summary,
        )

    def get_tools(self) -> list[dict[str, Any]]:
        allowed = {"search_mitre", "lookup_cve", "check_telemetry"}
        return [t for t in AGENT_TOOLS if t["function"]["name"] in allowed]

    def get_max_iterations(self, state: CampaignState) -> int:
        return state.config.phase_max_iterations.get("conclude", 15)

    def get_initial_user_message(self, state: CampaignState) -> str:
        return (
            f"Review the {len(state.findings)} findings from the hunt execution. "
            f"For each finding: validate classification, assign final severity, "
            f"build evidence chain narrative, map to MITRE, and generate recommendations."
        )

    def extract_artifacts(self, response_text: str, state: CampaignState) -> dict[str, Any]:
        """Update findings with refined classifications from LLM analysis."""
        # The LLM's response contains refined analysis — try to parse updates
        _refine_findings_from_text(response_text, state)

        return {
            "findings_reviewed": len(state.findings),
            "true_positives": sum(
                1 for f in state.findings
                if f.classification == FindingClassification.TRUE_POSITIVE
            ),
            "false_positives": sum(
                1 for f in state.findings
                if f.classification == FindingClassification.FALSE_POSITIVE
            ),
            "escalations": sum(
                1 for f in state.findings
                if f.classification == FindingClassification.REQUIRES_ESCALATION
            ),
        }


def _refine_findings_from_text(text: str, state: CampaignState) -> None:
    """Best-effort refinement of findings from the LLM's conclude analysis.

    Updates finding descriptions and recommendations based on the
    conclusion phase output.
    """
    text_lower = text.lower()

    # Try to extract recommendations from the response
    recommendations: list[str] = []
    if "recommend" in text_lower:
        lines = text.split("\n")
        for line in lines:
            stripped = line.strip().lstrip("-•*").strip()
            if stripped and any(word in stripped.lower() for word in [
                "recommend", "should", "consider", "implement", "enable",
                "monitor", "review", "investigate", "deploy",
            ]):
                recommendations.append(stripped)

    # Apply recommendations to actionable findings
    for finding in state.findings:
        if finding.is_actionable and recommendations:
            finding.recommendations = recommendations[:5]

        # Enrich the evidence chain narrative if the LLM provided better analysis
        if finding.finding_id in text:
            # Find the section about this finding
            idx = text.index(finding.finding_id)
            section = text[idx:idx + 1000]
            if len(section) > len(finding.evidence_chain.narrative):
                finding.evidence_chain.narrative = section
