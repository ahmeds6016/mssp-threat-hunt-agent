"""Phase 5: Delivery — generate the final campaign report."""

from __future__ import annotations

from typing import Any

from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS
from mssp_hunt_agent.hunter.models.campaign import CampaignPhase, CampaignState
from mssp_hunt_agent.hunter.models.finding import FindingClassification, FindingSeverity
from mssp_hunt_agent.hunter.models.report import CampaignReport, DetectionSuggestion
from mssp_hunt_agent.hunter.phases.base import PhaseRunner
from mssp_hunt_agent.hunter.prompts.phase_prompts import build_deliver_prompt


class DeliverPhaseRunner(PhaseRunner):
    """Generate the final professional threat hunt report."""

    def phase_name(self) -> CampaignPhase:
        return CampaignPhase.DELIVER

    def build_system_prompt(self, state: CampaignState) -> str:
        campaign_summary = {
            "campaign_id": state.campaign_id,
            "client_name": state.config.client_name,
            "time_range": state.config.time_range,
            "hypotheses_tested": len(state.hypotheses),
            "hypotheses_with_findings": sum(1 for h in state.hypotheses if h.findings_count > 0),
            "total_findings": len(state.findings),
            "total_kql_queries": state.total_kql_queries,
        }
        findings_data = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "classification": f.classification.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "description": f.description[:500],
                "mitre_techniques": f.mitre_techniques,
                "recommendations": f.recommendations,
                "affected_entities": f.affected_entities,
                "detection_rule_kql": f.detection_rule_kql,
            }
            for f in state.findings
        ]
        env_summary = state.environment_index.rich_summary() if state.environment_index else {}

        return build_deliver_prompt(
            client_name=state.config.client_name,
            campaign_summary=campaign_summary,
            findings_data=findings_data,
            env_summary=env_summary,
        )

    def get_tools(self) -> list[dict[str, Any]]:
        # Delivery phase needs minimal tools — mostly report generation
        allowed = {"search_mitre", "get_sentinel_rule_examples"}
        return [t for t in AGENT_TOOLS if t["function"]["name"] in allowed]

    def get_max_iterations(self, state: CampaignState) -> int:
        return state.config.phase_max_iterations.get("deliver", 10)

    def get_initial_user_message(self, state: CampaignState) -> str:
        return (
            f"Generate the complete threat hunt report for {state.config.client_name}. "
            f"Include all {len(state.findings)} findings, evidence chains, "
            f"MITRE mappings, detection recommendations, and next steps. "
            f"Format as professional Markdown."
        )

    def extract_artifacts(self, response_text: str, state: CampaignState) -> dict[str, Any]:
        """Build the CampaignReport from the LLM's report output."""
        report = _build_report(response_text, state)
        state.report = report
        return {
            "report_generated": True,
            "report_sections": len(report.sections),
            "markdown_length": len(report.markdown),
        }


def _build_report(markdown_text: str, state: CampaignState) -> CampaignReport:
    """Assemble the CampaignReport from LLM output + campaign state."""
    findings = state.findings

    # Count by classification
    tp = sum(1 for f in findings if f.classification == FindingClassification.TRUE_POSITIVE)
    fp = sum(1 for f in findings if f.classification == FindingClassification.FALSE_POSITIVE)
    inc = sum(1 for f in findings if f.classification == FindingClassification.INCONCLUSIVE)
    esc = sum(1 for f in findings if f.classification == FindingClassification.REQUIRES_ESCALATION)
    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)

    # Collect all MITRE techniques
    all_techniques: set[str] = set()
    all_tactics: set[str] = set()
    for f in findings:
        all_techniques.update(f.mitre_techniques)
        all_tactics.update(f.mitre_tactics)
    for h in state.hypotheses:
        all_techniques.update(h.mitre_techniques)
        all_tactics.update(h.mitre_tactics)

    # Collect recommendations
    all_recommendations: list[str] = []
    detection_suggestions: list[DetectionSuggestion] = []
    for f in findings:
        all_recommendations.extend(f.recommendations)
        if f.detection_rule_kql:
            detection_suggestions.append(DetectionSuggestion(
                title=f"Detection for: {f.title}",
                description=f.description[:200],
                kql_query=f.detection_rule_kql,
                severity=f.severity.value,
                mitre_techniques=f.mitre_techniques,
                source_finding_id=f.finding_id,
            ))

    # Hypothesis summaries
    hypothesis_summaries = [
        {
            "title": h.title,
            "priority": h.priority.value,
            "score": h.priority_score,
            "status": h.status,
            "findings": h.findings_count,
            "queries": h.queries_executed,
            "mitre": h.mitre_techniques,
        }
        for h in state.hypotheses
    ]

    # Tables queried
    tables_queried: set[str] = set()
    for h in state.hypotheses:
        tables_queried.update(h.available_tables)

    report = CampaignReport(
        campaign_id=state.campaign_id,
        client_name=state.config.client_name,
        total_findings=len(findings),
        true_positives=tp,
        false_positives=fp,
        inconclusive=inc,
        requires_escalation=esc,
        critical_findings=crit,
        high_findings=high,
        hypotheses_tested=len(state.hypotheses),
        hypotheses_with_findings=sum(1 for h in state.hypotheses if h.findings_count > 0),
        hypotheses_skipped=sum(1 for h in state.hypotheses if h.status == "skipped"),
        hypothesis_summaries=hypothesis_summaries,
        mitre_techniques_hunted=sorted(all_techniques),
        mitre_tactics_covered=sorted(all_tactics),
        recommendations=list(dict.fromkeys(all_recommendations)),  # dedupe, preserve order
        detection_suggestions=detection_suggestions,
        total_queries_executed=state.total_kql_queries,
        duration_minutes=state.duration_minutes,
        tables_queried=sorted(tables_queried),
        markdown=markdown_text,
        json_export=state.model_dump(
            mode="json",
            exclude={"environment_index"},  # Too large for JSON export
        ),
    )

    from mssp_hunt_agent.hunter.phases.base import _now_iso
    report.created_at = _now_iso()
    return report
