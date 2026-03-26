"""LLM-powered reasoning stage with rule-based fallback.

When an LLM adapter is available, formats structured evidence into a prompt,
sends it to the LLM, and parses the structured JSON response back into
Finding / EvidenceItem / ConfidenceAssessment models.

Falls back to the rule-based ``reasoning.analyse()`` on any LLM failure.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.models.hunt_models import HuntPlan
from mssp_hunt_agent.models.report_models import (
    ConfidenceAssessment,
    EvidenceItem,
    Finding,
)
from mssp_hunt_agent.models.result_models import EnrichmentRecord, QueryResult
from mssp_hunt_agent.pipeline import reasoning as rule_reasoning

logger = logging.getLogger(__name__)

# ── System prompt for the LLM ──────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an expert MSSP threat hunting analyst. You are given structured evidence
from Exabeam query results and threat intelligence enrichments. Your task is to
analyze the evidence and produce findings.

You MUST respond with a valid JSON object containing exactly these keys:

{
  "findings": [
    {
      "finding_id": "F-LLM-<8hex>",
      "title": "<concise title>",
      "description": "<detailed description with evidence citations>",
      "confidence": "low|medium|high",
      "evidence_ids": ["<evidence_id references>"],
      "benign_explanations": ["<possible benign explanation>"],
      "what_would_increase_confidence": ["<what would help>"]
    }
  ],
  "evidence_items": [
    {
      "evidence_id": "E-LLM-<8hex>",
      "source": "llm_analysis",
      "observation": "<what you observed>",
      "significance": "informational|suspicious|high_confidence",
      "supporting_data": "<supporting context>"
    }
  ],
  "confidence_assessment": {
    "overall_confidence": "low|medium|high",
    "rationale": "<why this confidence level>",
    "limiting_factors": ["<factor>"],
    "telemetry_impact": "<how telemetry affects analysis>"
  }
}

Guidelines:
- Ground every finding in specific evidence. Cite evidence_ids.
- Be conservative with confidence. Prefer "medium" unless evidence is strong.
- Consider benign explanations for every finding.
- Identify what additional data would increase confidence.
- If there is no evidence of threats, say so clearly as a finding.
- Never fabricate data. Only reference evidence provided.
"""


def llm_analyse(
    plan: HuntPlan,
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
    llm_adapter: LLMAdapter,
) -> tuple[list[Finding], list[EvidenceItem], ConfidenceAssessment]:
    """Analyse evidence using an LLM, falling back to rules on failure."""
    try:
        user_prompt = _build_user_prompt(plan, query_results, enrichments)
        raw = llm_adapter.analyze(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
        findings = _parse_findings(raw.get("findings", []))
        evidence = _parse_evidence(raw.get("evidence_items", []))
        confidence = _parse_confidence(raw.get("confidence_assessment", {}), plan)

        logger.info(
            "LLM reasoning produced %d findings (%s)",
            len(findings),
            llm_adapter.get_adapter_name(),
        )
        return findings, evidence, confidence

    except Exception as exc:
        logger.warning(
            "LLM reasoning failed (%s), falling back to rule-based: %s",
            llm_adapter.get_adapter_name(),
            exc,
        )
        return rule_reasoning.analyse(plan, query_results, enrichments)


# ── Prompt construction ─────────────────────────────────────────────────


def _build_user_prompt(
    plan: HuntPlan,
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
) -> str:
    """Format structured evidence into the LLM user prompt."""
    sections: list[str] = []

    # Hunt context
    sections.append("## Hunt Context")
    sections.append(f"- Client: {plan.client_name}")
    sections.append(f"- Objective: {plan.objective}")
    sections.append(f"- Hunt type: {plan.hunt_type}")
    sections.append(
        f"- Telemetry readiness: {plan.telemetry_assessment.readiness.value}"
    )
    if plan.hypotheses:
        for hyp in plan.hypotheses:
            sections.append(f"- Hypothesis: {hyp.description}")
            sections.append(f"  Tactics: {', '.join(hyp.attack_tactics)}")
            sections.append(
                f"  Techniques: {', '.join(hyp.attack_techniques) or 'None'}"
            )

    # Query results
    sections.append("\n## Query Results")
    for qr in query_results:
        sections.append(f"\n### {qr.query_id}")
        sections.append(f"- Status: {qr.status}")
        sections.append(f"- Result count: {qr.result_count}")
        sections.append(f"- Query: {qr.query_text}")
        if qr.error_message:
            sections.append(f"- Error: {qr.error_message}")
        if qr.events:
            sections.append("- Sample events (first 10):")
            for ev in qr.events[:10]:
                ev_data = {
                    k: v
                    for k, v in ev.model_dump().items()
                    if v is not None and k != "fields"
                }
                if ev.fields:
                    ev_data["fields"] = ev.fields
                sections.append(f"  {json.dumps(ev_data, default=str)}")

    # Enrichments
    sections.append("\n## Threat Intelligence Enrichments")
    if enrichments:
        for er in enrichments:
            sections.append(
                f"- {er.entity_type} '{er.entity_value}': "
                f"verdict={er.verdict}, confidence={er.confidence:.0%}, "
                f"source={er.source}, labels={er.labels}"
            )
    else:
        sections.append("- No enrichments available")

    # Telemetry gaps
    sections.append("\n## Telemetry Assessment")
    tel = plan.telemetry_assessment
    sections.append(f"- Readiness: {tel.readiness.value}")
    sections.append(f"- Rationale: {tel.rationale}")
    sections.append(f"- Impact: {tel.impact_on_hunt}")
    if tel.missing_sources:
        sections.append(f"- Missing sources: {', '.join(tel.missing_sources)}")

    return "\n".join(sections)


# ── Response parsing ────────────────────────────────────────────────────


def _parse_findings(raw_findings: list[dict[str, Any]]) -> list[Finding]:
    """Convert LLM finding dicts into Finding models."""
    findings: list[Finding] = []
    for rf in raw_findings:
        evidence_items = []
        for eid in rf.get("evidence_ids", []):
            evidence_items.append(
                EvidenceItem(
                    evidence_id=eid,
                    source="llm_reference",
                    observation=f"Referenced by LLM finding",
                    significance="informational",
                    supporting_data="",
                )
            )

        findings.append(
            Finding(
                finding_id=rf.get("finding_id", f"F-LLM-{uuid.uuid4().hex[:8]}"),
                title=rf.get("title", "LLM Finding"),
                description=rf.get("description", ""),
                confidence=rf.get("confidence", "low"),
                evidence=evidence_items,
                benign_explanations=rf.get("benign_explanations", []),
                what_would_increase_confidence=rf.get(
                    "what_would_increase_confidence", []
                ),
            )
        )
    return findings


def _parse_evidence(raw_evidence: list[dict[str, Any]]) -> list[EvidenceItem]:
    """Convert LLM evidence dicts into EvidenceItem models."""
    items: list[EvidenceItem] = []
    for re_ in raw_evidence:
        items.append(
            EvidenceItem(
                evidence_id=re_.get(
                    "evidence_id", f"E-LLM-{uuid.uuid4().hex[:8]}"
                ),
                source=re_.get("source", "llm_analysis"),
                observation=re_.get("observation", ""),
                significance=re_.get("significance", "informational"),
                supporting_data=re_.get("supporting_data", ""),
            )
        )
    return items


def _parse_confidence(
    raw: dict[str, Any], plan: HuntPlan
) -> ConfidenceAssessment:
    """Convert LLM confidence dict into ConfidenceAssessment model."""
    return ConfidenceAssessment(
        overall_confidence=raw.get("overall_confidence", "low"),
        rationale=raw.get("rationale", "LLM analysis complete"),
        limiting_factors=raw.get("limiting_factors", ["None identified"]),
        telemetry_impact=raw.get(
            "telemetry_impact", plan.telemetry_assessment.impact_on_hunt
        ),
    )
