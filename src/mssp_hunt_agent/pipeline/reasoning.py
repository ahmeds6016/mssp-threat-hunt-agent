"""Reasoning stage — analyse evidence and produce structured findings.

This is the v1 rule-based reasoning engine.  In a future version the
structured evidence would be passed to an LLM with the analyst reasoning
prompt for richer analysis.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from mssp_hunt_agent.models.hunt_models import HuntPlan
from mssp_hunt_agent.models.result_models import EnrichmentRecord, QueryResult
from mssp_hunt_agent.models.report_models import (
    ConfidenceAssessment,
    EvidenceItem,
    Finding,
)


def analyse(
    plan: HuntPlan,
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
) -> tuple[list[Finding], list[EvidenceItem], ConfidenceAssessment]:
    """Consume structured evidence and produce findings + confidence."""

    evidence_items = _build_evidence(query_results, enrichments)
    findings = _derive_findings(evidence_items, enrichments, plan)
    confidence = _assess_confidence(plan, query_results, enrichments, findings)

    return findings, evidence_items, confidence


# ── evidence construction ─────────────────────────────────────────────

def _build_evidence(
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []

    for qr in query_results:
        if qr.status == "error":
            items.append(EvidenceItem(
                evidence_id=f"E-{uuid.uuid4().hex[:8]}",
                source=qr.query_id,
                observation=f"Query {qr.query_id} failed: {qr.error_message}",
                significance="informational",
                supporting_data=qr.query_text,
            ))
            continue

        if qr.result_count == 0:
            items.append(EvidenceItem(
                evidence_id=f"E-{uuid.uuid4().hex[:8]}",
                source=qr.query_id,
                observation=f"Query {qr.query_id} returned 0 results",
                significance="informational",
                supporting_data=qr.query_text,
            ))
            continue

        # Summarise non-empty results
        event_types = set()
        users = set()
        src_ips = set()
        for ev in qr.events:
            event_types.add(ev.event_type)
            if ev.user:
                users.add(ev.user)
            if ev.src_ip:
                src_ips.add(ev.src_ip)

        items.append(EvidenceItem(
            evidence_id=f"E-{uuid.uuid4().hex[:8]}",
            source=qr.query_id,
            observation=(
                f"Query {qr.query_id} returned {qr.result_count} events. "
                f"Event types: {', '.join(sorted(event_types))}. "
                f"Unique users: {', '.join(sorted(users)[:5])}. "
                f"Unique source IPs: {', '.join(sorted(src_ips)[:5])}."
            ),
            significance="informational",
            supporting_data=f"Execution time: {qr.execution_time_ms} ms",
        ))

    # TI enrichments
    for er in enrichments:
        if er.verdict in ("malicious", "suspicious"):
            items.append(EvidenceItem(
                evidence_id=f"E-{uuid.uuid4().hex[:8]}",
                source=er.source,
                observation=(
                    f"{er.entity_type.upper()} '{er.entity_value}' classified as "
                    f"{er.verdict} (confidence {er.confidence:.0%}) by {er.source}. "
                    f"Labels: {', '.join(er.labels) or 'none'}."
                ),
                significance="suspicious" if er.verdict == "suspicious" else "high_confidence",
                supporting_data=er.raw_reference or "",
            ))

    return items


# ── findings derivation ───────────────────────────────────────────────

def _derive_findings(
    evidence: list[EvidenceItem],
    enrichments: list[EnrichmentRecord],
    plan: HuntPlan,
) -> list[Finding]:
    findings: list[Finding] = []

    # Finding 1: any malicious TI hits?
    mal_enrichments = [e for e in enrichments if e.verdict == "malicious"]
    sus_enrichments = [e for e in enrichments if e.verdict == "suspicious"]
    related_evidence = [e for e in evidence if e.significance in ("suspicious", "high_confidence")]

    if mal_enrichments:
        findings.append(Finding(
            finding_id=f"F-{uuid.uuid4().hex[:8]}",
            title="Threat Intel Match — Known Malicious Indicators",
            description=(
                f"{len(mal_enrichments)} entity/entities matched known-malicious indicators. "
                "Immediate triage and scoping recommended."
            ),
            confidence="medium",
            evidence=related_evidence,
            benign_explanations=[
                "Possible false positive from stale threat-intel feeds",
                "Shared infrastructure (CDN, cloud hosting) can produce false positives",
            ],
            what_would_increase_confidence=[
                "Correlate with EDR / endpoint telemetry for process-level context",
                "Validate with a second threat-intel source",
                "Check if entity appeared before or after the attack window",
            ],
        ))

    if sus_enrichments and not mal_enrichments:
        findings.append(Finding(
            finding_id=f"F-{uuid.uuid4().hex[:8]}",
            title="Suspicious Indicators Identified",
            description=(
                f"{len(sus_enrichments)} entity/entities flagged as suspicious. "
                "Further investigation warranted."
            ),
            confidence="low",
            evidence=related_evidence,
            benign_explanations=[
                "VPN / proxy services frequently flagged as suspicious",
                "Automated scanners or IT tooling may trigger false positives",
            ],
            what_would_increase_confidence=[
                "Review user account activity timeline for anomalous patterns",
                "Cross-reference with known benign patterns provided by client",
                "Enrich with additional threat-intel providers",
            ],
        ))

    # Finding 2: anomaly query results volume
    anomaly_results = [
        e for e in evidence
        if "returned" in e.observation and "anomal" not in e.observation.lower()
    ]
    if not findings and not mal_enrichments and not sus_enrichments:
        findings.append(Finding(
            finding_id=f"F-{uuid.uuid4().hex[:8]}",
            title="No High-Confidence Threats Identified",
            description=(
                "No indicators matched known threats at high confidence. "
                "This does not guarantee absence of compromise — see telemetry "
                "gaps and recommendations."
            ),
            confidence="low",
            evidence=[e for e in evidence if e.significance == "informational"][:3],
            benign_explanations=["Results are consistent with normal operations"],
            what_would_increase_confidence=[
                "Expand telemetry coverage (see gaps section)",
                "Conduct follow-up hunt with broader hypothesis",
                "Deploy new detection rules for this attack surface",
            ],
        ))

    return findings


# ── confidence assessment ─────────────────────────────────────────────

def _assess_confidence(
    plan: HuntPlan,
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
    findings: list[Finding],
) -> ConfidenceAssessment:
    limiting: list[str] = []

    # Telemetry
    tel = plan.telemetry_assessment
    if tel.readiness.value != "Green":
        limiting.append(f"Telemetry readiness is {tel.readiness.value}: {tel.impact_on_hunt}")

    # Error rate
    errors = [qr for qr in query_results if qr.status == "error"]
    if errors:
        limiting.append(f"{len(errors)} query/queries failed during execution")

    # Low enrichment coverage
    unknown = [e for e in enrichments if e.verdict == "unknown"]
    if len(unknown) > len(enrichments) * 0.5 and enrichments:
        limiting.append("More than 50% of enrichments returned 'unknown' verdict")

    if not limiting:
        overall = "medium"
        rationale = (
            "Telemetry is adequate and query execution succeeded. "
            "Confidence is medium because mock execution data does not reflect live environment."
        )
    else:
        overall = "low"
        rationale = (
            "Multiple factors limit confidence in these results. "
            "See limiting factors below."
        )

    return ConfidenceAssessment(
        overall_confidence=overall,
        rationale=rationale,
        limiting_factors=limiting or ["None identified"],
        telemetry_impact=tel.impact_on_hunt,
    )
