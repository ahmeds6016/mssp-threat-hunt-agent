"""Models for final reports and audit records."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    evidence_id: str
    source: str  # query_id or enrichment source
    observation: str
    significance: str  # informational | suspicious | high_confidence
    supporting_data: str


class Finding(BaseModel):
    finding_id: str
    title: str
    description: str
    confidence: str  # low | medium | high
    evidence: list[EvidenceItem] = Field(default_factory=list)
    benign_explanations: list[str] = Field(default_factory=list)
    what_would_increase_confidence: list[str] = Field(default_factory=list)


class ConfidenceAssessment(BaseModel):
    overall_confidence: str
    rationale: str
    limiting_factors: list[str] = Field(default_factory=list)
    telemetry_impact: str


class ExecutiveSummary(BaseModel):
    client_name: str
    hunt_objective: str
    hunt_type: str
    time_range: str
    execution_mode: str  # mock | live
    scope_summary: str
    key_findings: list[str] = Field(default_factory=list)
    risk_assessment: str
    recommended_next_steps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AnalystReport(BaseModel):
    """Full analyst‑grade report with all sections."""

    # Metadata
    client_name: str
    hunt_type: str
    plan_id: str
    execution_mode: str

    # Confirmed inputs
    hunt_objective: str
    hunt_hypothesis: str
    time_range: str
    data_sources: list[str] = Field(default_factory=list)
    telemetry_gaps: list[str] = Field(default_factory=list)

    # Analysis
    attack_mapping: list[dict[str, Any]] = Field(default_factory=list)
    telemetry_readiness: str
    telemetry_rationale: str

    # Findings
    findings: list[Finding] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    confidence_assessment: ConfidenceAssessment

    # Recommendations
    escalation_recommendation: str
    detection_engineering_followups: list[str] = Field(default_factory=list)
    additional_hunt_pivots: list[str] = Field(default_factory=list)

    # Gaps
    gaps: list[str] = Field(default_factory=list)
    analyst_notes: str = "Not provided"


class RunAuditRecord(BaseModel):
    """Full audit trail for a single pipeline run."""

    run_id: str
    timestamp: str
    client_name: str
    hunt_type: str
    execution_mode: str
    input_payload: dict[str, Any]
    hunt_plan: dict[str, Any]
    approved_queries: list[dict[str, Any]] = Field(default_factory=list)
    query_results: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_results: list[dict[str, Any]] = Field(default_factory=list)
    executive_summary: dict[str, Any] = Field(default_factory=dict)
    analyst_report: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    pipeline_steps: list[dict[str, Any]] = Field(default_factory=list)
