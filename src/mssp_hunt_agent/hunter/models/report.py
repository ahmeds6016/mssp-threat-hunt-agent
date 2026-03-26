"""Campaign report models for deliverable generation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ReportSection(BaseModel):
    """A single section of the campaign report."""

    title: str
    content: str
    order: int = 0


class MITREHeatmapEntry(BaseModel):
    """A single cell in the MITRE ATT&CK heatmap."""

    technique_id: str
    technique_name: str
    tactic: str
    status: str  # covered | gap | finding
    finding_id: str = ""
    notes: str = ""


class DetectionSuggestion(BaseModel):
    """A detection rule suggestion from hunt findings."""

    title: str
    description: str
    kql_query: str
    severity: str = "medium"
    mitre_techniques: list[str] = Field(default_factory=list)
    source_finding_id: str = ""


class CampaignReport(BaseModel):
    """Full campaign report — the final deliverable.

    Contains everything needed to produce a professional
    MSSP threat hunt report.
    """

    campaign_id: str
    client_name: str
    created_at: str = ""

    # Executive summary
    executive_summary: str = ""
    environment_overview: str = ""
    methodology: str = ""

    # Hypothesis tracking
    hypotheses_tested: int = 0
    hypotheses_with_findings: int = 0
    hypotheses_skipped: int = 0
    hypothesis_summaries: list[dict[str, Any]] = Field(default_factory=list)

    # Finding counts
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    inconclusive: int = 0
    requires_escalation: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    # MITRE coverage
    mitre_heatmap: list[MITREHeatmapEntry] = Field(default_factory=list)
    mitre_techniques_hunted: list[str] = Field(default_factory=list)
    mitre_tactics_covered: list[str] = Field(default_factory=list)

    # Recommendations
    recommendations: list[str] = Field(default_factory=list)
    detection_suggestions: list[DetectionSuggestion] = Field(default_factory=list)
    next_hunt_priorities: list[str] = Field(default_factory=list)
    posture_improvements: list[str] = Field(default_factory=list)

    # Operational metrics
    total_queries_executed: int = 0
    total_events_analyzed: int = 0
    duration_minutes: float = 0.0
    tables_queried: list[str] = Field(default_factory=list)

    # Report sections (for rendering)
    sections: list[ReportSection] = Field(default_factory=list)

    # Raw content (multiple formats)
    markdown: str = ""
    json_export: dict[str, Any] = Field(default_factory=dict)
