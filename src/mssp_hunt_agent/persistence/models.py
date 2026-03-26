"""Pydantic models for the persistence layer."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ClientRecord(BaseModel):
    """A managed client in the MSSP database."""

    client_id: str
    client_name: str
    industry: str = ""
    primary_contact: str = ""
    onboarded_at: str = ""
    notes: str = ""


class ProfileVersion(BaseModel):
    """A versioned snapshot of a client's telemetry profile."""

    version_id: str
    client_id: str
    version_number: int
    profile_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    source_count: int = 0
    total_event_count: int = 0
    execution_mode: str = "mock"
    notes: str = ""


class RunRecord(BaseModel):
    """A persisted hunt/IOC/profile pipeline run."""

    run_id: str
    client_id: str
    client_name: str
    hunt_type: str  # hypothesis | ioc_sweep | profile
    execution_mode: str = "mock"  # mock | live
    started_at: str = ""
    completed_at: str = ""
    status: str = "completed"  # completed | failed | stopped
    findings_count: int = 0
    high_confidence_count: int = 0
    queries_executed: int = 0
    total_events: int = 0
    output_dir: str = ""
    summary: str = ""
    errors: list[str] = Field(default_factory=list)


class FindingRecord(BaseModel):
    """A persisted finding from a hunt run."""

    finding_id: str
    run_id: str
    client_id: str
    title: str
    description: str = ""
    confidence: str = ""  # low | medium | high
    evidence_count: int = 0
    created_at: str = ""


class IOCSweepRecord(BaseModel):
    """A persisted IOC sweep result summary."""

    sweep_id: str
    run_id: str
    client_id: str
    total_iocs: int = 0
    valid_iocs: int = 0
    total_hits: int = 0
    total_misses: int = 0
    hit_iocs: list[str] = Field(default_factory=list)
    created_at: str = ""


class ClientStats(BaseModel):
    """Aggregated statistics for a client."""

    client_id: str
    client_name: str
    total_runs: int = 0
    hypothesis_runs: int = 0
    ioc_runs: int = 0
    profile_runs: int = 0
    total_findings: int = 0
    high_confidence_findings: int = 0
    last_run_at: Optional[str] = None
    last_profile_at: Optional[str] = None


# ── V3: Campaign persistence models ───────────────────────────────────


class CampaignRecord(BaseModel):
    """A persisted autonomous hunt campaign."""

    campaign_id: str
    client_id: str
    client_name: str
    status: str = "pending"  # pending | running | completed | failed
    started_at: str = ""
    completed_at: str = ""
    total_hypotheses: int = 0
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    inconclusive: int = 0
    escalations: int = 0
    total_kql_queries: int = 0
    total_llm_tokens: int = 0
    duration_minutes: float = 0.0
    focus_areas: str = "[]"  # JSON list
    config_json: str = "{}"  # Full CampaignConfig as JSON
    summary: str = ""
    errors: str = "[]"  # JSON list


class CampaignFindingRecord(BaseModel):
    """A persisted finding from an autonomous campaign."""

    finding_id: str
    campaign_id: str
    client_id: str
    hypothesis_id: str = ""
    title: str
    classification: str = "inconclusive"  # true_positive | false_positive | inconclusive | requires_escalation
    severity: str = "informational"
    confidence: float = 0.5
    mitre_techniques: str = "[]"  # JSON list
    mitre_tactics: str = "[]"  # JSON list
    affected_entities: str = "{}"  # JSON dict
    evidence_summary: str = ""
    recommendations: str = "[]"  # JSON list
    detection_rule_kql: str = ""
    created_at: str = ""


class CampaignHypothesisRecord(BaseModel):
    """A persisted hypothesis from an autonomous campaign."""

    hypothesis_id: str
    campaign_id: str
    client_id: str
    title: str
    description: str = ""
    source: str = ""  # coverage_gap | threat_landscape | etc.
    priority_score: float = 0.5
    status: str = "pending"  # pending | completed | skipped
    mitre_techniques: str = "[]"  # JSON list
    available_tables: str = "[]"  # JSON list
    findings_count: int = 0
    queries_executed: int = 0
    created_at: str = ""


class HuntLessonRecord(BaseModel):
    """A learned lesson extracted from campaign outcomes.

    Lessons encode what the agent learned: which hypotheses were productive,
    which query patterns found true positives, which false positive patterns
    to skip, and which MITRE techniques are most relevant for this client.
    """

    lesson_id: str
    client_id: str
    campaign_id: str
    lesson_type: str  # productive_hypothesis | false_positive_pattern | effective_query | technique_relevance | environmental_baseline
    title: str
    description: str = ""
    mitre_techniques: str = "[]"  # JSON list
    tables_involved: str = "[]"  # JSON list
    confidence: float = 0.5
    times_confirmed: int = 1  # incremented when same lesson re-learned
    created_at: str = ""
    updated_at: str = ""
