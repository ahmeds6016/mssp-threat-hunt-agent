"""Models for indicator-driven hunting (IOC sweeps / retro hunts)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from mssp_hunt_agent.models.input_models import HuntType, Priority
from mssp_hunt_agent.models.result_models import ExabeamEvent, EnrichmentRecord


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    URL = "url"
    USER_AGENT = "user_agent"


class IOCEntry(BaseModel):
    """A single indicator as submitted by the analyst."""

    value: str = Field(..., min_length=1)
    ioc_type: IOCType
    context: str = ""
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class IOCHuntInput(BaseModel):
    """Analyst intake for an indicator-driven hunt."""

    # Required
    client_name: str = Field(..., min_length=1)
    iocs: list[IOCEntry] = Field(..., min_length=1)
    time_range: str = Field(..., min_length=1)
    available_data_sources: list[str] = Field(..., min_length=1)

    # Optional
    sweep_objective: str = Field(default="IOC sweep / retro hunt")
    telemetry_gaps: list[str] = Field(default_factory=list)
    hunt_type: HuntType = Field(default=HuntType.IDENTITY)
    industry: str = Field(default="Not provided")
    priority: Priority = Field(default=Priority.HIGH)
    pre_enrich: bool = Field(default=True, description="Enrich IOCs via TI before sweep")
    analyst_notes: str = Field(default="Not provided")
    constraints: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)


# ── Post-validation models ────────────────────────────────────────────


class NormalizedIOC(BaseModel):
    """An IOC after validation, normalization, and defanging."""

    original_value: str
    normalized_value: str
    ioc_type: IOCType
    context: str = ""
    source: str = ""
    is_valid: bool = True
    validation_note: str = ""


class IOCBatch(BaseModel):
    """Grouped, deduplicated IOCs ready for sweep planning."""

    valid: list[NormalizedIOC] = Field(default_factory=list)
    invalid: list[NormalizedIOC] = Field(default_factory=list)
    dedup_removed: int = 0
    type_counts: dict[str, int] = Field(default_factory=dict)


# ── Hit / result models ──────────────────────────────────────────────


class IOCHit(BaseModel):
    """A confirmed hit for one IOC in the environment."""

    ioc_value: str
    ioc_type: str
    query_id: str
    hit_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    affected_users: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    sample_events: list[ExabeamEvent] = Field(default_factory=list)


class IOCSweepResult(BaseModel):
    """Aggregated results of an IOC sweep."""

    total_iocs_searched: int = 0
    total_hits: int = 0
    total_misses: int = 0
    hits: list[IOCHit] = Field(default_factory=list)
    misses: list[str] = Field(default_factory=list)


class IOCSweepReport(BaseModel):
    """Full report for an IOC sweep run."""

    # Metadata
    client_name: str
    plan_id: str
    execution_mode: str
    sweep_objective: str

    # Input summary
    total_iocs_submitted: int
    valid_iocs: int
    invalid_iocs: int
    dedup_removed: int
    type_breakdown: dict[str, int] = Field(default_factory=dict)

    # Pre-enrichment
    pre_enrichment_results: list[EnrichmentRecord] = Field(default_factory=list)

    # Sweep results
    sweep_result: IOCSweepResult
    time_range: str
    data_sources: list[str] = Field(default_factory=list)
    telemetry_gaps: list[str] = Field(default_factory=list)

    # Analysis
    telemetry_readiness: str
    telemetry_rationale: str
    escalation_recommendation: str
    benign_explanations: list[str] = Field(default_factory=list)
    detection_engineering_followups: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    analyst_notes: str = "Not provided"
    invalid_ioc_details: list[dict[str, str]] = Field(default_factory=list)
