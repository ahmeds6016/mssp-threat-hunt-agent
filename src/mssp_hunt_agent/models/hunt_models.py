"""Models produced by the hunt-planning stage."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TelemetryReadiness(str, Enum):
    GREEN = "Green"
    YELLOW = "Yellow"
    RED = "Red"


class QueryIntent(str, Enum):
    BASELINE = "baseline"
    ANOMALY_CANDIDATE = "anomaly_candidate"
    PIVOT = "pivot"
    CONFIRMATION = "confirmation"
    IOC_HUNT = "ioc_hunt"


class SafetyFlag(BaseModel):
    """A single guardrail violation or warning on a query."""

    rule: str
    severity: str  # "warning" | "error"
    message: str


class ExabeamQuery(BaseModel):
    """One candidate query to be executed (or reviewed) against Exabeam Search."""

    query_id: str
    intent: QueryIntent
    description: str
    query_text: str
    time_range: str
    expected_signal: str
    likely_false_positives: list[str] = Field(default_factory=list)
    fallback_query: Optional[str] = None
    required_data_sources: list[str] = Field(default_factory=list)
    safety_flags: list[SafetyFlag] = Field(default_factory=list)
    approved: bool = False
    is_pivot: bool = False


class HuntHypothesis(BaseModel):
    hypothesis_id: str
    description: str
    attack_tactics: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    technique_source: str  # "analyst_provided" | "inferred"
    confidence: str  # low / medium / high
    rationale: str


class HuntStep(BaseModel):
    step_number: int
    description: str
    queries: list[ExabeamQuery] = Field(default_factory=list)
    success_criteria: str
    next_if_positive: str
    next_if_negative: str


class TelemetryAssessment(BaseModel):
    readiness: TelemetryReadiness
    rationale: str
    available_sources: list[str] = Field(default_factory=list)
    missing_sources: list[str] = Field(default_factory=list)
    impact_on_hunt: str


class HuntPlan(BaseModel):
    """Complete plan emitted by the planning stage."""

    plan_id: str
    client_name: str
    hunt_type: str
    objective: str
    hypotheses: list[HuntHypothesis] = Field(default_factory=list)
    telemetry_assessment: TelemetryAssessment
    hunt_steps: list[HuntStep] = Field(default_factory=list)
    triage_checklist: list[str] = Field(default_factory=list)
    escalation_criteria: list[str] = Field(default_factory=list)
    expected_false_positives: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    created_at: str
