"""Models for analytics, KPIs, rollup reports, and client tuning."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ClientKPIs(BaseModel):
    """Key performance indicators for a single client."""

    client_name: str
    period: str  # e.g. "2024-W48" or "2024-12"
    total_hunts: int = 0
    hypothesis_hunts: int = 0
    ioc_sweeps: int = 0
    profile_runs: int = 0
    total_findings: int = 0
    high_confidence_findings: int = 0
    total_queries: int = 0
    total_events: int = 0
    hit_rate: float = 0.0  # findings / hunts (or 0 if no hunts)
    mean_queries_per_hunt: float = 0.0
    mean_events_per_hunt: float = 0.0


class WeeklyRollup(BaseModel):
    """Aggregated weekly rollup across all clients or a single client."""

    period: str  # e.g. "2024-W48"
    start_date: str
    end_date: str
    total_clients_active: int = 0
    total_hunts: int = 0
    total_findings: int = 0
    high_confidence_findings: int = 0
    client_kpis: list[ClientKPIs] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)


class MonthlyRollup(BaseModel):
    """Aggregated monthly rollup."""

    period: str  # e.g. "2024-12"
    total_clients_active: int = 0
    total_hunts: int = 0
    total_findings: int = 0
    high_confidence_findings: int = 0
    client_kpis: list[ClientKPIs] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    recurring_gaps: list[str] = Field(default_factory=list)


class TuningRule(BaseModel):
    """A single tuning exclusion or threshold override."""

    rule_id: str
    rule_type: str  # "exclusion" | "threshold" | "benign_pattern"
    pattern: str  # e.g. "ip:8.8.8.8" or "user:svc_backup@*"
    reason: str = ""
    created_at: str = ""


class ClientTuningConfig(BaseModel):
    """Per-client tuning configuration."""

    client_name: str
    exclusions: list[TuningRule] = Field(default_factory=list)
    benign_patterns: list[TuningRule] = Field(default_factory=list)
    custom_thresholds: dict[str, Any] = Field(default_factory=dict)
