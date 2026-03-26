"""Pydantic request/response schemas for the REST API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Requests ─────────────────────────────────────────────────────────


class HuntRequest(BaseModel):
    """POST /api/v1/hunts — start a hypothesis-driven hunt."""

    client_name: str = Field(..., min_length=1)
    hunt_objective: str = Field(..., min_length=1)
    hunt_hypothesis: str = Field(..., min_length=1)
    time_range: str = Field(..., min_length=1)
    available_data_sources: list[str] = Field(..., min_length=1)
    telemetry_gaps: list[str] = Field(default_factory=list)
    hunt_type: str = "identity"
    industry: str = "Not provided"
    priority: str = "Medium"
    attack_techniques: list[str] = Field(default_factory=list)
    known_benign_patterns: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    analyst_notes: str = "Not provided"
    plan_only: bool = False
    allow_pivots: bool = False
    persist: bool = True


class IOCItem(BaseModel):
    value: str = Field(..., min_length=1)
    ioc_type: str = "ip"
    context: str = ""


class IOCSweepRequest(BaseModel):
    """POST /api/v1/ioc-sweeps — start an IOC sweep."""

    client_name: str = Field(..., min_length=1)
    iocs: list[IOCItem] = Field(..., min_length=1)
    time_range: str = Field(..., min_length=1)
    available_data_sources: list[str] = Field(..., min_length=1)
    telemetry_gaps: list[str] = Field(default_factory=list)
    sweep_objective: str = "IOC sweep / retro hunt"
    pre_enrich: bool = True
    analyst_notes: str = "Not provided"
    plan_only: bool = False
    persist: bool = True


class ProfileRequest(BaseModel):
    """POST /api/v1/profiles — start a telemetry profiling run."""

    client_name: str = Field(..., min_length=1)
    time_range: str = Field(..., min_length=1)
    declared_data_sources: list[str] = Field(default_factory=list)
    hunt_types_of_interest: list[str] = Field(
        default_factory=lambda: ["identity", "endpoint", "network", "cloud"]
    )
    analyst_notes: str = "Not provided"
    plan_only: bool = False
    persist: bool = True


class ApproveRequest(BaseModel):
    """POST /api/v1/hunts/{run_id}/approve — approve a pending run."""

    approved: bool = True


# ── Responses ────────────────────────────────────────────────────────


class RunStatusResponse(BaseModel):
    """Returned by all pipeline start endpoints and status checks."""

    run_id: str
    status: str  # queued | running | completed | failed | stopped
    hunt_type: str
    client_name: str
    started_at: str = ""
    completed_at: str = ""
    message: str = ""
    output_dir: str = ""
    findings_count: int = 0
    queries_executed: int = 0
    total_events: int = 0
    errors: list[str] = Field(default_factory=list)
    executive_summary: Optional[str] = None
    analyst_report: Optional[str] = None


class HealthResponse(BaseModel):
    """GET /api/v1/health."""

    status: str = "ok"
    version: str = "0.3.0"
    adapter_mode: str = "mock"
    persist_enabled: bool = False
    sharepoint_enabled: bool = False


class ClientListResponse(BaseModel):
    """GET /api/v1/clients."""

    clients: list[dict[str, Any]] = Field(default_factory=list)


class RunListResponse(BaseModel):
    """GET /api/v1/runs."""

    runs: list[dict[str, Any]] = Field(default_factory=list)
