"""Models for client telemetry profiling (--mode profile)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mssp_hunt_agent.models.hunt_models import TelemetryReadiness
from mssp_hunt_agent.models.input_models import HuntType


class ProfileInput(BaseModel):
    """Analyst intake for a profiling run."""

    client_name: str = Field(..., min_length=1)
    time_range: str = Field(..., min_length=1)
    declared_data_sources: list[str] = Field(default_factory=list)
    hunt_types_of_interest: list[HuntType] = Field(
        default_factory=lambda: list(HuntType),
    )
    analyst_notes: str = Field(default="Not provided")
    constraints: list[str] = Field(default_factory=list)


class ParsedFieldInfo(BaseModel):
    """Statistics about a single parsed field within a data source."""

    field_name: str
    population_pct: float = Field(ge=0.0, le=100.0)
    sample_values: list[str] = Field(default_factory=list)
    null_pct: float = Field(ge=0.0, le=100.0)
    distinct_count_approx: int = Field(default=0)


class DataSourceProfile(BaseModel):
    """Profile of a single log source / vendor / product."""

    source_name: str
    vendor: str = "Unknown"
    product: str = "Unknown"
    category: HuntType = HuntType.IDENTITY
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    days_active: int = 0
    parsed_fields: list[ParsedFieldInfo] = Field(default_factory=list)
    is_simulated: bool = False


class HuntCapability(BaseModel):
    """Readiness assessment for one hunt type based on discovered telemetry."""

    hunt_type: HuntType
    readiness: TelemetryReadiness
    available_sources: list[str] = Field(default_factory=list)
    missing_sources: list[str] = Field(default_factory=list)
    coverage_pct: float = Field(ge=0.0, le=100.0)
    field_quality_notes: list[str] = Field(default_factory=list)
    rationale: str = ""


class ClientTelemetryProfile(BaseModel):
    """Top-level profile combining all discovered data sources and capability assessments."""

    profile_id: str
    client_name: str
    time_range: str
    execution_mode: str
    created_at: str
    is_simulated: bool = False

    data_sources: list[DataSourceProfile] = Field(default_factory=list)
    total_event_count: int = 0
    source_count: int = 0

    capabilities: list[HuntCapability] = Field(default_factory=list)

    declared_vs_discovered_gaps: list[str] = Field(default_factory=list)
    recency_warnings: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)

    analyst_notes: str = "Not provided"
