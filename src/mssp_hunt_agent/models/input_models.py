"""Input / intake models — everything the analyst provides."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HuntType(str, Enum):
    IDENTITY = "identity"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"


class Priority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class HuntInput(BaseModel):
    """Validated analyst intake for a single threat hunt engagement."""

    # ── Required fields ──────────────────────────────────────────────
    client_name: str = Field(..., min_length=1, description="Client / tenant name")
    hunt_objective: str = Field(..., min_length=1, description="What are we trying to find?")
    hunt_hypothesis: str = Field(
        ..., min_length=1, description="Hypothesis driving the hunt"
    )
    time_range: str = Field(
        ..., min_length=1, description="e.g. '2024-01-01 to 2024-01-31'"
    )
    available_data_sources: list[str] = Field(
        ..., min_length=1, description="Log sources available for this hunt"
    )
    telemetry_gaps: list[str] = Field(
        default_factory=list,
        description="Known telemetry blind spots",
    )

    # ── Optional fields ──────────────────────────────────────────────
    hunt_type: HuntType = Field(
        default=HuntType.IDENTITY, description="Category of hunt"
    )
    industry: str = Field(default="Not provided")
    key_assets: list[str] = Field(default_factory=list)
    priority: Priority = Field(default=Priority.MEDIUM)
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs e.g. T1078, T1059.001",
    )
    known_benign_patterns: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    prior_related_incidents: list[str] = Field(default_factory=list)
    analyst_notes: str = Field(default="Not provided")
    constraints: list[str] = Field(default_factory=list)
