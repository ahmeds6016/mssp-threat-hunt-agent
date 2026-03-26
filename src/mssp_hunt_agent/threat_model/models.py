"""Threat modeling data models."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AssetEntry(BaseModel):
    name: str
    asset_type: str  # server, workstation, cloud_service, identity, network_device
    data_sources: list[str] = Field(default_factory=list)
    criticality: str = "medium"  # low | medium | high | critical


class AssetMap(BaseModel):
    client_name: str
    assets: list[AssetEntry] = Field(default_factory=list)
    total_assets: int = 0
    coverage_summary: dict[str, int] = Field(default_factory=dict)


class AttackPath(BaseModel):
    path_id: str
    entry_point: str
    techniques: list[str] = Field(default_factory=list)
    target_assets: list[str] = Field(default_factory=list)
    detection_coverage: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    risk_level: str = "medium"


class BreachSimulation(BaseModel):
    scenario: str
    attack_paths: list[AttackPath] = Field(default_factory=list)
    overall_detection_probability: float = 0.0
    time_to_detect_estimate: str = "unknown"
    recommendations: list[str] = Field(default_factory=list)


class ThreatModelReport(BaseModel):
    client_name: str
    asset_map: Optional[AssetMap] = None
    attack_paths: list[AttackPath] = Field(default_factory=list)
    simulations: list[BreachSimulation] = Field(default_factory=list)
    overall_risk: str = "medium"
    key_gaps: list[str] = Field(default_factory=list)
