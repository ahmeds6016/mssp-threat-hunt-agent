"""Risk simulation data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskScenario(BaseModel):
    client_name: str
    change_type: str  # remove_source | add_source | degrade_source
    affected_source: str  # e.g., "DeviceProcessEvents", "SigninLogs"
    description: str = ""


class CoverageChange(BaseModel):
    path_name: str
    coverage_before: float
    coverage_after: float
    delta: float
    risk_before: str
    risk_after: str


class ImpactAssessment(BaseModel):
    scenario: RiskScenario
    changes: list[CoverageChange] = Field(default_factory=list)
    avg_coverage_before: float = 0.0
    avg_coverage_after: float = 0.0
    overall_delta: float = 0.0
    blind_spots: list[str] = Field(default_factory=list)
    risk_rating: str = "medium"  # low | medium | high | critical
    recommendations: list[str] = Field(default_factory=list)


class PortfolioRisk(BaseModel):
    total_clients: int = 0
    assessments: list[ImpactAssessment] = Field(default_factory=list)
    highest_risk_client: str = ""
    avg_portfolio_coverage: float = 0.0
    critical_gaps: list[str] = Field(default_factory=list)
