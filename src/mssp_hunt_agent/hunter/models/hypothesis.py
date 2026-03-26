"""Hypothesis models for autonomous hunt campaigns."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HypothesisSource(str, Enum):
    """Where the hunt hypothesis originated."""

    COVERAGE_GAP = "coverage_gap"
    THREAT_LANDSCAPE = "threat_landscape"
    INDUSTRY_THREAT = "industry_threat"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    HISTORICAL_FINDING = "historical_finding"
    POSTURE_WEAKNESS = "posture_weakness"
    CISA_KEV = "cisa_kev"
    ANALYST_INPUT = "analyst_input"


class HypothesisPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AutonomousHypothesis(BaseModel):
    """A single threat hunt hypothesis generated from the environment index.

    Priority is computed as:
        threat_likelihood × detection_feasibility × business_impact
    """

    hypothesis_id: str
    title: str
    description: str
    source: HypothesisSource
    priority: HypothesisPriority = HypothesisPriority.MEDIUM
    priority_score: float = Field(ge=0.0, le=1.0, default=0.5)

    # Threat context
    threat_likelihood: float = Field(ge=0.0, le=1.0, default=0.5)
    business_impact: float = Field(ge=0.0, le=1.0, default=0.5)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)

    # Feasibility
    detection_feasibility: float = Field(ge=0.0, le=1.0, default=0.5)
    required_tables: list[str] = Field(default_factory=list)
    available_tables: list[str] = Field(default_factory=list)
    missing_tables: list[str] = Field(default_factory=list)

    # Hunt approach
    kql_approach: str = ""
    expected_indicators: list[str] = Field(default_factory=list)
    false_positive_notes: str = ""
    time_range: str = "last 30 days"

    # Execution tracking
    status: str = "pending"  # pending | in_progress | completed | skipped
    reason_skipped: str = ""
    findings_count: int = 0
    queries_executed: int = 0

    def compute_priority_score(self) -> float:
        """Recompute priority_score from component scores."""
        self.priority_score = round(
            self.threat_likelihood * self.detection_feasibility * self.business_impact,
            3,
        )
        if self.priority_score >= 0.6:
            self.priority = HypothesisPriority.CRITICAL
        elif self.priority_score >= 0.4:
            self.priority = HypothesisPriority.HIGH
        elif self.priority_score >= 0.2:
            self.priority = HypothesisPriority.MEDIUM
        else:
            self.priority = HypothesisPriority.LOW
        return self.priority_score

    @property
    def is_feasible(self) -> bool:
        """Can we actually hunt this? Need at least one required table."""
        return len(self.available_tables) > 0 and self.detection_feasibility > 0.1
