"""Detection Engineering data models."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PerformanceRating(str, Enum):
    FAST = "fast"
    MODERATE = "moderate"
    SLOW = "slow"


class DetectionRule(BaseModel):
    """A KQL detection rule with metadata."""

    rule_id: str
    name: str
    description: str
    kql_query: str
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    data_sources: list[str] = Field(default_factory=list)
    created_by: str = "agent"  # "analyst" | "agent"
    enabled: bool = True
    false_positive_guidance: str = ""
    tags: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """Result of KQL syntax and schema validation."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    estimated_cost: str = ""  # "low" | "medium" | "high"
    tables_referenced: list[str] = Field(default_factory=list)
    time_range_detected: Optional[str] = None


class SimulationResult(BaseModel):
    """Result of running a detection rule against historical data."""

    rule_id: str
    total_matches: int = 0
    sample_events: list[dict] = Field(default_factory=list)
    time_range_tested: str = ""
    execution_time_ms: int = 0
    error: Optional[str] = None


class QualityScore(BaseModel):
    """Quality assessment of a detection rule."""

    rule_id: str
    coverage_score: float = 0.0       # ATT&CK coverage (0.0-1.0)
    precision_estimate: float = 0.0   # expected true positive rate
    noise_estimate: float = 0.0       # expected false positive rate
    performance_rating: PerformanceRating = PerformanceRating.MODERATE
    has_time_filter: bool = False
    has_field_filters: bool = False
    uses_aggregation: bool = False
    recommendations: list[str] = Field(default_factory=list)
    overall_grade: str = "C"  # A | B | C | D | F
