"""Finding and evidence chain models for autonomous hunt campaigns."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FindingClassification(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    REQUIRES_ESCALATION = "requires_escalation"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceLink(BaseModel):
    """A single piece of evidence in an evidence chain.

    Represents one query execution and its key observations.
    """

    evidence_id: str
    source_type: str  # kql_result | enrichment | mitre_mapping | correlation | pivot
    query_text: str = ""
    query_table: str = ""
    result_count: int = 0
    result_summary: str = ""
    key_observations: list[str] = Field(default_factory=list)
    timestamp_range: str = ""
    entities_involved: dict[str, list[str]] = Field(default_factory=dict)
    raw_sample: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceChain(BaseModel):
    """Ordered chain of evidence links building a narrative."""

    chain_id: str
    links: list[EvidenceLink] = Field(default_factory=list)
    narrative: str = ""
    timeline: list[dict[str, str]] = Field(default_factory=list)

    @property
    def total_events_analyzed(self) -> int:
        return sum(link.result_count for link in self.links)

    @property
    def all_entities(self) -> dict[str, set[str]]:
        """Merge all entities across evidence links."""
        merged: dict[str, set[str]] = {}
        for link in self.links:
            for entity_type, values in link.entities_involved.items():
                if entity_type not in merged:
                    merged[entity_type] = set()
                merged[entity_type].update(values)
        return merged


class HuntFinding(BaseModel):
    """A classified finding from a hunt hypothesis execution.

    This is the core output of the autonomous hunter — each finding
    represents a confirmed (or inconclusive) security observation
    with full evidence chain and recommendations.
    """

    finding_id: str
    hypothesis_id: str
    campaign_id: str = ""
    title: str
    description: str
    classification: FindingClassification
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    created_at: str = ""

    # Evidence
    evidence_chain: EvidenceChain = Field(default_factory=lambda: EvidenceChain(chain_id=""))

    # Context
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    affected_entities: dict[str, list[str]] = Field(default_factory=dict)
    affected_assets: list[str] = Field(default_factory=list)

    # Analysis
    benign_explanations: list[str] = Field(default_factory=list)
    what_would_increase_confidence: list[str] = Field(default_factory=list)
    analyst_notes: str = ""

    # Actionable output
    recommendations: list[str] = Field(default_factory=list)
    detection_rule_kql: str = ""
    containment_steps: list[str] = Field(default_factory=list)

    @property
    def is_actionable(self) -> bool:
        return self.classification in (
            FindingClassification.TRUE_POSITIVE,
            FindingClassification.REQUIRES_ESCALATION,
        )
