"""Campaign state models for autonomous hunt orchestration."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from mssp_hunt_agent.hunter.models.environment import EnvironmentIndex
from mssp_hunt_agent.hunter.models.finding import HuntFinding
from mssp_hunt_agent.hunter.models.hypothesis import AutonomousHypothesis
from mssp_hunt_agent.hunter.models.report import CampaignReport


class CampaignPhase(str, Enum):
    """Hunt campaign lifecycle phases."""

    INDEX_REFRESH = "index_refresh"  # Refresh dynamic index layer
    HYPOTHESIZE = "hypothesize"      # Generate prioritized hypotheses
    EXECUTE = "execute"              # Run hunts with pivoting
    CONCLUDE = "conclude"            # Classify findings, build evidence
    DELIVER = "deliver"              # Generate report
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class CampaignConfig(BaseModel):
    """Configuration for an autonomous hunt campaign."""

    client_name: str
    client_id: str = ""
    workspace_id: str = ""

    # Scope
    time_range: str = "last 30 days"
    focus_areas: list[str] = Field(default_factory=list)
    exclude_hypotheses: list[str] = Field(default_factory=list)

    # Limits
    max_hypotheses: int = 10
    max_queries_per_hypothesis: int = 20
    max_total_queries: int = 200
    max_duration_minutes: int = 60
    max_llm_tokens: int = 750_000
    max_pivot_depth: int = 2
    auto_pivot: bool = True
    priority_threshold: float = 0.2

    # Phase-specific iteration limits
    phase_max_iterations: dict[str, int] = Field(default_factory=lambda: {
        "index_refresh": 10,
        "hypothesize": 15,
        "execute": 20,   # per hypothesis
        "conclude": 15,
        "deliver": 10,
    })
    phase_timeout_minutes: dict[str, int] = Field(default_factory=lambda: {
        "index_refresh": 5,
        "hypothesize": 5,
        "execute": 30,
        "conclude": 10,
        "deliver": 5,
    })

    # Output
    output_formats: list[str] = Field(default_factory=lambda: ["markdown", "json"])


class PhaseResult(BaseModel):
    """Result of executing a single campaign phase."""

    phase: CampaignPhase
    status: str = "pending"  # pending | running | success | partial | failed | skipped
    started_at: str = ""
    completed_at: str = ""
    tool_calls: int = 0
    llm_tokens_used: int = 0
    kql_queries_run: int = 0
    iterations: int = 0
    summary: str = ""
    artifacts: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class CampaignState(BaseModel):
    """Full state of an autonomous hunt campaign.

    Persisted to SQLite after each phase for crash recovery.
    """

    campaign_id: str
    config: CampaignConfig
    current_phase: CampaignPhase = CampaignPhase.INDEX_REFRESH
    phase_results: list[PhaseResult] = Field(default_factory=list)

    # Phase artifacts (populated as campaign progresses)
    environment_index: Optional[EnvironmentIndex] = None
    hypotheses: list[AutonomousHypothesis] = Field(default_factory=list)
    findings: list[HuntFinding] = Field(default_factory=list)
    report: Optional[CampaignReport] = None

    # Learning context from past campaigns (not persisted — loaded at runtime)
    learning_context: dict[str, Any] = Field(default_factory=dict, exclude=True)

    # Budget tracking
    total_kql_queries: int = 0
    total_llm_tokens: int = 0
    total_tool_calls: int = 0
    started_at: str = ""
    completed_at: str = ""
    status: str = "pending"  # pending | running | completed | failed | paused
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_minutes(self) -> float:
        if not self.started_at or not self.completed_at:
            return 0.0
        from datetime import datetime
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.completed_at)
        return (end - start).total_seconds() / 60.0

    @property
    def true_positives(self) -> list[HuntFinding]:
        from mssp_hunt_agent.hunter.models.finding import FindingClassification
        return [f for f in self.findings if f.classification == FindingClassification.TRUE_POSITIVE]

    @property
    def actionable_findings(self) -> list[HuntFinding]:
        return [f for f in self.findings if f.is_actionable]

    def get_phase_result(self, phase: CampaignPhase) -> Optional[PhaseResult]:
        for pr in self.phase_results:
            if pr.phase == phase:
                return pr
        return None
