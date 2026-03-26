"""Agent data models — intents, parsed results, and responses."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentIntent(str, Enum):
    """Recognised user intents the agent can handle."""

    RUN_HUNT = "run_hunt"
    IOC_SWEEP = "ioc_sweep"
    CVE_CHECK = "cve_check"
    TELEMETRY_PROFILE = "telemetry_profile"
    THREAT_MODEL = "threat_model"
    RISK_ASSESSMENT = "risk_assessment"
    DETECTION_RULE = "detection_rule"
    LANDSCAPE_CHECK = "landscape_check"
    HUNT_STATUS = "hunt_status"
    GENERATE_REPORT = "generate_report"
    RUN_PLAYBOOK = "run_playbook"
    GENERAL_QUESTION = "general_question"


class ParsedIntent(BaseModel):
    """Result of parsing a natural-language message."""

    intent: AgentIntent
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    entities: dict[str, Any] = Field(default_factory=dict)
    original_message: str = ""
    needs_clarification: bool = False
    clarification_reason: str = ""


class ReasoningStep(BaseModel):
    """One step in the agent's chain-of-thought."""

    step_type: str  # planning | executing | result | synthesizing | error
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    """Full response from the agent controller."""

    summary: str
    intent: AgentIntent
    confidence: float = 0.5
    details: dict[str, Any] = Field(default_factory=dict)
    thinking_trace: list[ReasoningStep] = Field(default_factory=list)
    follow_up_suggestions: list[str] = Field(default_factory=list)
    run_id: str = ""
    error: str = ""


class ConversationTurn(BaseModel):
    """A single turn in an agent conversation."""

    role: str  # user | agent
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    response: AgentResponse | None = None
