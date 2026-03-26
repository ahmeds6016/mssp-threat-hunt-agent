"""Pydantic models for the policy engine and autonomy controls."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AutonomyLevel(str, Enum):
    """How much autonomy the agent has for a given client/action."""

    LEVEL_0 = "level_0"  # Fully manual — analyst does everything
    LEVEL_1 = "level_1"  # Agent plans, analyst approves every step
    LEVEL_2 = "level_2"  # Agent acts within policy; approval for high-impact
    LEVEL_3 = "level_3"  # Fully autonomous (future)


class PolicyAction(str, Enum):
    """The decision an evaluated policy rule produces."""

    AUTO_APPROVE = "auto_approve"
    REQUIRE_APPROVAL = "require_approval"
    AUTO_DENY = "auto_deny"


class ActionCategory(str, Enum):
    """Categories of actions the agent can take."""

    # Read-only / safe
    PROFILE_CLIENT = "profile_client"
    READ_HUNT_STATUS = "read_hunt_status"
    GENERATE_REPORT = "generate_report"
    SEARCH_MITRE = "search_mitre"
    PARSE_IOCS = "parse_iocs"
    DECONFLICT_IOCS = "deconflict_iocs"
    COMPUTE_KPIS = "compute_kpis"

    # Bounded execution
    RUN_HUNT = "run_hunt"
    RUN_IOC_SWEEP = "run_ioc_sweep"
    AUTO_SWEEP = "auto_sweep"
    ENRICH_ENTITIES = "enrich_entities"
    PIVOT_QUERY = "pivot_query"

    # High-impact
    NOTIFY_CLIENT = "notify_client"
    ADD_TUNING_RULE = "add_tuning_rule"
    EXPAND_SCOPE = "expand_scope"
    CREATE_INCIDENT = "create_incident"
    MODIFY_SIEM_RULE = "modify_siem_rule"


class PolicyRule(BaseModel):
    """A single policy rule that governs an action category."""

    rule_id: str
    client_name: str = "*"  # "*" means global default
    action_category: str  # ActionCategory value or custom string
    policy_action: str  # PolicyAction value
    max_queries: int = 0  # 0 = no limit
    max_iocs: int = 0  # 0 = no limit
    max_time_range_days: int = 0  # 0 = no limit
    conditions: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    enabled: bool = True
    created_at: str = ""


class PolicyDecision(BaseModel):
    """The result of evaluating a policy check."""

    action: str  # PolicyAction value
    rule_id: str = ""  # which rule produced this decision
    reason: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    """A pending approval request for analyst review."""

    request_id: str
    run_id: str
    client_name: str
    action_category: str
    context: dict[str, Any] = Field(default_factory=dict)
    policy_decision: PolicyDecision
    status: str = "pending"  # pending | approved | denied | expired
    requested_at: str = ""
    resolved_at: str = ""
    resolved_by: str = ""


class AuditLogEntry(BaseModel):
    """A single entry in the autonomy audit trail."""

    entry_id: str
    run_id: str = ""
    client_name: str = ""
    action_category: str = ""
    policy_decision: PolicyDecision = Field(
        default_factory=lambda: PolicyDecision(action="auto_approve")
    )
    context: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""
