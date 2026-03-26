"""Policy engine — evaluate actions against per-client autonomy rules."""

from __future__ import annotations

import logging
from typing import Any

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.policy.models import (
    ActionCategory,
    AutonomyLevel,
    PolicyAction,
    PolicyDecision,
    PolicyRule,
)

logger = logging.getLogger(__name__)

# Actions that are always safe (read-only) at Level 2
_SAFE_ACTIONS: set[str] = {
    ActionCategory.PROFILE_CLIENT.value,
    ActionCategory.READ_HUNT_STATUS.value,
    ActionCategory.GENERATE_REPORT.value,
    ActionCategory.SEARCH_MITRE.value,
    ActionCategory.PARSE_IOCS.value,
    ActionCategory.DECONFLICT_IOCS.value,
    ActionCategory.COMPUTE_KPIS.value,
}

# Actions that always require approval regardless of autonomy level
_HIGH_IMPACT_ACTIONS: set[str] = {
    ActionCategory.NOTIFY_CLIENT.value,
    ActionCategory.ADD_TUNING_RULE.value,
    ActionCategory.EXPAND_SCOPE.value,
    ActionCategory.CREATE_INCIDENT.value,
    ActionCategory.MODIFY_SIEM_RULE.value,
}


class PolicyEngine:
    """Evaluate every autonomous action against per-client rules.

    Decides: auto_approve, require_approval, or auto_deny.
    """

    def __init__(
        self,
        config: HuntAgentConfig,
        rules: list[PolicyRule] | None = None,
    ) -> None:
        self._config = config
        self._rules: list[PolicyRule] = rules or []

    # ── Rule management ────────────────────────────────────────────────

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a policy rule."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a policy rule by ID. Returns True if removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < before

    def get_rules(self, client_name: str | None = None) -> list[PolicyRule]:
        """Get active rules, optionally filtered to a specific client."""
        active = [r for r in self._rules if r.enabled]
        if client_name is None:
            return active
        return [
            r for r in active
            if r.client_name == client_name or r.client_name == "*"
        ]

    # ── Core evaluation ────────────────────────────────────────────────

    def evaluate_autonomous_action(
        self,
        action_category: str,
        client_name: str = "",
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate a single action against policy rules.

        Checks in order:
        1. If policy engine is disabled → auto_approve
        2. Level 0 → require_approval for everything
        3. Level 1 → require_approval for everything except reads
        4. Level 2 → auto_approve safe, check bounds for execution,
                      require_approval for high-impact
        5. Client-specific rules override defaults
        """
        ctx = context or {}

        if not self._config.policy_engine_enabled:
            return PolicyDecision(
                action=PolicyAction.AUTO_APPROVE.value,
                reason="Policy engine disabled",
            )

        level = AutonomyLevel(self._config.autonomy_level)

        # Level 0: everything needs approval
        if level == AutonomyLevel.LEVEL_0:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                reason="Autonomy level 0 — all actions require approval",
            )

        # Level 1: only safe reads are auto-approved
        if level == AutonomyLevel.LEVEL_1:
            if action_category in _SAFE_ACTIONS:
                return PolicyDecision(
                    action=PolicyAction.AUTO_APPROVE.value,
                    reason="Level 1 — read-only action auto-approved",
                )
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                reason="Autonomy level 1 — non-read actions require approval",
            )

        # Level 2: the main operating mode
        if level == AutonomyLevel.LEVEL_2:
            return self._evaluate_level_2(action_category, client_name, ctx)

        # Level 3: auto-approve everything (future)
        return PolicyDecision(
            action=PolicyAction.AUTO_APPROVE.value,
            reason="Autonomy level 3 — fully autonomous",
        )

    def _evaluate_level_2(
        self,
        action_category: str,
        client_name: str,
        context: dict[str, Any],
    ) -> PolicyDecision:
        """Level 2 evaluation: safe auto-approve, bounded execution, high-impact require approval."""
        # Check client-specific rules first
        client_rules = [
            r for r in self._rules
            if r.enabled
            and r.action_category == action_category
            and (r.client_name == client_name or r.client_name == "*")
        ]

        # Most specific rule wins (client-specific > global)
        client_specific = [r for r in client_rules if r.client_name == client_name]
        if client_specific:
            rule = client_specific[0]
            decision = self._apply_rule(rule, context)
            if decision is not None:
                return decision

        # Global rules
        global_rules = [r for r in client_rules if r.client_name == "*"]
        if global_rules:
            rule = global_rules[0]
            decision = self._apply_rule(rule, context)
            if decision is not None:
                return decision

        # Default behaviour by action category
        if action_category in _SAFE_ACTIONS:
            return PolicyDecision(
                action=PolicyAction.AUTO_APPROVE.value,
                reason="Level 2 — read-only action auto-approved",
            )

        if action_category in _HIGH_IMPACT_ACTIONS:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                reason=f"Level 2 — high-impact action '{action_category}' requires approval",
            )

        # Bounded execution actions — check limits
        return self._check_bounds(action_category, context)

    def _apply_rule(
        self, rule: PolicyRule, context: dict[str, Any]
    ) -> PolicyDecision | None:
        """Apply a specific rule. Returns None if the rule doesn't produce a decision."""
        # If rule explicitly sets a policy action, honour it
        if rule.policy_action == PolicyAction.AUTO_DENY.value:
            return PolicyDecision(
                action=PolicyAction.AUTO_DENY.value,
                rule_id=rule.rule_id,
                reason=rule.reason or f"Denied by rule {rule.rule_id}",
            )

        if rule.policy_action == PolicyAction.REQUIRE_APPROVAL.value:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                rule_id=rule.rule_id,
                reason=rule.reason or f"Approval required by rule {rule.rule_id}",
            )

        if rule.policy_action == PolicyAction.AUTO_APPROVE.value:
            # Check bounds if the rule has them
            exceeded = self._check_rule_bounds(rule, context)
            if exceeded:
                return PolicyDecision(
                    action=PolicyAction.REQUIRE_APPROVAL.value,
                    rule_id=rule.rule_id,
                    reason=exceeded,
                )
            return PolicyDecision(
                action=PolicyAction.AUTO_APPROVE.value,
                rule_id=rule.rule_id,
                reason=rule.reason or f"Auto-approved by rule {rule.rule_id}",
            )

        return None

    def _check_rule_bounds(self, rule: PolicyRule, context: dict[str, Any]) -> str:
        """Check if context exceeds rule bounds. Returns reason string if exceeded, empty if ok."""
        query_count = context.get("query_count", 0)
        if rule.max_queries > 0 and query_count > rule.max_queries:
            return (
                f"Query count {query_count} exceeds rule limit {rule.max_queries}"
            )

        ioc_count = context.get("ioc_count", 0)
        if rule.max_iocs > 0 and ioc_count > rule.max_iocs:
            return f"IOC count {ioc_count} exceeds rule limit {rule.max_iocs}"

        time_range_days = context.get("time_range_days", 0)
        if rule.max_time_range_days > 0 and time_range_days > rule.max_time_range_days:
            return (
                f"Time range {time_range_days}d exceeds rule limit "
                f"{rule.max_time_range_days}d"
            )

        return ""

    def _check_bounds(
        self, action_category: str, context: dict[str, Any]
    ) -> PolicyDecision:
        """Check global config bounds for bounded-execution actions."""
        query_count = context.get("query_count", 0)
        if self._config.max_auto_queries > 0 and query_count > self._config.max_auto_queries:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                reason=(
                    f"Query count {query_count} exceeds auto limit "
                    f"{self._config.max_auto_queries}"
                ),
            )

        ioc_count = context.get("ioc_count", 0)
        if self._config.max_auto_iocs > 0 and ioc_count > self._config.max_auto_iocs:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL.value,
                reason=(
                    f"IOC count {ioc_count} exceeds auto limit "
                    f"{self._config.max_auto_iocs}"
                ),
            )

        return PolicyDecision(
            action=PolicyAction.AUTO_APPROVE.value,
            reason=f"Level 2 — '{action_category}' within bounds",
        )

    # ── Plan-level evaluation ──────────────────────────────────────────

    def evaluate_plan(
        self,
        client_name: str,
        query_count: int = 0,
        ioc_count: int = 0,
        time_range_days: int = 0,
        hunt_type: str = "",
    ) -> PolicyDecision:
        """Evaluate an entire plan before execution."""
        context = {
            "query_count": query_count,
            "ioc_count": ioc_count,
            "time_range_days": time_range_days,
            "hunt_type": hunt_type,
        }

        # Determine the action category from the hunt type
        if "ioc" in hunt_type.lower():
            action = ActionCategory.RUN_IOC_SWEEP.value
        elif hunt_type == "profile":
            action = ActionCategory.PROFILE_CLIENT.value
        else:
            action = ActionCategory.RUN_HUNT.value

        return self.evaluate_autonomous_action(action, client_name, context)

    def evaluate_auto_sweep(
        self,
        client_name: str,
        ioc_count: int,
    ) -> PolicyDecision:
        """Evaluate whether an auto-sweep should proceed for a client."""
        if not self._config.auto_sweep_enabled:
            return PolicyDecision(
                action=PolicyAction.AUTO_DENY.value,
                reason="Auto-sweep disabled in config",
            )

        return self.evaluate_autonomous_action(
            ActionCategory.AUTO_SWEEP.value,
            client_name,
            {"ioc_count": ioc_count},
        )
