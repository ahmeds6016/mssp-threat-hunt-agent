"""Tests for the policy engine — V4.0 autonomy controls."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.policy.engine import PolicyEngine
from mssp_hunt_agent.policy.models import (
    ActionCategory,
    AutonomyLevel,
    PolicyAction,
    PolicyDecision,
    PolicyRule,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _make_config(**overrides) -> HuntAgentConfig:
    defaults = {
        "policy_engine_enabled": True,
        "autonomy_level": "level_2",
        "max_auto_queries": 20,
        "max_auto_iocs": 50,
        "auto_sweep_enabled": True,
    }
    defaults.update(overrides)
    return HuntAgentConfig(**defaults)


def _make_rule(**overrides) -> PolicyRule:
    defaults = {
        "rule_id": "TEST-001",
        "client_name": "*",
        "action_category": ActionCategory.RUN_HUNT.value,
        "policy_action": PolicyAction.AUTO_APPROVE.value,
    }
    defaults.update(overrides)
    return PolicyRule(**defaults)


# ── Policy engine disabled ─────────────────────────────────────────────


class TestPolicyEngineDisabled:
    def test_disabled_auto_approves_everything(self):
        config = _make_config(policy_engine_enabled=False)
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.NOTIFY_CLIENT.value, "Acme"
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value
        assert "disabled" in decision.reason.lower()


# ── Level 0: fully manual ─────────────────────────────────────────────


class TestLevel0:
    def test_level0_requires_approval_for_safe_action(self):
        config = _make_config(autonomy_level="level_0")
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.PROFILE_CLIENT.value, "Acme"
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value

    def test_level0_requires_approval_for_hunt(self):
        config = _make_config(autonomy_level="level_0")
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme"
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value


# ── Level 1: reads auto-approved, execution requires approval ─────────


class TestLevel1:
    def test_level1_auto_approves_read_only(self):
        config = _make_config(autonomy_level="level_1")
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.GENERATE_REPORT.value, "Acme"
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value

    def test_level1_requires_approval_for_hunt(self):
        config = _make_config(autonomy_level="level_1")
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme"
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value


# ── Level 2: the main operating mode ──────────────────────────────────


class TestLevel2:
    def test_safe_actions_auto_approved(self):
        config = _make_config()
        engine = PolicyEngine(config)
        for action in [
            ActionCategory.PROFILE_CLIENT.value,
            ActionCategory.READ_HUNT_STATUS.value,
            ActionCategory.GENERATE_REPORT.value,
            ActionCategory.SEARCH_MITRE.value,
            ActionCategory.PARSE_IOCS.value,
            ActionCategory.DECONFLICT_IOCS.value,
            ActionCategory.COMPUTE_KPIS.value,
        ]:
            decision = engine.evaluate_autonomous_action(action, "Acme")
            assert decision.action == PolicyAction.AUTO_APPROVE.value, f"Failed for {action}"

    def test_high_impact_requires_approval(self):
        config = _make_config()
        engine = PolicyEngine(config)
        for action in [
            ActionCategory.NOTIFY_CLIENT.value,
            ActionCategory.ADD_TUNING_RULE.value,
            ActionCategory.EXPAND_SCOPE.value,
            ActionCategory.CREATE_INCIDENT.value,
            ActionCategory.MODIFY_SIEM_RULE.value,
        ]:
            decision = engine.evaluate_autonomous_action(action, "Acme")
            assert decision.action == PolicyAction.REQUIRE_APPROVAL.value, f"Failed for {action}"

    def test_hunt_within_bounds_auto_approved(self):
        config = _make_config(max_auto_queries=20)
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme", {"query_count": 10}
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value

    def test_hunt_exceeding_query_limit_requires_approval(self):
        config = _make_config(max_auto_queries=20)
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme", {"query_count": 25}
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value

    def test_ioc_sweep_exceeding_ioc_limit_requires_approval(self):
        config = _make_config(max_auto_iocs=50)
        engine = PolicyEngine(config)
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_IOC_SWEEP.value, "Acme", {"ioc_count": 75}
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value


# ── Client-specific rules ─────────────────────────────────────────────


class TestClientSpecificRules:
    def test_client_deny_rule_overrides_default(self):
        config = _make_config()
        rule = _make_rule(
            rule_id="DENY-ACME",
            client_name="Acme",
            action_category=ActionCategory.RUN_HUNT.value,
            policy_action=PolicyAction.AUTO_DENY.value,
            reason="Acme hunts suspended",
        )
        engine = PolicyEngine(config, rules=[rule])
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme"
        )
        assert decision.action == PolicyAction.AUTO_DENY.value
        assert decision.rule_id == "DENY-ACME"

    def test_client_rule_does_not_affect_other_clients(self):
        config = _make_config()
        rule = _make_rule(
            rule_id="DENY-ACME",
            client_name="Acme",
            action_category=ActionCategory.RUN_HUNT.value,
            policy_action=PolicyAction.AUTO_DENY.value,
        )
        engine = PolicyEngine(config, rules=[rule])
        decision = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Contoso", {"query_count": 5}
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value

    def test_rule_with_bounds_escalates_on_exceed(self):
        config = _make_config()
        rule = _make_rule(
            rule_id="BOUND-ACME",
            client_name="Acme",
            action_category=ActionCategory.RUN_HUNT.value,
            policy_action=PolicyAction.AUTO_APPROVE.value,
            max_queries=5,
        )
        engine = PolicyEngine(config, rules=[rule])

        # Within bounds
        d1 = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme", {"query_count": 3}
        )
        assert d1.action == PolicyAction.AUTO_APPROVE.value

        # Exceeds bounds
        d2 = engine.evaluate_autonomous_action(
            ActionCategory.RUN_HUNT.value, "Acme", {"query_count": 10}
        )
        assert d2.action == PolicyAction.REQUIRE_APPROVAL.value


# ── Plan evaluation ───────────────────────────────────────────────────


class TestPlanEvaluation:
    def test_evaluate_plan_hypothesis(self):
        config = _make_config()
        engine = PolicyEngine(config)
        decision = engine.evaluate_plan(
            client_name="Acme",
            query_count=10,
            hunt_type="hypothesis",
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value

    def test_evaluate_plan_ioc_sweep_over_limit(self):
        config = _make_config(max_auto_iocs=30)
        engine = PolicyEngine(config)
        decision = engine.evaluate_plan(
            client_name="Acme",
            query_count=5,
            ioc_count=50,
            hunt_type="ioc_sweep",
        )
        assert decision.action == PolicyAction.REQUIRE_APPROVAL.value

    def test_evaluate_plan_profile_always_safe(self):
        config = _make_config()
        engine = PolicyEngine(config)
        decision = engine.evaluate_plan(
            client_name="Acme",
            hunt_type="profile",
        )
        assert decision.action == PolicyAction.AUTO_APPROVE.value


# ── Auto-sweep evaluation ─────────────────────────────────────────────


class TestAutoSweep:
    def test_auto_sweep_disabled_denies(self):
        config = _make_config(auto_sweep_enabled=False)
        engine = PolicyEngine(config)
        decision = engine.evaluate_auto_sweep("Acme", 10)
        assert decision.action == PolicyAction.AUTO_DENY.value

    def test_auto_sweep_enabled_within_limits(self):
        config = _make_config(auto_sweep_enabled=True, max_auto_iocs=50)
        engine = PolicyEngine(config)
        decision = engine.evaluate_auto_sweep("Acme", 20)
        assert decision.action == PolicyAction.AUTO_APPROVE.value


# ── Rule management ───────────────────────────────────────────────────


class TestRuleManagement:
    def test_add_and_remove_rule(self):
        config = _make_config()
        engine = PolicyEngine(config)
        rule = _make_rule(rule_id="R1")
        engine.add_rule(rule)
        assert len(engine.get_rules()) == 1

        removed = engine.remove_rule("R1")
        assert removed is True
        assert len(engine.get_rules()) == 0

    def test_remove_nonexistent_rule(self):
        config = _make_config()
        engine = PolicyEngine(config)
        assert engine.remove_rule("FAKE") is False

    def test_get_rules_filters_by_client(self):
        config = _make_config()
        r1 = _make_rule(rule_id="R1", client_name="Acme")
        r2 = _make_rule(rule_id="R2", client_name="Contoso")
        r3 = _make_rule(rule_id="R3", client_name="*")
        engine = PolicyEngine(config, rules=[r1, r2, r3])

        acme_rules = engine.get_rules("Acme")
        assert len(acme_rules) == 2  # R1 + R3 (global)
        rule_ids = {r.rule_id for r in acme_rules}
        assert rule_ids == {"R1", "R3"}
