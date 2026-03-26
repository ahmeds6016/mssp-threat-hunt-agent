"""Tests for the audit logger — V4.0 autonomy audit trail."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.policy.audit import AuditLogger
from mssp_hunt_agent.policy.models import AuditLogEntry, PolicyAction, PolicyDecision


# ── Helpers ────────────────────────────────────────────────────────────


def _make_db() -> HuntDatabase:
    return HuntDatabase(":memory:")


def _make_decision(**overrides) -> PolicyDecision:
    defaults = {
        "action": PolicyAction.AUTO_APPROVE.value,
        "rule_id": "R1",
        "reason": "Test decision",
    }
    defaults.update(overrides)
    return PolicyDecision(**defaults)


# ── Recording entries ──────────────────────────────────────────────────


class TestAuditRecord:
    def test_record_creates_entry(self):
        db = _make_db()
        logger = AuditLogger(db)
        decision = _make_decision()

        entry = logger.record(
            decision,
            run_id="RUN-001",
            client_name="Acme",
            action_category="run_hunt",
        )

        assert entry.entry_id.startswith("AUDIT-")
        assert entry.run_id == "RUN-001"
        assert entry.client_name == "Acme"
        assert entry.action_category == "run_hunt"
        assert entry.policy_decision.action == PolicyAction.AUTO_APPROVE.value
        assert entry.timestamp != ""
        db.close()

    def test_record_with_context(self):
        db = _make_db()
        logger = AuditLogger(db)
        decision = _make_decision()

        entry = logger.record(
            decision,
            run_id="RUN-002",
            client_name="Contoso",
            action_category="auto_sweep",
            context={"ioc_count": 25, "source_feed": "cisa_kev"},
        )

        assert entry.context["ioc_count"] == 25
        assert entry.context["source_feed"] == "cisa_kev"
        db.close()

    def test_record_multiple_entries(self):
        db = _make_db()
        logger = AuditLogger(db)

        for i in range(5):
            logger.record(
                _make_decision(),
                run_id=f"RUN-{i:03d}",
                client_name="Acme",
                action_category="run_hunt",
            )

        entries = logger.get_entries(client_name="Acme")
        assert len(entries) == 5
        db.close()


# ── Querying entries ───────────────────────────────────────────────────


class TestAuditQuery:
    def _setup_entries(self):
        db = _make_db()
        logger = AuditLogger(db)

        logger.record(
            _make_decision(action=PolicyAction.AUTO_APPROVE.value),
            run_id="RUN-001",
            client_name="Acme",
            action_category="run_hunt",
        )
        logger.record(
            _make_decision(action=PolicyAction.REQUIRE_APPROVAL.value),
            run_id="RUN-002",
            client_name="Contoso",
            action_category="notify_client",
        )
        logger.record(
            _make_decision(action=PolicyAction.AUTO_DENY.value),
            run_id="RUN-003",
            client_name="Acme",
            action_category="auto_sweep",
        )
        return db, logger

    def test_filter_by_client(self):
        db, logger = self._setup_entries()
        entries = logger.get_entries(client_name="Acme")
        assert len(entries) == 2
        assert all(e.client_name == "Acme" for e in entries)
        db.close()

    def test_filter_by_action(self):
        db, logger = self._setup_entries()
        entries = logger.get_entries(action=PolicyAction.AUTO_DENY.value)
        assert len(entries) == 1
        assert entries[0].policy_decision.action == PolicyAction.AUTO_DENY.value
        db.close()

    def test_filter_by_run_id(self):
        db, logger = self._setup_entries()
        entries = logger.get_entries(run_id="RUN-002")
        assert len(entries) == 1
        assert entries[0].run_id == "RUN-002"
        db.close()

    def test_limit_results(self):
        db, logger = self._setup_entries()
        entries = logger.get_entries(limit=2)
        assert len(entries) == 2
        db.close()

    def test_entries_ordered_by_timestamp_desc(self):
        db, logger = self._setup_entries()
        entries = logger.get_entries()
        # Most recent first
        assert len(entries) == 3
        timestamps = [e.timestamp for e in entries]
        assert timestamps == sorted(timestamps, reverse=True)
        db.close()


# ── Count by action ───────────────────────────────────────────────────


class TestAuditCounts:
    def test_count_by_action(self):
        db = _make_db()
        logger = AuditLogger(db)

        for _ in range(3):
            logger.record(_make_decision(action=PolicyAction.AUTO_APPROVE.value))
        for _ in range(2):
            logger.record(_make_decision(action=PolicyAction.REQUIRE_APPROVAL.value))
        logger.record(_make_decision(action=PolicyAction.AUTO_DENY.value))

        counts = logger.count_by_action()
        assert counts[PolicyAction.AUTO_APPROVE.value] == 3
        assert counts[PolicyAction.REQUIRE_APPROVAL.value] == 2
        assert counts[PolicyAction.AUTO_DENY.value] == 1
        db.close()

    def test_count_by_action_filtered(self):
        db = _make_db()
        logger = AuditLogger(db)

        logger.record(
            _make_decision(action=PolicyAction.AUTO_APPROVE.value),
            client_name="Acme",
        )
        logger.record(
            _make_decision(action=PolicyAction.AUTO_APPROVE.value),
            client_name="Contoso",
        )
        logger.record(
            _make_decision(action=PolicyAction.AUTO_DENY.value),
            client_name="Acme",
        )

        counts = logger.count_by_action("Acme")
        assert counts[PolicyAction.AUTO_APPROVE.value] == 1
        assert counts[PolicyAction.AUTO_DENY.value] == 1
        assert PolicyAction.REQUIRE_APPROVAL.value not in counts
        db.close()
