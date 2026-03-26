"""Audit logger — record every autonomous decision for compliance and review."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.policy.models import AuditLogEntry, PolicyDecision

logger = logging.getLogger(__name__)

_AUDIT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS autonomy_audit_log (
    entry_id        TEXT PRIMARY KEY,
    run_id          TEXT DEFAULT '',
    client_name     TEXT DEFAULT '',
    action_category TEXT DEFAULT '',
    policy_action   TEXT DEFAULT '',
    rule_id         TEXT DEFAULT '',
    reason          TEXT DEFAULT '',
    context         TEXT DEFAULT '{}',
    timestamp       TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_client ON autonomy_audit_log(client_name);
CREATE INDEX IF NOT EXISTS idx_audit_run ON autonomy_audit_log(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON autonomy_audit_log(policy_action);
"""


class AuditLogger:
    """Records every autonomous decision in the SQLite audit trail."""

    def __init__(self, db: HuntDatabase) -> None:
        self._db = db
        self._ensure_table()

    def _ensure_table(self) -> None:
        self._db._conn.executescript(_AUDIT_SCHEMA)
        self._db._conn.commit()

    def record(
        self,
        decision: PolicyDecision,
        run_id: str = "",
        client_name: str = "",
        action_category: str = "",
        context: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Record a policy decision to the audit trail."""
        entry = AuditLogEntry(
            entry_id=f"AUDIT-{uuid.uuid4().hex[:8]}",
            run_id=run_id,
            client_name=client_name,
            action_category=action_category,
            policy_decision=decision,
            context=context or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self._db._conn.execute(
            "INSERT INTO autonomy_audit_log "
            "(entry_id, run_id, client_name, action_category, policy_action, "
            "rule_id, reason, context, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                entry.run_id,
                entry.client_name,
                entry.action_category,
                decision.action,
                decision.rule_id,
                decision.reason,
                json.dumps(entry.context),
                entry.timestamp,
            ),
        )
        self._db._conn.commit()
        logger.debug(
            "Audit: %s %s → %s (%s)",
            client_name or "global",
            action_category,
            decision.action,
            decision.reason,
        )
        return entry

    def get_entries(
        self,
        client_name: str | None = None,
        run_id: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Query audit log entries with optional filters."""
        sql = "SELECT * FROM autonomy_audit_log WHERE 1=1"
        params: list[Any] = []

        if client_name:
            sql += " AND client_name = ?"
            params.append(client_name)
        if run_id:
            sql += " AND run_id = ?"
            params.append(run_id)
        if action:
            sql += " AND policy_action = ?"
            params.append(action)

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._db._conn.execute(sql, params).fetchall()
        entries = []
        for r in rows:
            d = dict(r)
            entries.append(AuditLogEntry(
                entry_id=d["entry_id"],
                run_id=d["run_id"],
                client_name=d["client_name"],
                action_category=d["action_category"],
                policy_decision=PolicyDecision(
                    action=d["policy_action"],
                    rule_id=d["rule_id"],
                    reason=d["reason"],
                ),
                context=json.loads(d["context"]),
                timestamp=d["timestamp"],
            ))
        return entries

    def count_by_action(self, client_name: str | None = None) -> dict[str, int]:
        """Count audit entries grouped by policy action."""
        sql = "SELECT policy_action, COUNT(*) as cnt FROM autonomy_audit_log"
        params: list[Any] = []

        if client_name:
            sql += " WHERE client_name = ?"
            params.append(client_name)

        sql += " GROUP BY policy_action"

        rows = self._db._conn.execute(sql, params).fetchall()
        return {r["policy_action"]: r["cnt"] for r in rows}
