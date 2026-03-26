"""Per-client tuning — exclusions, benign patterns, custom thresholds."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from mssp_hunt_agent.analytics.models import ClientTuningConfig, TuningRule
from mssp_hunt_agent.persistence.database import HuntDatabase

logger = logging.getLogger(__name__)

# ── SQLite table for client tuning ───────────────────────────────────

_TUNING_SCHEMA = """\
CREATE TABLE IF NOT EXISTS client_tuning (
    rule_id     TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    rule_type   TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    reason      TEXT DEFAULT '',
    created_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tuning_client ON client_tuning(client_name);
"""


class TuningStore:
    """CRUD for per-client tuning rules backed by SQLite."""

    def __init__(self, db: HuntDatabase) -> None:
        self._db = db
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create tuning table if it doesn't exist."""
        self._db._conn.executescript(_TUNING_SCHEMA)
        self._db._conn.commit()

    # ── CRUD ──────────────────────────────────────────────────────────

    def add_rule(
        self,
        client_name: str,
        rule_type: str,
        pattern: str,
        reason: str = "",
    ) -> TuningRule:
        """Add a new tuning rule for a client."""
        rule = TuningRule(
            rule_id=f"TUNE-{uuid.uuid4().hex[:8]}",
            rule_type=rule_type,
            pattern=pattern,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._db._conn.execute(
            "INSERT INTO client_tuning (rule_id, client_name, rule_type, pattern, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rule.rule_id, client_name, rule.rule_type, rule.pattern, rule.reason, rule.created_at),
        )
        self._db._conn.commit()
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a tuning rule by ID. Returns True if deleted."""
        cursor = self._db._conn.execute(
            "DELETE FROM client_tuning WHERE rule_id = ?", (rule_id,)
        )
        self._db._conn.commit()
        return cursor.rowcount > 0

    def get_config(self, client_name: str) -> ClientTuningConfig:
        """Load all tuning rules for a client into a config object."""
        rows = self._db._conn.execute(
            "SELECT * FROM client_tuning WHERE client_name = ? ORDER BY created_at",
            (client_name,),
        ).fetchall()

        exclusions = []
        benign_patterns = []
        for r in rows:
            rule = TuningRule(**{k: r[k] for k in ["rule_id", "rule_type", "pattern", "reason", "created_at"]})
            if rule.rule_type == "exclusion":
                exclusions.append(rule)
            elif rule.rule_type == "benign_pattern":
                benign_patterns.append(rule)

        return ClientTuningConfig(
            client_name=client_name,
            exclusions=exclusions,
            benign_patterns=benign_patterns,
        )

    def list_rules(self, client_name: str) -> list[TuningRule]:
        """List all tuning rules for a client."""
        rows = self._db._conn.execute(
            "SELECT * FROM client_tuning WHERE client_name = ? ORDER BY created_at",
            (client_name,),
        ).fetchall()
        return [
            TuningRule(**{k: r[k] for k in ["rule_id", "rule_type", "pattern", "reason", "created_at"]})
            for r in rows
        ]

    def get_exclusion_values(self, client_name: str) -> set[str]:
        """Return the set of exclusion pattern values for a client.

        These can be used to filter out known-benign entities during
        enrichment or finding generation.
        """
        rows = self._db._conn.execute(
            "SELECT pattern FROM client_tuning WHERE client_name = ? AND rule_type = 'exclusion'",
            (client_name,),
        ).fetchall()
        return {r["pattern"] for r in rows}
