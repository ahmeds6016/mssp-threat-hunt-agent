"""SQLite persistence layer for hunt agent state and analytics."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mssp_hunt_agent.persistence.models import (
    CampaignFindingRecord,
    CampaignHypothesisRecord,
    CampaignRecord,
    ClientRecord,
    ClientStats,
    FindingRecord,
    HuntLessonRecord,
    IOCSweepRecord,
    ProfileVersion,
    RunRecord,
)

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 3

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    client_name     TEXT NOT NULL UNIQUE,
    industry        TEXT DEFAULT '',
    primary_contact TEXT DEFAULT '',
    onboarded_at    TEXT DEFAULT '',
    notes           TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS profiles (
    version_id        TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL REFERENCES clients(client_id),
    version_number    INTEGER NOT NULL,
    profile_data      TEXT DEFAULT '{}',
    created_at        TEXT DEFAULT '',
    source_count      INTEGER DEFAULT 0,
    total_event_count INTEGER DEFAULT 0,
    execution_mode    TEXT DEFAULT 'mock',
    notes             TEXT DEFAULT '',
    UNIQUE(client_id, version_number)
);

CREATE TABLE IF NOT EXISTS hunt_runs (
    run_id              TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    client_name         TEXT NOT NULL,
    hunt_type           TEXT NOT NULL,
    execution_mode      TEXT DEFAULT 'mock',
    started_at          TEXT DEFAULT '',
    completed_at        TEXT DEFAULT '',
    status              TEXT DEFAULT 'completed',
    findings_count      INTEGER DEFAULT 0,
    high_confidence_count INTEGER DEFAULT 0,
    queries_executed    INTEGER DEFAULT 0,
    total_events        INTEGER DEFAULT 0,
    output_dir          TEXT DEFAULT '',
    summary             TEXT DEFAULT '',
    errors              TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES hunt_runs(run_id),
    client_id      TEXT NOT NULL REFERENCES clients(client_id),
    title          TEXT NOT NULL,
    description    TEXT DEFAULT '',
    confidence     TEXT DEFAULT '',
    evidence_count INTEGER DEFAULT 0,
    created_at     TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ioc_sweeps (
    sweep_id     TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES hunt_runs(run_id),
    client_id    TEXT NOT NULL REFERENCES clients(client_id),
    total_iocs   INTEGER DEFAULT 0,
    valid_iocs   INTEGER DEFAULT 0,
    total_hits   INTEGER DEFAULT 0,
    total_misses INTEGER DEFAULT 0,
    hit_iocs     TEXT DEFAULT '[]',
    created_at   TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_runs_client ON hunt_runs(client_id);
CREATE INDEX IF NOT EXISTS idx_runs_type ON hunt_runs(hunt_type);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_profiles_client ON profiles(client_id);

-- V2: Policy engine tables
CREATE TABLE IF NOT EXISTS policy_rules (
    rule_id             TEXT PRIMARY KEY,
    client_name         TEXT DEFAULT '*',
    action_category     TEXT NOT NULL,
    policy_action       TEXT NOT NULL,
    max_queries         INTEGER DEFAULT 0,
    max_iocs            INTEGER DEFAULT 0,
    max_time_range_days INTEGER DEFAULT 0,
    conditions          TEXT DEFAULT '{}',
    reason              TEXT DEFAULT '',
    enabled             INTEGER DEFAULT 1,
    created_at          TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_policy_client ON policy_rules(client_name);
CREATE INDEX IF NOT EXISTS idx_policy_category ON policy_rules(action_category);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id     TEXT PRIMARY KEY,
    run_id          TEXT DEFAULT '',
    client_name     TEXT DEFAULT '',
    action_category TEXT DEFAULT '',
    policy_action   TEXT DEFAULT '',
    rule_id         TEXT DEFAULT '',
    reason          TEXT DEFAULT '',
    context         TEXT DEFAULT '{}',
    created_at      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON policy_decisions(run_id);

CREATE TABLE IF NOT EXISTS approval_requests (
    request_id      TEXT PRIMARY KEY,
    run_id          TEXT DEFAULT '',
    client_name     TEXT DEFAULT '',
    action_category TEXT DEFAULT '',
    context         TEXT DEFAULT '{}',
    policy_action   TEXT DEFAULT '',
    rule_id         TEXT DEFAULT '',
    reason          TEXT DEFAULT '',
    status          TEXT DEFAULT 'pending',
    requested_at    TEXT DEFAULT '',
    resolved_at     TEXT DEFAULT '',
    resolved_by     TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);

-- V3: Campaign persistence + learning tables
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id       TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    client_name       TEXT NOT NULL,
    status            TEXT DEFAULT 'pending',
    started_at        TEXT DEFAULT '',
    completed_at      TEXT DEFAULT '',
    total_hypotheses  INTEGER DEFAULT 0,
    total_findings    INTEGER DEFAULT 0,
    true_positives    INTEGER DEFAULT 0,
    false_positives   INTEGER DEFAULT 0,
    inconclusive      INTEGER DEFAULT 0,
    escalations       INTEGER DEFAULT 0,
    total_kql_queries INTEGER DEFAULT 0,
    total_llm_tokens  INTEGER DEFAULT 0,
    duration_minutes  REAL DEFAULT 0.0,
    focus_areas       TEXT DEFAULT '[]',
    config_json       TEXT DEFAULT '{}',
    summary           TEXT DEFAULT '',
    errors            TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_campaigns_client ON campaigns(client_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
CREATE INDEX IF NOT EXISTS idx_campaigns_started ON campaigns(started_at);

CREATE TABLE IF NOT EXISTS campaign_findings (
    finding_id        TEXT PRIMARY KEY,
    campaign_id       TEXT NOT NULL REFERENCES campaigns(campaign_id),
    client_id         TEXT NOT NULL,
    hypothesis_id     TEXT DEFAULT '',
    title             TEXT NOT NULL,
    classification    TEXT DEFAULT 'inconclusive',
    severity          TEXT DEFAULT 'informational',
    confidence        REAL DEFAULT 0.5,
    mitre_techniques  TEXT DEFAULT '[]',
    mitre_tactics     TEXT DEFAULT '[]',
    affected_entities TEXT DEFAULT '{}',
    evidence_summary  TEXT DEFAULT '',
    recommendations   TEXT DEFAULT '[]',
    detection_rule_kql TEXT DEFAULT '',
    created_at        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cf_campaign ON campaign_findings(campaign_id);
CREATE INDEX IF NOT EXISTS idx_cf_client ON campaign_findings(client_id);
CREATE INDEX IF NOT EXISTS idx_cf_classification ON campaign_findings(classification);

CREATE TABLE IF NOT EXISTS campaign_hypotheses (
    hypothesis_id   TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(campaign_id),
    client_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    source          TEXT DEFAULT '',
    priority_score  REAL DEFAULT 0.5,
    status          TEXT DEFAULT 'pending',
    mitre_techniques TEXT DEFAULT '[]',
    available_tables TEXT DEFAULT '[]',
    findings_count  INTEGER DEFAULT 0,
    queries_executed INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ch_campaign ON campaign_hypotheses(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ch_client ON campaign_hypotheses(client_id);

CREATE TABLE IF NOT EXISTS hunt_lessons (
    lesson_id         TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    campaign_id       TEXT NOT NULL,
    lesson_type       TEXT NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT DEFAULT '',
    mitre_techniques  TEXT DEFAULT '[]',
    tables_involved   TEXT DEFAULT '[]',
    confidence        REAL DEFAULT 0.5,
    times_confirmed   INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT '',
    updated_at        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_lessons_client ON hunt_lessons(client_id);
CREATE INDEX IF NOT EXISTS idx_lessons_type ON hunt_lessons(lesson_type);
"""


class HuntDatabase:
    """SQLite-backed persistence for the hunt agent.

    Parameters
    ----------
    db_path:
        File path for the SQLite database. Use `":memory:"` for in-memory (tests).
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn: sqlite3.Connection = sqlite3.connect(
            self._db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # ── schema bootstrap ──────────────────────────────────────────────

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)
        # Record schema version
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, ?)",
            ("schema_version", str(_SCHEMA_VERSION)),
        )
        self._conn.commit()

    # ── clients ───────────────────────────────────────────────────────

    def ensure_client(self, client_name: str, **kwargs: str) -> ClientRecord:
        """Get or create a client by name. Returns the ClientRecord."""
        row = self._conn.execute(
            "SELECT * FROM clients WHERE client_name = ?", (client_name,)
        ).fetchone()
        if row:
            return ClientRecord(**dict(row))

        client_id = kwargs.get("client_id", _slug(client_name))
        now = _now_iso()
        self._conn.execute(
            "INSERT INTO clients (client_id, client_name, industry, primary_contact, onboarded_at, notes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                client_id,
                client_name,
                kwargs.get("industry", ""),
                kwargs.get("primary_contact", ""),
                kwargs.get("onboarded_at", now),
                kwargs.get("notes", ""),
            ),
        )
        self._conn.commit()
        return ClientRecord(
            client_id=client_id,
            client_name=client_name,
            industry=kwargs.get("industry", ""),
            primary_contact=kwargs.get("primary_contact", ""),
            onboarded_at=kwargs.get("onboarded_at", now),
            notes=kwargs.get("notes", ""),
        )

    def get_client(self, client_name: str) -> Optional[ClientRecord]:
        row = self._conn.execute(
            "SELECT * FROM clients WHERE client_name = ?", (client_name,)
        ).fetchone()
        return ClientRecord(**dict(row)) if row else None

    def list_clients(self) -> list[ClientRecord]:
        rows = self._conn.execute(
            "SELECT * FROM clients ORDER BY client_name"
        ).fetchall()
        return [ClientRecord(**dict(r)) for r in rows]

    # ── hunt runs ────────────────────────────────────────────────────

    def save_run(self, run: RunRecord) -> None:
        """Insert or replace a hunt run record."""
        self._conn.execute(
            "INSERT OR REPLACE INTO hunt_runs "
            "(run_id, client_id, client_name, hunt_type, execution_mode, "
            "started_at, completed_at, status, findings_count, high_confidence_count, "
            "queries_executed, total_events, output_dir, summary, errors) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.client_id,
                run.client_name,
                run.hunt_type,
                run.execution_mode,
                run.started_at,
                run.completed_at,
                run.status,
                run.findings_count,
                run.high_confidence_count,
                run.queries_executed,
                run.total_events,
                run.output_dir,
                run.summary,
                json.dumps(run.errors),
            ),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        row = self._conn.execute(
            "SELECT * FROM hunt_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["errors"] = json.loads(d["errors"])
        return RunRecord(**d)

    def get_runs(
        self,
        client_name: Optional[str] = None,
        hunt_type: Optional[str] = None,
        limit: int = 50,
    ) -> list[RunRecord]:
        """Query runs with optional filters."""
        sql = "SELECT * FROM hunt_runs WHERE 1=1"
        params: list = []
        if client_name:
            sql += " AND client_name = ?"
            params.append(client_name)
        if hunt_type:
            sql += " AND hunt_type = ?"
            params.append(hunt_type)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["errors"] = json.loads(d["errors"])
            results.append(RunRecord(**d))
        return results

    # ── profiles (versioned) ──────────────────────────────────────────

    def save_profile(self, profile: ProfileVersion) -> None:
        """Save a new profile version."""
        self._conn.execute(
            "INSERT INTO profiles "
            "(version_id, client_id, version_number, profile_data, created_at, "
            "source_count, total_event_count, execution_mode, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                profile.version_id,
                profile.client_id,
                profile.version_number,
                json.dumps(profile.profile_data),
                profile.created_at or _now_iso(),
                profile.source_count,
                profile.total_event_count,
                profile.execution_mode,
                profile.notes,
            ),
        )
        self._conn.commit()

    def get_latest_profile(self, client_id: str) -> Optional[ProfileVersion]:
        row = self._conn.execute(
            "SELECT * FROM profiles WHERE client_id = ? "
            "ORDER BY version_number DESC LIMIT 1",
            (client_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["profile_data"] = json.loads(d["profile_data"])
        return ProfileVersion(**d)

    def list_profile_versions(self, client_id: str) -> list[ProfileVersion]:
        rows = self._conn.execute(
            "SELECT * FROM profiles WHERE client_id = ? ORDER BY version_number ASC",
            (client_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["profile_data"] = json.loads(d["profile_data"])
            results.append(ProfileVersion(**d))
        return results

    def get_next_profile_version(self, client_id: str) -> int:
        """Return the next available version number for a client."""
        row = self._conn.execute(
            "SELECT MAX(version_number) as max_ver FROM profiles WHERE client_id = ?",
            (client_id,),
        ).fetchone()
        current = row["max_ver"] if row and row["max_ver"] is not None else 0
        return current + 1

    def compare_profiles(
        self, client_id: str, version_a: int, version_b: int
    ) -> dict:
        """Compare two profile versions and return a diff summary."""
        a = self._conn.execute(
            "SELECT * FROM profiles WHERE client_id = ? AND version_number = ?",
            (client_id, version_a),
        ).fetchone()
        b = self._conn.execute(
            "SELECT * FROM profiles WHERE client_id = ? AND version_number = ?",
            (client_id, version_b),
        ).fetchone()
        if not a or not b:
            return {"error": "One or both versions not found"}

        da = json.loads(a["profile_data"])
        db = json.loads(b["profile_data"])

        return {
            "client_id": client_id,
            "version_a": version_a,
            "version_b": version_b,
            "source_count_a": a["source_count"],
            "source_count_b": b["source_count"],
            "source_count_delta": b["source_count"] - a["source_count"],
            "event_count_a": a["total_event_count"],
            "event_count_b": b["total_event_count"],
            "event_count_delta": b["total_event_count"] - a["total_event_count"],
            "profile_data_a": da,
            "profile_data_b": db,
        }

    # ── findings ──────────────────────────────────────────────────────

    def save_finding(self, finding: FindingRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO findings "
            "(finding_id, run_id, client_id, title, description, confidence, "
            "evidence_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.run_id,
                finding.client_id,
                finding.title,
                finding.description,
                finding.confidence,
                finding.evidence_count,
                finding.created_at or _now_iso(),
            ),
        )
        self._conn.commit()

    def get_findings(self, run_id: str) -> list[FindingRecord]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
        return [FindingRecord(**dict(r)) for r in rows]

    # ── IOC sweeps ────────────────────────────────────────────────────

    def save_ioc_sweep(self, sweep: IOCSweepRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ioc_sweeps "
            "(sweep_id, run_id, client_id, total_iocs, valid_iocs, "
            "total_hits, total_misses, hit_iocs, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sweep.sweep_id,
                sweep.run_id,
                sweep.client_id,
                sweep.total_iocs,
                sweep.valid_iocs,
                sweep.total_hits,
                sweep.total_misses,
                json.dumps(sweep.hit_iocs),
                sweep.created_at or _now_iso(),
            ),
        )
        self._conn.commit()

    def get_ioc_sweeps(self, client_id: str) -> list[IOCSweepRecord]:
        rows = self._conn.execute(
            "SELECT * FROM ioc_sweeps WHERE client_id = ? ORDER BY created_at DESC",
            (client_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["hit_iocs"] = json.loads(d["hit_iocs"])
            results.append(IOCSweepRecord(**d))
        return results

    # ── client stats ──────────────────────────────────────────────────

    def get_client_stats(self, client_name: str) -> Optional[ClientStats]:
        """Compute aggregated stats for a client."""
        client = self.get_client(client_name)
        if not client:
            return None

        cid = client.client_id
        total = self._count("hunt_runs", "client_id = ?", cid)
        hypothesis = self._count("hunt_runs", "client_id = ? AND hunt_type = 'hypothesis'", cid)
        ioc = self._count("hunt_runs", "client_id = ? AND hunt_type LIKE '%ioc%'", cid)
        profile = self._count("hunt_runs", "client_id = ? AND hunt_type = 'profile'", cid)
        total_findings = self._count("findings", "client_id = ?", cid)
        high_conf = self._count("findings", "client_id = ? AND confidence = 'high'", cid)

        last_run = self._conn.execute(
            "SELECT MAX(started_at) as last FROM hunt_runs WHERE client_id = ?",
            (cid,),
        ).fetchone()
        last_profile = self._conn.execute(
            "SELECT MAX(created_at) as last FROM profiles WHERE client_id = ?",
            (cid,),
        ).fetchone()

        return ClientStats(
            client_id=cid,
            client_name=client_name,
            total_runs=total,
            hypothesis_runs=hypothesis,
            ioc_runs=ioc,
            profile_runs=profile,
            total_findings=total_findings,
            high_confidence_findings=high_conf,
            last_run_at=last_run["last"] if last_run else None,
            last_profile_at=last_profile["last"] if last_profile else None,
        )

    # ── campaigns (V3) ─────────────────────────────────────────────────

    def save_campaign(self, campaign: CampaignRecord) -> None:
        """Insert or replace a campaign record."""
        self._conn.execute(
            "INSERT OR REPLACE INTO campaigns "
            "(campaign_id, client_id, client_name, status, started_at, completed_at, "
            "total_hypotheses, total_findings, true_positives, false_positives, "
            "inconclusive, escalations, total_kql_queries, total_llm_tokens, "
            "duration_minutes, focus_areas, config_json, summary, errors) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                campaign.campaign_id, campaign.client_id, campaign.client_name,
                campaign.status, campaign.started_at, campaign.completed_at,
                campaign.total_hypotheses, campaign.total_findings,
                campaign.true_positives, campaign.false_positives,
                campaign.inconclusive, campaign.escalations,
                campaign.total_kql_queries, campaign.total_llm_tokens,
                campaign.duration_minutes, campaign.focus_areas,
                campaign.config_json, campaign.summary, campaign.errors,
            ),
        )
        self._conn.commit()

    def get_campaign(self, campaign_id: str) -> Optional[CampaignRecord]:
        row = self._conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        return CampaignRecord(**dict(row)) if row else None

    def get_campaigns(
        self,
        client_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[CampaignRecord]:
        """Get recent campaigns, optionally filtered by client."""
        sql = "SELECT * FROM campaigns WHERE 1=1"
        params: list = []
        if client_id:
            sql += " AND client_id = ?"
            params.append(client_id)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [CampaignRecord(**dict(r)) for r in rows]

    def save_campaign_finding(self, finding: CampaignFindingRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO campaign_findings "
            "(finding_id, campaign_id, client_id, hypothesis_id, title, "
            "classification, severity, confidence, mitre_techniques, mitre_tactics, "
            "affected_entities, evidence_summary, recommendations, "
            "detection_rule_kql, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id, finding.campaign_id, finding.client_id,
                finding.hypothesis_id, finding.title, finding.classification,
                finding.severity, finding.confidence,
                finding.mitre_techniques, finding.mitre_tactics,
                finding.affected_entities, finding.evidence_summary,
                finding.recommendations, finding.detection_rule_kql,
                finding.created_at,
            ),
        )
        self._conn.commit()

    def get_campaign_findings(
        self,
        client_id: str,
        classification: Optional[str] = None,
        limit: int = 50,
    ) -> list[CampaignFindingRecord]:
        """Get findings for a client, optionally filtered by classification."""
        sql = "SELECT * FROM campaign_findings WHERE client_id = ?"
        params: list = [client_id]
        if classification:
            sql += " AND classification = ?"
            params.append(classification)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [CampaignFindingRecord(**dict(r)) for r in rows]

    def save_campaign_hypothesis(self, hypothesis: CampaignHypothesisRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO campaign_hypotheses "
            "(hypothesis_id, campaign_id, client_id, title, description, source, "
            "priority_score, status, mitre_techniques, available_tables, "
            "findings_count, queries_executed, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                hypothesis.hypothesis_id, hypothesis.campaign_id,
                hypothesis.client_id, hypothesis.title, hypothesis.description,
                hypothesis.source, hypothesis.priority_score, hypothesis.status,
                hypothesis.mitre_techniques, hypothesis.available_tables,
                hypothesis.findings_count, hypothesis.queries_executed,
                hypothesis.created_at,
            ),
        )
        self._conn.commit()

    # ── hunt lessons (V3) ────────────────────────────────────────────

    def save_lesson(self, lesson: HuntLessonRecord) -> None:
        """Save or update a learned lesson."""
        self._conn.execute(
            "INSERT OR REPLACE INTO hunt_lessons "
            "(lesson_id, client_id, campaign_id, lesson_type, title, description, "
            "mitre_techniques, tables_involved, confidence, times_confirmed, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                lesson.lesson_id, lesson.client_id, lesson.campaign_id,
                lesson.lesson_type, lesson.title, lesson.description,
                lesson.mitre_techniques, lesson.tables_involved,
                lesson.confidence, lesson.times_confirmed,
                lesson.created_at, lesson.updated_at,
            ),
        )
        self._conn.commit()

    def get_lessons(
        self,
        client_id: str,
        lesson_type: Optional[str] = None,
        limit: int = 30,
    ) -> list[HuntLessonRecord]:
        """Get lessons for a client, optionally filtered by type."""
        sql = "SELECT * FROM hunt_lessons WHERE client_id = ?"
        params: list = [client_id]
        if lesson_type:
            sql += " AND lesson_type = ?"
            params.append(lesson_type)
        sql += " ORDER BY times_confirmed DESC, updated_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [HuntLessonRecord(**dict(r)) for r in rows]

    def increment_lesson(self, lesson_id: str) -> None:
        """Increment times_confirmed for a lesson that was re-validated."""
        self._conn.execute(
            "UPDATE hunt_lessons SET times_confirmed = times_confirmed + 1, "
            "updated_at = ? WHERE lesson_id = ?",
            (_now_iso(), lesson_id),
        )
        self._conn.commit()

    def get_past_campaign_context(self, client_id: str, limit: int = 5) -> dict:
        """Build a context summary from past campaigns for this client.

        Returns a dict ready for injection into LLM prompts.
        """
        campaigns = self.get_campaigns(client_id=client_id, limit=limit)
        if not campaigns:
            return {}

        # Past findings summary
        tp_findings = self.get_campaign_findings(client_id, classification="true_positive", limit=20)
        fp_findings = self.get_campaign_findings(client_id, classification="false_positive", limit=10)
        escalations = self.get_campaign_findings(client_id, classification="requires_escalation", limit=10)

        # Lessons learned
        lessons = self.get_lessons(client_id, limit=20)

        return {
            "past_campaigns": [
                {
                    "campaign_id": c.campaign_id,
                    "date": c.started_at[:10] if c.started_at else "",
                    "status": c.status,
                    "hypotheses": c.total_hypotheses,
                    "findings": c.total_findings,
                    "true_positives": c.true_positives,
                    "false_positives": c.false_positives,
                    "queries": c.total_kql_queries,
                    "summary": c.summary[:500],
                }
                for c in campaigns
            ],
            "past_true_positives": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "mitre_techniques": f.mitre_techniques,
                    "affected_entities": f.affected_entities,
                    "confidence": f.confidence,
                    "date": f.created_at[:10] if f.created_at else "",
                }
                for f in tp_findings
            ],
            "known_false_positives": [
                {
                    "title": f.title,
                    "evidence_summary": f.evidence_summary[:300],
                }
                for f in fp_findings
            ],
            "escalations": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "mitre_techniques": f.mitre_techniques,
                }
                for f in escalations
            ],
            "lessons_learned": [
                {
                    "type": l.lesson_type,
                    "title": l.title,
                    "description": l.description[:300],
                    "confidence": l.confidence,
                    "times_confirmed": l.times_confirmed,
                }
                for l in lessons
            ],
        }

    # ── internal helpers ──────────────────────────────────────────────

    def _count(self, table: str, where: str, *params) -> int:
        row = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM {table} WHERE {where}", params
        ).fetchone()
        return row["cnt"] if row else 0

    def close(self) -> None:
        self._conn.close()


# ── module-level helpers ──────────────────────────────────────────────


def _slug(name: str) -> str:
    """Turn 'Acme Corp' into 'acme-corp'."""
    return name.strip().lower().replace(" ", "-").replace("_", "-")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
