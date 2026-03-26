"""KPI engine — compute metrics from the SQLite database."""

from __future__ import annotations

import logging
from typing import Any, Optional

from mssp_hunt_agent.analytics.models import ClientKPIs
from mssp_hunt_agent.persistence.database import HuntDatabase

logger = logging.getLogger(__name__)


class KPIEngine:
    """Computes hunt-program KPIs from the persistence layer."""

    def __init__(self, db: HuntDatabase) -> None:
        self._db = db

    def client_kpis(self, client_name: str, period: str = "all") -> Optional[ClientKPIs]:
        """Compute KPIs for a single client.

        Parameters
        ----------
        client_name:
            The client to compute KPIs for.
        period:
            Filter string. "all" = no filter.
            "2024-W48" = ISO week.
            "2024-12" = calendar month.
        """
        client = self._db.get_client(client_name)
        if not client:
            return None

        cid = client.client_id
        conn = self._db._conn

        where, params = self._build_period_filter(cid, period)

        total = self._count(conn, "hunt_runs", where, params)
        hypothesis = self._count(
            conn, "hunt_runs", f"{where} AND hunt_type = 'hypothesis'", params
        )
        ioc = self._count(
            conn, "hunt_runs", f"{where} AND hunt_type LIKE '%ioc%'", params
        )
        profile = self._count(
            conn, "hunt_runs", f"{where} AND hunt_type = 'profile'", params
        )

        # Aggregated metrics
        row = conn.execute(
            f"SELECT COALESCE(SUM(findings_count), 0) as f, "
            f"COALESCE(SUM(high_confidence_count), 0) as hc, "
            f"COALESCE(SUM(queries_executed), 0) as q, "
            f"COALESCE(SUM(total_events), 0) as e "
            f"FROM hunt_runs WHERE {where}",
            params,
        ).fetchone()

        total_findings = row["f"]
        high_conf = row["hc"]
        total_queries = row["q"]
        total_events = row["e"]

        hit_rate = total_findings / total if total > 0 else 0.0
        mean_queries = total_queries / total if total > 0 else 0.0
        mean_events = total_events / total if total > 0 else 0.0

        return ClientKPIs(
            client_name=client_name,
            period=period,
            total_hunts=total,
            hypothesis_hunts=hypothesis,
            ioc_sweeps=ioc,
            profile_runs=profile,
            total_findings=total_findings,
            high_confidence_findings=high_conf,
            total_queries=total_queries,
            total_events=total_events,
            hit_rate=round(hit_rate, 3),
            mean_queries_per_hunt=round(mean_queries, 1),
            mean_events_per_hunt=round(mean_events, 1),
        )

    def all_client_kpis(self, period: str = "all") -> list[ClientKPIs]:
        """Compute KPIs for every client."""
        clients = self._db.list_clients()
        results = []
        for c in clients:
            kpi = self.client_kpis(c.client_name, period)
            if kpi and kpi.total_hunts > 0:
                results.append(kpi)
        return results

    def top_findings(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most frequent finding titles across all runs."""
        rows = self._db._conn.execute(
            "SELECT title, confidence, COUNT(*) as cnt "
            "FROM findings GROUP BY title, confidence "
            "ORDER BY cnt DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def recurring_gaps(self, limit: int = 10) -> list[str]:
        """Identify recurring telemetry gaps from run summaries.

        This is a simplified version that looks at run summaries for
        common gap keywords. A production system would query a dedicated
        gaps table.
        """
        rows = self._db._conn.execute(
            "SELECT summary FROM hunt_runs "
            "WHERE summary != '' ORDER BY started_at DESC LIMIT 100"
        ).fetchall()
        # Simple heuristic — aggregate unique summaries
        seen: dict[str, int] = {}
        for r in rows:
            s = r["summary"]
            seen[s] = seen.get(s, 0) + 1
        # Return most common
        sorted_gaps = sorted(seen.items(), key=lambda x: x[1], reverse=True)
        return [g[0] for g in sorted_gaps[:limit]]

    # ── internal ──────────────────────────────────────────────────────

    @staticmethod
    def _build_period_filter(client_id: str, period: str) -> tuple[str, list]:
        """Build WHERE clause for period filtering."""
        where = "client_id = ?"
        params: list = [client_id]

        if period == "all":
            return where, params

        # ISO week: "2024-W48"
        if "-W" in period:
            # SQLite doesn't have native ISO week, so use strftime
            # Week starts Monday in ISO. Use started_at field.
            where += " AND strftime('%Y-W%W', started_at) = ?"
            params.append(period)
        elif len(period) == 7 and "-" in period:
            # Calendar month: "2024-12"
            where += " AND strftime('%Y-%m', started_at) = ?"
            params.append(period)

        return where, params

    @staticmethod
    def _count(conn, table: str, where: str, params: list) -> int:
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM {table} WHERE {where}", params
        ).fetchone()
        return row["cnt"] if row else 0
