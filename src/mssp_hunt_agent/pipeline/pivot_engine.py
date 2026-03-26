"""Pivot engine — generate bounded follow-up queries from findings.

Design constraints:
  - Maximum 1 hop (no recursive pivoting)
  - All pivots are time-scoped and client-scoped
  - Hard cap on generated queries (default 5)
"""

from __future__ import annotations

import uuid
from typing import Sequence

from mssp_hunt_agent.models.hunt_models import ExabeamQuery, HuntPlan, QueryIntent
from mssp_hunt_agent.models.result_models import EnrichmentRecord, ExabeamEvent, QueryResult


# ── Pivot types ──────────────────────────────────────────────────────

def _ip_to_users(ip: str, time_range: str) -> ExabeamQuery:
    """Pivot: find all users associated with a suspicious IP."""
    return ExabeamQuery(
        query_id=f"PIV-{uuid.uuid4().hex[:8]}",
        intent=QueryIntent.PIVOT,
        description=f"Pivot: users associated with IP {ip}",
        query_text=f'sourceIp = "{ip}" OR destinationIp = "{ip}" | fields user, sourceIp, destinationIp, eventType, timestamp',
        time_range=time_range,
        expected_signal=f"Users communicating with {ip}",
        is_pivot=True,
    )


def _user_to_hosts(user: str, time_range: str) -> ExabeamQuery:
    """Pivot: find all hosts accessed by a suspicious user."""
    return ExabeamQuery(
        query_id=f"PIV-{uuid.uuid4().hex[:8]}",
        intent=QueryIntent.PIVOT,
        description=f"Pivot: hosts accessed by user {user}",
        query_text=f'user = "{user}" | fields host, sourceIp, eventType, timestamp',
        time_range=time_range,
        expected_signal=f"Hosts associated with {user}",
        is_pivot=True,
    )


def _hash_to_hosts(file_hash: str, time_range: str) -> ExabeamQuery:
    """Pivot: find all hosts where a suspicious file hash was observed."""
    return ExabeamQuery(
        query_id=f"PIV-{uuid.uuid4().hex[:8]}",
        intent=QueryIntent.PIVOT,
        description=f"Pivot: hosts with file hash {file_hash[:16]}...",
        query_text=f'fileHash = "{file_hash}" | fields host, user, eventType, timestamp',
        time_range=time_range,
        expected_signal=f"Hosts executing file {file_hash[:16]}...",
        is_pivot=True,
    )


# ── Entity extraction from results ──────────────────────────────────

def _extract_suspicious_ips(
    enrichments: list[EnrichmentRecord],
) -> list[str]:
    """Return IPs with malicious or suspicious verdicts."""
    return [
        e.entity_value
        for e in enrichments
        if e.entity_type == "ip" and e.verdict in ("malicious", "suspicious")
    ]


def _extract_suspicious_users(
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
) -> list[str]:
    """Return users that appeared in events alongside suspicious indicators."""
    sus_ips = set(_extract_suspicious_ips(enrichments))
    users: set[str] = set()
    for qr in query_results:
        for ev in qr.events:
            if ev.user and (ev.src_ip in sus_ips or ev.dst_ip in sus_ips):
                users.add(ev.user)
    return sorted(users)


def _extract_suspicious_hashes(
    enrichments: list[EnrichmentRecord],
) -> list[str]:
    """Return file hashes with malicious or suspicious verdicts."""
    return [
        e.entity_value
        for e in enrichments
        if e.entity_type == "hash" and e.verdict in ("malicious", "suspicious")
    ]


# ── Public API ───────────────────────────────────────────────────────


class PivotEngine:
    """Generate bounded follow-up queries from hunt findings.

    Parameters
    ----------
    max_pivots : int
        Hard cap on the number of pivot queries generated.
    """

    def __init__(self, *, max_pivots: int = 5) -> None:
        self._max_pivots = max_pivots

    def generate_pivots(
        self,
        plan: HuntPlan,
        query_results: list[QueryResult],
        enrichments: list[EnrichmentRecord],
    ) -> list[ExabeamQuery]:
        """Return up to *max_pivots* follow-up queries.

        Pivot types (in priority order):
          1. IP → users  (suspicious/malicious IPs)
          2. user → hosts (users tied to suspicious IPs)
          3. hash → hosts (suspicious file hashes)
        """
        time_range = plan.hypotheses[0].rationale if plan.hypotheses else ""
        # Try to extract time_range from the plan's hunt steps
        for step in plan.hunt_steps:
            for q in step.queries:
                if q.time_range:
                    time_range = q.time_range
                    break
            if time_range:
                break

        pivots: list[ExabeamQuery] = []

        # 1. IP → users
        sus_ips = _extract_suspicious_ips(enrichments)
        for ip in sus_ips:
            if len(pivots) >= self._max_pivots:
                break
            pivots.append(_ip_to_users(ip, time_range))

        # 2. User → hosts
        sus_users = _extract_suspicious_users(query_results, enrichments)
        for user in sus_users:
            if len(pivots) >= self._max_pivots:
                break
            pivots.append(_user_to_hosts(user, time_range))

        # 3. Hash → hosts
        sus_hashes = _extract_suspicious_hashes(enrichments)
        for h in sus_hashes:
            if len(pivots) >= self._max_pivots:
                break
            pivots.append(_hash_to_hosts(h, time_range))

        return pivots[:self._max_pivots]
