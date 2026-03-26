"""IOC hit analyzer — match query results back to indicators and produce hit summary.

In mock mode, uses deterministic logic to simulate realistic hit/miss patterns
since the mock adapter returns synthetic events that won't contain actual IOC values.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from mssp_hunt_agent.models.ioc_models import (
    IOCBatch,
    IOCHit,
    IOCSweepResult,
    NormalizedIOC,
)
from mssp_hunt_agent.models.result_models import ExabeamEvent, QueryResult

_MOCK_USERS = ["jsmith", "admin.svc", "m.jones", "c.rodriguez", "k.chen"]
_MOCK_HOSTS = ["WS-PC0012", "SRV-DC01", "SRV-FILE03", "WS-PC0087"]


def analyze_sweep_results(
    ioc_batch: IOCBatch,
    query_results: list[QueryResult],
    mock_mode: bool = True,
) -> IOCSweepResult:
    """Match query results against IOCs and produce a sweep summary.

    In live mode, scans event fields for exact IOC value matches.
    In mock mode, generates deterministic synthetic hits (~40% hit rate).
    """
    if mock_mode:
        return _mock_analysis(ioc_batch, query_results)
    return _live_analysis(ioc_batch, query_results)


# ── Live analysis (for future real adapter) ───────────────────────────


def _live_analysis(
    ioc_batch: IOCBatch,
    query_results: list[QueryResult],
) -> IOCSweepResult:
    """Scan actual query results for IOC value matches."""
    hits: list[IOCHit] = []
    hit_values: set[str] = set()

    for ioc in ioc_batch.valid:
        matching_events = _find_matching_events(ioc, query_results)
        if matching_events:
            hit_values.add(ioc.normalized_value)
            hits.append(_build_hit(ioc, matching_events, query_results))

    misses = [
        ioc.normalized_value
        for ioc in ioc_batch.valid
        if ioc.normalized_value not in hit_values
    ]

    return IOCSweepResult(
        total_iocs_searched=len(ioc_batch.valid),
        total_hits=len(hits),
        total_misses=len(misses),
        hits=hits,
        misses=misses,
    )


def _find_matching_events(
    ioc: NormalizedIOC, results: list[QueryResult]
) -> list[ExabeamEvent]:
    """Check all events for exact field matches against this IOC."""
    matches: list[ExabeamEvent] = []
    val = ioc.normalized_value.lower()
    for qr in results:
        for ev in qr.events:
            if _event_contains_ioc(ev, val):
                matches.append(ev)
    return matches


def _event_contains_ioc(event: ExabeamEvent, value: str) -> bool:
    searchable = [
        event.src_ip, event.dst_ip, event.domain, event.hostname,
        event.file_hash, event.user, event.user_agent,
    ]
    return any(f and f.lower() == value for f in searchable)


def _build_hit(
    ioc: NormalizedIOC,
    events: list[ExabeamEvent],
    query_results: list[QueryResult],
) -> IOCHit:
    users = sorted({e.user for e in events if e.user})
    hosts = sorted({e.hostname for e in events if e.hostname})
    timestamps = sorted(e.timestamp for e in events if e.timestamp)
    query_id = query_results[0].query_id if query_results else "unknown"

    return IOCHit(
        ioc_value=ioc.normalized_value,
        ioc_type=ioc.ioc_type.value,
        query_id=query_id,
        hit_count=len(events),
        first_seen=timestamps[0] if timestamps else "",
        last_seen=timestamps[-1] if timestamps else "",
        affected_users=users[:10],
        affected_hosts=hosts[:10],
        sample_events=events[:3],
    )


# ── Mock analysis ─────────────────────────────────────────────────────


def _mock_analysis(
    ioc_batch: IOCBatch,
    query_results: list[QueryResult],
) -> IOCSweepResult:
    """Deterministic mock: ~40% of IOCs get synthetic hits."""
    hits: list[IOCHit] = []
    misses: list[str] = []

    for ioc in ioc_batch.valid:
        # Deterministic hit/miss based on IOC value hash
        h = int(hashlib.md5(ioc.normalized_value.encode()).hexdigest(), 16)
        if h % 10 < 4:  # ~40% hit rate
            hits.append(_synthetic_hit(ioc, query_results))
        else:
            misses.append(ioc.normalized_value)

    return IOCSweepResult(
        total_iocs_searched=len(ioc_batch.valid),
        total_hits=len(hits),
        total_misses=len(misses),
        hits=hits,
        misses=misses,
    )


def _synthetic_hit(
    ioc: NormalizedIOC,
    query_results: list[QueryResult],
) -> IOCHit:
    """Generate a plausible hit for mock mode."""
    h = int(hashlib.md5(ioc.normalized_value.encode()).hexdigest(), 16)
    hit_count = (h % 15) + 1
    base_time = datetime.now(timezone.utc) - timedelta(days=h % 30)

    num_users = min(hit_count, 3)
    num_hosts = min(hit_count, 2)
    random.seed(h)
    users = random.sample(_MOCK_USERS, min(num_users, len(_MOCK_USERS)))
    hosts = random.sample(_MOCK_HOSTS, min(num_hosts, len(_MOCK_HOSTS)))

    query_id = query_results[0].query_id if query_results else "Q-mock"

    sample_events = [
        ExabeamEvent(
            timestamp=(base_time - timedelta(hours=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            event_type="ioc-match",
            user=users[i % len(users)],
            src_ip=ioc.normalized_value if ioc.ioc_type.value == "ip" else "10.10.5.22",
            dst_ip="10.0.0.1",
            hostname=hosts[i % len(hosts)],
            domain=ioc.normalized_value if ioc.ioc_type.value == "domain" else "corp.local",
            file_hash=ioc.normalized_value if "hash" in ioc.ioc_type.value else None,
            user_agent=ioc.normalized_value if ioc.ioc_type.value == "user_agent" else None,
            fields={"mock": True, "ioc_sweep": True},
        )
        for i in range(min(hit_count, 3))
    ]

    return IOCHit(
        ioc_value=ioc.normalized_value,
        ioc_type=ioc.ioc_type.value,
        query_id=query_id,
        hit_count=hit_count,
        first_seen=sample_events[-1].timestamp if sample_events else "",
        last_seen=sample_events[0].timestamp if sample_events else "",
        affected_users=users,
        affected_hosts=hosts,
        sample_events=sample_events,
    )
