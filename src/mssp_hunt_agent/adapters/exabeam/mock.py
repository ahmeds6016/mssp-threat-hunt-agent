"""Backward-compatibility shim — re-exports MockSentinelAdapter as MockExabeamAdapter.

The real mock implementation has moved to adapters.sentinel.mock.
This module is kept so existing test imports don't break during the Sentinel pivot.
"""

from mssp_hunt_agent.adapters.sentinel.mock import MockSentinelAdapter as MockExabeamAdapter  # noqa: F401

__all__ = ["MockExabeamAdapter"]

# Everything below is kept for reference only — not executed.
import random  # noqa: E402
from datetime import datetime, timedelta, timezone

from mssp_hunt_agent.adapters.exabeam.base import ExabeamAdapter
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent
from mssp_hunt_agent.models.result_models import ExabeamEvent, QueryResult

# ---------------------------------------------------------------------------
# Pools of realistic fake data used to assemble events
# ---------------------------------------------------------------------------
_USERS = ["jsmith", "admin.svc", "m.jones", "backup_agent", "c.rodriguez", "sa_deploy"]
_SRC_IPS = ["10.10.5.22", "192.168.1.105", "172.16.0.44", "203.0.113.77", "198.51.100.12"]
_DST_IPS = ["10.0.0.1", "10.0.0.50", "10.10.10.10", "52.96.166.130"]
_HOSTNAMES = ["WS-PC0012", "SRV-DC01", "SRV-FILE03", "WS-PC0087", "VDI-POOL-05"]
_DOMAINS = ["corp.local", "partner-ext.com", "login.microsoftonline.com", "unknown-cdn.ru"]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "python-requests/2.31.0",
    "curl/7.88.1",
]
_PROCESSES = ["powershell.exe", "cmd.exe", "rundll32.exe", "svchost.exe", "notepad.exe"]
_HASHES = [
    "e99a18c428cb38d5f260853678922e03",
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
]
_EVENT_TYPES_BY_INTENT: dict[QueryIntent, list[str]] = {
    QueryIntent.BASELINE: ["authentication-success", "vpn-connect", "logon-session"],
    QueryIntent.ANOMALY_CANDIDATE: [
        "authentication-failure",
        "privilege-escalation",
        "lateral-movement",
        "unusual-process-execution",
    ],
    QueryIntent.PIVOT: ["dns-query", "file-access", "registry-modification"],
    QueryIntent.CONFIRMATION: ["alert-triggered", "edr-detection", "dlp-match"],
}


def _random_timestamp(base: datetime, spread_hours: int = 720) -> str:
    delta = timedelta(hours=random.randint(0, spread_hours))
    return (base - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_events(query: ExabeamQuery, count: int) -> list[ExabeamEvent]:
    """Produce *count* synthetic events that look plausible for *query.intent*."""
    base_time = datetime.now(timezone.utc)
    event_pool = _EVENT_TYPES_BY_INTENT.get(query.intent, ["generic-event"])
    events: list[ExabeamEvent] = []
    for _ in range(count):
        events.append(
            ExabeamEvent(
                timestamp=_random_timestamp(base_time),
                event_type=random.choice(event_pool),
                user=random.choice(_USERS),
                src_ip=random.choice(_SRC_IPS),
                dst_ip=random.choice(_DST_IPS),
                hostname=random.choice(_HOSTNAMES),
                domain=random.choice(_DOMAINS),
                process_name=random.choice(_PROCESSES) if query.intent != QueryIntent.BASELINE else None,
                command_line="Get-Process | Out-File C:\\temp\\ps.txt" if random.random() > 0.7 else None,
                file_hash=random.choice(_HASHES) if random.random() > 0.6 else None,
                user_agent=random.choice(_USER_AGENTS) if random.random() > 0.5 else None,
                fields={"mock": True, "query_intent": query.intent.value},
            )
        )
    return events


class MockExabeamAdapter(ExabeamAdapter):
    """Returns realistic synthetic results without hitting any real API."""

    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        # Simulate variable result counts by intent
        count_ranges = {
            QueryIntent.BASELINE: (20, 80),
            QueryIntent.ANOMALY_CANDIDATE: (2, 15),
            QueryIntent.PIVOT: (5, 30),
            QueryIntent.CONFIRMATION: (0, 5),
        }
        lo, hi = count_ranges.get(query.intent, (1, 10))
        count = random.randint(lo, hi)
        events = _generate_events(query, count)

        return QueryResult(
            query_id=query.query_id,
            query_text=query.query_text,
            status="success",
            result_count=len(events),
            events=events,
            execution_time_ms=random.randint(120, 3500),
            metadata={"adapter": "mock", "simulated": True},
        )

    def test_connection(self) -> bool:
        return True

    def get_adapter_name(self) -> str:
        return "MockExabeamAdapter"
