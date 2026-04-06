"""IOC Sweep — runs targeted KQL queries directly from extracted IOCs.

No hypotheses, no LLM reasoning loops. Takes structured IOCs (IPs, domains,
hashes, file paths, package names, registry keys, user agents) and builds
precise KQL queries to check each one against Sentinel tables.

Returns a structured sweep result with hits/misses per IOC.

Usage:
    sweeper = IOCSweeper(adapter=sentinel_adapter)
    result = sweeper.run_sweep(intel_event, progress=tracker)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from mssp_hunt_agent.adapters.base import SIEMAdapter
    from mssp_hunt_agent.intel.intel_processor import IntelEvent
    from mssp_hunt_agent.persistence.progress import ProgressTracker

logger = logging.getLogger(__name__)


@dataclass
class IOCHit:
    """A single IOC match found in Sentinel."""
    ioc_type: str
    ioc_value: str
    ioc_context: str
    table: str
    query: str
    match_count: int
    sample_events: list[dict] = field(default_factory=list)


@dataclass
class SweepResult:
    """Result of an IOC sweep."""
    sweep_id: str
    started_at: str
    completed_at: str = ""
    total_iocs: int = 0
    total_queries: int = 0
    total_hits: int = 0
    total_misses: int = 0
    hits: list[IOCHit] = field(default_factory=list)
    misses: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Additional sweep categories
    package_checks: list[dict] = field(default_factory=list)
    persistence_checks: list[dict] = field(default_factory=list)
    network_checks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sweep_id": self.sweep_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_iocs": self.total_iocs,
            "total_queries": self.total_queries,
            "total_hits": self.total_hits,
            "total_misses": self.total_misses,
            "hits": [{"ioc_type": h.ioc_type, "ioc_value": h.ioc_value, "table": h.table,
                       "match_count": h.match_count, "context": h.ioc_context} for h in self.hits],
            "misses": self.misses,
            "errors": self.errors,
        }


# ── KQL Query Builders ────────────────────────────────────────────────

def _build_ip_queries(ip: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for an IP across all relevant tables."""
    return [
        ("SigninLogs", f'SigninLogs | where TimeGenerated > ago(30d) | where IPAddress == "{ip}" | summarize count(), dcount(UserPrincipalName), min(TimeGenerated), max(TimeGenerated) by IPAddress | take 10'),
        ("SecurityEvent", f'SecurityEvent | where TimeGenerated > ago(30d) | where IpAddress == "{ip}" or EventData has "{ip}" | summarize count() by Computer, EventID | take 10'),
        ("DeviceNetworkEvents", f'DeviceNetworkEvents | where TimeGenerated > ago(30d) | where RemoteIP == "{ip}" | summarize count(), dcount(DeviceName), min(TimeGenerated), max(TimeGenerated) by RemoteIP | take 10'),
        ("Syslog", f'Syslog | where TimeGenerated > ago(30d) | where SyslogMessage has "{ip}" | summarize count() by Computer | take 10'),
        ("CommonSecurityLog", f'CommonSecurityLog | where TimeGenerated > ago(30d) | where DestinationIP == "{ip}" or SourceIP == "{ip}" | summarize count() by DeviceVendor | take 10'),
        ("ThreatIntelligenceIndicator", f'ThreatIntelligenceIndicator | where TimeGenerated > ago(90d) | where NetworkIP == "{ip}" or NetworkSourceIP == "{ip}" | summarize count() | take 10'),
    ]


def _build_domain_queries(domain: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for a domain."""
    return [
        ("DeviceNetworkEvents", f'DeviceNetworkEvents | where TimeGenerated > ago(30d) | where RemoteUrl has "{domain}" | summarize count(), dcount(DeviceName) by RemoteUrl | take 10'),
        ("DnsEvents", f'DnsEvents | where TimeGenerated > ago(30d) | where Name has "{domain}" | summarize count() by Name, ClientIP | take 10'),
        ("Syslog", f'Syslog | where TimeGenerated > ago(30d) | where SyslogMessage has "{domain}" | summarize count() by Computer | take 10'),
        ("SecurityEvent", f'SecurityEvent | where TimeGenerated > ago(30d) | where EventData has "{domain}" | summarize count() by Computer, EventID | take 10'),
        ("CommonSecurityLog", f'CommonSecurityLog | where TimeGenerated > ago(30d) | where RequestURL has "{domain}" or DestinationHostName has "{domain}" | summarize count() by DeviceVendor | take 10'),
        ("ThreatIntelligenceIndicator", f'ThreatIntelligenceIndicator | where TimeGenerated > ago(90d) | where DomainName has "{domain}" or Url has "{domain}" | summarize count() | take 10'),
    ]


def _build_hash_queries(hash_value: str, hash_type: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for a file hash."""
    queries = [
        ("DeviceFileEvents", f'DeviceFileEvents | where TimeGenerated > ago(30d) | where SHA256 == "{hash_value}" or SHA1 == "{hash_value}" or MD5 == "{hash_value}" | summarize count(), dcount(DeviceName) by FileName | take 10'),
        ("DeviceProcessEvents", f'DeviceProcessEvents | where TimeGenerated > ago(30d) | where SHA256 == "{hash_value}" or SHA1 == "{hash_value}" or MD5 == "{hash_value}" | summarize count() by FileName, DeviceName | take 10'),
    ]
    # Also search in event data as raw string
    queries.append(
        ("SecurityEvent", f'SecurityEvent | where TimeGenerated > ago(30d) | where EventData has "{hash_value}" | summarize count() by Computer, EventID | take 10')
    )
    return queries


def _build_filepath_queries(filepath: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for a file path."""
    # Escape backslashes for KQL
    fp = filepath.replace("\\", "\\\\")
    return [
        ("DeviceFileEvents", f'DeviceFileEvents | where TimeGenerated > ago(30d) | where FolderPath has "{fp}" or FileName has "{fp}" | summarize count() by DeviceName, FileName | take 10'),
        ("DeviceProcessEvents", f'DeviceProcessEvents | where TimeGenerated > ago(30d) | where ProcessCommandLine has "{fp}" or FolderPath has "{fp}" | summarize count() by DeviceName, FileName | take 10'),
        ("Syslog", f'Syslog | where TimeGenerated > ago(30d) | where SyslogMessage has "{fp}" | summarize count() by Computer | take 10'),
    ]


def _build_package_queries(package_name: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for a software package name in process telemetry."""
    return [
        ("DeviceProcessEvents", f'DeviceProcessEvents | where TimeGenerated > ago(30d) | where ProcessCommandLine has "{package_name}" | summarize count() by DeviceName, FileName, AccountName | take 10'),
        ("SecurityEvent", f'SecurityEvent | where TimeGenerated > ago(30d) | where EventID == 4688 | where CommandLine has "{package_name}" | summarize count() by Computer, Account | take 10'),
        ("Syslog", f'Syslog | where TimeGenerated > ago(30d) | where SyslogMessage has "{package_name}" | summarize count() by Computer, ProcessName | take 10'),
    ]


def _build_useragent_queries(ua_string: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for a specific User-Agent string."""
    # Use a distinctive substring
    ua_fragment = ua_string[:50] if len(ua_string) > 50 else ua_string
    return [
        ("DeviceNetworkEvents", f'DeviceNetworkEvents | where TimeGenerated > ago(30d) | where AdditionalFields has "{ua_fragment}" | summarize count() by DeviceName | take 10'),
        ("CommonSecurityLog", f'CommonSecurityLog | where TimeGenerated > ago(30d) | where RequestClientApplication has "{ua_fragment}" | summarize count() by DeviceVendor | take 10'),
    ]


def _build_registry_queries(reg_key: str) -> list[tuple[str, str]]:
    """Build KQL queries to search for registry key modifications."""
    return [
        ("DeviceRegistryEvents", f'DeviceRegistryEvents | where TimeGenerated > ago(30d) | where RegistryKey has "{reg_key}" or RegistryValueName has "{reg_key}" | summarize count() by DeviceName, ActionType | take 10'),
        ("SecurityEvent", f'SecurityEvent | where TimeGenerated > ago(30d) | where EventData has "{reg_key}" | summarize count() by Computer, EventID | take 10'),
    ]


# ── IOC Sweeper ───────────────────────────────────────────────────────

class IOCSweeper:
    """Runs precise IOC-based KQL queries against Sentinel — no hypotheses needed."""

    def __init__(self, adapter: SIEMAdapter) -> None:
        self._adapter = adapter

    def run_sweep(
        self,
        intel_event: IntelEvent,
        progress: Optional[ProgressTracker] = None,
        timespan: str = "P30D",
    ) -> SweepResult:
        """Run a complete IOC sweep for an intel event.

        Builds and executes KQL queries for every IOC, affected software,
        and known persistence mechanism in the event.
        """
        from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent

        sweep_id = f"SWEEP-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M')}"
        result = SweepResult(
            sweep_id=sweep_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        if progress:
            progress.log("ioc_sweep_started", sweep_id=sweep_id,
                         ioc_count=len(intel_event.iocs),
                         title=intel_event.title)

        # Collect all queries to run
        all_queries: list[tuple[str, str, str, str, str]] = []  # (ioc_type, ioc_value, context, table, kql)

        # 1. IOC-based queries
        for ioc in intel_event.iocs:
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            context = ioc.get("context", "")

            if not value:
                continue

            if ioc_type == "ip":
                for table, kql in _build_ip_queries(value):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type == "domain":
                for table, kql in _build_domain_queries(value):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type in ("hash_sha256", "hash_sha1", "hash_md5"):
                for table, kql in _build_hash_queries(value, ioc_type):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type == "url":
                # Extract domain from URL for domain queries
                from urllib.parse import urlparse
                parsed = urlparse(value)
                domain = parsed.hostname or value
                for table, kql in _build_domain_queries(domain):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type == "filepath":
                for table, kql in _build_filepath_queries(value):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type == "useragent":
                for table, kql in _build_useragent_queries(value):
                    all_queries.append((ioc_type, value, context, table, kql))
            elif ioc_type == "registry":
                for table, kql in _build_registry_queries(value):
                    all_queries.append((ioc_type, value, context, table, kql))

        # 2. Affected software queries
        for software in intel_event.affected_software:
            for table, kql in _build_package_queries(software):
                all_queries.append(("software", software, "Affected software", table, kql))

        # 3. Known file paths from the attack (if present in recommended_queries)
        # These are already covered by the IOCs above

        result.total_iocs = len(set((q[0], q[1]) for q in all_queries))

        logger.info("IOC sweep %s: %d IOCs, %d queries to run", sweep_id, result.total_iocs, len(all_queries))

        if progress:
            progress.log("ioc_sweep_queries_planned", total_iocs=result.total_iocs,
                         total_queries=len(all_queries))

        # Execute queries
        seen_ioc_results: dict[str, bool] = {}  # "type:value" -> has_hit

        for i, (ioc_type, ioc_value, context, table, kql) in enumerate(all_queries):
            result.total_queries += 1
            ioc_key = f"{ioc_type}:{ioc_value}"

            try:
                t0 = time.time()
                eq = ExabeamQuery(
                    query_id=f"sweep-{i:04d}",
                    intent=QueryIntent.IOC_HUNT,
                    description=f"IOC sweep: {ioc_type} {ioc_value} in {table}",
                    query_text=kql,
                    time_range="30d",
                    expected_signal=f"{ioc_type} indicator match",
                )
                query_result = self._adapter.execute_query(eq)
                duration_ms = int((time.time() - t0) * 1000)

                if query_result.result_count > 0:
                    hit = IOCHit(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        ioc_context=context,
                        table=table,
                        query=kql,
                        match_count=query_result.result_count,
                        sample_events=[e.model_dump() for e in query_result.events[:5]],
                    )
                    result.hits.append(hit)
                    seen_ioc_results[ioc_key] = True

                    if progress:
                        progress.log("ioc_hit", ioc_type=ioc_type, ioc_value=ioc_value,
                                     table=table, count=query_result.result_count, ms=duration_ms)

                    logger.info("HIT: %s %s in %s — %d matches (%dms)",
                                ioc_type, ioc_value, table, query_result.result_count, duration_ms)
                else:
                    if ioc_key not in seen_ioc_results:
                        seen_ioc_results[ioc_key] = False

                    if progress:
                        progress.log("ioc_miss", ioc_type=ioc_type, ioc_value=ioc_value,
                                     table=table, ms=duration_ms)

            except Exception as exc:
                result.errors.append(f"Query failed for {ioc_type} {ioc_value} in {table}: {exc}")
                logger.warning("Sweep query failed: %s", exc)

        # Summarize misses
        for ioc_key, has_hit in seen_ioc_results.items():
            if not has_hit:
                parts = ioc_key.split(":", 1)
                result.misses.append({"ioc_type": parts[0], "ioc_value": parts[1] if len(parts) > 1 else ""})
                result.total_misses += 1

        result.total_hits = len(result.hits)
        result.completed_at = datetime.now(timezone.utc).isoformat()

        if progress:
            progress.log("ioc_sweep_completed", sweep_id=sweep_id,
                         total_queries=result.total_queries,
                         hits=result.total_hits, misses=result.total_misses)

        logger.info("IOC sweep %s complete: %d queries, %d hits, %d misses",
                     sweep_id, result.total_queries, result.total_hits, result.total_misses)

        return result
