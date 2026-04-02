"""Microsoft Sentinel adapter — executes KQL hunt queries via Log Analytics API."""

from __future__ import annotations

import logging
import time
from typing import Any

from mssp_hunt_agent.adapters.base import SIEMAdapter
from mssp_hunt_agent.adapters.sentinel.api_client import (
    SentinelAPIError,
    SentinelQueryClient,
    SentinelTransientError,
)
from mssp_hunt_agent.models.hunt_models import ExabeamQuery
from mssp_hunt_agent.models.result_models import ExabeamEvent, QueryResult

logger = logging.getLogger(__name__)

# Map Sentinel / Log Analytics column names → ExabeamEvent field names
_COLUMN_MAP: dict[str, str] = {
    # Timestamp
    "TimeGenerated": "timestamp",
    "TimeCreated": "timestamp",
    "StartTime": "timestamp",
    # User / Account
    "Account": "user",
    "UserName": "user",
    "UserId": "user",
    "SubjectUserName": "user",
    "TargetUserName": "user",
    "AccountName": "user",
    # Source IP
    "SourceIp": "src_ip",
    "IpAddress": "src_ip",
    "ClientIP": "src_ip",
    "SourceAddress": "src_ip",
    "InitiatingProcessSHA256": "file_hash",
    # Destination IP
    "DestinationIp": "dst_ip",
    "DestinationAddress": "dst_ip",
    "RemoteIP": "dst_ip",
    # Hostname / Computer
    "Computer": "hostname",
    "HostName": "hostname",
    "DeviceName": "hostname",
    "WorkstationName": "hostname",
    "DeviceId": "hostname",
    # Process
    "ProcessName": "process_name",
    "ImageFile": "process_name",
    "InitiatingProcessFileName": "process_name",
    "NewProcessName": "process_name",
    # Command line
    "CommandLine": "command_line",
    "ProcessCommandLine": "command_line",
    "InitiatingProcessCommandLine": "command_line",
    # File hash
    "FileHash": "file_hash",
    "SHA256": "file_hash",
    "SHA1": "file_hash",
    "MD5": "file_hash",
    # User agent
    "UserAgent": "user_agent",
    "RequestUserAgent": "user_agent",
    # Domain
    "DomainName": "domain",
    "Domain": "domain",
    "DNSHostName": "domain",
    "Fqdn": "domain",
}

# Columns that carry the event type / category
_EVENT_TYPE_COLUMNS = [
    "EventID", "Type", "Activity", "Category", "ActionType",
    "EventType", "AlertName", "OperationName",
]


def _map_row_to_event(row: dict[str, Any]) -> ExabeamEvent:
    """Map a flat Sentinel row dict to an ExabeamEvent."""
    mapped: dict[str, Any] = {}
    extra: dict[str, Any] = {}

    for col, val in row.items():
        target = _COLUMN_MAP.get(col)
        if target and target not in mapped:
            mapped[target] = str(val) if val is not None else None
        else:
            extra[col] = val

    # Derive event_type from known columns
    event_type = "sentinel-event"
    for col in _EVENT_TYPE_COLUMNS:
        if col in row and row[col] is not None:
            event_type = str(row[col])
            break

    return ExabeamEvent(
        timestamp=mapped.get("timestamp", ""),
        event_type=event_type,
        user=mapped.get("user"),
        src_ip=mapped.get("src_ip"),
        dst_ip=mapped.get("dst_ip"),
        hostname=mapped.get("hostname"),
        domain=mapped.get("domain"),
        process_name=mapped.get("process_name"),
        command_line=mapped.get("command_line"),
        file_hash=mapped.get("file_hash"),
        user_agent=mapped.get("user_agent"),
        fields=extra,
    )


class SentinelAdapter(SIEMAdapter):
    """Execute KQL threat-hunt queries against Microsoft Sentinel
    via the Azure Log Analytics Query API.

    Parameters
    ----------
    client:
        Pre-built SentinelQueryClient (handles auth + HTTP).
    max_results:
        If > 0, appends ``| limit {max_results}`` to every query to bound
        result size.  Set to 0 to disable.
    """

    def __init__(
        self,
        client: SentinelQueryClient,
        max_results: int = 1000,
    ) -> None:
        self._client = client
        self._max_results = max_results

    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        kql = self._bound_query(query.query_text)
        try:
            resp = self._client.query(kql)
            rows = resp.to_dicts()
            events = [_map_row_to_event(r) for r in rows]
            return QueryResult(
                query_id=query.query_id,
                query_text=kql,
                status="success",
                result_count=len(events),
                events=events,
                execution_time_ms=resp.execution_time_ms,
                metadata={"adapter": "sentinel", "workspace_id": self._client._workspace_id},
            )
        except SentinelTransientError as exc:
            logger.warning("Sentinel transient error for %s: %s", query.query_id, exc)
            return QueryResult(
                query_id=query.query_id,
                query_text=kql,
                status="error",
                error_message=f"Transient: {exc}",
            )
        except SentinelAPIError as exc:
            logger.error("Sentinel API error for %s: %s", query.query_id, exc)
            return QueryResult(
                query_id=query.query_id,
                query_text=kql,
                status="error",
                error_message=f"API error: {exc}",
            )

    def test_connection(self) -> bool:
        return self._client.test_connection()

    def get_adapter_name(self) -> str:
        return "SentinelAdapter"

    def _bound_query(self, kql: str) -> str:
        """Append a limit clause if max_results is configured."""
        if self._max_results <= 0:
            return kql
        kql = kql.rstrip().rstrip(";")
        if "| limit " not in kql.lower() and "| take " not in kql.lower():
            kql = f"{kql}\n| limit {self._max_results}"
        return kql
