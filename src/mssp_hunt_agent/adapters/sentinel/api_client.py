"""Azure Log Analytics Query API client for Microsoft Sentinel."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from mssp_hunt_agent.adapters.sentinel.auth import SentinelAuth, SentinelAuthError

logger = logging.getLogger(__name__)

_QUERY_API_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"


class SentinelAPIError(Exception):
    """Non-retryable API error (4xx, bad query, etc.)."""


class SentinelTransientError(Exception):
    """Retryable error (429, 5xx, connection issues)."""


# ── Response models ───────────────────────────────────────────────────


@dataclass
class SentinelColumn:
    name: str
    type: str


@dataclass
class SentinelTable:
    name: str
    columns: list[SentinelColumn]
    rows: list[list[Any]]


@dataclass
class SentinelQueryResponse:
    tables: list[SentinelTable]
    execution_time_ms: int = 0

    @property
    def primary_table(self) -> SentinelTable | None:
        """Return the first (primary) result table, if any."""
        return self.tables[0] if self.tables else None

    def to_dicts(self) -> list[dict[str, Any]]:
        """Flatten the primary table into a list of row dicts."""
        table = self.primary_table
        if table is None:
            return []
        col_names = [c.name for c in table.columns]
        return [dict(zip(col_names, row)) for row in table.rows]


# ── API client ────────────────────────────────────────────────────────


class SentinelQueryClient:
    """Thin wrapper around the Log Analytics REST Query API.

    Parameters
    ----------
    workspace_id:
        The Log Analytics workspace GUID.
    auth:
        Authenticated token provider.
    timeout:
        HTTP timeout in seconds.
    """

    def __init__(
        self,
        workspace_id: str,
        auth: SentinelAuth,
        timeout: int = 30,
    ) -> None:
        self._workspace_id = workspace_id
        self._auth = auth
        self._url = _QUERY_API_URL.format(workspace_id=workspace_id)
        self._client = httpx.Client(timeout=timeout)

    def query(
        self,
        kql: str,
        timespan: str | None = None,
    ) -> SentinelQueryResponse:
        """Execute a KQL query against the Log Analytics workspace.

        Parameters
        ----------
        kql:
            The Kusto Query Language query string.
        timespan:
            Optional ISO 8601 duration or interval (e.g. 'P30D', 'PT24H').
            If provided, overrides any time filter in the query.
        """
        token = self._auth.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {"query": kql}
        if timespan:
            body["timespan"] = timespan

        start_ms = int(time.time() * 1000)
        try:
            resp = self._client.post(self._url, json=body, headers=headers)
        except httpx.TransportError as exc:
            raise SentinelTransientError(f"Connection error: {exc}") from exc

        elapsed_ms = int(time.time() * 1000) - start_ms

        if resp.status_code == 200:
            return self._parse_response(resp.json(), elapsed_ms)

        if resp.status_code == 401:
            self._auth.invalidate()
            raise SentinelTransientError(
                f"401 Unauthorized — token invalidated, retry: {resp.text[:200]}"
            )

        if resp.status_code in (429, 503):
            raise SentinelTransientError(
                f"Transient {resp.status_code}: {resp.text[:200]}"
            )

        if resp.status_code >= 500:
            raise SentinelTransientError(
                f"Server error {resp.status_code}: {resp.text[:200]}"
            )

        # 4xx: bad query or bad request — not retryable
        raise SentinelAPIError(
            f"API error {resp.status_code}: {resp.text[:500]}"
        )

    def test_connection(self) -> bool:
        """Return True if a minimal query succeeds."""
        try:
            self.query("union * | take 1", timespan="PT1M")
            return True
        except (SentinelAPIError, SentinelTransientError, SentinelAuthError):
            return False
        except Exception:
            return False

    def _parse_response(
        self, data: dict[str, Any], elapsed_ms: int
    ) -> SentinelQueryResponse:
        tables: list[SentinelTable] = []
        for t in data.get("tables", []):
            columns = [
                SentinelColumn(name=c["name"], type=c.get("type", "string"))
                for c in t.get("columns", [])
            ]
            tables.append(
                SentinelTable(
                    name=t.get("name", "PrimaryResult"),
                    columns=columns,
                    rows=t.get("rows", []),
                )
            )
        return SentinelQueryResponse(tables=tables, execution_time_ms=elapsed_ms)

    def close(self) -> None:
        self._client.close()
