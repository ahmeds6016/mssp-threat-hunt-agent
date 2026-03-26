"""Exabeam New-Scale adapter — translates ExabeamQuery to the search API."""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime

from mssp_hunt_agent.adapters.exabeam.api_client import ExabeamAPIClient, ExabeamAPIError, ExabeamTransientError
from mssp_hunt_agent.adapters.exabeam.base import ExabeamAdapter
from mssp_hunt_agent.adapters.exabeam.mappers import (
    DEFAULT_FIELDS,
    SearchParams,
    map_event_response,
    parse_query_text,
)
from mssp_hunt_agent.models.hunt_models import ExabeamQuery
from mssp_hunt_agent.models.result_models import QueryResult

logger = logging.getLogger(__name__)

# ── Time-range helpers ───────────────────────────────────────────────

_DATE_FORMATS = [
    "%Y-%m-%d",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%m/%d/%Y",
]

_RANGE_RE = re.compile(
    r"(\d[\d\-/T:Z+]+)\s*(?:to|through|-|–)\s*(\d[\d\-/T:Z+]+)",
    re.IGNORECASE,
)


def _parse_time_range(time_range: str) -> tuple[str, str]:
    """Parse 'YYYY-MM-DD to YYYY-MM-DD' → (ISO-8601 start, ISO-8601 end)."""
    m = _RANGE_RE.search(time_range)
    if not m:
        raise ValueError(f"Cannot parse time_range: {time_range!r}")
    start_str, end_str = m.group(1).strip(), m.group(2).strip()
    return _to_iso(start_str), _to_iso(end_str, end_of_day=True)


def _to_iso(raw: str, *, end_of_day: bool = False) -> str:
    """Best-effort conversion of a date string to ISO-8601."""
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if end_of_day and dt.hour == 0 and dt.minute == 0 and dt.second == 0:
                dt = dt.replace(hour=23, minute=59, second=59)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    # If nothing matches, return as-is (the API will validate)
    return raw


# ── Adapter ──────────────────────────────────────────────────────────


class NewScaleExabeamAdapter(ExabeamAdapter):
    """Concrete adapter that talks to the Exabeam New-Scale search API."""

    def __init__(
        self,
        api_client: ExabeamAPIClient,
        *,
        max_results: int = 10_000,
        page_size: int = 3000,
    ) -> None:
        self._client = api_client
        self._max_results = max_results
        self._page_size = page_size

    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        """Execute *query* against Exabeam and return mapped results."""
        t0 = time.perf_counter()
        try:
            start_time, end_time = _parse_time_range(query.time_range)
        except ValueError as exc:
            return QueryResult(
                query_id=query.query_id,
                query_text=query.query_text,
                status="error",
                error_message=str(exc),
            )

        params: SearchParams = parse_query_text(query.query_text)

        try:
            resp = self._client.search_events(
                fields=params.fields or list(DEFAULT_FIELDS),
                filter_expr=params.filter,
                start_time=start_time,
                end_time=end_time,
                limit=params.limit or self._page_size,
                group_by=params.group_by or None,
                order_by=params.order_by or None,
                distinct=params.distinct,
            )
        except (ExabeamAPIError, ExabeamTransientError) as exc:
            return QueryResult(
                query_id=query.query_id,
                query_text=query.query_text,
                status="error",
                error_message=str(exc),
                execution_time_ms=int((time.perf_counter() - t0) * 1000),
            )

        events = [map_event_response(raw) for raw in resp.events]
        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        return QueryResult(
            query_id=query.query_id,
            query_text=query.query_text,
            status="success" if events else "no_results",
            result_count=len(events),
            events=events,
            execution_time_ms=elapsed_ms,
            metadata={
                "adapter": "NewScaleExabeamAdapter",
                "total_count": resp.total_count,
                **resp.metadata,
            },
        )

    def test_connection(self) -> bool:
        """Verify the Exabeam API is reachable."""
        health = self._client.get_service_health()
        return health.healthy

    def get_adapter_name(self) -> str:
        return "NewScaleExabeamAdapter"
