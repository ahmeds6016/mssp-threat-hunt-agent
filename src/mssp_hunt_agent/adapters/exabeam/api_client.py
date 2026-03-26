"""HTTP client for the Exabeam New-Scale REST API."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from mssp_hunt_agent.adapters.exabeam.auth import ExabeamAuth

logger = logging.getLogger(__name__)


# ── Response dataclasses ─────────────────────────────────────────────


@dataclass
class EventSearchResponse:
    """Parsed result from POST /search/v2/events."""

    events: list[dict[str, Any]] = field(default_factory=list)
    total_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NotableEntity:
    """A notable user or asset returned by the analytics API."""

    name: str = ""
    risk_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaseInfo:
    """Simplified case representation from Threat Center."""

    case_id: str = ""
    title: str = ""
    status: str = ""
    priority: str = ""
    assignee: str = ""
    created_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceHealth:
    """Result from /service-health/v1/status."""

    healthy: bool = True
    details: dict[str, Any] = field(default_factory=dict)


# ── Retry predicate ──────────────────────────────────────────────────


class ExabeamAPIError(Exception):
    """Non-retryable API error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        super().__init__(f"Exabeam API error {status_code}: {detail}")


class ExabeamTransientError(Exception):
    """Retryable (429 / 5xx) API error."""


# ── Client ───────────────────────────────────────────────────────────


class ExabeamAPIClient:
    """Low-level HTTP client wrapping the Exabeam New-Scale REST API.

    All public methods return dataclass results; callers never deal with
    raw ``httpx.Response`` objects.
    """

    def __init__(
        self,
        base_url: str,
        auth: ExabeamAuth,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = httpx.Client(timeout=self._timeout)

    def close(self) -> None:
        self._client.close()

    # ── Search ────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(ExabeamTransientError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def search_events(
        self,
        *,
        fields: list[str],
        filter_expr: str,
        start_time: str,
        end_time: str,
        limit: int = 3000,
        group_by: list[str] | None = None,
        order_by: list[str] | None = None,
        distinct: bool = False,
    ) -> EventSearchResponse:
        """POST /search/v2/events."""
        body: dict[str, Any] = {
            "fields": fields,
            "filter": filter_expr,
            "startTime": start_time,
            "endTime": end_time,
            "limit": limit,
        }
        if group_by:
            body["groupBy"] = group_by
        if order_by:
            body["orderBy"] = order_by
        if distinct:
            body["distinct"] = True

        data = self._post("/search/v2/events", body)

        events = data.get("rows") or data.get("events") or data.get("results") or []
        total = int(data.get("totalCount", data.get("total", len(events))))

        return EventSearchResponse(
            events=events,
            total_count=total,
            metadata={k: v for k, v in data.items() if k not in ("rows", "events", "results")},
        )

    # ── Analytics ─────────────────────────────────────────────────────

    def get_notable_users(
        self, start_time: str, end_time: str, *, limit: int = 50,
    ) -> list[NotableEntity]:
        """GET /analytics/v1/notable-users."""
        params = {"startTime": start_time, "endTime": end_time, "limit": str(limit)}
        data = self._get("/analytics/v1/notable-users", params=params)
        return [
            NotableEntity(
                name=u.get("userName", u.get("name", "")),
                risk_score=float(u.get("riskScore", 0)),
                reasons=u.get("reasons", []),
                extra=u,
            )
            for u in (data.get("users") or data.get("results") or [])
        ]

    def get_notable_assets(
        self, start_time: str, end_time: str, *, limit: int = 50,
    ) -> list[NotableEntity]:
        """GET /analytics/v1/notable-assets."""
        params = {"startTime": start_time, "endTime": end_time, "limit": str(limit)}
        data = self._get("/analytics/v1/notable-assets", params=params)
        return [
            NotableEntity(
                name=a.get("hostName", a.get("name", "")),
                risk_score=float(a.get("riskScore", 0)),
                reasons=a.get("reasons", []),
                extra=a,
            )
            for a in (data.get("assets") or data.get("results") or [])
        ]

    # ── Threat Center (Cases) ─────────────────────────────────────────

    def search_cases(self, **filters: Any) -> list[CaseInfo]:
        """POST /threat-center/v1/search/cases."""
        data = self._post("/threat-center/v1/search/cases", filters)
        return [self._parse_case(c) for c in (data.get("cases") or data.get("results") or [])]

    def get_case(self, case_id: str) -> CaseInfo:
        """GET /threat-center/v1/cases/{id}."""
        data = self._get(f"/threat-center/v1/cases/{case_id}")
        return self._parse_case(data)

    def update_case(self, case_id: str, **updates: Any) -> CaseInfo:
        """PATCH /threat-center/v1/cases/{id}."""
        data = self._patch(f"/threat-center/v1/cases/{case_id}", updates)
        return self._parse_case(data)

    def add_case_note(self, case_id: str, content: str) -> dict[str, Any]:
        """POST /threat-center/v1/cases/{id}/notes."""
        return self._post(f"/threat-center/v1/cases/{case_id}/notes", {"content": content})

    # ── Service Health ────────────────────────────────────────────────

    def get_service_health(self) -> ServiceHealth:
        """GET /service-health/v1/status."""
        try:
            data = self._get("/service-health/v1/status")
            return ServiceHealth(healthy=True, details=data)
        except (ExabeamAPIError, ExabeamTransientError, httpx.RequestError):
            return ServiceHealth(healthy=False, details={})

    # ── Internal HTTP helpers ────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        token = self._auth.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _handle_response(self, resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code == 401:
            self._auth.invalidate()
            raise ExabeamTransientError(f"401 Unauthorized — token invalidated for retry")
        if resp.status_code == 429 or resp.status_code >= 500:
            raise ExabeamTransientError(
                f"Transient error {resp.status_code}: {resp.text[:200]}"
            )
        if resp.status_code >= 400:
            raise ExabeamAPIError(resp.status_code, resp.text[:500])
        if not resp.content:
            return {}
        return resp.json()

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        resp = self._client.get(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=params,
        )
        return self._handle_response(resp)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(
            f"{self._base_url}{path}",
            headers=self._headers(),
            json=body,
        )
        return self._handle_response(resp)

    def _patch(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.patch(
            f"{self._base_url}{path}",
            headers=self._headers(),
            json=body,
        )
        return self._handle_response(resp)

    @staticmethod
    def _parse_case(data: dict[str, Any]) -> CaseInfo:
        return CaseInfo(
            case_id=str(data.get("caseId", data.get("id", ""))),
            title=data.get("title", ""),
            status=data.get("status", ""),
            priority=data.get("priority", ""),
            assignee=data.get("assignee", ""),
            created_at=data.get("createdAt", data.get("created_at", "")),
            extra=data,
        )
