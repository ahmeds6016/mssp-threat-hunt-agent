"""Stub for a real Exabeam Search integration.

TODO — implement when real API credentials are available.
Required:
    1. Authenticate via EXABEAM_BASE_URL + EXABEAM_API_KEY.
    2. Translate ExabeamQuery.query_text into the tenant's query syntax.
    3. Handle pagination, timeouts, and rate limits.
    4. Map raw JSON response rows to ExabeamEvent models.
"""

from __future__ import annotations

from mssp_hunt_agent.adapters.exabeam.base import ExabeamAdapter
from mssp_hunt_agent.models.hunt_models import ExabeamQuery
from mssp_hunt_agent.models.result_models import QueryResult


class RealExabeamAdapter(ExabeamAdapter):
    """Placeholder for real Exabeam Search integration.

    To wire this up:
        1. Set EXABEAM_BASE_URL and EXABEAM_API_KEY in .env
        2. Implement the three abstract methods below
        3. Use ``httpx.Client`` for HTTP calls with retry via tenacity
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url
        self._api_key = api_key
        # TODO: initialise httpx.Client with auth headers

    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        # TODO: POST to /search/jobs, poll for results, parse response
        raise NotImplementedError(
            "RealExabeamAdapter.execute_query is not implemented. "
            "See docstring for integration guide."
        )

    def test_connection(self) -> bool:
        # TODO: GET /health or /api/auth/check
        raise NotImplementedError(
            "RealExabeamAdapter.test_connection is not implemented."
        )

    def get_adapter_name(self) -> str:
        return "RealExabeamAdapter"
