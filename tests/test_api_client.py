"""Tests for the Sentinel Log Analytics Query API client.

This file was previously test_api_client.py (Exabeam) — migrated to Sentinel.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from mssp_hunt_agent.adapters.sentinel.api_client import (
    SentinelQueryClient,
    SentinelAPIError,
    SentinelTransientError,
    SentinelQueryResponse,
    SentinelTable,
    SentinelColumn,
)
from mssp_hunt_agent.adapters.sentinel.auth import SentinelAuth


@pytest.fixture
def mock_auth() -> MagicMock:
    auth = MagicMock(spec=SentinelAuth)
    auth.get_token.return_value = "test-bearer-token"
    return auth


@pytest.fixture
def client(mock_auth: MagicMock) -> SentinelQueryClient:
    return SentinelQueryClient(
        workspace_id="ws-00000000-0000-0000-0000-000000000000",
        auth=mock_auth,
    )


def _make_response(rows: list, columns: list | None = None) -> dict:
    cols = columns or [
        {"name": "TimeGenerated", "type": "datetime"},
        {"name": "Account", "type": "string"},
        {"name": "Computer", "type": "string"},
    ]
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": cols,
                "rows": rows,
            }
        ]
    }


class TestSentinelQuery:
    def test_successful_query(self, client: SentinelQueryClient) -> None:
        resp_data = _make_response(
            rows=[
                ["2024-11-15T10:00:00Z", "CONTOSO\\jsmith", "SRV-DC01"],
                ["2024-11-15T10:01:00Z", "CONTOSO\\admin", "WS-PC001"],
            ]
        )
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data

        with patch.object(client._client, "post", return_value=mock_resp):
            result = client.query("SecurityEvent | limit 100")

        assert isinstance(result, SentinelQueryResponse)
        assert len(result.tables) == 1
        assert len(result.primary_table.rows) == 2

    def test_to_dicts_flattens_rows(self, client: SentinelQueryClient) -> None:
        resp_data = _make_response(
            rows=[["2024-01-01T00:00:00Z", "jsmith", "SRV-01"]],
        )
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data

        with patch.object(client._client, "post", return_value=mock_resp):
            result = client.query("SecurityEvent | limit 1")

        dicts = result.to_dicts()
        assert len(dicts) == 1
        assert dicts[0]["Account"] == "jsmith"
        assert dicts[0]["Computer"] == "SRV-01"

    def test_empty_result(self, client: SentinelQueryClient) -> None:
        resp_data = _make_response(rows=[])
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data

        with patch.object(client._client, "post", return_value=mock_resp):
            result = client.query("SecurityEvent | limit 0")

        assert result.to_dicts() == []

    def test_400_raises_api_error(self, client: SentinelQueryClient) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 400
        mock_resp.text = "Bad KQL syntax"

        with patch.object(client._client, "post", return_value=mock_resp):
            with pytest.raises(SentinelAPIError, match="400"):
                client.query("INVALID KQL !!!")

    @patch("mssp_hunt_agent.adapters.sentinel.api_client.time.sleep")
    def test_429_raises_transient_error(self, _sleep, client: SentinelQueryClient) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 429
        mock_resp.text = "Too many requests"

        with patch.object(client._client, "post", return_value=mock_resp):
            with pytest.raises(SentinelTransientError):
                client.query("SecurityEvent | limit 1")

    @patch("mssp_hunt_agent.adapters.sentinel.api_client.time.sleep")
    def test_500_raises_transient_error(self, _sleep, client: SentinelQueryClient) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 500
        mock_resp.text = "Internal server error"

        with patch.object(client._client, "post", return_value=mock_resp):
            with pytest.raises(SentinelTransientError):
                client.query("SecurityEvent | limit 1")

    @patch("mssp_hunt_agent.adapters.sentinel.api_client.time.sleep")
    def test_401_invalidates_token(
        self, _sleep, client: SentinelQueryClient, mock_auth: MagicMock
    ) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"

        with patch.object(client._client, "post", return_value=mock_resp):
            with pytest.raises(SentinelTransientError, match="401"):
                client.query("SecurityEvent | limit 1")

        # Retries call invalidate on each attempt
        assert mock_auth.invalidate.call_count == client._MAX_RETRIES + 1

    @patch("mssp_hunt_agent.adapters.sentinel.api_client.time.sleep")
    def test_connection_error_raises_transient(self, _sleep, client: SentinelQueryClient) -> None:
        with patch.object(
            client._client, "post", side_effect=httpx.ConnectError("connection refused")
        ):
            with pytest.raises(SentinelTransientError):
                client.query("SecurityEvent | limit 1")

    def test_timespan_included_in_body(
        self, client: SentinelQueryClient, mock_auth: MagicMock
    ) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_response(rows=[])

        captured: list[dict] = []

        def _post(url, json, headers):
            captured.append(json)
            return mock_resp

        with patch.object(client._client, "post", side_effect=_post):
            client.query("SecurityEvent | limit 1", timespan="P7D")

        assert captured[0]["timespan"] == "P7D"
