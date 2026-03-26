"""Tests for the Sentinel adapter row-to-event mapping.

This file was previously test_newscale_adapter.py — migrated to Sentinel adapter.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssp_hunt_agent.adapters.sentinel.adapter import SentinelAdapter, _map_row_to_event
from mssp_hunt_agent.adapters.sentinel.api_client import (
    SentinelQueryClient,
    SentinelQueryResponse,
    SentinelTable,
    SentinelColumn,
)
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent
from mssp_hunt_agent.models.result_models import QueryResult


def _make_query(**kw) -> ExabeamQuery:
    defaults = dict(
        query_id="Q-test",
        intent=QueryIntent.ANOMALY_CANDIDATE,
        description="Test query",
        query_text="SecurityEvent | where EventID == 4625 | limit 100",
        time_range="last 30 days",
        expected_signal="Failed logon events",
        approved=True,
    )
    defaults.update(kw)
    return ExabeamQuery(**defaults)


def _make_response_with_rows(rows, columns=None) -> SentinelQueryResponse:
    cols = columns or [
        SentinelColumn("TimeGenerated", "datetime"),
        SentinelColumn("Account", "string"),
        SentinelColumn("Computer", "string"),
        SentinelColumn("EventID", "int"),
        SentinelColumn("IpAddress", "string"),
    ]
    table = SentinelTable(name="PrimaryResult", columns=cols, rows=rows)
    return SentinelQueryResponse(tables=[table], execution_time_ms=250)


class TestRowMapping:
    def test_maps_timestamp(self):
        event = _map_row_to_event({"TimeGenerated": "2024-01-01T00:00:00Z"})
        assert event.timestamp == "2024-01-01T00:00:00Z"

    def test_maps_account_to_user(self):
        event = _map_row_to_event({"Account": "CONTOSO\\jsmith"})
        assert event.user == "CONTOSO\\jsmith"

    def test_maps_ip_address_to_src_ip(self):
        event = _map_row_to_event({"IpAddress": "10.10.5.22"})
        assert event.src_ip == "10.10.5.22"

    def test_maps_computer_to_hostname(self):
        event = _map_row_to_event({"Computer": "WS-PC001"})
        assert event.hostname == "WS-PC001"

    def test_maps_event_id_to_event_type(self):
        event = _map_row_to_event({"EventID": "4625"})
        assert event.event_type == "4625"

    def test_maps_command_line(self):
        event = _map_row_to_event({"CommandLine": "powershell.exe -enc dGVzdA=="})
        assert event.command_line == "powershell.exe -enc dGVzdA=="

    def test_maps_file_hash(self):
        event = _map_row_to_event({"SHA256": "abc123def456"})
        assert event.file_hash == "abc123def456"

    def test_unmapped_columns_go_to_fields(self):
        event = _map_row_to_event({
            "TimeGenerated": "2024-01-01T00:00:00Z",
            "CustomColumn": "custom_value",
        })
        assert "CustomColumn" in event.fields
        assert event.fields["CustomColumn"] == "custom_value"

    def test_none_values_handled(self):
        event = _map_row_to_event({"Account": None, "Computer": "SRV-DC01"})
        assert event.hostname == "SRV-DC01"


class TestSentinelAdapterExecute:
    def _make_adapter(self, response: SentinelQueryResponse) -> SentinelAdapter:
        mock_client = MagicMock(spec=SentinelQueryClient)
        mock_client.query.return_value = response
        mock_client._workspace_id = "test-ws"
        return SentinelAdapter(mock_client, max_results=100)

    def test_successful_query_returns_result(self):
        resp = _make_response_with_rows([
            ["2024-01-01T00:00:00Z", "CONTOSO\\jsmith", "WS-001", "4625", "10.0.0.1"],
            ["2024-01-01T00:01:00Z", "CONTOSO\\admin", "SRV-DC01", "4740", "192.168.1.1"],
        ])
        adapter = self._make_adapter(resp)
        result = adapter.execute_query(_make_query())

        assert result.status == "success"
        assert result.result_count == 2
        assert len(result.events) == 2
        assert result.events[0].user == "CONTOSO\\jsmith"

    def test_execution_time_propagated(self):
        resp = _make_response_with_rows(rows=[])
        resp.execution_time_ms = 999
        adapter = self._make_adapter(resp)
        result = adapter.execute_query(_make_query())
        assert result.execution_time_ms == 999

    def test_query_limit_appended(self):
        resp = _make_response_with_rows(rows=[])
        mock_client = MagicMock(spec=SentinelQueryClient)
        mock_client.query.return_value = resp
        mock_client._workspace_id = "test-ws"
        adapter = SentinelAdapter(mock_client, max_results=500)

        query = _make_query(query_text="SecurityEvent | where EventID == 4625")
        adapter.execute_query(query)

        called_kql = mock_client.query.call_args[0][0]
        assert "limit 500" in called_kql

    def test_transient_error_returns_error_result(self):
        from mssp_hunt_agent.adapters.sentinel.api_client import SentinelTransientError
        mock_client = MagicMock(spec=SentinelQueryClient)
        mock_client.query.side_effect = SentinelTransientError("429 rate limit")
        mock_client._workspace_id = "test-ws"
        adapter = SentinelAdapter(mock_client)

        result = adapter.execute_query(_make_query())
        assert result.status == "error"
        assert "Transient" in result.error_message

    def test_api_error_returns_error_result(self):
        from mssp_hunt_agent.adapters.sentinel.api_client import SentinelAPIError
        mock_client = MagicMock(spec=SentinelQueryClient)
        mock_client.query.side_effect = SentinelAPIError("400 bad KQL")
        mock_client._workspace_id = "test-ws"
        adapter = SentinelAdapter(mock_client)

        result = adapter.execute_query(_make_query())
        assert result.status == "error"
        assert "API error" in result.error_message

    def test_adapter_name(self):
        resp = _make_response_with_rows(rows=[])
        adapter = self._make_adapter(resp)
        assert adapter.get_adapter_name() == "SentinelAdapter"

    def test_test_connection_delegates(self):
        mock_client = MagicMock(spec=SentinelQueryClient)
        mock_client.test_connection.return_value = True
        mock_client._workspace_id = "test-ws"
        adapter = SentinelAdapter(mock_client)
        assert adapter.test_connection() is True
