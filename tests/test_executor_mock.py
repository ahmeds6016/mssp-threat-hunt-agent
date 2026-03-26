"""Tests for the mock Sentinel adapter (executor layer)."""

from __future__ import annotations

from mssp_hunt_agent.adapters.sentinel.mock import MockSentinelAdapter
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent


def _make_query(intent: QueryIntent = QueryIntent.ANOMALY_CANDIDATE) -> ExabeamQuery:
    return ExabeamQuery(
        query_id="Q-test",
        intent=intent,
        description="test",
        query_text="SecurityEvent | where EventID == 4625 | limit 100",
        time_range="last 30 days",
        expected_signal="Failed logon events",
    )


class TestMockSentinelAdapter:
    def test_returns_success_status(self) -> None:
        adapter = MockSentinelAdapter()
        result = adapter.execute_query(_make_query())
        assert result.status == "success"

    def test_returns_events(self) -> None:
        adapter = MockSentinelAdapter()
        result = adapter.execute_query(_make_query())
        assert result.result_count > 0
        assert len(result.events) == result.result_count

    def test_events_have_required_fields(self) -> None:
        adapter = MockSentinelAdapter()
        result = adapter.execute_query(_make_query())
        for event in result.events:
            assert event.timestamp
            assert event.event_type

    def test_baseline_returns_more_results(self) -> None:
        adapter = MockSentinelAdapter()
        # Run multiple times and check baseline tends to return more
        baseline_counts = [
            adapter.execute_query(_make_query(QueryIntent.BASELINE)).result_count
            for _ in range(5)
        ]
        confirm_counts = [
            adapter.execute_query(_make_query(QueryIntent.CONFIRMATION)).result_count
            for _ in range(5)
        ]
        # Baseline average should generally be higher than confirmation
        assert sum(baseline_counts) >= sum(confirm_counts)

    def test_connection_test(self) -> None:
        assert MockSentinelAdapter().test_connection() is True

    def test_adapter_name(self) -> None:
        assert MockSentinelAdapter().get_adapter_name() == "MockSentinelAdapter"

    def test_metadata_indicates_sentinel(self) -> None:
        adapter = MockSentinelAdapter()
        result = adapter.execute_query(_make_query())
        assert result.metadata.get("adapter") == "mock_sentinel"
