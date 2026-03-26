"""Tests for query safety guardrails."""

from __future__ import annotations

from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent
from mssp_hunt_agent.pipeline.query_safety import check_query, has_errors


def _make_query(text: str, time_range: str = "2024-01-01 to 2024-01-31") -> ExabeamQuery:
    return ExabeamQuery(
        query_id="Q-test",
        intent=QueryIntent.ANOMALY_CANDIDATE,
        description="test query",
        query_text=text,
        time_range=time_range,
        expected_signal="test",
    )


class TestQuerySafety:
    def test_clean_query_passes(self) -> None:
        q = _make_query(
            'activity_type = "auth" AND tenant = "test" '
            '| where time >= "2024-01-01" | head 100'
        )
        flags = check_query(q)
        assert not has_errors(flags)

    def test_no_time_range_flagged_as_error(self) -> None:
        q = _make_query('activity_type = "auth" | head 100', time_range="")
        flags = check_query(q)
        time_flags = [f for f in flags if f.rule == "no_time_range"]
        assert len(time_flags) == 1
        assert time_flags[0].severity == "error"

    def test_free_text_only_flagged(self) -> None:
        q = _make_query('suspicious login activity | where time >= "2024-01-01" | head 100')
        flags = check_query(q)
        rules = {f.rule for f in flags}
        assert "free_text_only" in rules

    def test_broad_wildcard_flagged(self) -> None:
        q = _make_query('activity_type = "*" | where time >= "2024-01-01" | head 100')
        flags = check_query(q)
        rules = {f.rule for f in flags}
        assert "broad_wildcard" in rules

    def test_no_limit_flagged(self) -> None:
        q = _make_query('activity_type = "auth" | where time >= "2024-01-01"')
        flags = check_query(q)
        rules = {f.rule for f in flags}
        assert "no_result_limit" in rules

    def test_no_client_scope_flagged(self) -> None:
        q = _make_query('activity_type = "auth" | where time >= "2024-01-01" | head 100')
        flags = check_query(q)
        rules = {f.rule for f in flags}
        assert "no_client_scope" in rules

    def test_has_errors_util(self) -> None:
        q = _make_query('just some text', time_range="")
        flags = check_query(q)
        assert has_errors(flags)
