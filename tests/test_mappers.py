"""Tests for Exabeam API → model event mapping and query text parsing."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.adapters.exabeam.mappers import (
    DEFAULT_FIELDS,
    SearchParams,
    map_event_response,
    parse_query_text,
)
from mssp_hunt_agent.models.result_models import ExabeamEvent


# ── map_event_response ───────────────────────────────────────────────


class TestMapEventResponse:
    def test_complete_event(self) -> None:
        raw = {
            "timestamp": "2024-11-15T10:30:00Z",
            "eventType": "authentication-success",
            "user": "jsmith",
            "sourceIp": "10.10.5.22",
            "destinationIp": "10.0.0.1",
            "host": "SRV-DC01",
            "domain": "corp.local",
            "rawLog": "raw syslog line",
            "riskScore": 42,
        }
        ev = map_event_response(raw)

        assert isinstance(ev, ExabeamEvent)
        assert ev.timestamp == "2024-11-15T10:30:00Z"
        assert ev.event_type == "authentication-success"
        assert ev.user == "jsmith"
        assert ev.src_ip == "10.10.5.22"
        assert ev.dst_ip == "10.0.0.1"
        assert ev.hostname == "SRV-DC01"
        assert ev.domain == "corp.local"
        assert ev.raw_log == "raw syslog line"
        assert ev.fields["riskScore"] == 42

    def test_sparse_event(self) -> None:
        raw = {"timestamp": "2024-11-15T10:30:00Z", "eventType": "generic"}
        ev = map_event_response(raw)

        assert ev.timestamp == "2024-11-15T10:30:00Z"
        assert ev.event_type == "generic"
        assert ev.user is None
        assert ev.src_ip is None

    def test_unknown_fields_go_to_extras(self) -> None:
        raw = {
            "timestamp": "2024-11-15T10:30:00Z",
            "eventType": "test",
            "customField": "hello",
            "anotherOne": 99,
        }
        ev = map_event_response(raw)
        assert ev.fields["customField"] == "hello"
        assert ev.fields["anotherOne"] == 99

    def test_missing_timestamp_defaults(self) -> None:
        raw = {"eventType": "no-timestamp"}
        ev = map_event_response(raw)
        assert ev.timestamp == ""

    def test_missing_event_type_defaults(self) -> None:
        raw = {"timestamp": "2024-01-01T00:00:00Z"}
        ev = map_event_response(raw)
        assert ev.event_type == "unknown"

    def test_snake_case_fields(self) -> None:
        """API sometimes returns snake_case instead of camelCase."""
        raw = {
            "timestamp": "2024-01-01",
            "event_type": "logon",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "process_name": "cmd.exe",
        }
        ev = map_event_response(raw)
        assert ev.event_type == "logon"
        assert ev.src_ip == "1.2.3.4"
        assert ev.dst_ip == "5.6.7.8"
        assert ev.process_name == "cmd.exe"

    def test_extra_fields_preserved(self) -> None:
        raw = {
            "timestamp": "2024-01-01",
            "eventType": "test",
            "severity": "high",
            "category": "auth",
        }
        ev = map_event_response(raw)
        assert ev.fields["severity"] == "high"
        assert ev.fields["category"] == "auth"


# ── parse_query_text ─────────────────────────────────────────────────


class TestParseQueryText:
    def test_simple_filter(self) -> None:
        params = parse_query_text('src_ip = "10.0.0.1" AND event_type = "authentication"')
        assert 'src_ip = "10.0.0.1"' in params.filter
        assert 'event_type = "authentication"' in params.filter
        assert params.fields == list(DEFAULT_FIELDS)

    def test_fields_clause(self) -> None:
        params = parse_query_text('user = "admin" | fields user, src_ip, timestamp')
        assert "user" in params.fields
        assert "src_ip" in params.fields
        assert "timestamp" in params.fields
        assert 'user = "admin"' in params.filter

    def test_sort_clause(self) -> None:
        params = parse_query_text('eventType = "auth" | sort timestamp DESC')
        assert any("timestamp" in o for o in params.order_by)
        assert 'eventType = "auth"' in params.filter

    def test_limit_clause(self) -> None:
        params = parse_query_text('src_ip = "1.2.3.4" | head 500')
        assert params.limit == 500

    def test_stats_clause(self) -> None:
        params = parse_query_text('event_type = "auth" | stats user, src_ip')
        assert "user" in params.group_by
        assert "src_ip" in params.group_by

    def test_distinct_clause(self) -> None:
        params = parse_query_text('user = "jsmith" | dedup')
        assert params.distinct is True

    def test_no_clauses(self) -> None:
        params = parse_query_text('src_ip = "10.0.0.1"')
        assert params.filter == 'src_ip = "10.0.0.1"'
        assert params.fields == list(DEFAULT_FIELDS)
        assert params.group_by == []
        assert params.order_by == []
        assert params.limit is None
        assert params.distinct is False

    def test_combined_clauses(self) -> None:
        query = 'user = "admin" | fields user, host | sort timestamp DESC | head 100 | dedup'
        params = parse_query_text(query)
        assert 'user = "admin"' in params.filter
        assert "user" in params.fields
        assert "host" in params.fields
        assert params.limit == 100
        assert params.distinct is True
