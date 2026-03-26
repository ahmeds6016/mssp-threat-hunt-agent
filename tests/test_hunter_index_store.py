"""Tests for V7 IndexStore — JSON persistence and refresh logic."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from mssp_hunt_agent.hunter.index_store import IndexStore
from mssp_hunt_agent.hunter.models.environment import (
    EnvironmentIndex,
    IndexMetadata,
    TelemetryIndex,
    TableProfile,
    IdentityIndex,
)


@pytest.fixture
def store(tmp_path: Path) -> IndexStore:
    return IndexStore(base_dir=str(tmp_path))


@pytest.fixture
def sample_index() -> EnvironmentIndex:
    return EnvironmentIndex(
        metadata=IndexMetadata(
            client_id="acme-corp",
            workspace_id="ws-456",
            index_version=2,
            total_tables=5,
            static_refreshed_at=datetime.now(timezone.utc).isoformat(),
            semi_static_refreshed_at=datetime.now(timezone.utc).isoformat(),
            dynamic_refreshed_at=datetime.now(timezone.utc).isoformat(),
        ),
        telemetry=TelemetryIndex(
            tables=[
                TableProfile(table_name="SigninLogs", row_count_7d=1000),
                TableProfile(table_name="SecurityEvent", row_count_7d=5000),
            ],
        ),
        identity=IdentityIndex(total_users=25, admin_count=3),
    )


class TestIndexStore:
    def test_save_and_load(self, store: IndexStore, sample_index: EnvironmentIndex):
        path = store.save(sample_index)
        assert Path(path).exists()

        loaded = store.load("acme-corp")
        assert loaded is not None
        assert loaded.metadata.client_id == "acme-corp"
        assert loaded.metadata.index_version == 2
        assert len(loaded.telemetry.tables) == 2

    def test_load_nonexistent(self, store: IndexStore):
        assert store.load("nonexistent") is None

    def test_exists(self, store: IndexStore, sample_index: EnvironmentIndex):
        assert store.exists("acme-corp") is False
        store.save(sample_index)
        assert store.exists("acme-corp") is True

    def test_delete(self, store: IndexStore, sample_index: EnvironmentIndex):
        store.save(sample_index)
        assert store.delete("acme-corp") is True
        assert store.exists("acme-corp") is False

    def test_delete_nonexistent(self, store: IndexStore):
        assert store.delete("nonexistent") is False

    def test_list_clients(self, store: IndexStore, sample_index: EnvironmentIndex):
        assert store.list_clients() == []
        store.save(sample_index)
        assert "acme-corp" in store.list_clients()

    def test_list_clients_multiple(self, store: IndexStore, sample_index: EnvironmentIndex):
        store.save(sample_index)
        # Save another with different client_id
        idx2 = sample_index.model_copy(deep=True)
        idx2.metadata.client_id = "beta-inc"
        store.save(idx2)
        clients = store.list_clients()
        assert len(clients) == 2
        assert "acme-corp" in clients
        assert "beta-inc" in clients

    def test_needs_refresh_no_index(self, store: IndexStore):
        assert store.needs_refresh("nonexistent", "static", max_age_hours=24) is True

    def test_needs_refresh_fresh(self, store: IndexStore, sample_index: EnvironmentIndex):
        store.save(sample_index)
        assert store.needs_refresh("acme-corp", "static", max_age_hours=24) is False
        assert store.needs_refresh("acme-corp", "semi_static", max_age_hours=168) is False
        assert store.needs_refresh("acme-corp", "dynamic", max_age_hours=1) is False

    def test_needs_refresh_stale(self, store: IndexStore, sample_index: EnvironmentIndex):
        # Set refreshed_at to 2 days ago
        old_time = (datetime.now(timezone.utc) - timedelta(hours=49)).isoformat()
        sample_index.metadata.dynamic_refreshed_at = old_time
        store.save(sample_index)
        assert store.needs_refresh("acme-corp", "dynamic", max_age_hours=1) is True

    def test_needs_refresh_empty_timestamp(self, store: IndexStore, sample_index: EnvironmentIndex):
        sample_index.metadata.static_refreshed_at = ""
        store.save(sample_index)
        assert store.needs_refresh("acme-corp", "static", max_age_hours=720) is True

    def test_load_corrupted_file(self, store: IndexStore):
        # Write invalid JSON
        path = Path(store._base) / "bad-client.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        assert store.load("bad-client") is None

    def test_save_overwrite(self, store: IndexStore, sample_index: EnvironmentIndex):
        store.save(sample_index)
        sample_index.metadata.index_version = 3
        store.save(sample_index)
        loaded = store.load("acme-corp")
        assert loaded.metadata.index_version == 3


# ── IndexBuilder fallback tests ──────────────────────────────────

class TestIndexBuilderFallback:
    """Test that IndexBuilder falls back when Usage table returns 0 rows."""

    def test_discover_tables_fallback_to_search(self):
        """When Usage returns 0 rows, fallback to search * by Type."""
        from unittest.mock import MagicMock, call
        from mssp_hunt_agent.hunter.index_builder import IndexBuilder
        from mssp_hunt_agent.models.result_models import QueryResult, ExabeamEvent

        adapter = MagicMock()

        # First call (Usage) returns empty, second call (search *) returns tables
        def side_effect(query):
            if "Usage" in query.query_text:
                return QueryResult(query_id="q1", query_text="", status="success", result_count=0)
            if "search *" in query.query_text:
                events = [
                    ExabeamEvent(timestamp="", event_type="", fields={"Type": "SigninLogs", "Count": "100"}),
                    ExabeamEvent(timestamp="", event_type="", fields={"Type": "AuditLogs", "Count": "50"}),
                ]
                return QueryResult(query_id="q2", query_text="", status="success",
                                   result_count=2, events=events)
            return QueryResult(query_id="q3", query_text="", status="success", result_count=0)

        adapter.execute_query.side_effect = side_effect

        builder = IndexBuilder(adapter=adapter, client_id="test")
        index = EnvironmentIndex(metadata=IndexMetadata(client_id="test"))
        builder._discover_tables(index)

        assert len(index.telemetry.tables) == 2
        names = [t.table_name for t in index.telemetry.tables]
        assert "SigninLogs" in names
        assert "AuditLogs" in names

    def test_discover_tables_fallback_to_wellknown(self):
        """When both Usage and union fail, use well-known table list."""
        from unittest.mock import MagicMock
        from mssp_hunt_agent.hunter.index_builder import IndexBuilder
        from mssp_hunt_agent.models.result_models import QueryResult

        adapter = MagicMock()
        adapter.execute_query.return_value = QueryResult(
            query_id="q1", query_text="", status="success", result_count=0,
        )

        builder = IndexBuilder(adapter=adapter, client_id="test")
        index = EnvironmentIndex(metadata=IndexMetadata(client_id="test"))
        builder._discover_tables(index)

        assert len(index.telemetry.tables) >= 15  # well-known list
        names = [t.table_name for t in index.telemetry.tables]
        assert "SigninLogs" in names
        assert "SecurityEvent" in names
