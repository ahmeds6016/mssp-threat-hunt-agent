"""Tests for mock threat-intel enrichment."""

from __future__ import annotations

import tempfile
from pathlib import Path

from mssp_hunt_agent.adapters.intel.cache import CachedIntelAdapter
from mssp_hunt_agent.adapters.intel.mock import MockThreatIntelAdapter


class TestMockThreatIntel:
    def test_enrich_ip(self) -> None:
        adapter = MockThreatIntelAdapter()
        record = adapter.enrich_ip("198.51.100.12")
        assert record.entity_type == "ip"
        assert record.entity_value == "198.51.100.12"
        assert record.source == "MockTI"
        assert record.verdict in ("malicious", "suspicious", "benign", "unknown")
        assert 0.0 <= record.confidence <= 1.0

    def test_enrich_domain(self) -> None:
        record = MockThreatIntelAdapter().enrich_domain("evil.example.com")
        assert record.entity_type == "domain"

    def test_enrich_hash(self) -> None:
        record = MockThreatIntelAdapter().enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert record.entity_type == "hash"

    def test_enrich_user_agent(self) -> None:
        record = MockThreatIntelAdapter().enrich_user_agent("python-requests/2.31.0")
        assert record.entity_type == "user_agent"

    def test_deterministic_results(self) -> None:
        """Same input should always produce the same verdict."""
        adapter = MockThreatIntelAdapter()
        r1 = adapter.enrich_ip("10.0.0.1")
        r2 = adapter.enrich_ip("10.0.0.1")
        assert r1.verdict == r2.verdict
        assert r1.confidence == r2.confidence

    def test_provider_name(self) -> None:
        assert MockThreatIntelAdapter().get_provider_name() == "MockThreatIntelAdapter"


class TestCachedIntelAdapter:
    def test_caches_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inner = MockThreatIntelAdapter()
            cached = CachedIntelAdapter(inner, Path(tmpdir))

            r1 = cached.enrich_ip("1.2.3.4")
            assert r1.cached is False

            r2 = cached.enrich_ip("1.2.3.4")
            assert r2.cached is True
            assert r1.verdict == r2.verdict

    def test_provider_name_wraps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cached = CachedIntelAdapter(MockThreatIntelAdapter(), Path(tmpdir))
            assert "Cached" in cached.get_provider_name()
