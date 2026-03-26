"""Tests for the composite threat-intel adapter."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.adapters.intel.composite import CompositeIntelAdapter, _pick_best
from mssp_hunt_agent.models.result_models import EnrichmentRecord


def _make_record(
    verdict: str = "benign",
    confidence: float = 0.5,
    source: str = "TestProvider",
    **kwargs,
) -> EnrichmentRecord:
    defaults = {
        "entity_type": "ip",
        "entity_value": "1.2.3.4",
        "source": source,
        "verdict": verdict,
        "confidence": confidence,
    }
    defaults.update(kwargs)
    return EnrichmentRecord(**defaults)


class TestPickBest:
    def test_single_record(self) -> None:
        r = _make_record(verdict="malicious", confidence=0.9)
        assert _pick_best([r]).verdict == "malicious"

    def test_malicious_beats_benign(self) -> None:
        r1 = _make_record(verdict="benign", confidence=0.9, source="A")
        r2 = _make_record(verdict="malicious", confidence=0.7, source="B")
        best = _pick_best([r1, r2])
        assert best.verdict == "malicious"
        assert "Composite" in best.source

    def test_suspicious_beats_unknown(self) -> None:
        r1 = _make_record(verdict="unknown", confidence=0.2, source="A")
        r2 = _make_record(verdict="suspicious", confidence=0.5, source="B")
        best = _pick_best([r1, r2])
        assert best.verdict == "suspicious"

    def test_higher_confidence_wins_same_verdict(self) -> None:
        r1 = _make_record(verdict="malicious", confidence=0.7, source="A")
        r2 = _make_record(verdict="malicious", confidence=0.95, source="B")
        best = _pick_best([r1, r2])
        assert best.confidence == 0.95

    def test_labels_merged(self) -> None:
        r1 = _make_record(source="A", labels=["c2-infra"])
        r2 = _make_record(source="B", labels=["tor-exit"])
        best = _pick_best([r1, r2])
        assert "c2-infra" in best.labels
        assert "tor-exit" in best.labels

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            _pick_best([])


class TestCompositeIntelAdapter:
    def test_requires_at_least_one_provider(self) -> None:
        with pytest.raises(ValueError):
            CompositeIntelAdapter([])

    def test_aggregates_ip_verdicts(self) -> None:
        p1 = MagicMock(spec=ThreatIntelAdapter)
        p1.enrich_ip.return_value = _make_record(verdict="benign", confidence=0.9, source="P1")
        p1.get_provider_name.return_value = "P1"

        p2 = MagicMock(spec=ThreatIntelAdapter)
        p2.enrich_ip.return_value = _make_record(verdict="malicious", confidence=0.85, source="P2")
        p2.get_provider_name.return_value = "P2"

        comp = CompositeIntelAdapter([p1, p2])
        result = comp.enrich_ip("1.2.3.4")

        assert result.verdict == "malicious"
        assert "Composite" in result.source

    def test_partial_failure(self) -> None:
        p1 = MagicMock(spec=ThreatIntelAdapter)
        p1.enrich_ip.side_effect = RuntimeError("API down")
        p1.get_provider_name.return_value = "Broken"

        p2 = MagicMock(spec=ThreatIntelAdapter)
        p2.enrich_ip.return_value = _make_record(verdict="suspicious", confidence=0.6, source="Working")
        p2.get_provider_name.return_value = "Working"

        comp = CompositeIntelAdapter([p1, p2])
        result = comp.enrich_ip("1.2.3.4")

        assert result.verdict == "suspicious"

    def test_all_providers_fail(self) -> None:
        p1 = MagicMock(spec=ThreatIntelAdapter)
        p1.enrich_ip.side_effect = RuntimeError("fail")
        p1.get_provider_name.return_value = "A"

        comp = CompositeIntelAdapter([p1])
        result = comp.enrich_ip("1.2.3.4")

        assert result.verdict == "unknown"
        assert "All providers failed" in result.context

    def test_domain_enrichment(self) -> None:
        p1 = MagicMock(spec=ThreatIntelAdapter)
        p1.enrich_domain.return_value = _make_record(
            entity_type="domain", entity_value="evil.com",
            verdict="malicious", confidence=0.8, source="P1",
        )
        p1.get_provider_name.return_value = "P1"

        comp = CompositeIntelAdapter([p1])
        result = comp.enrich_domain("evil.com")

        assert result.verdict == "malicious"

    def test_provider_name(self) -> None:
        p1 = MagicMock(spec=ThreatIntelAdapter)
        p1.get_provider_name.return_value = "VT"
        p2 = MagicMock(spec=ThreatIntelAdapter)
        p2.get_provider_name.return_value = "AIPDB"

        comp = CompositeIntelAdapter([p1, p2])
        assert "VT" in comp.get_provider_name()
        assert "AIPDB" in comp.get_provider_name()
