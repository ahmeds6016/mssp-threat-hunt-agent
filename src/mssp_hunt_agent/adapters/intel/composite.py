"""Composite threat-intel adapter — aggregates verdicts from multiple providers."""

from __future__ import annotations

import logging
from typing import Callable

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import EnrichmentRecord

logger = logging.getLogger(__name__)

# Verdict precedence for aggregation (higher = more concerning)
_VERDICT_RANK = {
    "malicious": 4,
    "suspicious": 3,
    "unknown": 2,
    "benign": 1,
}


def _pick_best(records: list[EnrichmentRecord]) -> EnrichmentRecord:
    """Select the highest-confidence, most-concerning verdict from multiple providers."""
    if not records:
        raise ValueError("Cannot pick from empty list")
    if len(records) == 1:
        return records[0]

    # Sort by verdict severity first, then confidence
    ranked = sorted(
        records,
        key=lambda r: (_VERDICT_RANK.get(r.verdict, 0), r.confidence),
        reverse=True,
    )
    best = ranked[0]

    # Merge labels and sources
    all_labels = []
    sources = []
    for r in records:
        all_labels.extend(r.labels)
        sources.append(r.source)

    return EnrichmentRecord(
        entity_type=best.entity_type,
        entity_value=best.entity_value,
        source=f"Composite({', '.join(sources)})",
        verdict=best.verdict,
        confidence=best.confidence,
        labels=sorted(set(all_labels)),
        context=f"Best verdict from {best.source}. All providers: {', '.join(sources)}",
        raw_reference=best.raw_reference,
    )


class CompositeIntelAdapter(ThreatIntelAdapter):
    """Queries multiple TI providers and returns the highest-confidence verdict."""

    def __init__(self, providers: list[ThreatIntelAdapter]) -> None:
        if not providers:
            raise ValueError("CompositeIntelAdapter requires at least one provider")
        self._providers = providers

    def enrich_ip(self, ip: str) -> EnrichmentRecord:
        return self._aggregate("enrich_ip", ip, "ip")

    def enrich_domain(self, domain: str) -> EnrichmentRecord:
        return self._aggregate("enrich_domain", domain, "domain")

    def enrich_hash(self, file_hash: str) -> EnrichmentRecord:
        return self._aggregate("enrich_hash", file_hash, "hash")

    def enrich_user_agent(self, ua: str) -> EnrichmentRecord:
        return self._aggregate("enrich_user_agent", ua, "user_agent")

    def get_provider_name(self) -> str:
        names = [p.get_provider_name() for p in self._providers]
        return f"Composite({', '.join(names)})"

    def _aggregate(self, method_name: str, value: str, entity_type: str) -> EnrichmentRecord:
        records: list[EnrichmentRecord] = []
        for provider in self._providers:
            fn: Callable = getattr(provider, method_name)
            try:
                records.append(fn(value))
            except Exception as exc:
                logger.warning(
                    "%s.%s(%s) failed: %s",
                    provider.get_provider_name(), method_name, value, exc,
                )
        if not records:
            return EnrichmentRecord(
                entity_type=entity_type,
                entity_value=value,
                source=self.get_provider_name(),
                verdict="unknown",
                confidence=0.0,
                context="All providers failed",
            )
        return _pick_best(records)
