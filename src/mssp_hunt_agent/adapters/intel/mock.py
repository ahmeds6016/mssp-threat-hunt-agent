"""Mock threat‑intel adapter returning plausible enrichment data."""

from __future__ import annotations

import hashlib

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import EnrichmentRecord

# Deterministic verdict lookup keyed on entity value hash parity
# so the same entity always returns the same verdict within a session.


def _deterministic_verdict(value: str) -> tuple[str, float, list[str]]:
    """Return (verdict, confidence, labels) deterministically based on value hash."""
    h = int(hashlib.md5(value.encode()).hexdigest(), 16)
    bucket = h % 10
    if bucket < 2:
        return "malicious", 0.85, ["known-bad", "c2-infra"]
    if bucket < 4:
        return "suspicious", 0.55, ["tor-exit", "proxy"]
    if bucket < 7:
        return "benign", 0.90, ["cdn", "corporate"]
    return "unknown", 0.20, []


class MockThreatIntelAdapter(ThreatIntelAdapter):
    """Returns deterministic but realistic enrichment without any API calls."""

    def enrich_ip(self, ip: str) -> EnrichmentRecord:
        verdict, confidence, labels = _deterministic_verdict(ip)
        return EnrichmentRecord(
            entity_type="ip",
            entity_value=ip,
            source="MockTI",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=f"Mock enrichment for IP {ip}",
            raw_reference=f"https://mock-ti.example.com/ip/{ip}",
        )

    def enrich_domain(self, domain: str) -> EnrichmentRecord:
        verdict, confidence, labels = _deterministic_verdict(domain)
        return EnrichmentRecord(
            entity_type="domain",
            entity_value=domain,
            source="MockTI",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=f"Mock enrichment for domain {domain}",
            raw_reference=f"https://mock-ti.example.com/domain/{domain}",
        )

    def enrich_hash(self, file_hash: str) -> EnrichmentRecord:
        verdict, confidence, labels = _deterministic_verdict(file_hash)
        return EnrichmentRecord(
            entity_type="hash",
            entity_value=file_hash,
            source="MockTI",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=f"Mock enrichment for hash {file_hash}",
            raw_reference=f"https://mock-ti.example.com/hash/{file_hash}",
        )

    def enrich_user_agent(self, ua: str) -> EnrichmentRecord:
        verdict, confidence, labels = _deterministic_verdict(ua)
        return EnrichmentRecord(
            entity_type="user_agent",
            entity_value=ua,
            source="MockTI",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=f"Mock enrichment for user-agent string",
        )

    def get_provider_name(self) -> str:
        return "MockThreatIntelAdapter"
