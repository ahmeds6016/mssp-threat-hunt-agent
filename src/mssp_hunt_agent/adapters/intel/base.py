"""Abstract base class for threat‑intel enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mssp_hunt_agent.models.result_models import EnrichmentRecord


class ThreatIntelAdapter(ABC):
    """Contract that every TI provider must implement."""

    @abstractmethod
    def enrich_ip(self, ip: str) -> EnrichmentRecord: ...

    @abstractmethod
    def enrich_domain(self, domain: str) -> EnrichmentRecord: ...

    @abstractmethod
    def enrich_hash(self, file_hash: str) -> EnrichmentRecord: ...

    @abstractmethod
    def enrich_user_agent(self, ua: str) -> EnrichmentRecord: ...

    @abstractmethod
    def get_provider_name(self) -> str: ...
