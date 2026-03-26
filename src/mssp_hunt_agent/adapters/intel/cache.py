"""File‑backed enrichment cache that wraps any ThreatIntelAdapter."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import EnrichmentRecord


def _cache_key(entity_type: str, value: str) -> str:
    h = hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()[:16]
    return f"{entity_type}_{h}.json"


class CachedIntelAdapter(ThreatIntelAdapter):
    """Transparent file cache in front of any real or mock TI provider."""

    def __init__(self, inner: ThreatIntelAdapter, cache_dir: Path) -> None:
        self._inner = inner
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    # ── helpers ───────────────────────────────────────────────────────

    def _read_cache(self, entity_type: str, value: str) -> EnrichmentRecord | None:
        path = self._cache_dir / _cache_key(entity_type, value)
        if path.exists():
            data = json.loads(path.read_text())
            record = EnrichmentRecord(**data)
            record.cached = True
            return record
        return None

    def _write_cache(self, record: EnrichmentRecord) -> None:
        path = self._cache_dir / _cache_key(record.entity_type, record.entity_value)
        path.write_text(record.model_dump_json(indent=2))

    def _enrich(
        self,
        entity_type: str,
        value: str,
        enricher: callable,
    ) -> EnrichmentRecord:
        cached = self._read_cache(entity_type, value)
        if cached is not None:
            return cached
        result = enricher(value)
        self._write_cache(result)
        return result

    # ── interface ─────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> EnrichmentRecord:
        return self._enrich("ip", ip, self._inner.enrich_ip)

    def enrich_domain(self, domain: str) -> EnrichmentRecord:
        return self._enrich("domain", domain, self._inner.enrich_domain)

    def enrich_hash(self, file_hash: str) -> EnrichmentRecord:
        return self._enrich("hash", file_hash, self._inner.enrich_hash)

    def enrich_user_agent(self, ua: str) -> EnrichmentRecord:
        return self._enrich("user_agent", ua, self._inner.enrich_user_agent)

    def get_provider_name(self) -> str:
        return f"Cached({self._inner.get_provider_name()})"
