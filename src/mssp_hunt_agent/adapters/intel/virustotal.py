"""VirusTotal v3 threat-intel adapter."""

from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import EnrichmentRecord

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    """Non-retryable VT error."""


class VirusTotalTransient(Exception):
    """Retryable VT error (429 / 5xx)."""


def _verdict_from_stats(stats: dict) -> tuple[str, float, list[str]]:
    """Derive (verdict, confidence, labels) from VT last_analysis_stats."""
    if not stats:
        return "unknown", 0.2, []

    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    ratio = (mal + sus) / total

    labels: list[str] = []
    if mal:
        labels.append("malicious-detections")
    if sus:
        labels.append("suspicious-detections")

    if ratio >= 0.30:
        return "malicious", min(ratio + 0.2, 1.0), labels
    if ratio >= 0.10:
        return "suspicious", ratio + 0.1, labels
    if ratio == 0:
        return "benign", 0.85, ["clean"]
    return "unknown", 0.2, []


class VirusTotalAdapter(ThreatIntelAdapter):
    """Enriches IPs, domains, and file hashes via the VirusTotal v3 API."""

    def __init__(self, api_key: str, *, timeout: float = 15.0) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._client = httpx.Client(timeout=self._timeout)

    def close(self) -> None:
        self._client.close()

    # ── Interface ────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> EnrichmentRecord:
        return self._lookup("ip", f"/ip_addresses/{ip}", ip)

    def enrich_domain(self, domain: str) -> EnrichmentRecord:
        return self._lookup("domain", f"/domains/{domain}", domain)

    def enrich_hash(self, file_hash: str) -> EnrichmentRecord:
        return self._lookup("hash", f"/files/{file_hash}", file_hash)

    def enrich_user_agent(self, ua: str) -> EnrichmentRecord:
        return EnrichmentRecord(
            entity_type="user_agent",
            entity_value=ua,
            source="VirusTotal",
            verdict="unknown",
            confidence=0.0,
            context="VirusTotal does not support user-agent lookups",
        )

    def get_provider_name(self) -> str:
        return "VirusTotal"

    # ── Internal ─────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(VirusTotalTransient),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def _request(self, path: str) -> dict:
        resp = self._client.get(
            f"{_BASE}{path}",
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        if resp.status_code == 429 or resp.status_code >= 500:
            raise VirusTotalTransient(f"VT {resp.status_code}")
        if resp.status_code == 404:
            return {}
        if resp.status_code >= 400:
            raise VirusTotalError(f"VT error {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def _lookup(self, entity_type: str, path: str, value: str) -> EnrichmentRecord:
        try:
            data = self._request(path)
        except (VirusTotalError, VirusTotalTransient) as exc:
            logger.warning("VT lookup failed for %s %s: %s", entity_type, value, exc)
            return EnrichmentRecord(
                entity_type=entity_type,
                entity_value=value,
                source="VirusTotal",
                verdict="unknown",
                confidence=0.0,
                context=f"Lookup error: {exc}",
            )

        if not data:
            return EnrichmentRecord(
                entity_type=entity_type,
                entity_value=value,
                source="VirusTotal",
                verdict="unknown",
                confidence=0.1,
                context="Not found in VirusTotal",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        verdict, confidence, labels = _verdict_from_stats(stats)

        return EnrichmentRecord(
            entity_type=entity_type,
            entity_value=value,
            source="VirusTotal",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=f"VT stats: {stats}",
            raw_reference=f"https://www.virustotal.com/gui/search/{value}",
        )
