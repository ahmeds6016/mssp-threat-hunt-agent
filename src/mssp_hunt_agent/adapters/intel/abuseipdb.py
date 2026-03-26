"""AbuseIPDB threat-intel adapter — IP reputation lookups."""

from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import EnrichmentRecord

logger = logging.getLogger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBError(Exception):
    """Non-retryable error."""


class AbuseIPDBTransient(Exception):
    """Retryable (429 / 5xx) error."""


def _verdict_from_score(score: int) -> tuple[str, float, list[str]]:
    """Map abuseConfidenceScore (0-100) to (verdict, confidence, labels)."""
    if score >= 80:
        return "malicious", score / 100.0, ["high-abuse-score"]
    if score >= 40:
        return "suspicious", score / 100.0, ["moderate-abuse-score"]
    if score > 0:
        return "suspicious", score / 100.0, ["low-abuse-score"]
    return "benign", 0.85, ["clean"]


class AbuseIPDBAdapter(ThreatIntelAdapter):
    """Enriches IP addresses via the AbuseIPDB v2 API."""

    def __init__(self, api_key: str, *, timeout: float = 15.0) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._client = httpx.Client(timeout=self._timeout)

    def close(self) -> None:
        self._client.close()

    # ── Interface ────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> EnrichmentRecord:
        return self._check_ip(ip)

    def enrich_domain(self, domain: str) -> EnrichmentRecord:
        return EnrichmentRecord(
            entity_type="domain",
            entity_value=domain,
            source="AbuseIPDB",
            verdict="unknown",
            confidence=0.0,
            context="AbuseIPDB only supports IP lookups",
        )

    def enrich_hash(self, file_hash: str) -> EnrichmentRecord:
        return EnrichmentRecord(
            entity_type="hash",
            entity_value=file_hash,
            source="AbuseIPDB",
            verdict="unknown",
            confidence=0.0,
            context="AbuseIPDB only supports IP lookups",
        )

    def enrich_user_agent(self, ua: str) -> EnrichmentRecord:
        return EnrichmentRecord(
            entity_type="user_agent",
            entity_value=ua,
            source="AbuseIPDB",
            verdict="unknown",
            confidence=0.0,
            context="AbuseIPDB only supports IP lookups",
        )

    def get_provider_name(self) -> str:
        return "AbuseIPDB"

    # ── Internal ─────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(AbuseIPDBTransient),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def _request(self, ip: str) -> dict:
        resp = self._client.get(
            f"{_BASE}/check",
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
        )
        if resp.status_code == 429 or resp.status_code >= 500:
            raise AbuseIPDBTransient(f"AbuseIPDB {resp.status_code}")
        if resp.status_code >= 400:
            raise AbuseIPDBError(f"AbuseIPDB error {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def _check_ip(self, ip: str) -> EnrichmentRecord:
        try:
            data = self._request(ip)
        except (AbuseIPDBError, AbuseIPDBTransient) as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return EnrichmentRecord(
                entity_type="ip",
                entity_value=ip,
                source="AbuseIPDB",
                verdict="unknown",
                confidence=0.0,
                context=f"Lookup error: {exc}",
            )

        entry = data.get("data", {})
        score = int(entry.get("abuseConfidenceScore", 0))
        verdict, confidence, labels = _verdict_from_score(score)

        country = entry.get("countryCode", "")
        isp = entry.get("isp", "")
        total_reports = entry.get("totalReports", 0)

        return EnrichmentRecord(
            entity_type="ip",
            entity_value=ip,
            source="AbuseIPDB",
            verdict=verdict,
            confidence=confidence,
            labels=labels,
            context=(
                f"AbuseIPDB score={score}, reports={total_reports}, "
                f"country={country}, isp={isp}"
            ),
            raw_reference=f"https://www.abuseipdb.com/check/{ip}",
        )
