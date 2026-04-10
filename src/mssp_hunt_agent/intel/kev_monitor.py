"""CISA KEV catalog monitor — proactive vulnerability exposure detection.

Watches the CISA Known Exploited Vulnerabilities (KEV) catalog for new entries
and turns each new CVE into an actionable hunt against the tenant. Built on the
same pattern as ``feed_monitor.py``: stateful dedup against blob storage so a
poll only emits genuinely new entries, and the catalog is the source of truth
(no LLM correlation needed — CISA already curates and confirms exploitation).

The catalog is fetched from:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Each new entry becomes a ``KEVAlert`` which carries enough context for the
``KEVPipeline`` to enrich it (CVE detail + EPSS), match it against tenant
software/processes, run an IOC sweep over the inferred Sentinel tables, and
generate an executive report.

Why this is separate from the threat-intel ``FeedMonitor``:

* The KEV catalog is a single JSON document, not an RSS/Atom feed. The
  parser is trivial — we already have ``parse_kev_catalog`` in
  ``intel/cisa_kev.py`` and just wrap it with persistence + dedup here.
* KEV entries are inherently relevant: every one is a CVE that is *actively
  being exploited in the wild*. We skip the GPT-5.3 relevance scoring stage
  the threat-intel pipeline does and go straight to environment matching.
* Different blob namespace (``kev-feeds/``) keeps the audit trail isolated
  from the threat-intel pipeline so the two never collide on dedup state.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from mssp_hunt_agent.intel.cisa_kev import infer_detection_sources, parse_kev_catalog
from mssp_hunt_agent.intel.landscape_models import KEVEntry

logger = logging.getLogger(__name__)


KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cap the dedup state at this many CVE IDs. The KEV catalog is bounded
# (~1200 entries as of 2026) so this will never trim, but the cap prevents
# pathological growth if CISA ever republishes IDs.
_MAX_SEEN_IDS = 5000

# How long to wait for the catalog HTTP request.
_FETCH_TIMEOUT_SECONDS = 30


# ── Data Models ───────────────────────────────────────────────────────


@dataclass
class KEVAlert:
    """A single newly-observed KEV entry, ready for downstream enrichment.

    Mirrors the shape of ``ThreatArticle`` from ``feed_monitor.py`` so the
    KEV pipeline can flow through the same blob/persistence patterns.
    """

    alert_id: str  # SHA256(cve_id)[:16] — stable, deterministic
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    short_description: str
    date_added: str  # ISO date when CISA added the CVE to KEV
    due_date: str  # CISA-mandated remediation date
    known_ransomware_use: str  # "Known", "Unknown"
    inferred_detection_sources: list[str] = field(default_factory=list)
    # Populated by the pipeline after fetching from cve_lookup
    cvss_score: float = 0.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    severity: str = "unknown"
    description: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "short_description": self.short_description,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "known_ransomware_use": self.known_ransomware_use,
            "inferred_detection_sources": self.inferred_detection_sources,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "severity": self.severity,
            "description": self.description,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "mitre_techniques": self.mitre_techniques,
        }

    @classmethod
    def from_kev_entry(cls, entry: KEVEntry) -> "KEVAlert":
        return cls(
            alert_id=_make_alert_id(entry.cve_id),
            cve_id=entry.cve_id,
            vendor=entry.vendor,
            product=entry.product,
            vulnerability_name=entry.vulnerability_name,
            short_description=entry.short_description,
            date_added=entry.date_added,
            due_date=entry.due_date,
            known_ransomware_use=entry.known_ransomware_use,
            inferred_detection_sources=infer_detection_sources(entry),
            mitre_techniques=list(entry.mitre_techniques),
        )


def _make_alert_id(cve_id: str) -> str:
    """Stable 16-char ID for dedup. SHA256 keeps the same shape as feed_monitor."""
    return hashlib.sha256(cve_id.strip().upper().encode()).hexdigest()[:16]


# ── Monitor ───────────────────────────────────────────────────────────


class KEVMonitor:
    """Polls the CISA KEV catalog and emits new entries as ``KEVAlert``s.

    This is intentionally narrow — it does HTTP fetch, parsing, dedup,
    and persistence. Enrichment, exposure matching, and hunt execution
    live in ``KEVPipeline`` so each layer is independently testable.
    """

    def __init__(
        self,
        catalog_url: str = KEV_CATALOG_URL,
        blob_store: Any | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._catalog_url = catalog_url
        self._blob = blob_store
        self._http = http_client  # injection point for tests
        self._seen_ids: set[str] = set()
        self._load_seen_ids()

    # ── Persistence ───────────────────────────────────────────────────

    def _load_seen_ids(self) -> None:
        if not self._blob:
            return
        try:
            data = self._blob._download_json("kev-feeds/seen_ids.json")
            if data and isinstance(data.get("ids"), list):
                self._seen_ids = set(data["ids"])
                logger.info("KEVMonitor: loaded %d seen alert IDs", len(self._seen_ids))
        except Exception as exc:
            logger.debug("KEVMonitor: no existing seen IDs (%s)", exc)

    def _save_seen_ids(self) -> None:
        if not self._blob:
            return
        try:
            ids = list(self._seen_ids)[-_MAX_SEEN_IDS:]
            self._blob._upload_json(
                "kev-feeds/seen_ids.json",
                {
                    "ids": ids,
                    "count": len(ids),
                    "updated": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception as exc:
            logger.warning("KEVMonitor: failed to persist seen IDs: %s", exc)

    def _save_alerts_batch(self, alerts: list[KEVAlert]) -> None:
        if not self._blob or not alerts:
            return
        try:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d")
            self._blob._upload_json(
                f"kev-feeds/batches/{ts}.json",
                {
                    "date": ts,
                    "count": len(alerts),
                    "alerts": [a.to_dict() for a in alerts],
                },
            )
            logger.info("KEVMonitor: persisted %d new alerts to kev-feeds/batches/%s.json", len(alerts), ts)
        except Exception as exc:
            logger.warning("KEVMonitor: failed to persist alerts batch: %s", exc)

    # ── Fetch ─────────────────────────────────────────────────────────

    def _fetch_catalog(self) -> dict[str, Any] | None:
        """GET the CISA KEV catalog. Returns ``None`` on any failure."""
        client = self._http or httpx.Client(timeout=_FETCH_TIMEOUT_SECONDS, follow_redirects=True)
        owns_client = self._http is None
        try:
            resp = client.get(
                self._catalog_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                logger.warning("KEVMonitor: catalog returned HTTP %d", resp.status_code)
                return None
            return resp.json()
        except Exception as exc:
            logger.warning("KEVMonitor: catalog fetch failed: %s", exc)
            return None
        finally:
            if owns_client:
                try:
                    client.close()
                except Exception:
                    pass

    # ── Public API ────────────────────────────────────────────────────

    def check_catalog(self) -> list[KEVAlert]:
        """Fetch the KEV catalog and return only newly-observed entries.

        Idempotent — calling repeatedly with no catalog change returns ``[]``.
        Persists dedup state and a batch record on every call that finds new
        entries.
        """
        raw = self._fetch_catalog()
        if not raw:
            return []

        try:
            entries = parse_kev_catalog(raw)
        except Exception as exc:
            logger.warning("KEVMonitor: failed to parse catalog: %s", exc)
            return []

        if not entries:
            logger.warning("KEVMonitor: catalog parsed but contained zero entries")
            return []

        new_alerts: list[KEVAlert] = []
        for entry in entries:
            if not entry.cve_id:
                continue
            alert = KEVAlert.from_kev_entry(entry)
            if alert.alert_id in self._seen_ids:
                continue
            self._seen_ids.add(alert.alert_id)
            new_alerts.append(alert)

        # Sort by date_added desc so the most recent CISA additions are first.
        new_alerts.sort(key=lambda a: a.date_added or "", reverse=True)

        logger.info(
            "KEVMonitor: catalog has %d entries, %d new (%d already seen)",
            len(entries),
            len(new_alerts),
            len(entries) - len(new_alerts),
        )

        if new_alerts:
            self._save_seen_ids()
            self._save_alerts_batch(new_alerts)

        return new_alerts

    def get_recent_alerts(self, days: int = 7) -> list[KEVAlert]:
        """Replay recent KEV alerts from blob storage (audit / debugging).

        Reads ``kev-feeds/batches/{YYYYMMDD}.json`` for each day in the window
        and returns the union, deduplicated by ``alert_id``. Returns ``[]`` if
        no blob store is configured.
        """
        if not self._blob:
            return []
        seen: set[str] = set()
        alerts: list[KEVAlert] = []
        now = datetime.now(timezone.utc)
        for day_offset in range(days):
            date = (now - timedelta(days=day_offset)).strftime("%Y%m%d")
            try:
                data = self._blob._download_json(f"kev-feeds/batches/{date}.json")
            except Exception:
                continue
            if not data or not isinstance(data.get("alerts"), list):
                continue
            for raw in data["alerts"]:
                aid = raw.get("alert_id")
                if not aid or aid in seen:
                    continue
                seen.add(aid)
                alerts.append(_alert_from_dict(raw))
        return alerts

    def reset_dedup_state(self) -> None:
        """Forget all seen IDs. Next ``check_catalog`` will treat every entry
        as new — useful for testing or for forcing a full backfill."""
        self._seen_ids.clear()
        self._save_seen_ids()


def _alert_from_dict(raw: dict[str, Any]) -> KEVAlert:
    """Reconstruct a KEVAlert from its persisted dict shape."""
    return KEVAlert(
        alert_id=raw.get("alert_id", ""),
        cve_id=raw.get("cve_id", ""),
        vendor=raw.get("vendor", ""),
        product=raw.get("product", ""),
        vulnerability_name=raw.get("vulnerability_name", ""),
        short_description=raw.get("short_description", ""),
        date_added=raw.get("date_added", ""),
        due_date=raw.get("due_date", ""),
        known_ransomware_use=raw.get("known_ransomware_use", "Unknown"),
        inferred_detection_sources=list(raw.get("inferred_detection_sources", [])),
        cvss_score=float(raw.get("cvss_score", 0.0) or 0.0),
        epss_score=float(raw.get("epss_score", 0.0) or 0.0),
        epss_percentile=float(raw.get("epss_percentile", 0.0) or 0.0),
        severity=raw.get("severity", "unknown"),
        description=raw.get("description", ""),
        references=list(raw.get("references", [])),
        cwe_ids=list(raw.get("cwe_ids", [])),
        mitre_techniques=list(raw.get("mitre_techniques", [])),
    )
