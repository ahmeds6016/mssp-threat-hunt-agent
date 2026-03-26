"""Threat Landscape Engine — orchestrates feed ingestion and correlation."""

from __future__ import annotations

import logging
from typing import Any

from mssp_hunt_agent.intel.cisa_kev import parse_kev_catalog
from mssp_hunt_agent.intel.correlation import build_landscape_report
from mssp_hunt_agent.intel.landscape_models import KEVEntry, LandscapeReport

logger = logging.getLogger(__name__)


class ThreatLandscapeEngine:
    """Orchestrates threat landscape ingestion and client correlation."""

    def __init__(self) -> None:
        self._kev_entries: list[KEVEntry] = []

    def ingest_kev(self, raw_json: dict[str, Any]) -> list[KEVEntry]:
        """Parse and store CISA KEV catalog entries."""
        self._kev_entries = parse_kev_catalog(raw_json)
        logger.info("Ingested %d KEV entries", len(self._kev_entries))
        return self._kev_entries

    @property
    def kev_entries(self) -> list[KEVEntry]:
        return self._kev_entries

    def correlate(
        self,
        client_sources: dict[str, list[str]],
        threats: list[KEVEntry] | None = None,
    ) -> LandscapeReport:
        """Correlate threats against client capabilities."""
        active_threats = threats or self._kev_entries
        if not active_threats:
            return LandscapeReport()
        return build_landscape_report(active_threats, client_sources)
