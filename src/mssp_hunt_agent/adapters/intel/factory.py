"""Factory for building the active threat-intel adapter from config."""

from __future__ import annotations

import logging

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.adapters.intel.cache import CachedIntelAdapter
from mssp_hunt_agent.adapters.intel.composite import CompositeIntelAdapter
from mssp_hunt_agent.adapters.intel.mock import MockThreatIntelAdapter
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


def build_intel_adapter(config: HuntAgentConfig) -> ThreatIntelAdapter:
    """Construct the appropriate TI adapter(s) from *config*.

    Returns a ``CachedIntelAdapter`` wrapping either:
      - ``MockThreatIntelAdapter`` (default)
      - ``VirusTotalAdapter``
      - ``AbuseIPDBAdapter``
      - ``CompositeIntelAdapter`` (when multiple real providers configured)
    """
    provider_names = config.intel_providers

    providers: list[ThreatIntelAdapter] = []

    for name in provider_names:
        name_lower = name.strip().lower()

        if name_lower == "mock":
            providers.append(MockThreatIntelAdapter())
            continue

        if name_lower == "virustotal":
            if not config.virustotal_api_key:
                logger.warning("VirusTotal requested but VIRUSTOTAL_API_KEY not set — skipping")
                continue
            from mssp_hunt_agent.adapters.intel.virustotal import VirusTotalAdapter
            providers.append(VirusTotalAdapter(config.virustotal_api_key))
            continue

        if name_lower == "abuseipdb":
            if not config.abuseipdb_api_key:
                logger.warning("AbuseIPDB requested but ABUSEIPDB_API_KEY not set — skipping")
                continue
            from mssp_hunt_agent.adapters.intel.abuseipdb import AbuseIPDBAdapter
            providers.append(AbuseIPDBAdapter(config.abuseipdb_api_key))
            continue

        logger.warning("Unknown intel provider '%s' — skipping", name)

    # Fallback to mock if nothing was configured
    if not providers:
        logger.info("No TI providers configured — using MockThreatIntelAdapter")
        providers.append(MockThreatIntelAdapter())

    # Single provider → use directly; multiple → composite
    inner: ThreatIntelAdapter
    if len(providers) == 1:
        inner = providers[0]
    else:
        inner = CompositeIntelAdapter(providers)

    return CachedIntelAdapter(inner, config.enrichment_cache_dir)
