"""Threat-intel enrichment adapters."""

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.adapters.intel.mock import MockThreatIntelAdapter
from mssp_hunt_agent.adapters.intel.cache import CachedIntelAdapter
from mssp_hunt_agent.adapters.intel.composite import CompositeIntelAdapter
from mssp_hunt_agent.adapters.intel.factory import build_intel_adapter

__all__ = [
    "ThreatIntelAdapter",
    "MockThreatIntelAdapter",
    "CachedIntelAdapter",
    "CompositeIntelAdapter",
    "build_intel_adapter",
]
