"""Microsoft Sentinel adapter package."""

from mssp_hunt_agent.adapters.sentinel.mock import MockSentinelAdapter
from mssp_hunt_agent.adapters.sentinel.adapter import SentinelAdapter

__all__ = ["MockSentinelAdapter", "SentinelAdapter"]
