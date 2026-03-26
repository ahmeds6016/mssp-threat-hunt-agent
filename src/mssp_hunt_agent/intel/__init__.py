"""Continuous intel package — feed ingestion, deconfliction, auto-sweep."""

from mssp_hunt_agent.intel.models import (
    FeedSource,
    FeedType,
    IngestResult,
    NormalizedIOC,
    DeconflictionResult,
)
from mssp_hunt_agent.intel.feed_ingester import FeedIngester
from mssp_hunt_agent.intel.deconfliction import deconflict
from mssp_hunt_agent.intel.auto_sweep import AutoSweepScheduler

__all__ = [
    "FeedSource",
    "FeedType",
    "IngestResult",
    "NormalizedIOC",
    "DeconflictionResult",
    "FeedIngester",
    "deconflict",
    "AutoSweepScheduler",
]
