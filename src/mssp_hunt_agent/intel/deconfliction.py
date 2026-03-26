"""Deconfliction — deduplicate, suppress known-benign, track first/last seen."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from mssp_hunt_agent.intel.models import DeconflictionResult, NormalizedIOC

logger = logging.getLogger(__name__)


def deconflict(
    new_iocs: list[NormalizedIOC],
    existing_iocs: list[NormalizedIOC] | None = None,
    known_benign: set[str] | None = None,
) -> DeconflictionResult:
    """Compare new IOCs against existing state and known-benign list.

    Parameters
    ----------
    new_iocs:
        Freshly ingested IOCs from a feed.
    existing_iocs:
        IOCs already in the database (keyed by value).
    known_benign:
        Set of values to suppress (e.g. internal infrastructure IPs,
        common CDN domains).

    Returns
    -------
    DeconflictionResult with new, updated, suppressed, and duplicate lists.
    """
    existing_iocs = existing_iocs or []
    known_benign = known_benign or set()

    existing_map: dict[str, NormalizedIOC] = {ioc.value: ioc for ioc in existing_iocs}

    result = DeconflictionResult(total_input=len(new_iocs))
    seen_in_batch: set[str] = set()

    for ioc in new_iocs:
        value = ioc.value.strip()

        # 1. Known benign suppression
        if value in known_benign:
            result.suppressed.append(value)
            continue

        # 2. Duplicate within this batch
        if value in seen_in_batch:
            result.duplicate_values.append(value)
            continue
        seen_in_batch.add(value)

        # 3. Already exists — update last_seen and merge tags
        if value in existing_map:
            existing = existing_map[value]
            merged = _merge_ioc(existing, ioc)
            result.updated.append(merged)
            continue

        # 4. Genuinely new
        result.new.append(ioc)

    logger.info(
        "Deconfliction: %d input → %d new, %d updated, %d suppressed, %d dupes",
        result.total_input,
        len(result.new),
        len(result.updated),
        len(result.suppressed),
        len(result.duplicate_values),
    )
    return result


def _merge_ioc(existing: NormalizedIOC, new: NormalizedIOC) -> NormalizedIOC:
    """Merge a new IOC sighting into an existing record."""
    merged_tags = list(set(existing.tags + new.tags))
    confidence = max(existing.confidence, new.confidence)

    return NormalizedIOC(
        ioc_type=existing.ioc_type,
        value=existing.value,
        source_feed=existing.source_feed,
        first_seen=existing.first_seen,
        last_seen=new.last_seen,
        tags=merged_tags,
        confidence=confidence,
        context=new.context or existing.context,
        raw=existing.raw,
    )
