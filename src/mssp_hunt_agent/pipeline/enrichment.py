"""Enrichment stage — extract entities from results and enrich via TI adapters."""

from __future__ import annotations

import logging
from typing import Sequence

from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.models.result_models import (
    EnrichmentRecord,
    ExabeamEvent,
    ExtractedEntity,
    QueryResult,
)

logger = logging.getLogger(__name__)


def extract_entities(results: list[QueryResult]) -> list[ExtractedEntity]:
    """Pull unique IOCs / entities from all query result events."""
    seen: set[tuple[str, str]] = set()
    entities: list[ExtractedEntity] = []

    for qr in results:
        for event in qr.events:
            _extract_from_event(event, qr.query_id, seen, entities)

    return entities


def enrich_entities(
    entities: list[ExtractedEntity],
    provider: ThreatIntelAdapter,
) -> list[EnrichmentRecord]:
    """Enrich each unique entity via the given provider.

    Errors on individual enrichments are logged and skipped — one failed
    lookup must never crash the pipeline.
    """
    records: list[EnrichmentRecord] = []
    enriched_keys: set[tuple[str, str]] = set()

    for ent in entities:
        key = (ent.entity_type, ent.value)
        if key in enriched_keys:
            continue
        enriched_keys.add(key)

        try:
            record = _enrich_single(ent, provider)
            if record:
                records.append(record)
        except Exception as exc:
            logger.warning(
                "Enrichment failed for %s %s: %s", ent.entity_type, ent.value, exc
            )

    return records


# ── private helpers ───────────────────────────────────────────────────

def _extract_from_event(
    event: ExabeamEvent,
    query_id: str,
    seen: set[tuple[str, str]],
    out: list[ExtractedEntity],
) -> None:
    _maybe_add(seen, out, "ip", event.src_ip, query_id, "source IP")
    _maybe_add(seen, out, "ip", event.dst_ip, query_id, "destination IP")
    _maybe_add(seen, out, "domain", event.domain, query_id, "domain field")
    _maybe_add(seen, out, "hash", event.file_hash, query_id, "file hash")
    _maybe_add(seen, out, "user_agent", event.user_agent, query_id, "user-agent string")
    _maybe_add(seen, out, "hostname", event.hostname, query_id, "hostname field")
    _maybe_add(seen, out, "user", event.user, query_id, "user field")


def _maybe_add(
    seen: set[tuple[str, str]],
    out: list[ExtractedEntity],
    entity_type: str,
    value: str | None,
    query_id: str,
    context: str,
) -> None:
    if not value:
        return
    key = (entity_type, value)
    if key in seen:
        return
    seen.add(key)
    out.append(ExtractedEntity(
        entity_type=entity_type,
        value=value,
        source_query_id=query_id,
        context=context,
    ))


def _enrich_single(
    entity: ExtractedEntity,
    provider: ThreatIntelAdapter,
) -> EnrichmentRecord | None:
    dispatch = {
        "ip": provider.enrich_ip,
        "domain": provider.enrich_domain,
        "hash": provider.enrich_hash,
        "user_agent": provider.enrich_user_agent,
    }
    fn = dispatch.get(entity.entity_type)
    if fn is None:
        return None
    return fn(entity.value)
