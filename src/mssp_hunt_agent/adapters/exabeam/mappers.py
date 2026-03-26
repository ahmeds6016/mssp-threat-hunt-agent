"""Map Exabeam New-Scale API responses to internal models and vice-versa."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mssp_hunt_agent.models.result_models import ExabeamEvent

# ── API → Model field mapping ────────────────────────────────────────

_API_TO_MODEL: dict[str, str] = {
    "sourceIp": "src_ip",
    "source_ip": "src_ip",
    "src_ip": "src_ip",
    "destinationIp": "dst_ip",
    "destination_ip": "dst_ip",
    "dst_ip": "dst_ip",
    "eventType": "event_type",
    "event_type": "event_type",
    "host": "hostname",
    "hostname": "hostname",
    "user": "user",
    "userName": "user",
    "timestamp": "timestamp",
    "rawLog": "raw_log",
    "raw_log": "raw_log",
    "processName": "process_name",
    "process_name": "process_name",
    "commandLine": "command_line",
    "command_line": "command_line",
    "fileHash": "file_hash",
    "file_hash": "file_hash",
    "domain": "domain",
    "userAgent": "user_agent",
    "user_agent": "user_agent",
}

# Fields that go into ExabeamEvent.fields rather than top-level attrs
_EXTRA_FIELDS = {"riskScore", "risk_score", "severity", "category", "product", "vendor"}

# Known ExabeamEvent top-level attribute names
_MODEL_ATTRS = {
    "timestamp", "event_type", "user", "src_ip", "dst_ip",
    "hostname", "domain", "process_name", "command_line",
    "file_hash", "user_agent", "raw_log",
}


def map_event_response(event: dict[str, Any]) -> ExabeamEvent:
    """Convert a single raw API event dict to an ExabeamEvent model.

    Recognised keys are mapped to the appropriate model attribute.
    Unrecognised keys are placed into ``ExabeamEvent.fields``.
    """
    mapped: dict[str, Any] = {}
    extras: dict[str, Any] = {}

    for key, value in event.items():
        if key in _EXTRA_FIELDS:
            extras[key] = value
            continue

        target = _API_TO_MODEL.get(key)
        if target and target in _MODEL_ATTRS:
            mapped[target] = value
        elif key in _MODEL_ATTRS:
            mapped[key] = value
        else:
            extras[key] = value

    # Ensure required fields have a fallback
    if "timestamp" not in mapped:
        mapped["timestamp"] = ""
    if "event_type" not in mapped:
        mapped["event_type"] = extras.pop("eventType", extras.pop("event_type", "unknown"))

    mapped["fields"] = extras
    return ExabeamEvent(**mapped)


# ── Query text → Search API params ──────────────────────────────────


@dataclass
class SearchParams:
    """Decomposed search parameters extracted from a query_text string."""

    filter: str = ""
    fields: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    limit: int | None = None
    distinct: bool = False


# Default fields to request when none are specified
DEFAULT_FIELDS = [
    "timestamp", "user", "sourceIp", "destinationIp",
    "eventType", "host", "domain", "rawLog", "riskScore",
]

# Regex patterns for extracting clauses from query text
_FIELDS_RE = re.compile(r"\|\s*fields\s+([\w,\s]+?)(?:\||$)", re.IGNORECASE)
_GROUP_BY_RE = re.compile(r"\|\s*(?:stats|group\s*by)\s+([\w,\s]+?)(?:\||$)", re.IGNORECASE)
_ORDER_BY_RE = re.compile(r"\|\s*(?:sort|order\s*by)\s+([\w,\s]+(?:\s+(?:ASC|DESC))?)(?:\||$)", re.IGNORECASE)
_LIMIT_RE = re.compile(r"\|\s*(?:head|limit)\s+(\d+)", re.IGNORECASE)
_DISTINCT_RE = re.compile(r"\|\s*(?:dedup|distinct)", re.IGNORECASE)


def _split_csv(raw: str) -> list[str]:
    """Split a comma-or-space-separated list into trimmed tokens."""
    return [tok.strip() for tok in re.split(r"[,\s]+", raw.strip()) if tok.strip()]


def parse_query_text(query_text: str) -> SearchParams:
    """Extract filter + optional clauses from a query_text string.

    The query_text may contain pipe-delimited clauses like:
        ``src_ip = "10.0.0.1" | fields user, src_ip | sort timestamp DESC | head 500``

    The filter is everything before the first pipe clause we recognise.
    """
    params = SearchParams()

    # Extract fields clause
    m = _FIELDS_RE.search(query_text)
    if m:
        params.fields = _split_csv(m.group(1))

    # Extract group-by
    m = _GROUP_BY_RE.search(query_text)
    if m:
        params.group_by = _split_csv(m.group(1))

    # Extract order-by (keep ASC/DESC as part of token)
    m = _ORDER_BY_RE.search(query_text)
    if m:
        params.order_by = [tok.strip() for tok in m.group(1).split(",") if tok.strip()]

    # Extract limit
    m = _LIMIT_RE.search(query_text)
    if m:
        params.limit = int(m.group(1))

    # Check distinct
    if _DISTINCT_RE.search(query_text):
        params.distinct = True

    # Filter is everything before the first recognised pipe clause
    # Remove all the clauses we matched, then strip trailing pipes
    filter_text = query_text
    for pattern in (_FIELDS_RE, _GROUP_BY_RE, _ORDER_BY_RE, _LIMIT_RE, _DISTINCT_RE):
        filter_text = pattern.sub("", filter_text)
    # Clean up leftover pipes and whitespace
    filter_text = re.sub(r"\|\s*$", "", filter_text).strip()
    filter_text = re.sub(r"^\|\s*", "", filter_text).strip()
    params.filter = filter_text

    # Default fields if none specified
    if not params.fields:
        params.fields = list(DEFAULT_FIELDS)

    return params
