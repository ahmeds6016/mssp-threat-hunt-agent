"""Models for query results and enrichment data."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ExabeamEvent(BaseModel):
    """A single event row returned from an Exabeam Search query."""

    timestamp: str
    event_type: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    user_agent: Optional[str] = None
    raw_log: Optional[str] = None
    fields: dict[str, Any] = Field(default_factory=dict)


class QueryResult(BaseModel):
    """Outcome of executing a single Exabeam query."""

    query_id: str
    query_text: str
    status: str  # success | error | timeout | no_results
    result_count: int = 0
    events: list[ExabeamEvent] = Field(default_factory=list)
    execution_time_ms: int = 0
    error_message: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtractedEntity(BaseModel):
    """An IOC / entity pulled from query result events."""

    entity_type: str  # ip | domain | hash | user_agent | user | hostname
    value: str
    source_query_id: str
    context: str


class EnrichmentRecord(BaseModel):
    """Normalised enrichment from any threat-intel provider."""

    entity_type: str
    entity_value: str
    source: str  # provider name
    verdict: str  # malicious | suspicious | benign | unknown
    confidence: float = Field(ge=0.0, le=1.0)
    labels: list[str] = Field(default_factory=list)
    context: str = ""
    raw_reference: Optional[str] = None
    cached: bool = False
