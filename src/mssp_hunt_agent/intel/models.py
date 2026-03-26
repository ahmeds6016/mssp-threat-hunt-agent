"""Models for the continuous-intel subsystem."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class FeedType(str, Enum):
    CSV = "csv"
    STIX = "stix"
    JSON = "json"


class FeedSource(BaseModel):
    """Describes a threat-intel feed to ingest."""

    name: str
    url: str
    feed_type: FeedType = FeedType.CSV
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    last_ingested_at: Optional[str] = None


class NormalizedIOC(BaseModel):
    """A single IOC normalised from any feed format."""

    ioc_type: str  # ip, domain, hash_md5, hash_sha256, url, email
    value: str
    source_feed: str
    first_seen: str  # ISO-8601
    last_seen: str
    tags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class IngestResult(BaseModel):
    """Summary of a feed ingestion run."""

    feed_name: str
    total_parsed: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    new_iocs: list[NormalizedIOC] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DeconflictionResult(BaseModel):
    """Result of deconflicting new IOCs against existing state."""

    total_input: int = 0
    new: list[NormalizedIOC] = Field(default_factory=list)
    updated: list[NormalizedIOC] = Field(default_factory=list)
    suppressed: list[str] = Field(default_factory=list)  # values suppressed (known benign)
    duplicate_values: list[str] = Field(default_factory=list)
