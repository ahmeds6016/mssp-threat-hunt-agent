"""Feed ingester — parse CSV, STIX-JSON, and plain-JSON threat-intel feeds."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from mssp_hunt_agent.intel.models import FeedSource, FeedType, IngestResult, NormalizedIOC

logger = logging.getLogger(__name__)

# ── IOC type detection heuristics ────────────────────────────────────────

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def detect_ioc_type(value: str) -> str | None:
    """Heuristically detect the IOC type from a raw string."""
    v = value.strip()
    if _IPV4_RE.match(v):
        return "ip"
    if _SHA256_RE.match(v):
        return "hash_sha256"
    if _MD5_RE.match(v):
        return "hash_md5"
    if _URL_RE.match(v):
        return "url"
    if _EMAIL_RE.match(v):
        return "email"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


class FeedIngester:
    """Parses threat-intel feeds into normalized IOCs."""

    def ingest(self, source: FeedSource, raw_content: str) -> IngestResult:
        """Parse raw content from a feed and return normalized IOCs."""
        if source.feed_type == FeedType.CSV:
            return self._ingest_csv(source, raw_content)
        elif source.feed_type == FeedType.STIX:
            return self._ingest_stix(source, raw_content)
        elif source.feed_type == FeedType.JSON:
            return self._ingest_json(source, raw_content)
        else:
            return IngestResult(
                feed_name=source.name,
                errors=[f"Unsupported feed type: {source.feed_type}"],
            )

    # ── CSV ───────────────────────────────────────────────────────────

    def _ingest_csv(self, source: FeedSource, raw: str) -> IngestResult:
        """Parse a CSV feed.

        Expected columns (flexible): indicator/ioc/value, type (optional), tags (optional).
        If no 'type' column, auto-detect from value.
        """
        result = IngestResult(feed_name=source.name)
        now = datetime.now(timezone.utc).isoformat()

        reader = csv.DictReader(io.StringIO(raw))
        seen: set[str] = set()

        for row in reader:
            result.total_parsed += 1

            # Find the value column (flexible naming)
            value = (
                row.get("indicator")
                or row.get("ioc")
                or row.get("value")
                or row.get("Indicator")
                or row.get("IOC")
                or ""
            ).strip()

            if not value:
                result.invalid += 1
                continue

            # Deduplicate within this batch
            if value in seen:
                result.duplicates += 1
                continue
            seen.add(value)

            # Detect or read type
            ioc_type = (
                row.get("type", "") or row.get("ioc_type", "")
            ).strip().lower()
            if not ioc_type:
                ioc_type = detect_ioc_type(value)
            if not ioc_type:
                result.invalid += 1
                continue

            tags = source.tags.copy()
            row_tags = row.get("tags", "")
            if row_tags:
                tags.extend(t.strip() for t in row_tags.split(",") if t.strip())

            confidence = 0.5
            raw_conf = row.get("confidence", "")
            if raw_conf:
                try:
                    confidence = float(raw_conf)
                except ValueError:
                    pass

            result.new_iocs.append(
                NormalizedIOC(
                    ioc_type=ioc_type,
                    value=value,
                    source_feed=source.name,
                    first_seen=now,
                    last_seen=now,
                    tags=tags,
                    confidence=min(max(confidence, 0.0), 1.0),
                    context=row.get("context", ""),
                )
            )
            result.valid += 1

        return result

    # ── STIX/JSON ─────────────────────────────────────────────────────

    def _ingest_stix(self, source: FeedSource, raw: str) -> IngestResult:
        """Parse a STIX 2.x JSON bundle."""
        result = IngestResult(feed_name=source.name)
        now = datetime.now(timezone.utc).isoformat()

        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.errors.append(f"JSON parse error: {exc}")
            return result

        objects = bundle.get("objects", [])
        seen: set[str] = set()

        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            result.total_parsed += 1
            pattern = obj.get("pattern", "")

            # Extract value from STIX pattern like [ipv4-addr:value = '1.2.3.4']
            value, ioc_type = self._parse_stix_pattern(pattern)
            if not value or not ioc_type:
                result.invalid += 1
                continue

            if value in seen:
                result.duplicates += 1
                continue
            seen.add(value)

            tags = source.tags.copy()
            labels = obj.get("labels", [])
            tags.extend(labels)

            first_seen = obj.get("created", now)
            last_seen = obj.get("modified", now)

            result.new_iocs.append(
                NormalizedIOC(
                    ioc_type=ioc_type,
                    value=value,
                    source_feed=source.name,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    tags=tags,
                    confidence=obj.get("confidence", 50) / 100.0,
                    context=obj.get("description", ""),
                    raw={"stix_id": obj.get("id", "")},
                )
            )
            result.valid += 1

        return result

    def _parse_stix_pattern(self, pattern: str) -> tuple[str | None, str | None]:
        """Extract value and type from a STIX 2.x pattern string."""
        type_map = {
            "ipv4-addr": "ip",
            "ipv6-addr": "ip",
            "domain-name": "domain",
            "url": "url",
            "file:hashes.MD5": "hash_md5",
            "file:hashes.'SHA-256'": "hash_sha256",
            "email-addr": "email",
        }

        # Pattern format: [type:value = 'x'] or [file:hashes.MD5 = 'x']
        match = re.search(r"\[(.+?):.*?=\s*'([^']+)'\]", pattern)
        if not match:
            # Try simpler: [type:value = 'x']
            match = re.search(r"\[([^:]+):value\s*=\s*'([^']+)'\]", pattern)
        if not match:
            return None, None

        stix_type = match.group(1).strip()
        value = match.group(2).strip()

        ioc_type = type_map.get(stix_type)
        if not ioc_type:
            ioc_type = detect_ioc_type(value)

        return value, ioc_type

    # ── Plain JSON ────────────────────────────────────────────────────

    def _ingest_json(self, source: FeedSource, raw: str) -> IngestResult:
        """Parse a plain JSON feed (list of objects with value/type fields)."""
        result = IngestResult(feed_name=source.name)
        now = datetime.now(timezone.utc).isoformat()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.errors.append(f"JSON parse error: {exc}")
            return result

        items = data if isinstance(data, list) else data.get("indicators", data.get("iocs", []))
        seen: set[str] = set()

        for item in items:
            result.total_parsed += 1

            value = (
                item.get("indicator") or item.get("value") or item.get("ioc") or ""
            ).strip()
            if not value:
                result.invalid += 1
                continue

            if value in seen:
                result.duplicates += 1
                continue
            seen.add(value)

            ioc_type = (item.get("type") or item.get("ioc_type") or "").lower()
            if not ioc_type:
                ioc_type = detect_ioc_type(value)
            if not ioc_type:
                result.invalid += 1
                continue

            tags = source.tags.copy()
            if item.get("tags"):
                if isinstance(item["tags"], list):
                    tags.extend(item["tags"])
                elif isinstance(item["tags"], str):
                    tags.extend(t.strip() for t in item["tags"].split(",") if t.strip())

            confidence = item.get("confidence", 0.5)
            if isinstance(confidence, (int, float)):
                confidence = min(max(float(confidence), 0.0), 1.0)
            else:
                confidence = 0.5

            result.new_iocs.append(
                NormalizedIOC(
                    ioc_type=ioc_type,
                    value=value,
                    source_feed=source.name,
                    first_seen=now,
                    last_seen=now,
                    tags=tags,
                    confidence=confidence,
                    context=item.get("context", item.get("description", "")),
                )
            )
            result.valid += 1

        return result
