"""IOC intake — validate, normalize, defang, deduplicate indicators."""

from __future__ import annotations

import ipaddress
import re

from mssp_hunt_agent.models.ioc_models import (
    IOCBatch,
    IOCEntry,
    IOCType,
    NormalizedIOC,
)


def process_iocs(entries: list[IOCEntry]) -> IOCBatch:
    """Validate, normalize, defang, and deduplicate a list of IOC entries."""
    normalized: list[NormalizedIOC] = []
    for entry in entries:
        normalized.append(_normalize_one(entry))

    valid = [n for n in normalized if n.is_valid]
    invalid = [n for n in normalized if not n.is_valid]

    # Deduplicate by (type, normalized_value)
    seen: set[tuple[str, str]] = set()
    deduped: list[NormalizedIOC] = []
    dedup_removed = 0
    for n in valid:
        key = (n.ioc_type.value, n.normalized_value)
        if key in seen:
            dedup_removed += 1
            continue
        seen.add(key)
        deduped.append(n)

    # Type counts
    type_counts: dict[str, int] = {}
    for n in deduped:
        type_counts[n.ioc_type.value] = type_counts.get(n.ioc_type.value, 0) + 1

    return IOCBatch(
        valid=deduped,
        invalid=invalid,
        dedup_removed=dedup_removed,
        type_counts=type_counts,
    )


# ── Defanging ─────────────────────────────────────────────────────────


def defang(value: str) -> str:
    """Convert defanged indicators back to standard form."""
    value = value.replace("hxxps://", "https://")
    value = value.replace("hxxp://", "http://")
    value = value.replace("[.]", ".")
    value = value.replace("[:]", ":")
    value = value.replace("[@]", "@")
    return value


# ── Per-type validation ───────────────────────────────────────────────


def _normalize_one(entry: IOCEntry) -> NormalizedIOC:
    raw = entry.value.strip()
    cleaned = defang(raw)

    validators = {
        IOCType.IP: _validate_ip,
        IOCType.DOMAIN: _validate_domain,
        IOCType.HASH_MD5: lambda v: _validate_hash(v, 32),
        IOCType.HASH_SHA1: lambda v: _validate_hash(v, 40),
        IOCType.HASH_SHA256: lambda v: _validate_hash(v, 64),
        IOCType.EMAIL: _validate_email,
        IOCType.URL: _validate_url,
        IOCType.USER_AGENT: _validate_user_agent,
    }

    validator = validators.get(entry.ioc_type, _validate_user_agent)
    is_valid, note, normalized = validator(cleaned)

    return NormalizedIOC(
        original_value=raw,
        normalized_value=normalized,
        ioc_type=entry.ioc_type,
        context=entry.context,
        source=entry.source,
        is_valid=is_valid,
        validation_note=note,
    )


def _validate_ip(value: str) -> tuple[bool, str, str]:
    try:
        addr = ipaddress.ip_address(value)
        return True, "", str(addr)
    except ValueError:
        return False, f"Invalid IP address: {value}", value


def _validate_domain(value: str) -> tuple[bool, str, str]:
    normalized = value.lower().rstrip(".")
    pattern = r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
    if re.match(pattern, normalized):
        return True, "", normalized
    return False, f"Invalid domain format: {value}", value


def _validate_hash(value: str, expected_len: int) -> tuple[bool, str, str]:
    normalized = value.lower()
    if len(normalized) == expected_len and re.match(r"^[a-f0-9]+$", normalized):
        return True, "", normalized
    return (
        False,
        f"Expected {expected_len} hex characters, got {len(normalized)}",
        value,
    )


def _validate_email(value: str) -> tuple[bool, str, str]:
    normalized = value.lower().strip()
    if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", normalized):
        return True, "", normalized
    return False, f"Invalid email format: {value}", value


def _validate_url(value: str) -> tuple[bool, str, str]:
    if re.match(r"^https?://\S+", value):
        return True, "", value
    return False, f"Invalid URL (must start with http:// or https://): {value}", value


def _validate_user_agent(value: str) -> tuple[bool, str, str]:
    # Any non-empty string is valid as a user-agent
    if value.strip():
        return True, "", value.strip()
    return False, "Empty user-agent string", value
