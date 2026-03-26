"""Query safety guardrails — flag risky queries before execution."""

from __future__ import annotations

import re

from mssp_hunt_agent.models.hunt_models import ExabeamQuery, SafetyFlag


def check_query(query: ExabeamQuery) -> list[SafetyFlag]:
    """Run all safety rules against a query. Returns list of flags (empty = clean)."""
    flags: list[SafetyFlag] = []

    text = query.query_text

    # 1. No explicit time range
    if not _has_time_bound(text, query.time_range):
        flags.append(SafetyFlag(
            rule="no_time_range",
            severity="error",
            message="Query does not contain an explicit time-range filter. "
                    "Unbounded queries can be extremely expensive.",
        ))

    # 2. Free-text-only (no parsed field filters)
    if _is_free_text_only(text):
        flags.append(SafetyFlag(
            rule="free_text_only",
            severity="warning",
            message="Query relies entirely on free-text search with no parsed-field "
                    "filters. This may return excessive noise.",
        ))

    # 3. Broad wildcard
    if re.search(r'=\s*"\*"', text) or text.strip() == "*":
        flags.append(SafetyFlag(
            rule="broad_wildcard",
            severity="warning",
            message="Query contains a broad wildcard pattern that may match "
                    "all events. Consider narrowing scope.",
        ))

    # 4. Missing result limit
    if not re.search(r"\b(head|limit|top)\b", text, re.IGNORECASE):
        flags.append(SafetyFlag(
            rule="no_result_limit",
            severity="warning",
            message="Query has no result limit (head/limit). Large result sets "
                    "can overwhelm the analyst and the platform.",
        ))

    # 5. Missing client-scoping field
    if not _has_client_scope(text):
        flags.append(SafetyFlag(
            rule="no_client_scope",
            severity="warning",
            message="Query does not appear to include client/tenant scoping. "
                    "In multi-tenant environments this could leak cross-client data.",
        ))

    return flags


def has_errors(flags: list[SafetyFlag]) -> bool:
    """Return True if any flag is severity 'error'."""
    return any(f.severity == "error" for f in flags)


# ── private helpers ───────────────────────────────────────────────────

def _has_time_bound(text: str, declared_time_range: str) -> bool:
    """Check if the query text contains time-filtering keywords."""
    time_patterns = [r"\btime\b", r"\btimestamp\b", r"\bwhere\s+time", r"\bdate\b", r">=", r"<="]
    for p in time_patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    # Also accept if the declared time_range string appears literally
    if declared_time_range and declared_time_range in text:
        return True
    return False


def _is_free_text_only(text: str) -> bool:
    """True when the query has no 'field = value' patterns."""
    # Look for parsed-field assignment: field_name = "value" or field_name = value
    return not re.search(r"\w+\s*=\s*", text)


def _has_client_scope(text: str) -> bool:
    """Check for client/tenant scoping fields in the query."""
    scope_fields = ["tenant", "client", "org", "customer", "partition", "namespace"]
    lower = text.lower()
    return any(f in lower for f in scope_fields)
