"""KQL validation and schema checking for detection rules."""

from __future__ import annotations

import re

from mssp_hunt_agent.detection.models import ValidationResult


# Known Sentinel table names for schema checking
_KNOWN_TABLES = {
    "SecurityEvent", "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs",
    "DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents",
    "DeviceLogonEvents", "DeviceAlertEvents", "CommonSecurityLog",
    "DnsEvents", "OfficeActivity", "AzureActivity", "SecurityAlert",
    "Syslog", "Heartbeat", "ThreatIntelligenceIndicator", "BehaviorAnalytics",
    "NetworkCommunicationEvents", "AzureDiagnostics",
}

# Dangerous patterns that could cause performance issues
_DANGEROUS_PATTERNS = [
    (r"\|\s*where\s+\*", "Wildcard filter on all columns is expensive"),
    (r"search\s+\*", "'search *' scans all tables — extremely expensive"),
    (r"union\s+\*", "'union *' joins all tables — use specific tables"),
]

# Required elements for a good detection rule
_BEST_PRACTICES = [
    (r"\bwhere\b", "Query should have at least one 'where' filter"),
    (r"TimeGenerated|ago\(|between\(|datetime\(", "Query should include a time filter"),
]


def validate_kql(kql: str) -> ValidationResult:
    """Validate a KQL query for syntax issues, schema references, and best practices."""
    errors: list[str] = []
    warnings: list[str] = []
    tables: list[str] = []
    time_range: str | None = None

    if not kql or not kql.strip():
        return ValidationResult(valid=False, errors=["Empty query"])

    # Extract table references (first word of query or after union)
    lines = kql.strip().split("\n")
    first_token = lines[0].strip().split("|")[0].strip().split()[0] if lines else ""
    if first_token in _KNOWN_TABLES:
        tables.append(first_token)
    elif first_token and first_token not in ("let", "search", "union", "print", "range", "datatable"):
        warnings.append(f"Unknown table: '{first_token}' — verify it exists in your workspace")

    # Find all table references
    for table in _KNOWN_TABLES:
        if table in kql and table not in tables:
            tables.append(table)

    # Check for dangerous patterns
    for pattern, message in _DANGEROUS_PATTERNS:
        if re.search(pattern, kql, re.IGNORECASE):
            errors.append(message)

    # Check best practices
    for pattern, message in _BEST_PRACTICES:
        if not re.search(pattern, kql, re.IGNORECASE):
            warnings.append(message)

    # Detect time range
    ago_match = re.search(r"ago\((\d+[dhms])\)", kql)
    if ago_match:
        time_range = ago_match.group(1)

    between_match = re.search(r"between\s*\(datetime\(([^)]+)\)\s*\.\.\s*datetime\(([^)]+)\)\)", kql)
    if between_match:
        time_range = f"{between_match.group(1)} to {between_match.group(2)}"

    # Estimate cost
    cost = "low"
    if "join" in kql.lower() or "union" in kql.lower():
        cost = "high"
    elif "summarize" in kql.lower():
        cost = "medium"
    if not time_range:
        cost = "high"  # no time filter = scan everything

    # Check balanced parentheses and quotes
    if kql.count("(") != kql.count(")"):
        errors.append("Unbalanced parentheses")
    if kql.count('"') % 2 != 0:
        errors.append("Unbalanced double quotes")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        estimated_cost=cost,
        tables_referenced=tables,
        time_range_detected=time_range,
    )
