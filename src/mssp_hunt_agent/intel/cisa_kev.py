"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion."""

from __future__ import annotations

import json
import logging
from typing import Any

from mssp_hunt_agent.intel.landscape_models import KEVEntry

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Mapping of product categories to Sentinel detection sources
_PRODUCT_SOURCE_MAP: dict[str, list[str]] = {
    "windows": ["SecurityEvent", "DeviceProcessEvents"],
    "office": ["OfficeActivity", "DeviceProcessEvents"],
    "exchange": ["SecurityEvent", "OfficeActivity"],
    "azure": ["AzureActivity", "AuditLogs", "SigninLogs"],
    "active directory": ["SecurityEvent", "AuditLogs"],
    "linux": ["Syslog"],
    "apache": ["CommonSecurityLog"],
    "nginx": ["CommonSecurityLog"],
    "fortinet": ["CommonSecurityLog"],
    "palo alto": ["CommonSecurityLog"],
    "cisco": ["CommonSecurityLog"],
    "vmware": ["Syslog", "CommonSecurityLog"],
    "chrome": ["DeviceProcessEvents"],
    "edge": ["DeviceProcessEvents"],
    "adobe": ["DeviceProcessEvents", "DeviceFileEvents"],
}


def parse_kev_catalog(raw_json: dict[str, Any]) -> list[KEVEntry]:
    """Parse the CISA KEV JSON catalog into KEVEntry objects."""
    entries: list[KEVEntry] = []
    for vuln in raw_json.get("vulnerabilities", []):
        entry = KEVEntry(
            cve_id=vuln.get("cveID", ""),
            vendor=vuln.get("vendorProject", ""),
            product=vuln.get("product", ""),
            vulnerability_name=vuln.get("vulnerabilityName", ""),
            date_added=vuln.get("dateAdded", ""),
            due_date=vuln.get("dueDate", ""),
            known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown"),
            short_description=vuln.get("shortDescription", ""),
        )
        entries.append(entry)
    return entries


def infer_detection_sources(entry: KEVEntry) -> list[str]:
    """Infer which Sentinel data sources could detect exploitation of this vulnerability."""
    sources: set[str] = set()
    searchable = f"{entry.vendor} {entry.product}".lower()

    for keyword, data_sources in _PRODUCT_SOURCE_MAP.items():
        if keyword in searchable:
            sources.update(data_sources)

    # Fallback: if we can't infer, assume endpoint + network
    if not sources:
        sources = {"CommonSecurityLog", "DeviceProcessEvents"}

    return sorted(sources)
