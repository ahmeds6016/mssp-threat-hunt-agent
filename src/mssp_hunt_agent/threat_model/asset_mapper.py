"""Asset mapper — builds a client asset inventory from telemetry profile."""

from __future__ import annotations

import uuid

from mssp_hunt_agent.threat_model.models import AssetEntry, AssetMap


# Map Sentinel table names to asset types they reveal
_TABLE_ASSET_MAP: dict[str, list[tuple[str, str]]] = {
    "SecurityEvent": [("Windows Servers", "server"), ("Windows Workstations", "workstation")],
    "Syslog": [("Linux Servers", "server")],
    "SigninLogs": [("Azure AD Identities", "identity")],
    "AuditLogs": [("Azure AD Directory", "cloud_service")],
    "DeviceProcessEvents": [("MDE Endpoints", "workstation")],
    "DeviceNetworkEvents": [("MDE Network Monitoring", "network_device")],
    "DeviceFileEvents": [("MDE File Monitoring", "workstation")],
    "DeviceLogonEvents": [("MDE Logon Monitoring", "workstation")],
    "CommonSecurityLog": [("Firewall/Proxy", "network_device")],
    "DnsEvents": [("DNS Infrastructure", "network_device")],
    "OfficeActivity": [("Microsoft 365 Services", "cloud_service")],
    "AzureActivity": [("Azure Subscriptions", "cloud_service")],
    "AzureDiagnostics": [("Azure PaaS Services", "cloud_service")],
    "SecurityAlert": [("Security Alerts", "cloud_service")],
}


def map_assets(
    client_name: str,
    available_data_sources: list[str],
) -> AssetMap:
    """Build an asset map from the client's available data sources."""
    seen: set[str] = set()
    assets: list[AssetEntry] = []

    for source in available_data_sources:
        mappings = _TABLE_ASSET_MAP.get(source, [])
        for name, asset_type in mappings:
            if name not in seen:
                seen.add(name)
                assets.append(AssetEntry(
                    name=name,
                    asset_type=asset_type,
                    data_sources=[source],
                    criticality="high" if asset_type in ("identity", "server") else "medium",
                ))

    coverage: dict[str, int] = {}
    for a in assets:
        coverage[a.asset_type] = coverage.get(a.asset_type, 0) + 1

    return AssetMap(
        client_name=client_name,
        assets=assets,
        total_assets=len(assets),
        coverage_summary=coverage,
    )
