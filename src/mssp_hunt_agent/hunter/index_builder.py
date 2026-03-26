"""Environment Index Builder — populates the client index from Sentinel KQL.

Three refresh layers:
- build_static():      Monthly — table schemas, MITRE coverage
- build_semi_static(): Weekly  — users, assets, baselines, posture
- build_dynamic():     Per-hunt — row counts, active incidents, recent changes

Each method runs KQL queries via the SentinelAdapter and populates
the corresponding fields in the EnvironmentIndex.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from mssp_hunt_agent.adapters.base import SIEMAdapter
from mssp_hunt_agent.hunter.models.environment import (
    AssetIndex,
    AssetProfile,
    EnvironmentIndex,
    IdentityIndex,
    IndexMetadata,
    IngestionBaseline,
    NetworkContext,
    OrgContext,
    SecurityPosture,
    TableProfile,
    TelemetryIndex,
    UserProfile,
)
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent

logger = logging.getLogger(__name__)

# Well-known Sentinel tables used as a last-resort fallback when both
# Usage and search * discovery fail.  These are standard in most workspaces.
_WELL_KNOWN_TABLES: list[str] = [
    "SigninLogs",
    "AuditLogs",
    "SecurityEvent",
    "SecurityAlert",
    "SecurityIncident",
    "Syslog",
    "CommonSecurityLog",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceLogonEvents",
    "AADNonInteractiveUserSignInLogs",
    "OfficeActivity",
    "AzureActivity",
    "ThreatIntelligenceIndicator",
    "Heartbeat",
    "IdentityInfo",
    "BehaviorAnalytics",
    "AzureDiagnostics",
    "W3CIISLog",
]


def _query(adapter: SIEMAdapter, kql: str, query_id: str = "") -> list[dict[str, Any]]:
    """Execute a KQL query and return rows as dicts."""
    if not query_id:
        query_id = f"idx-{uuid.uuid4().hex[:8]}"
    eq = ExabeamQuery(
        query_id=query_id,
        intent=QueryIntent.BASELINE,
        description="Index builder query",
        query_text=kql,
        time_range="30d",
        expected_signal="index data",
    )
    result = adapter.execute_query(eq)
    if result.status != "success":
        logger.warning("Index query %s failed: %s", query_id, result.error_message)
        return []
    return [e.fields | {"_user": e.user, "_hostname": e.hostname, "_timestamp": e.timestamp}
            for e in result.events]


class IndexBuilder:
    """Builds and refreshes the EnvironmentIndex from Sentinel KQL queries."""

    def __init__(self, adapter: SIEMAdapter, workspace_id: str = "", client_id: str = "") -> None:
        self._adapter = adapter
        self._workspace_id = workspace_id
        self._client_id = client_id

    def build_full(self) -> EnvironmentIndex:
        """Build a complete index (all three layers). ~40-60 queries."""
        index = EnvironmentIndex(
            metadata=IndexMetadata(
                client_id=self._client_id,
                workspace_id=self._workspace_id,
            ),
        )
        self.build_static(index)
        self.build_semi_static(index)
        self.build_dynamic(index)
        return index

    # ── STATIC LAYER (monthly) ───────────────────────────────────

    def build_static(self, index: EnvironmentIndex) -> None:
        """Refresh static layer: table schemas, MITRE coverage."""
        now = datetime.now(timezone.utc).isoformat()

        # 1. Discover all tables with their 30d volume
        self._discover_tables(index)

        # 2. Get column schemas for important tables
        self._discover_schemas(index)

        # 3. Discover domains from UPNs
        self._discover_domains(index)

        index.metadata.static_refreshed_at = now
        index.metadata.total_tables = len(index.telemetry.tables)
        logger.info("Static layer built: %d tables", len(index.telemetry.tables))

    def _discover_tables(self, index: EnvironmentIndex) -> None:
        """Discover all tables and their 30-day volume.

        Strategy:
        1. Query Usage table (best source — has volume per DataType)
        2. Fallback: search * | summarize count() by Type
        3. Fallback: well-known Sentinel table list
        """
        # Usage table: summarize by DataType using Quantity (MB).
        # Note: DatapointsCount doesn't exist in all workspaces — use Quantity.
        rows = _query(self._adapter, """
Usage
| where TimeGenerated > ago(30d)
| summarize TotalMB=sum(Quantity), RowCount=count() by DataType
| sort by TotalMB desc
| take 100
""", "idx-discover-tables")

        for row in rows:
            dt = row.get("DataType", "")
            if not dt:
                continue
            total_mb = float(row.get("TotalMB", 0))
            index.telemetry.tables.append(TableProfile(
                table_name=dt,
                avg_daily_events=round(total_mb / 30, 1),
                row_count_30d=int(float(row.get("RowCount", 0))),
            ))

        if index.telemetry.tables:
            return

        # Fallback 1: search * with Type column — more reliable than
        # union withsource which can timeout on large workspaces.
        logger.warning("Usage table returned 0 rows, trying search * fallback")
        rows = _query(self._adapter, """
search *
| where TimeGenerated > ago(1d)
| summarize Count=count() by Type
| sort by Count desc
| take 100
""", "idx-discover-tables-fallback")

        for row in rows:
            dt = row.get("Type", "") or row.get("TableName", "")
            if not dt:
                continue
            index.telemetry.tables.append(TableProfile(
                table_name=dt,
                row_count_30d=int(float(row.get("Count", 0))),
            ))

        if index.telemetry.tables:
            return

        # Fallback 2: well-known Sentinel tables — assume they exist and
        # let downstream queries discover which ones actually have data
        logger.warning("Table discovery failed, using well-known Sentinel tables")
        for table_name in _WELL_KNOWN_TABLES:
            index.telemetry.tables.append(TableProfile(
                table_name=table_name,
                ingestion_healthy=False,  # unknown until verified
            ))

    def _discover_schemas(self, index: EnvironmentIndex) -> None:
        """Get column names for top tables (by volume)."""
        top_tables = [t.table_name for t in index.telemetry.tables[:15]]
        for table_name in top_tables:
            rows = _query(self._adapter, f"""
{table_name}
| take 1
| project-keep *
| getschema
""", f"idx-schema-{table_name}")
            if rows:
                columns = [r.get("ColumnName", "") for r in rows if r.get("ColumnName")]
                types = {r.get("ColumnName", ""): r.get("ColumnType", "")
                         for r in rows if r.get("ColumnName")}
                tp = index.telemetry.get_table(table_name)
                if tp:
                    tp.columns = columns
                    tp.column_types = types

    def _discover_domains(self, index: EnvironmentIndex) -> None:
        """Extract email domains from user principal names."""
        rows = _query(self._adapter, """
SigninLogs
| where TimeGenerated > ago(30d)
| extend Domain = tostring(split(UserPrincipalName, "@")[1])
| where isnotempty(Domain)
| summarize Count=count() by Domain
| sort by Count desc
| take 20
""", "idx-domains")
        index.org.domains = [r.get("Domain", "") for r in rows if r.get("Domain")]

    # ── SEMI-STATIC LAYER (weekly) ───────────────────────────────

    def build_semi_static(self, index: EnvironmentIndex) -> None:
        """Refresh semi-static layer: users, assets, baselines, posture."""
        now = datetime.now(timezone.utc).isoformat()

        self._build_identity_index(index)
        self._build_asset_index(index)
        self._build_ingestion_baselines(index)
        self._build_network_context(index)
        self._build_security_posture(index)
        self._build_connector_health(index)

        index.metadata.semi_static_refreshed_at = now
        index.metadata.total_users = index.identity.total_users
        index.metadata.total_assets = index.assets.total_assets
        logger.info(
            "Semi-static layer built: %d users, %d assets",
            index.identity.total_users, index.assets.total_assets,
        )

    def _build_identity_index(self, index: EnvironmentIndex) -> None:
        """Discover users from IdentityInfo or SigninLogs."""
        # Try IdentityInfo first (richest source)
        if index.telemetry.get_table("IdentityInfo"):
            self._identity_from_identityinfo(index)
        else:
            self._identity_from_signinlogs(index)

        # MFA status
        self._check_mfa_status(index)

        # Compute stats
        users = index.identity.users
        index.identity.total_users = len(users)
        index.identity.admin_count = sum(1 for u in users if u.is_admin)
        index.identity.guest_count = sum(1 for u in users if u.is_guest)
        index.identity.service_account_count = sum(1 for u in users if u.is_service_account)

    def _identity_from_identityinfo(self, index: EnvironmentIndex) -> None:
        rows = _query(self._adapter, """
IdentityInfo
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project AccountUPN, AccountDisplayName, AssignedRoles, UserType,
          IsAccountEnabled, Department, JobTitle, RiskLevel
| take 500
""", "idx-users-identityinfo")

        for row in rows:
            upn = row.get("AccountUPN", "") or row.get("_user", "")
            if not upn:
                continue
            roles = row.get("AssignedRoles", "") or ""
            user_type = row.get("UserType", "") or ""
            is_svc = _is_service_account(upn)
            index.identity.users.append(UserProfile(
                user_principal_name=upn,
                display_name=row.get("AccountDisplayName", "") or "",
                is_admin=bool(roles.strip()),
                admin_roles=[r.strip() for r in roles.split(",") if r.strip()],
                is_service_account=is_svc,
                is_guest=user_type.lower() == "guest",
                is_enabled=row.get("IsAccountEnabled", True),
                department=row.get("Department", "") or "",
                job_title=row.get("JobTitle", "") or "",
                risk_level=row.get("RiskLevel", "") or "",
            ))

    def _identity_from_signinlogs(self, index: EnvironmentIndex) -> None:
        rows = _query(self._adapter, """
SigninLogs
| where TimeGenerated > ago(30d)
| summarize SignInCount=count(), DistinctIPs=dcount(IPAddress)
    by UserPrincipalName, UserDisplayName
| sort by SignInCount desc
| take 200
""", "idx-users-signinlogs")

        for row in rows:
            upn = row.get("UserPrincipalName", "") or row.get("_user", "")
            if not upn:
                continue
            index.identity.users.append(UserProfile(
                user_principal_name=upn,
                display_name=row.get("UserDisplayName", "") or "",
                is_service_account=_is_service_account(upn),
                sign_in_count_30d=int(float(row.get("SignInCount", 0))),
                distinct_ips_7d=int(float(row.get("DistinctIPs", 0))),
            ))

    def _check_mfa_status(self, index: EnvironmentIndex) -> None:
        rows = _query(self._adapter, """
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| summarize
    MFA=countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SFA=countif(AuthenticationRequirement == "singleFactorAuthentication")
    by UserPrincipalName
| extend MFAEnforced = (MFA > 0 and SFA == 0)
| project UserPrincipalName, MFAEnforced, MFA, SFA
| take 500
""", "idx-mfa-status")

        mfa_map = {r.get("UserPrincipalName", ""): r.get("MFAEnforced", False) for r in rows}
        mfa_count = 0
        for user in index.identity.users:
            if user.user_principal_name in mfa_map:
                user.mfa_enforced = bool(mfa_map[user.user_principal_name])
                if user.mfa_enforced:
                    mfa_count += 1
        total = len(index.identity.users) or 1
        index.identity.mfa_adoption_pct = round(mfa_count / total * 100, 1)

    def _build_asset_index(self, index: EnvironmentIndex) -> None:
        """Discover assets from Heartbeat, SecurityEvent, Syslog."""
        assets: dict[str, AssetProfile] = {}

        # Heartbeat (best source — has OS, version, agent)
        if index.telemetry.get_table("Heartbeat"):
            rows = _query(self._adapter, """
Heartbeat
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Computer
| project Computer, OSType, OSName, Version, Category
| take 500
""", "idx-assets-heartbeat")
            for row in rows:
                hostname = (row.get("Computer", "") or row.get("_hostname", "")).upper()
                if not hostname:
                    continue
                assets[hostname] = AssetProfile(
                    hostname=hostname,
                    os_type=row.get("OSType", "") or "",
                    os_version=row.get("OSName", "") or "",
                    agent_version=row.get("Version", "") or "",
                    edr_enrolled=True,
                    last_heartbeat=row.get("_timestamp", "") or "",
                )

        # SecurityEvent — find DCs via Kerberos events
        if index.telemetry.get_table("SecurityEvent"):
            rows = _query(self._adapter, """
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4768, 4769, 4770)
| distinct Computer
| take 50
""", "idx-dcs")
            for row in rows:
                hostname = (row.get("Computer", "") or row.get("_hostname", "")).upper()
                if not hostname:
                    continue
                if hostname in assets:
                    assets[hostname].is_domain_controller = True
                    assets[hostname].is_server = True
                    assets[hostname].is_critical = True
                else:
                    assets[hostname] = AssetProfile(
                        hostname=hostname,
                        is_domain_controller=True,
                        is_server=True,
                        is_critical=True,
                    )

        # Syslog — Linux hosts
        if index.telemetry.get_table("Syslog"):
            rows = _query(self._adapter, """
Syslog
| where TimeGenerated > ago(7d)
| distinct Computer
| take 200
""", "idx-linux-hosts")
            for row in rows:
                hostname = (row.get("Computer", "") or row.get("_hostname", "")).upper()
                if not hostname:
                    continue
                if hostname not in assets:
                    assets[hostname] = AssetProfile(
                        hostname=hostname,
                        os_type="Linux",
                    )

        asset_list = list(assets.values())
        index.assets = AssetIndex(
            assets=asset_list,
            total_assets=len(asset_list),
            windows_count=sum(1 for a in asset_list if a.os_type and a.os_type.lower() == "windows"),
            linux_count=sum(1 for a in asset_list if a.os_type and a.os_type.lower() == "linux"),
            domain_controllers=[a.hostname for a in asset_list if a.is_domain_controller],
            critical_assets=[a.hostname for a in asset_list if a.is_critical],
            edr_coverage_pct=round(
                sum(1 for a in asset_list if a.edr_enrolled) / max(len(asset_list), 1) * 100, 1
            ),
        )

    def _build_ingestion_baselines(self, index: EnvironmentIndex) -> None:
        rows = _query(self._adapter, """
Usage
| where TimeGenerated > ago(30d)
| summarize DailyMB=sum(Quantity) by DataType, bin(TimeGenerated, 1d)
| summarize AvgMB=avg(DailyMB), StdDev=stdev(DailyMB),
            MinMB=min(DailyMB), MaxMB=max(DailyMB),
            ZeroDays=countif(DailyMB == 0)
    by DataType
| sort by AvgMB desc
| take 50
""", "idx-baselines")
        for row in rows:
            dt = row.get("DataType", "")
            if not dt:
                continue
            index.telemetry.ingestion_baselines.append(IngestionBaseline(
                table_name=dt,
                avg_daily_mb=round(float(row.get("AvgMB", 0)), 2),
                stddev_daily_mb=round(float(row.get("StdDev", 0)), 2),
                min_daily_mb=round(float(row.get("MinMB", 0)), 2),
                max_daily_mb=round(float(row.get("MaxMB", 0)), 2),
                days_with_zero=int(float(row.get("ZeroDays", 0))),
            ))

    def _build_network_context(self, index: EnvironmentIndex) -> None:
        rows = _query(self._adapter, """
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| summarize Count=count() by IPAddress, Location
| sort by Count desc
| take 50
""", "idx-network")

        ips: list[dict[str, Any]] = []
        geo: dict[str, int] = {}
        locations: set[str] = set()
        for row in rows:
            ip = row.get("IPAddress", "")
            loc = row.get("Location", "") or ""
            cnt = int(float(row.get("Count", 0)))
            if ip:
                ips.append({"ip": ip, "location": loc, "count": cnt})
            if loc:
                geo[loc] = geo.get(loc, 0) + cnt
                locations.add(loc)

        index.network = NetworkContext(
            top_source_ips=ips[:20],
            geo_distribution=geo,
            known_locations=sorted(locations),
        )

    def _build_security_posture(self, index: EnvironmentIndex) -> None:
        # Incidents last 90 days
        if index.telemetry.get_table("SecurityIncident"):
            rows = _query(self._adapter, """
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize
    Total=count(),
    Open=countif(Status != "Closed"),
    BySeverity=make_bag(pack(Severity, 1))
""", "idx-incidents")
            if rows:
                r = rows[0]
                index.posture.incidents_last_90d = int(float(r.get("Total", 0)))
                index.posture.open_incidents = int(float(r.get("Open", 0)))

        # Top alert rules
        if index.telemetry.get_table("SecurityAlert"):
            rows = _query(self._adapter, """
SecurityAlert
| where TimeGenerated > ago(90d)
| summarize Count=count() by AlertName, AlertSeverity
| sort by Count desc
| take 20
""", "idx-alerts")
            index.posture.top_alert_rules = [
                {"name": r.get("AlertName", ""), "severity": r.get("AlertSeverity", ""),
                 "count": int(float(r.get("Count", 0)))}
                for r in rows
            ]

        # TI indicator count
        if index.telemetry.get_table("ThreatIntelIndicators") or index.telemetry.get_table("ThreatIntelligenceIndicator"):
            ti_table = "ThreatIntelIndicators" if index.telemetry.get_table("ThreatIntelIndicators") else "ThreatIntelligenceIndicator"
            rows = _query(self._adapter, f"""
{ti_table}
| where TimeGenerated > ago(90d)
| summarize Count=count()
""", "idx-ti-count")
            if rows:
                index.posture.ti_indicator_count = int(float(rows[0].get("Count", 0)))

    def _build_connector_health(self, index: EnvironmentIndex) -> None:
        if not index.telemetry.get_table("SentinelHealth"):
            return
        rows = _query(self._adapter, """
SentinelHealth
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "DataConnector"
| summarize arg_max(TimeGenerated, *) by SentinelResourceName
| project SentinelResourceName, Status
| take 50
""", "idx-connector-health")
        for row in rows:
            name = row.get("SentinelResourceName", "")
            status = row.get("Status", "")
            if name:
                index.telemetry.connector_health[name] = status

    # ── DYNAMIC LAYER (per-hunt, ~30 sec) ────────────────────────

    def build_dynamic(self, index: EnvironmentIndex) -> None:
        """Refresh dynamic layer: row counts, active incidents, recent changes."""
        now = datetime.now(timezone.utc).isoformat()

        self._refresh_row_counts(index)
        self._refresh_active_incidents(index)
        self._refresh_recent_changes(index)

        index.metadata.dynamic_refreshed_at = now
        logger.info("Dynamic layer refreshed")

    def _refresh_row_counts(self, index: EnvironmentIndex) -> None:
        """Update row counts for all known tables."""
        table_names = [t.table_name for t in index.telemetry.tables[:30]]
        if not table_names:
            return

        # Build a union query for efficiency
        union_parts = []
        for t in table_names:
            union_parts.append(
                f"{t} | where TimeGenerated > ago(30d) "
                f"| summarize R30d=count(), "
                f"R7d=countif(TimeGenerated > ago(7d)), "
                f"R24h=countif(TimeGenerated > ago(24h)) "
                f"| extend TableName='{t}'"
            )

        def _build_union_kql(parts: list[str]) -> str:
            """Build correct KQL union syntax: union (expr1), (expr2), ..."""
            wrapped = [f"({p})" for p in parts]
            return "union " + ", ".join(wrapped)

        if len(union_parts) > 10:
            # Split into batches to avoid query length limits
            for batch_start in range(0, len(union_parts), 10):
                batch = union_parts[batch_start:batch_start + 10]
                kql = _build_union_kql(batch)
                self._apply_row_counts(index, kql, batch_start)
        else:
            kql = _build_union_kql(union_parts)
            self._apply_row_counts(index, kql, 0)

    def _apply_row_counts(self, index: EnvironmentIndex, kql: str, batch_idx: int) -> None:
        rows = _query(self._adapter, kql, f"idx-rowcounts-{batch_idx}")
        for row in rows:
            table_name = row.get("TableName", "")
            tp = index.telemetry.get_table(table_name)
            if tp:
                tp.row_count_30d = int(float(row.get("R30d", 0)))
                tp.row_count_7d = int(float(row.get("R7d", 0)))
                tp.row_count_24h = int(float(row.get("R24h", 0)))
                tp.ingestion_healthy = tp.row_count_24h > 0

    def _refresh_active_incidents(self, index: EnvironmentIndex) -> None:
        if not index.telemetry.get_table("SecurityIncident"):
            return
        rows = _query(self._adapter, """
SecurityIncident
| where Status != "Closed"
| project IncidentNumber, Title, Severity, Status, CreatedTime
| sort by CreatedTime desc
| take 20
""", "idx-active-incidents")
        index.posture.active_incidents = [
            {"number": r.get("IncidentNumber", ""), "title": r.get("Title", ""),
             "severity": r.get("Severity", ""), "status": r.get("Status", "")}
            for r in rows
        ]

    def _refresh_recent_changes(self, index: EnvironmentIndex) -> None:
        """Check for recent role changes, new apps, etc."""
        if not index.telemetry.get_table("AuditLogs"):
            return
        rows = _query(self._adapter, """
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add member to role", "Add application",
    "Add service principal", "Add owner", "Update application")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| sort by TimeGenerated desc
| take 20
""", "idx-recent-changes")
        index.posture.recent_alerts_24h = [
            {"operation": r.get("OperationName", ""), "time": r.get("_timestamp", ""),
             "initiated_by": str(r.get("InitiatedBy", ""))}
            for r in rows
        ]


# ── Helpers ──────────────────────────────────────────────────────────

def _is_service_account(upn: str) -> bool:
    """Heuristic: detect service accounts by UPN pattern."""
    lower = upn.lower()
    return any(pattern in lower for pattern in [
        "svc", "service", "noreply", "mailbox", "system", "sync",
        "automation", "bot", "api", "app@", "scanner",
    ])
