"""Environment Index models — cached knowledge about a client's Sentinel workspace.

Three refresh layers:
- STATIC (monthly):  table schemas, MITRE coverage, org context
- SEMI_STATIC (weekly): users, assets, baselines, posture
- DYNAMIC (per-hunt):  row counts, active incidents, recent changes
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Refresh layer enum ────────────────────────────────────────────────

class IndexRefreshLayer(str, Enum):
    STATIC = "static"           # monthly
    SEMI_STATIC = "semi_static"  # weekly
    DYNAMIC = "dynamic"          # per-hunt (~30s)


# ── Metadata ──────────────────────────────────────────────────────────

class IndexMetadata(BaseModel):
    """Tracks when each layer was last refreshed."""

    client_id: str
    workspace_id: str = ""
    index_version: int = 1
    static_refreshed_at: str = ""
    semi_static_refreshed_at: str = ""
    dynamic_refreshed_at: str = ""
    total_tables: int = 0
    total_users: int = 0
    total_assets: int = 0


# ── Telemetry layer ──────────────────────────────────────────────────

class TableProfile(BaseModel):
    """Profile of a single Sentinel / Log Analytics table."""

    table_name: str
    # Static (monthly) — schema doesn't change often
    columns: list[str] = Field(default_factory=list)
    column_types: dict[str, str] = Field(default_factory=dict)
    mitre_data_sources: list[str] = Field(default_factory=list)
    mitre_techniques_covered: list[str] = Field(default_factory=list)

    # Semi-static (weekly) — baselines shift slowly
    avg_daily_events: float = 0.0
    first_event_seen: str = ""
    last_event_seen: str = ""
    ingestion_healthy: bool = True
    key_fields: list[str] = Field(default_factory=list)
    sample_values: dict[str, list[str]] = Field(default_factory=dict)

    # Dynamic (per-hunt) — changes constantly
    row_count_24h: int = 0
    row_count_7d: int = 0
    row_count_30d: int = 0


class IngestionBaseline(BaseModel):
    """Daily ingestion baseline for anomaly detection."""

    table_name: str
    avg_daily_mb: float = 0.0
    stddev_daily_mb: float = 0.0
    min_daily_mb: float = 0.0
    max_daily_mb: float = 0.0
    days_with_zero: int = 0
    baseline_period_days: int = 30


class TelemetryIndex(BaseModel):
    """All telemetry knowledge for a client workspace."""

    tables: list[TableProfile] = Field(default_factory=list)
    ingestion_baselines: list[IngestionBaseline] = Field(default_factory=list)
    connector_health: dict[str, str] = Field(default_factory=dict)
    active_analytics_rules: list[dict[str, Any]] = Field(default_factory=list)
    # MITRE coverage computed from table profiles
    mitre_coverage: dict[str, list[str]] = Field(default_factory=dict)
    mitre_gaps: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def table_names(self) -> list[str]:
        return [t.table_name for t in self.tables]

    def get_table(self, name: str) -> Optional[TableProfile]:
        for t in self.tables:
            if t.table_name.lower() == name.lower():
                return t
        return None

    @property
    def healthy_tables(self) -> list[str]:
        return [t.table_name for t in self.tables if t.ingestion_healthy and t.row_count_7d > 0]


# ── Identity layer ───────────────────────────────────────────────────

class UserProfile(BaseModel):
    """A user discovered from Sentinel identity tables."""

    user_principal_name: str
    display_name: str = ""
    # Semi-static (weekly)
    is_admin: bool = False
    admin_roles: list[str] = Field(default_factory=list)
    is_service_account: bool = False
    is_guest: bool = False
    is_enabled: bool = True
    department: str = ""
    job_title: str = ""
    risk_level: str = ""  # from IdentityInfo / BehaviorAnalytics
    # Dynamic
    sign_in_count_7d: int = 0
    sign_in_count_30d: int = 0
    distinct_ips_7d: int = 0
    last_sign_in: str = ""
    mfa_enforced: bool = False
    legacy_auth_used: bool = False


class IdentityIndex(BaseModel):
    """All identity knowledge for a client."""

    users: list[UserProfile] = Field(default_factory=list)
    total_users: int = 0
    admin_count: int = 0
    guest_count: int = 0
    service_account_count: int = 0
    stale_account_count: int = 0
    mfa_adoption_pct: float = 0.0
    legacy_auth_user_count: int = 0
    risky_users: list[str] = Field(default_factory=list)

    @property
    def admin_accounts(self) -> list[str]:
        return [u.user_principal_name for u in self.users if u.is_admin]

    @property
    def service_accounts(self) -> list[str]:
        return [u.user_principal_name for u in self.users if u.is_service_account]


# ── Asset layer ──────────────────────────────────────────────────────

class AssetProfile(BaseModel):
    """A host / device discovered from Sentinel tables."""

    hostname: str
    os_type: str = ""  # Windows, Linux, etc.
    os_version: str = ""
    # Semi-static
    is_server: bool = False
    is_domain_controller: bool = False
    is_critical: bool = False
    edr_enrolled: bool = False
    agent_version: str = ""
    last_heartbeat: str = ""
    # Dynamic
    event_count_7d: int = 0
    event_sources: list[str] = Field(default_factory=list)


class AssetIndex(BaseModel):
    """All asset knowledge for a client."""

    assets: list[AssetProfile] = Field(default_factory=list)
    total_assets: int = 0
    windows_count: int = 0
    linux_count: int = 0
    domain_controllers: list[str] = Field(default_factory=list)
    critical_assets: list[str] = Field(default_factory=list)
    edr_coverage_pct: float = 0.0
    unmanaged_assets: list[str] = Field(default_factory=list)


# ── Network context ─────────────────────────────────────────────────

class NetworkContext(BaseModel):
    """Network intelligence derived from Sentinel logs."""

    # Semi-static (weekly)
    known_ip_ranges: list[str] = Field(default_factory=list)
    top_source_ips: list[dict[str, Any]] = Field(default_factory=list)
    geo_distribution: dict[str, int] = Field(default_factory=dict)
    known_locations: list[str] = Field(default_factory=list)
    vpn_indicators: list[str] = Field(default_factory=list)


# ── Security posture ────────────────────────────────────────────────

class SecurityPosture(BaseModel):
    """Security posture from incidents, alerts, and UEBA."""

    # Semi-static (weekly)
    open_incidents: int = 0
    incidents_last_90d: int = 0
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    incidents_by_tactic: dict[str, int] = Field(default_factory=dict)
    top_alert_rules: list[dict[str, Any]] = Field(default_factory=list)
    ti_indicator_count: int = 0
    ueba_anomaly_count: int = 0
    # Dynamic (per-hunt)
    active_incidents: list[dict[str, Any]] = Field(default_factory=list)
    recent_alerts_24h: list[dict[str, Any]] = Field(default_factory=list)


# ── Org context (manual / inferred) ─────────────────────────────────

class OrgContext(BaseModel):
    """Organizational context — some manual, some inferred."""

    industry: str = ""
    company_size: str = ""  # small, medium, large, enterprise
    domains: list[str] = Field(default_factory=list)
    risk_appetite: str = ""  # conservative, moderate, aggressive
    compliance_frameworks: list[str] = Field(default_factory=list)
    crown_jewels: list[str] = Field(default_factory=list)
    notes: str = ""


# ── Top-level index ─────────────────────────────────────────────────

class EnvironmentIndex(BaseModel):
    """Complete environment knowledge for a client — the central data structure.

    Three refresh cadences:
    - Static fields:      monthly rebuild (table schemas, MITRE maps)
    - Semi-static fields: weekly refresh (users, assets, baselines, posture)
    - Dynamic fields:     per-hunt refresh (row counts, active incidents)
    """

    metadata: IndexMetadata
    telemetry: TelemetryIndex = Field(default_factory=TelemetryIndex)
    identity: IdentityIndex = Field(default_factory=IdentityIndex)
    assets: AssetIndex = Field(default_factory=AssetIndex)
    network: NetworkContext = Field(default_factory=NetworkContext)
    posture: SecurityPosture = Field(default_factory=SecurityPosture)
    org: OrgContext = Field(default_factory=OrgContext)

    def summary(self) -> dict[str, Any]:
        """Compact summary for injection into LLM system prompts."""
        return {
            "workspace_id": self.metadata.workspace_id,
            "tables": len(self.telemetry.tables),
            "healthy_tables": self.telemetry.healthy_tables,
            "total_users": self.identity.total_users,
            "admin_count": self.identity.admin_count,
            "guest_count": self.identity.guest_count,
            "service_accounts": self.identity.service_account_count,
            "mfa_adoption_pct": self.identity.mfa_adoption_pct,
            "total_assets": self.assets.total_assets,
            "domain_controllers": self.assets.domain_controllers,
            "edr_coverage_pct": self.assets.edr_coverage_pct,
            "open_incidents": self.posture.open_incidents,
            "incidents_90d": self.posture.incidents_last_90d,
            "ti_indicators": self.posture.ti_indicator_count,
            "mitre_gaps": {k: len(v) for k, v in self.telemetry.mitre_gaps.items()},
            "industry": self.org.industry,
        }

    def rich_summary(self) -> dict[str, Any]:
        """Detailed environment summary for LLM hunt phases.

        Unlike summary(), this includes table schemas, admin identities,
        critical assets, active incidents, and MITRE gap details — giving
        the LLM enough context to generate targeted hypotheses and queries.
        """
        # Table profiles: name, key columns, MITRE coverage, row counts
        table_profiles = []
        for t in self.telemetry.tables:
            if not t.ingestion_healthy or t.row_count_7d == 0:
                continue
            profile: dict[str, Any] = {
                "table": t.table_name,
                "columns": t.key_fields if t.key_fields else t.columns[:20],
                "mitre_techniques": t.mitre_techniques_covered[:10],
                "row_count_7d": t.row_count_7d,
                "row_count_30d": t.row_count_30d,
            }
            if t.sample_values:
                # Include up to 3 sample value fields to ground the LLM
                profile["sample_values"] = {
                    k: v[:5] for k, v in list(t.sample_values.items())[:3]
                }
            table_profiles.append(profile)

        # Admin and risky user identities (names, not just counts)
        admin_users = [
            {
                "upn": u.user_principal_name,
                "roles": u.admin_roles[:3],
                "mfa": u.mfa_enforced,
                "risk_level": u.risk_level,
                "sign_ins_7d": u.sign_in_count_7d,
                "distinct_ips_7d": u.distinct_ips_7d,
            }
            for u in self.identity.users
            if u.is_admin
        ][:15]  # Cap at 15 to avoid prompt bloat

        risky_users = [
            {
                "upn": u.user_principal_name,
                "risk_level": u.risk_level,
                "legacy_auth": u.legacy_auth_used,
                "mfa": u.mfa_enforced,
            }
            for u in self.identity.users
            if u.risk_level in ("high", "critical") or u.legacy_auth_used
        ][:10]

        service_accounts = [
            {
                "upn": u.user_principal_name,
                "mfa": u.mfa_enforced,
                "sign_ins_7d": u.sign_in_count_7d,
            }
            for u in self.identity.users
            if u.is_service_account
        ][:10]

        # Critical assets with detail
        critical_assets = [
            {
                "hostname": a.hostname,
                "os": f"{a.os_type} {a.os_version}".strip(),
                "is_dc": a.is_domain_controller,
                "edr": a.edr_enrolled,
                "events_7d": a.event_count_7d,
            }
            for a in self.assets.assets
            if a.is_critical or a.is_domain_controller
        ][:10]

        unmanaged = self.assets.unmanaged_assets[:10]

        # Active incidents with detail (not just count)
        active_incidents = [
            {
                "title": inc.get("title", ""),
                "severity": inc.get("severity", ""),
                "tactics": inc.get("tactics", []),
                "status": inc.get("status", ""),
            }
            for inc in self.posture.active_incidents[:10]
        ]

        # Full MITRE gap details (technique IDs, not just counts)
        mitre_gaps_detail: dict[str, list[str]] = {}
        for tactic, techniques in self.telemetry.mitre_gaps.items():
            mitre_gaps_detail[tactic] = techniques[:10]

        # Network context
        network = {
            "known_ip_ranges": self.network.known_ip_ranges[:10],
            "known_locations": self.network.known_locations[:10],
            "geo_distribution": dict(list(self.network.geo_distribution.items())[:10]),
        }

        # Org context
        org = {
            "industry": self.org.industry,
            "company_size": self.org.company_size,
            "compliance": self.org.compliance_frameworks,
            "crown_jewels": self.org.crown_jewels,
            "risk_appetite": self.org.risk_appetite,
        }

        return {
            "workspace_id": self.metadata.workspace_id,
            "table_profiles": table_profiles,
            "healthy_tables": self.telemetry.healthy_tables,
            "identity": {
                "total_users": self.identity.total_users,
                "admin_users": admin_users,
                "risky_users": risky_users,
                "service_accounts": service_accounts,
                "mfa_adoption_pct": self.identity.mfa_adoption_pct,
                "legacy_auth_users": self.identity.legacy_auth_user_count,
                "stale_accounts": self.identity.stale_account_count,
                "guest_count": self.identity.guest_count,
            },
            "assets": {
                "total": self.assets.total_assets,
                "critical_assets": critical_assets,
                "domain_controllers": self.assets.domain_controllers,
                "unmanaged": unmanaged,
                "edr_coverage_pct": self.assets.edr_coverage_pct,
            },
            "network": network,
            "posture": {
                "open_incidents": self.posture.open_incidents,
                "active_incidents": active_incidents,
                "incidents_90d": self.posture.incidents_last_90d,
                "incidents_by_severity": self.posture.incidents_by_severity,
                "incidents_by_tactic": self.posture.incidents_by_tactic,
                "top_alert_rules": [
                    r.get("name", "") for r in self.posture.top_alert_rules[:5]
                ],
                "ti_indicators": self.posture.ti_indicator_count,
                "ueba_anomalies": self.posture.ueba_anomaly_count,
            },
            "mitre_gaps": mitre_gaps_detail,
            "org": org,
        }
