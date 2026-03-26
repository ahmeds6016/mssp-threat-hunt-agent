"""Profile engine — generate profiling queries, build structured telemetry profile."""

from __future__ import annotations

import hashlib
import logging
import random
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any

from mssp_hunt_agent.models.hunt_models import (
    ExabeamQuery,
    HuntHypothesis,
    HuntPlan,
    HuntStep,
    QueryIntent,
    TelemetryAssessment,
    TelemetryReadiness,
)
from mssp_hunt_agent.models.input_models import HuntType
from mssp_hunt_agent.models.profile_models import (
    ClientTelemetryProfile,
    DataSourceProfile,
    HuntCapability,
    ParsedFieldInfo,
    ProfileInput,
)
from mssp_hunt_agent.models.result_models import QueryResult
from mssp_hunt_agent.pipeline.intake import EXPECTED_SOURCES

logger = logging.getLogger(__name__)

# ── Pluggable query strategy ─────────────────────────────────────────


class ProfileQueryStrategy(ABC):
    """Pluggable strategy for generating profiling queries."""

    @abstractmethod
    def source_discovery_queries(self, profile_input: ProfileInput) -> list[ExabeamQuery]:
        """Queries to discover what log source types exist."""

    @abstractmethod
    def field_population_queries(self, profile_input: ProfileInput) -> list[ExabeamQuery]:
        """Queries to assess parsed field coverage."""

    @abstractmethod
    def recency_queries(self, profile_input: ProfileInput) -> list[ExabeamQuery]:
        """Queries to check when data sources were last active."""

    @abstractmethod
    def category_mapping_queries(self, profile_input: ProfileInput) -> list[ExabeamQuery]:
        """Queries to map sources into hunt-type categories."""


class ParsedFieldStrategy(ProfileQueryStrategy):
    """Default: parsed-field-oriented profiling queries."""

    def source_discovery_queries(self, pi: ProfileInput) -> list[ExabeamQuery]:
        return [
            ExabeamQuery(
                query_id=f"Q-PROF-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent.BASELINE,
                description="Source discovery — vendor/product/activity_type breakdown",
                query_text=(
                    f'activity_type = "*" '
                    f'| where time >= "{pi.time_range}" '
                    f'| stats count as event_count by vendor, product, activity_type '
                    f'| sort -event_count '
                    f'| head 200'
                ),
                time_range=pi.time_range,
                expected_signal="List of all log sources/vendors/products with event counts",
            ),
            ExabeamQuery(
                query_id=f"Q-PROF-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent.BASELINE,
                description="Source discovery — event_type distribution",
                query_text=(
                    f'activity_type = "*" '
                    f'| where time >= "{pi.time_range}" '
                    f'| stats count as event_count by event_type '
                    f'| sort -event_count '
                    f'| head 100'
                ),
                time_range=pi.time_range,
                expected_signal="Distribution of event types in the environment",
            ),
        ]

    def field_population_queries(self, pi: ProfileInput) -> list[ExabeamQuery]:
        field_clusters = [
            ("identity_fields", ["user", "src_ip", "country", "user_agent"]),
            ("endpoint_fields", ["hostname", "process_name", "command_line", "file_hash"]),
            ("network_fields", ["src_ip", "dst_ip", "domain", "dst_port"]),
            ("cloud_fields", ["cloud_provider", "resource_type", "action", "region"]),
        ]
        queries: list[ExabeamQuery] = []
        for cluster_name, fields in field_clusters:
            field_stats = ", ".join(f"count({f}) as {f}_pop" for f in fields)
            queries.append(ExabeamQuery(
                query_id=f"Q-PROF-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent.BASELINE,
                description=f"Field population — {cluster_name}",
                query_text=(
                    f'activity_type = "*" '
                    f'| where time >= "{pi.time_range}" '
                    f'| stats count as total, {field_stats} '
                    f'| head 1'
                ),
                time_range=pi.time_range,
                expected_signal=f"Population percentages for {cluster_name}",
            ))
        return queries

    def recency_queries(self, pi: ProfileInput) -> list[ExabeamQuery]:
        return [
            ExabeamQuery(
                query_id=f"Q-PROF-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent.BASELINE,
                description="Recency check — last event per source type",
                query_text=(
                    f'activity_type = "*" '
                    f'| where time >= "{pi.time_range}" '
                    f'| stats max(timestamp) as last_event, '
                    f'min(timestamp) as first_event, '
                    f'dc(timestamp) as days_active '
                    f'by vendor, product '
                    f'| sort -last_event '
                    f'| head 100'
                ),
                time_range=pi.time_range,
                expected_signal="First/last event timestamps per source",
            ),
        ]

    def category_mapping_queries(self, pi: ProfileInput) -> list[ExabeamQuery]:
        return []


# ── Source-to-category keyword mapping ────────────────────────────────

_SOURCE_CATEGORY_KEYWORDS: dict[HuntType, list[str]] = {
    HuntType.IDENTITY: [
        "sign-in", "signin", "auth", "login", "sso", "mfa", "vpn",
        "active directory", "azure ad", "okta", "casb", "saml", "ldap",
    ],
    HuntType.ENDPOINT: [
        "edr", "sysmon", "windows event", "powershell", "antivirus",
        "endpoint", "process", "carbon black", "crowdstrike", "sentinel one",
    ],
    HuntType.NETWORK: [
        "firewall", "dns", "proxy", "web-filter", "netflow", "ipfix",
        "ids", "ips", "snort", "suricata", "zeek", "pcap",
    ],
    HuntType.CLOUD: [
        "cloudtrail", "activity log", "vpc flow", "cloud audit",
        "iam", "container", "kubernetes", "aws", "azure", "gcp",
    ],
}


def _classify_source_category(source_name: str) -> HuntType:
    """Map a discovered source name to a hunt-type category."""
    lower = source_name.lower()
    for hunt_type, keywords in _SOURCE_CATEGORY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return hunt_type
    return HuntType.IDENTITY


# ── Plan generation ──────────────────────────────────────────────────


def generate_profile_plan(
    profile_input: ProfileInput,
    strategy: ProfileQueryStrategy | None = None,
) -> HuntPlan:
    """Generate a HuntPlan containing profiling queries."""
    if strategy is None:
        strategy = ParsedFieldStrategy()

    all_queries = (
        strategy.source_discovery_queries(profile_input)
        + strategy.field_population_queries(profile_input)
        + strategy.recency_queries(profile_input)
        + strategy.category_mapping_queries(profile_input)
    )

    steps = _build_profile_steps(all_queries)

    hypothesis = HuntHypothesis(
        hypothesis_id=f"H-PROF-{uuid.uuid4().hex[:8]}",
        description=(
            f"Telemetry profiling for {profile_input.client_name}: "
            f"discover log sources, assess field population, check recency"
        ),
        attack_tactics=["Telemetry Profiling"],
        attack_techniques=[],
        technique_source="profile_mode",
        confidence="high",
        rationale="Profiling queries — no threat hypothesis; mapping the environment.",
    )

    telemetry = TelemetryAssessment(
        readiness=TelemetryReadiness.YELLOW,
        rationale="Profiling run — readiness will be determined after execution.",
        available_sources=list(profile_input.declared_data_sources),
        missing_sources=[],
        impact_on_hunt="This is a profiling run, not a threat hunt.",
    )

    return HuntPlan(
        plan_id=f"HP-PROF-{uuid.uuid4().hex[:8]}",
        client_name=profile_input.client_name,
        hunt_type="profile",
        objective=f"Build client telemetry profile for {profile_input.client_name}",
        hypotheses=[hypothesis],
        telemetry_assessment=telemetry,
        hunt_steps=steps,
        triage_checklist=["Review discovered sources against client documentation"],
        escalation_criteria=["N/A — profiling only"],
        expected_false_positives=["N/A — profiling only"],
        constraints=profile_input.constraints or ["None specified"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _build_profile_steps(queries: list[ExabeamQuery]) -> list[HuntStep]:
    """Group profiling queries into logical steps."""
    discovery = [q for q in queries if "discovery" in q.description.lower()]
    field_pop = [q for q in queries if "field population" in q.description.lower()]
    recency = [q for q in queries if "recency" in q.description.lower()]
    other = [q for q in queries if q not in discovery + field_pop + recency]

    steps: list[HuntStep] = []
    step_num = 0

    for label, group in [
        ("Source Discovery", discovery),
        ("Field Population Assessment", field_pop),
        ("Recency Check", recency),
        ("Additional Profiling", other),
    ]:
        if not group:
            continue
        step_num += 1
        steps.append(HuntStep(
            step_number=step_num,
            description=f"{label} — {len(group)} profiling queries",
            queries=group,
            success_criteria=f"{label} queries return data",
            next_if_positive="Proceed to next profiling stage",
            next_if_negative="Document missing data and proceed",
        ))

    return steps


# ── Result parsing ───────────────────────────────────────────────────


def parse_profile_results(
    query_results: list[QueryResult],
    profile_input: ProfileInput,
    mock_mode: bool = True,
) -> list[DataSourceProfile]:
    """Parse query results into structured DataSourceProfile objects."""
    if mock_mode:
        return mock_build_profiles(profile_input)
    return _live_parse_profiles(query_results, profile_input)


def _live_parse_profiles(
    query_results: list[QueryResult],
    profile_input: ProfileInput,
) -> list[DataSourceProfile]:
    """Parse real Exabeam query results into DataSourceProfiles."""
    # Future: iterate query_results, extract vendor/product/event_count
    # from stats-based source discovery results.
    profiles: list[DataSourceProfile] = []
    return profiles


# ── Mock profile builder ─────────────────────────────────────────────

_MOCK_SOURCE_CATALOG: list[dict[str, Any]] = [
    {
        "source_name": "Azure AD sign-in logs",
        "vendor": "Microsoft",
        "product": "Azure Active Directory",
        "category": HuntType.IDENTITY,
        "event_count_range": (50_000, 200_000),
        "fields": [
            ("user", 98.0, ["jsmith", "m.jones", "admin.svc"]),
            ("src_ip", 95.0, ["10.10.5.22", "192.168.1.105", "203.0.113.77"]),
            ("country", 85.0, ["US", "CA", "GB", "DE"]),
            ("user_agent", 72.0, ["Mozilla/5.0", "python-requests/2.31.0"]),
            ("result", 99.0, ["success", "failure"]),
        ],
    },
    {
        "source_name": "VPN logs",
        "vendor": "Cisco",
        "product": "AnyConnect",
        "category": HuntType.IDENTITY,
        "event_count_range": (10_000, 50_000),
        "fields": [
            ("user", 99.0, ["jsmith", "c.rodriguez"]),
            ("src_ip", 100.0, ["198.51.100.12", "203.0.113.77"]),
            ("dst_ip", 100.0, ["10.0.0.1"]),
            ("session_duration", 80.0, ["3600", "7200"]),
        ],
    },
    {
        "source_name": "MFA logs",
        "vendor": "Microsoft",
        "product": "Azure MFA",
        "category": HuntType.IDENTITY,
        "event_count_range": (5_000, 30_000),
        "fields": [
            ("user", 100.0, ["jsmith", "m.jones"]),
            ("result", 100.0, ["success", "denied", "timeout"]),
            ("method", 90.0, ["push", "sms", "phone"]),
        ],
    },
    {
        "source_name": "EDR telemetry",
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "category": HuntType.ENDPOINT,
        "event_count_range": (100_000, 500_000),
        "fields": [
            ("hostname", 99.0, ["WS-PC0012", "SRV-DC01"]),
            ("process_name", 95.0, ["powershell.exe", "cmd.exe", "svchost.exe"]),
            ("command_line", 60.0, ["Get-Process", "dir /s"]),
            ("file_hash", 45.0, ["e99a18c428cb38d5f260853678922e03"]),
            ("user", 90.0, ["jsmith", "SYSTEM"]),
        ],
    },
    {
        "source_name": "Windows event logs",
        "vendor": "Microsoft",
        "product": "Windows Security",
        "category": HuntType.ENDPOINT,
        "event_count_range": (200_000, 800_000),
        "fields": [
            ("hostname", 100.0, ["SRV-DC01", "WS-PC0087"]),
            ("user", 85.0, ["jsmith", "admin.svc"]),
            ("event_type", 100.0, ["4624", "4625", "4688"]),
            ("process_name", 40.0, ["powershell.exe"]),
        ],
    },
    {
        "source_name": "Firewall logs",
        "vendor": "Palo Alto",
        "product": "PAN-OS",
        "category": HuntType.NETWORK,
        "event_count_range": (500_000, 2_000_000),
        "fields": [
            ("src_ip", 100.0, ["10.10.5.22", "192.168.1.105"]),
            ("dst_ip", 100.0, ["52.96.166.130", "10.0.0.50"]),
            ("dst_port", 99.0, ["443", "80", "53"]),
            ("action", 100.0, ["allow", "deny"]),
        ],
    },
    {
        "source_name": "DNS logs",
        "vendor": "Infoblox",
        "product": "DNS Firewall",
        "category": HuntType.NETWORK,
        "event_count_range": (300_000, 1_000_000),
        "fields": [
            ("domain", 100.0, ["corp.local", "login.microsoftonline.com"]),
            ("src_ip", 98.0, ["10.10.5.22"]),
            ("query_type", 95.0, ["A", "AAAA", "MX", "TXT"]),
            ("response_code", 90.0, ["NOERROR", "NXDOMAIN"]),
        ],
    },
    {
        "source_name": "CloudTrail / Activity Log",
        "vendor": "AWS",
        "product": "CloudTrail",
        "category": HuntType.CLOUD,
        "event_count_range": (20_000, 100_000),
        "fields": [
            ("user", 95.0, ["arn:aws:iam::root", "deploy-svc"]),
            ("action", 100.0, ["AssumeRole", "CreateInstance"]),
            ("region", 98.0, ["us-east-1", "eu-west-1"]),
            ("src_ip", 80.0, ["10.10.5.22"]),
        ],
    },
]


def mock_build_profiles(profile_input: ProfileInput) -> list[DataSourceProfile]:
    """Build realistic mock DataSourceProfile objects.

    Deterministic: same client_name always produces the same profile.
    """
    seed = int(hashlib.md5(profile_input.client_name.encode()).hexdigest(), 16)
    rng = random.Random(seed)

    num_sources = rng.randint(5, len(_MOCK_SOURCE_CATALOG))
    selected = rng.sample(_MOCK_SOURCE_CATALOG, num_sources)

    base_time = datetime.now(timezone.utc)
    profiles: list[DataSourceProfile] = []

    for src in selected:
        lo, hi = src["event_count_range"]
        event_count = rng.randint(lo, hi)

        days_back = rng.choice([1, 1, 2, 3, 3, 14, 30])
        last_seen = (base_time - timedelta(days=days_back)).isoformat()
        first_seen = (base_time - timedelta(days=30)).isoformat()
        days_active = rng.randint(max(1, 30 - days_back), 30)

        parsed_fields: list[ParsedFieldInfo] = []
        for field_name, base_pop, samples in src["fields"]:
            pop_pct = min(100.0, max(0.0, base_pop + rng.uniform(-5, 5)))
            null_pct = 100.0 - pop_pct
            parsed_fields.append(ParsedFieldInfo(
                field_name=field_name,
                population_pct=round(pop_pct, 1),
                sample_values=samples[:5],
                null_pct=round(null_pct, 1),
                distinct_count_approx=rng.randint(10, 10_000),
            ))

        profiles.append(DataSourceProfile(
            source_name=src["source_name"],
            vendor=src["vendor"],
            product=src["product"],
            category=src["category"],
            event_count=event_count,
            first_seen=first_seen,
            last_seen=last_seen,
            days_active=days_active,
            parsed_fields=parsed_fields,
            is_simulated=True,
        ))

    return profiles


# ── Capability classification ─────────────────────────────────────────


def classify_capabilities(
    discovered_sources: list[DataSourceProfile],
    hunt_types: list[HuntType] | None = None,
) -> list[HuntCapability]:
    """Classify Green/Yellow/Red readiness per hunt type.

    Uses EXPECTED_SOURCES from intake.py with thresholds:
      >=80% -> Green, >=40% -> Yellow, <40% -> Red.
    Green is downgraded to Yellow if key fields have <30% population.
    """
    if hunt_types is None:
        hunt_types = list(HuntType)

    discovered_lower = {ds.source_name.lower(): ds for ds in discovered_sources}
    sources_by_category: dict[HuntType, list[DataSourceProfile]] = {}
    for ds in discovered_sources:
        sources_by_category.setdefault(ds.category, []).append(ds)

    capabilities: list[HuntCapability] = []

    for ht in hunt_types:
        expected = EXPECTED_SOURCES.get(ht, [])
        present = [s for s in expected if s.lower() in discovered_lower]
        missing = [s for s in expected if s.lower() not in discovered_lower]

        coverage = len(present) / max(len(expected), 1) * 100.0

        field_notes: list[str] = []
        for ds in sources_by_category.get(ht, []):
            for pf in ds.parsed_fields:
                if pf.population_pct < 30.0:
                    field_notes.append(
                        f"{ds.source_name}: field '{pf.field_name}' has only "
                        f"{pf.population_pct:.0f}% population"
                    )

        if coverage >= 80.0 and not field_notes:
            readiness = TelemetryReadiness.GREEN
            rationale = (
                f"{len(present)}/{len(expected)} expected sources discovered. "
                f"Sufficient telemetry for meaningful {ht.value} hunting."
            )
        elif coverage >= 40.0:
            readiness = TelemetryReadiness.YELLOW
            rationale = (
                f"{len(present)}/{len(expected)} expected sources discovered. "
                f"Partial coverage — {ht.value} hunt possible but limited."
            )
            if field_notes:
                rationale += f" Field quality concerns: {len(field_notes)} issue(s)."
        else:
            readiness = TelemetryReadiness.RED
            rationale = (
                f"Only {len(present)}/{len(expected)} expected sources discovered. "
                f"Major gaps limit {ht.value} hunt effectiveness."
            )

        # Field quality can downgrade Green -> Yellow
        if readiness == TelemetryReadiness.GREEN and field_notes:
            readiness = TelemetryReadiness.YELLOW
            rationale += " Downgraded due to low field population quality."

        capabilities.append(HuntCapability(
            hunt_type=ht,
            readiness=readiness,
            available_sources=[ds.source_name for ds in sources_by_category.get(ht, [])],
            missing_sources=missing,
            coverage_pct=round(coverage, 1),
            field_quality_notes=field_notes,
            rationale=rationale,
        ))

    return capabilities


# ── Full profile assembly ─────────────────────────────────────────────


def build_profile(
    profile_input: ProfileInput,
    discovered_sources: list[DataSourceProfile],
    capabilities: list[HuntCapability],
    execution_mode: str,
) -> ClientTelemetryProfile:
    """Assemble the final ClientTelemetryProfile."""
    discovered_names_lower = {ds.source_name.lower() for ds in discovered_sources}
    declared_gaps = [
        ds for ds in profile_input.declared_data_sources
        if ds.lower() not in discovered_names_lower
    ]

    recency_warnings: list[str] = []
    for ds in discovered_sources:
        if ds.last_seen:
            try:
                last = datetime.fromisoformat(ds.last_seen.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - last).days
                if age > 7:
                    recency_warnings.append(
                        f"{ds.source_name}: last event was {age} days ago"
                    )
            except (ValueError, TypeError):
                pass

    caveats: list[str] = []
    if execution_mode == "mock":
        caveats.append(
            "SIMULATED DATA — This profile was built from mock/synthetic data. "
            "Do not use for production hunt planning without a live re-run."
        )

    return ClientTelemetryProfile(
        profile_id=f"PROF-{uuid.uuid4().hex[:8]}",
        client_name=profile_input.client_name,
        time_range=profile_input.time_range,
        execution_mode=execution_mode,
        created_at=datetime.now(timezone.utc).isoformat(),
        is_simulated=(execution_mode == "mock"),
        data_sources=discovered_sources,
        total_event_count=sum(ds.event_count for ds in discovered_sources),
        source_count=len(discovered_sources),
        capabilities=capabilities,
        declared_vs_discovered_gaps=declared_gaps,
        recency_warnings=recency_warnings,
        caveats=caveats,
        analyst_notes=profile_input.analyst_notes,
    )
