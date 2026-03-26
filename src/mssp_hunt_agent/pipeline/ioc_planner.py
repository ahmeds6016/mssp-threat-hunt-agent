"""IOC planner — generate Exabeam sweep queries grouped by IOC type."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mssp_hunt_agent.models.hunt_models import (
    ExabeamQuery,
    HuntPlan,
    HuntStep,
    HuntHypothesis,
    QueryIntent,
    TelemetryAssessment,
)
from mssp_hunt_agent.models.ioc_models import IOCBatch, IOCHuntInput, IOCType, NormalizedIOC


# ── Field mappings per IOC type ───────────────────────────────────────
# Maps IOC types to the Exabeam parsed fields we search against.
# Each entry: (primary_field, secondary_field_or_None)

_FIELD_MAP: dict[IOCType, tuple[str, str | None]] = {
    IOCType.IP: ("src_ip", "dst_ip"),
    IOCType.DOMAIN: ("domain", "hostname"),
    IOCType.HASH_MD5: ("file_hash", None),
    IOCType.HASH_SHA1: ("file_hash", None),
    IOCType.HASH_SHA256: ("file_hash", None),
    IOCType.EMAIL: ("user", None),
    IOCType.URL: ("url", None),
    IOCType.USER_AGENT: ("user_agent", None),
}

_REQUIRED_SOURCES: dict[IOCType, list[str]] = {
    IOCType.IP: ["Firewall logs", "Proxy / web-filter logs", "VPN logs", "Azure AD sign-in logs"],
    IOCType.DOMAIN: ["DNS logs", "Proxy / web-filter logs"],
    IOCType.HASH_MD5: ["EDR telemetry", "Antivirus logs"],
    IOCType.HASH_SHA1: ["EDR telemetry", "Antivirus logs"],
    IOCType.HASH_SHA256: ["EDR telemetry", "Antivirus logs"],
    IOCType.EMAIL: ["Azure AD sign-in logs", "Email gateway logs"],
    IOCType.URL: ["Proxy / web-filter logs"],
    IOCType.USER_AGENT: ["Proxy / web-filter logs", "Azure AD sign-in logs"],
}

_FALSE_POSITIVES: dict[IOCType, list[str]] = {
    IOCType.IP: [
        "Shared hosting / CDN IPs used by many services",
        "VPN exit nodes that rotate frequently",
    ],
    IOCType.DOMAIN: [
        "Legitimate domains with similar names to malicious ones",
        "Sinkholed domains now under security researcher control",
    ],
    IOCType.HASH_MD5: ["Benign files with same hash due to empty-file edge case"],
    IOCType.HASH_SHA1: ["Benign files with same hash due to empty-file edge case"],
    IOCType.HASH_SHA256: [],
    IOCType.EMAIL: ["Spoofed email addresses in phishing campaigns"],
    IOCType.URL: ["URL shorteners that redirect to benign content"],
    IOCType.USER_AGENT: ["Legitimate tools sharing the same user-agent string"],
}

# Max IOCs per single query to avoid query-size limits
_BATCH_SIZE = 20


def generate_ioc_plan(
    hunt_input: IOCHuntInput,
    ioc_batch: IOCBatch,
    telemetry: TelemetryAssessment,
) -> HuntPlan:
    """Generate a HuntPlan containing sweep queries for each IOC type group."""
    queries = _build_all_queries(ioc_batch, hunt_input.time_range, telemetry)
    steps = _build_steps(queries)

    hypothesis = HuntHypothesis(
        hypothesis_id=f"H-{uuid.uuid4().hex[:8]}",
        description=(
            f"IOC sweep: searching for {len(ioc_batch.valid)} indicators "
            f"across {len(ioc_batch.type_counts)} IOC types in client environment"
        ),
        attack_tactics=["Indicator Sweep"],
        attack_techniques=[],
        technique_source="ioc_sweep",
        confidence="high",
        rationale="Searching for analyst-provided indicators — confidence in IOC provenance depends on source.",
    )

    return HuntPlan(
        plan_id=f"HP-IOC-{uuid.uuid4().hex[:8]}",
        client_name=hunt_input.client_name,
        hunt_type=f"ioc_sweep ({hunt_input.hunt_type.value})",
        objective=hunt_input.sweep_objective,
        hypotheses=[hypothesis],
        telemetry_assessment=telemetry,
        hunt_steps=steps,
        triage_checklist=_ioc_triage_checklist(),
        escalation_criteria=_ioc_escalation_criteria(),
        expected_false_positives=_combined_fps(ioc_batch),
        constraints=hunt_input.constraints or ["None specified"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ── Query generation ──────────────────────────────────────────────────


def _build_all_queries(
    batch: IOCBatch,
    time_range: str,
    telemetry: TelemetryAssessment,
) -> list[ExabeamQuery]:
    queries: list[ExabeamQuery] = []
    available_lower = {s.lower() for s in telemetry.available_sources}

    # Group valid IOCs by type
    by_type: dict[IOCType, list[NormalizedIOC]] = {}
    for ioc in batch.valid:
        by_type.setdefault(ioc.ioc_type, []).append(ioc)

    for ioc_type, iocs in by_type.items():
        # Batch into groups to avoid oversized queries
        for chunk_idx in range(0, len(iocs), _BATCH_SIZE):
            chunk = iocs[chunk_idx : chunk_idx + _BATCH_SIZE]
            values = [c.normalized_value for c in chunk]

            primary, secondary = _FIELD_MAP.get(ioc_type, ("raw_log", None))
            required_sources = _REQUIRED_SOURCES.get(ioc_type, [])

            # Direct hit query
            query_text = _build_query_text(primary, secondary, values, time_range)
            queries.append(ExabeamQuery(
                query_id=f"Q-IOC-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent.ANOMALY_CANDIDATE,
                description=f"IOC sweep — {ioc_type.value} direct hit ({len(values)} indicators)",
                query_text=query_text,
                time_range=time_range,
                expected_signal=f"Events matching {len(values)} {ioc_type.value} indicator(s)",
                likely_false_positives=_FALSE_POSITIVES.get(ioc_type, []),
                required_data_sources=required_sources,
                fallback_query=_build_fallback(values, time_range),
            ))

            # Pivot query (contextual — look for related activity)
            pivot_text = _build_pivot_query(primary, values, time_range)
            if pivot_text:
                queries.append(ExabeamQuery(
                    query_id=f"Q-IOC-{uuid.uuid4().hex[:8]}",
                    intent=QueryIntent.PIVOT,
                    description=f"IOC pivot — related activity around {ioc_type.value} hits",
                    query_text=pivot_text,
                    time_range=time_range,
                    expected_signal="Activity context around IOC hits (users, hosts, processes)",
                    likely_false_positives=["Unrelated activity in the same time window"],
                    required_data_sources=required_sources,
                ))

    return queries


def _build_query_text(
    primary: str, secondary: str | None, values: list[str], time_range: str
) -> str:
    quoted = '", "'.join(values)
    if secondary:
        return (
            f'({primary} IN ("{quoted}") OR {secondary} IN ("{quoted}")) '
            f'| where time >= "{time_range}" | head 1000'
        )
    return (
        f'{primary} IN ("{quoted}") '
        f'| where time >= "{time_range}" | head 1000'
    )


def _build_fallback(values: list[str], time_range: str) -> str:
    """Free-text fallback when parsed fields aren't available."""
    terms = " OR ".join(f'"{v}"' for v in values[:5])
    return f'{terms} | where time >= "{time_range}" | head 500'


def _build_pivot_query(primary: str, values: list[str], time_range: str) -> str | None:
    if len(values) > 5:
        # Only pivot on first 5 to keep the query manageable
        values = values[:5]
    quoted = '", "'.join(values)
    return (
        f'{primary} IN ("{quoted}") '
        f'| where time >= "{time_range}" '
        f'| stats count by user, hostname, src_ip, dst_ip '
        f'| head 200'
    )


# ── Steps ─────────────────────────────────────────────────────────────


def _build_steps(queries: list[ExabeamQuery]) -> list[HuntStep]:
    direct = [q for q in queries if q.intent == QueryIntent.ANOMALY_CANDIDATE]
    pivots = [q for q in queries if q.intent == QueryIntent.PIVOT]

    steps: list[HuntStep] = []
    if direct:
        steps.append(HuntStep(
            step_number=1,
            description="IOC Direct Hit Search — sweep all indicator types against available telemetry",
            queries=direct,
            success_criteria="Any IOC has at least one hit in the environment",
            next_if_positive="Proceed to pivot queries for contextual analysis",
            next_if_negative="Document negative sweep result; review telemetry coverage",
        ))
    if pivots:
        steps.append(HuntStep(
            step_number=2,
            description="IOC Pivot & Context — gather surrounding activity for hits",
            queries=pivots,
            success_criteria="Pivot queries return user/host context for IOC hits",
            next_if_positive="Compile hit summary and triage affected entities",
            next_if_negative="Document limited context; recommend manual investigation",
        ))
    return steps


# ── Triage / escalation ──────────────────────────────────────────────


def _ioc_triage_checklist() -> list[str]:
    return [
        "Verify each IOC hit against the original threat intel source and context",
        "Cross-reference affected users and hosts with the client's asset inventory",
        "Check timeline: when did the IOC first and last appear in the environment?",
        "Determine if the IOC hit preceded or followed known incident dates",
        "Validate whether the IOC is still active or has been sinkholed/deprecated",
        "Check for IOC overlap with known benign infrastructure (CDNs, cloud providers)",
        "Review enrichment confidence and source attribution before escalating",
    ]


def _ioc_escalation_criteria() -> list[str]:
    return [
        "Any IOC with confirmed malicious TI verdict AND active hits in the environment",
        "Hash IOC hit on a host that also shows lateral movement indicators",
        "IP/domain IOC with hits on multiple distinct user accounts",
        "IOC hits on tier-0 or critical assets",
        "IOC associated with known APT campaign targeting client's industry",
        "IOC hit with active beaconing pattern (repeated connections over time)",
    ]


def _combined_fps(batch: IOCBatch) -> list[str]:
    fps: list[str] = []
    seen_types = set(batch.type_counts.keys())
    for ioc_type_str in seen_types:
        try:
            ioc_type = IOCType(ioc_type_str)
            fps.extend(_FALSE_POSITIVES.get(ioc_type, []))
        except ValueError:
            pass
    return list(dict.fromkeys(fps))  # dedupe preserving order
