"""Hunt planner — generate hypotheses, ATT&CK mappings, query candidates, and execution steps."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from mssp_hunt_agent.models.input_models import HuntInput, HuntType
from mssp_hunt_agent.models.hunt_models import (
    ExabeamQuery,
    HuntHypothesis,
    HuntPlan,
    HuntStep,
    QueryIntent,
    TelemetryAssessment,
    TelemetryReadiness,
)

if TYPE_CHECKING:
    from mssp_hunt_agent.models.profile_models import ClientTelemetryProfile

_PLAYBOOK_DIR = Path(__file__).parent.parent / "data" / "hunt_playbooks"

# Broad tactic inference from hypothesis keywords.
# Used only when the analyst does not supply explicit technique IDs.
_TACTIC_KEYWORDS: dict[str, list[str]] = {
    "Initial Access": ["phishing", "external", "brute force", "credential stuff", "exposed", "public-facing"],
    "Credential Access": ["password", "credential", "hash", "kerberos", "token", "mfa", "auth"],
    "Persistence": ["persistence", "scheduled task", "startup", "registry", "backdoor", "implant"],
    "Privilege Escalation": ["privilege", "escalat", "admin", "root", "uac", "sudo"],
    "Lateral Movement": ["lateral", "rdp", "smb", "psexec", "wmi", "remote", "pivot"],
    "Defense Evasion": ["evasion", "obfuscat", "encode", "bypass", "disable", "tamper"],
    "Exfiltration": ["exfiltrat", "upload", "transfer", "staging", "compress"],
    "Command and Control": ["c2", "beacon", "callback", "command and control", "dns tunnel"],
    "Discovery": ["discover", "recon", "enumerate", "scan", "whoami", "net user"],
    "Collection": ["collect", "keylog", "screenshot", "clipboard", "email"],
}


def _infer_tactics(hypothesis: str) -> list[str]:
    """Return broad ATT&CK tactic names that match keywords in the hypothesis."""
    lower = hypothesis.lower()
    return [tactic for tactic, kws in _TACTIC_KEYWORDS.items() if any(k in lower for k in kws)]


def _load_playbook(hunt_type: HuntType) -> dict:
    """Load the YAML playbook for a given hunt type. Returns empty dict on miss."""
    path = _PLAYBOOK_DIR / f"{hunt_type.value}.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text()) or {}
    return {}


def _build_queries_from_playbook(
    playbook: dict,
    hunt_input: HuntInput,
    telemetry: TelemetryAssessment,
    client_profile: ClientTelemetryProfile | None = None,
) -> list[ExabeamQuery]:
    """Turn playbook query templates into concrete ExabeamQuery objects.

    If *client_profile* is provided, field-quality annotations are added
    to descriptions for fields with <30 % population.
    """
    queries: list[ExabeamQuery] = []
    available_lower = {s.lower() for s in telemetry.available_sources}

    # Build field-population lookup from profile
    field_population: dict[str, float] = {}
    if client_profile:
        for ds in client_profile.data_sources:
            for pf in ds.parsed_fields:
                key = pf.field_name.lower()
                field_population[key] = max(field_population.get(key, 0.0), pf.population_pct)

    for idx, qt in enumerate(playbook.get("queries", []), start=1):
        # Skip queries whose required sources are entirely absent
        required = qt.get("required_sources", [])
        if required and not any(r.lower() in available_lower for r in required):
            continue

        query_text = qt.get("query_template", "").replace("{{TIME_RANGE}}", hunt_input.time_range)
        query_text = query_text.replace("{{CLIENT}}", hunt_input.client_name)

        description = qt.get("description", f"Playbook query #{idx}")
        if client_profile and field_population:
            description = _annotate_field_quality(description, query_text, field_population)

        fallback = qt.get("fallback_query")
        if fallback:
            fallback = fallback.replace("{{TIME_RANGE}}", hunt_input.time_range)

        queries.append(
            ExabeamQuery(
                query_id=f"Q-{uuid.uuid4().hex[:8]}",
                intent=QueryIntent(qt.get("intent", "anomaly_candidate")),
                description=description,
                query_text=query_text,
                time_range=hunt_input.time_range,
                expected_signal=qt.get("expected_signal", "Variable"),
                likely_false_positives=qt.get("false_positives", []),
                fallback_query=fallback,
                required_data_sources=required,
            )
        )
    return queries


def generate_plan(
    hunt_input: HuntInput,
    telemetry: TelemetryAssessment,
    client_profile: ClientTelemetryProfile | None = None,
) -> HuntPlan:
    """Produce a full HuntPlan from validated input and telemetry assessment.

    If *client_profile* is provided the telemetry assessment is overridden
    with profile-discovered sources and field-quality annotations are added
    to query descriptions.
    """
    if client_profile:
        telemetry = _override_telemetry_from_profile(
            hunt_input.hunt_type, client_profile, telemetry,
        )

    playbook = _load_playbook(hunt_input.hunt_type)

    # ── Hypotheses ────────────────────────────────────────────────────
    if hunt_input.attack_techniques:
        technique_source = "analyst_provided"
        tactics = _infer_tactics(hunt_input.hunt_hypothesis) or ["General"]
        techniques = hunt_input.attack_techniques
    else:
        technique_source = "inferred"
        tactics = _infer_tactics(hunt_input.hunt_hypothesis) or ["General"]
        techniques = []

    primary_hypothesis = HuntHypothesis(
        hypothesis_id=f"H-{uuid.uuid4().hex[:8]}",
        description=hunt_input.hunt_hypothesis,
        attack_tactics=tactics,
        attack_techniques=techniques,
        technique_source=technique_source,
        confidence="medium" if technique_source == "analyst_provided" else "low",
        rationale=(
            "Based on analyst-provided techniques and hypothesis."
            if technique_source == "analyst_provided"
            else "Broad planning assumption inferred from hypothesis keywords. "
            "Analyst did not provide specific ATT&CK technique IDs."
        ),
    )

    # ── Queries ───────────────────────────────────────────────────────
    queries = _build_queries_from_playbook(playbook, hunt_input, telemetry, client_profile)

    # If no playbook queries matched, generate a minimal generic set
    if not queries:
        queries = _generate_fallback_queries(hunt_input)

    # ── Steps ─────────────────────────────────────────────────────────
    steps = _build_steps(queries, playbook)

    # ── Triage / escalation from playbook or defaults ─────────────────
    triage_checklist = playbook.get("triage_checklist", [
        "Verify event timestamps align with expected activity windows",
        "Cross-reference flagged accounts against known service accounts and exclusion lists",
        "Check source IPs against threat intel and geo-location baselines",
        "Validate any suspicious processes against known-good software inventory",
        "Confirm findings with a second data source where available",
    ])

    escalation_criteria = playbook.get("escalation_criteria", [
        "Confirmed credential use from unrecognised geographic location",
        "Evidence of lateral movement to tier-0 assets",
        "Execution of known offensive tools (e.g., Mimikatz, Cobalt Strike beacon)",
        "Data staging or exfiltration indicators",
        "Tampering with security tooling or audit logs",
    ])

    expected_fps = playbook.get("expected_false_positives", [
        "Legitimate remote workers using VPN from unusual locations",
        "Scheduled tasks or automation service accounts",
        "Vulnerability scanners and IT admin tools",
    ])

    return HuntPlan(
        plan_id=f"HP-{uuid.uuid4().hex[:8]}",
        client_name=hunt_input.client_name,
        hunt_type=hunt_input.hunt_type.value,
        objective=hunt_input.hunt_objective,
        hypotheses=[primary_hypothesis],
        telemetry_assessment=telemetry,
        hunt_steps=steps,
        triage_checklist=triage_checklist,
        escalation_criteria=escalation_criteria,
        expected_false_positives=expected_fps,
        constraints=hunt_input.constraints or ["None specified"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _generate_fallback_queries(hunt_input: HuntInput) -> list[ExabeamQuery]:
    """When no playbook queries matched, emit a small generic set."""
    return [
        ExabeamQuery(
            query_id=f"Q-{uuid.uuid4().hex[:8]}",
            intent=QueryIntent.BASELINE,
            description="Baseline activity for key users/assets in scope",
            query_text=f'activity_type = "*" | where time >= "{hunt_input.time_range}" | head 500',
            time_range=hunt_input.time_range,
            expected_signal="Normal operating baseline",
            likely_false_positives=["All results expected benign — this is baseline"],
        ),
        ExabeamQuery(
            query_id=f"Q-{uuid.uuid4().hex[:8]}",
            intent=QueryIntent.ANOMALY_CANDIDATE,
            description="Anomalous events matching hunt hypothesis keywords",
            query_text=(
                f'activity_type != "authentication-success" AND risk_score > 50 '
                f'| where time >= "{hunt_input.time_range}" | head 200'
            ),
            time_range=hunt_input.time_range,
            expected_signal="Events with elevated risk scores",
            likely_false_positives=["High-privilege scheduled tasks", "IT admin activity"],
        ),
    ]


def _build_steps(queries: list[ExabeamQuery], playbook: dict) -> list[HuntStep]:
    """Group queries into logical hunt execution steps."""
    # Strategy: one step per query intent group, in execution order
    intent_order = [QueryIntent.BASELINE, QueryIntent.ANOMALY_CANDIDATE, QueryIntent.PIVOT, QueryIntent.CONFIRMATION]
    step_descriptions = {
        QueryIntent.BASELINE: ("Establish Baseline", "Collect normal activity to calibrate anomaly detection"),
        QueryIntent.ANOMALY_CANDIDATE: ("Identify Anomalies", "Run detection-oriented queries against available telemetry"),
        QueryIntent.PIVOT: ("Pivot and Correlate", "Follow leads from anomaly hits with additional context queries"),
        QueryIntent.CONFIRMATION: ("Confirm Findings", "Validate suspicious observations with corroborating evidence"),
    }

    steps: list[HuntStep] = []
    step_num = 0
    for intent in intent_order:
        group = [q for q in queries if q.intent == intent]
        if not group:
            continue
        step_num += 1
        title, desc = step_descriptions.get(intent, (intent.value, ""))
        steps.append(
            HuntStep(
                step_number=step_num,
                description=f"{title} — {desc}",
                queries=group,
                success_criteria=f"At least one query returns actionable results for {intent.value}",
                next_if_positive=f"Proceed to next step; flag results for triage",
                next_if_negative=f"Document null result and proceed",
            )
        )
    return steps


# ── Profile-aware helpers ─────────────────────────────────────────────


def _override_telemetry_from_profile(
    hunt_type: HuntType,
    profile: ClientTelemetryProfile,
    declared_telemetry: TelemetryAssessment,
) -> TelemetryAssessment:
    """Replace declared-sources telemetry assessment with profile-based one."""
    matching_cap = next(
        (c for c in profile.capabilities if c.hunt_type == hunt_type),
        None,
    )
    if matching_cap is None:
        return declared_telemetry

    discovered_source_names = [
        ds.source_name
        for ds in profile.data_sources
        if ds.category == hunt_type
    ]

    return TelemetryAssessment(
        readiness=matching_cap.readiness,
        rationale=(
            f"[Profile-based] {matching_cap.rationale} "
            f"(from profile {profile.profile_id})"
        ),
        available_sources=discovered_source_names or declared_telemetry.available_sources,
        missing_sources=matching_cap.missing_sources,
        impact_on_hunt=declared_telemetry.impact_on_hunt,
    )


def _annotate_field_quality(
    description: str,
    query_text: str,
    field_population: dict[str, float],
) -> str:
    """Add field-quality annotations when query references low-population fields."""
    field_refs = re.findall(r"(\w+)\s*=", query_text)
    low_pop_fields = []
    for field in field_refs:
        pop = field_population.get(field.lower(), -1.0)
        if 0.0 <= pop < 30.0:
            low_pop_fields.append(f"{field} ({pop:.0f}%)")

    if low_pop_fields:
        description += f" [PROFILE WARNING: low-pop fields: {', '.join(low_pop_fields)}]"
    return description
