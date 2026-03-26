"""Action router — maps parsed intents to pipeline calls."""

from __future__ import annotations

import logging
from typing import Any

from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse, ParsedIntent, ReasoningStep
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


class ActionRouter:
    """Executes the right pipeline action for a given intent."""

    def __init__(self, config: HuntAgentConfig) -> None:
        self.config = config
        self._client_name = config.default_client_name or "Unknown"

    def execute(self, intent: ParsedIntent) -> AgentResponse:
        """Route a parsed intent to the correct handler."""
        handler = _HANDLERS.get(intent.intent, _handle_general_question)
        try:
            return handler(self, intent)
        except Exception as exc:
            logger.exception("Action failed for intent %s", intent.intent)
            return AgentResponse(
                summary=f"Error executing {intent.intent.value}: {exc}",
                intent=intent.intent,
                confidence=intent.confidence,
                error=str(exc),
            )

    # ── Individual handlers ──────────────────────────────────────────

    def _handle_run_hunt(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.api import background as bg
        from mssp_hunt_agent.models.input_models import HuntInput

        config = self.config.model_copy()
        config.approval_required = False

        hypothesis = intent.entities.get("hypothesis", intent.original_message)
        techniques = intent.entities.get("technique", [])
        if isinstance(techniques, str):
            techniques = [techniques]

        hunt_input = HuntInput(
            client_name=self._client_name,
            hunt_objective=hypothesis,
            hunt_hypothesis=hypothesis,
            time_range=intent.entities.get("time_range", "last 7 days"),
            available_data_sources=["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"],
            attack_techniques=techniques,
        )

        run_id = bg.generate_run_id("RUN")
        status = bg.launch_hunt(run_id, hunt_input, config)

        return AgentResponse(
            summary=f"Threat hunt started for '{hypothesis}'. Tracking as {run_id}.",
            intent=intent.intent,
            confidence=intent.confidence,
            run_id=run_id,
            details={"status": status.status, "client": self._client_name},
            follow_up_suggestions=[
                f"Check status: what's the status of {run_id}?",
                f"Get report: generate report for {run_id}",
            ],
        )

    def _handle_ioc_sweep(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.api import background as bg
        from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType

        config = self.config.model_copy()
        config.approval_required = False

        # Collect all IOC entities
        ioc_entries: list[IOCEntry] = []
        for key in ("ip", "hash_md5", "hash_sha256", "domain", "url", "email"):
            vals = intent.entities.get(key, [])
            if isinstance(vals, str):
                vals = [vals]
            for val in vals:
                ioc_type = _infer_ioc_type(val)
                ioc_entries.append(IOCEntry(value=val, ioc_type=ioc_type))

        if not ioc_entries:
            return AgentResponse(
                summary="No IOCs found in your message. Please provide IPs, hashes, domains, or URLs to sweep.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="no_iocs",
            )

        ioc_input = IOCHuntInput(
            client_name=self._client_name,
            iocs=ioc_entries,
            time_range=intent.entities.get("time_range", "last 30 days"),
            available_data_sources=["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"],
        )

        run_id = bg.generate_run_id("RUN-IOC")
        status = bg.launch_ioc_sweep(run_id, ioc_input, config)

        ioc_summary = ", ".join(e.value for e in ioc_entries[:5])
        if len(ioc_entries) > 5:
            ioc_summary += f" (+{len(ioc_entries) - 5} more)"

        return AgentResponse(
            summary=f"IOC sweep started for {ioc_summary}. Tracking as {run_id}.",
            intent=intent.intent,
            confidence=intent.confidence,
            run_id=run_id,
            details={"ioc_count": len(ioc_entries), "status": status.status},
            follow_up_suggestions=[f"Check status: what's the status of {run_id}?"],
        )

    def _handle_cve_check(self, intent: ParsedIntent) -> AgentResponse:
        """Assess vulnerability to a CVE using the CVEAssessor pipeline."""
        cve_id = intent.entities.get("cve", "")
        if isinstance(cve_id, list):
            cve_id = cve_id[0]

        if not cve_id:
            return AgentResponse(
                summary="No CVE ID found in your message. Please provide a CVE ID like CVE-2025-55182.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="no_cve",
            )

        from mssp_hunt_agent.agent.cve_assessor import CVEAssessor
        assessor = CVEAssessor(self.config)
        return assessor.assess(cve_id)

    def _handle_telemetry_profile(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.api import background as bg
        from mssp_hunt_agent.models.input_models import HuntType
        from mssp_hunt_agent.models.profile_models import ProfileInput

        config = self.config.model_copy()
        config.approval_required = False

        profile_input = ProfileInput(
            client_name=self._client_name,
            time_range=intent.entities.get("time_range", "last 30 days"),
            hunt_types_of_interest=list(HuntType),
        )

        run_id = bg.generate_run_id("RUN-PROF")
        status = bg.launch_profile(run_id, profile_input, config)

        return AgentResponse(
            summary=f"Telemetry profile started for {self._client_name}. Tracking as {run_id}.",
            intent=intent.intent,
            confidence=intent.confidence,
            run_id=run_id,
            details={"status": status.status},
            follow_up_suggestions=[f"Check status: what's the status of {run_id}?"],
        )

    def _handle_threat_model(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths

        data_sources = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
        paths = identify_attack_paths(data_sources)

        path_summaries = []
        for p in paths[:5]:
            gap_str = f" (gaps: {', '.join(p.gaps)})" if p.gaps else " (fully covered)"
            path_summaries.append(
                f"- {p.entry_point} -> {' -> '.join(p.techniques)}{gap_str}"
            )

        return AgentResponse(
            summary=f"Identified {len(paths)} attack paths for {self._client_name}.\n" + "\n".join(path_summaries),
            intent=intent.intent,
            confidence=intent.confidence,
            details={
                "path_count": len(paths),
                "paths": [p.model_dump() for p in paths[:10]],
            },
            follow_up_suggestions=[
                "Simulate breach: simulate a breach scenario",
                "Check risk: what if we lose EDR?",
            ],
        )

    def _handle_risk_assessment(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.risk.models import RiskScenario
        from mssp_hunt_agent.risk.simulator import simulate_risk_scenario

        # Extract what source is being removed/changed
        msg_lower = intent.original_message.lower()
        affected_source = "EDR"  # default
        for src in ["edr", "syslog", "azure ad", "signinlogs", "securityevent", "firewall"]:
            if src in msg_lower:
                affected_source = src.upper()
                break

        change_type = "remove_source"
        if any(w in msg_lower for w in ("add", "gain", "enable")):
            change_type = "add_source"

        scenario = RiskScenario(
            client_name=self._client_name,
            change_type=change_type,
            affected_source=affected_source,
        )

        current_sources = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
        assessment = simulate_risk_scenario(scenario, current_sources)

        return AgentResponse(
            summary=(
                f"Risk assessment for {change_type.replace('_', ' ')} '{affected_source}': "
                f"Risk rating = {assessment.risk_rating}. "
                f"Blind spots: {', '.join(assessment.blind_spots[:5]) if assessment.blind_spots else 'none'}."
            ),
            intent=intent.intent,
            confidence=intent.confidence,
            details=assessment.model_dump(),
            follow_up_suggestions=[
                "View attack paths: what are our attack paths?",
                "Check landscape: any active threats we can't detect?",
            ],
        )

    def _handle_detection_rule(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.detection.generator import generate_detection_rule

        technique = intent.entities.get("technique", "")
        if isinstance(technique, list):
            technique = technique[0] if technique else ""

        description = intent.entities.get("hypothesis", intent.original_message)

        rule = generate_detection_rule(
            technique_id=technique or None,
            description=description or None,
        )

        # Format severity cleanly (handle enum values like Severity.MEDIUM)
        sev_str = str(rule.severity)
        if "." in sev_str:
            sev_str = sev_str.split(".")[-1]
        sev_display = sev_str.title()

        return AgentResponse(
            summary=(
                f"Detection rule generated: '{rule.name}'\n"
                f"Severity: {sev_display}\n"
                f"KQL:\n{rule.kql_query}"
            ),
            intent=intent.intent,
            confidence=intent.confidence,
            details=rule.model_dump(),
            follow_up_suggestions=[
                "Validate this rule: validate the KQL query",
                "Score quality: score the detection quality",
            ],
        )

    def _handle_landscape_check(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.intel.landscape import ThreatLandscapeEngine

        engine = ThreatLandscapeEngine()
        client_sources = {self._client_name: ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]}
        report = engine.correlate(client_sources)

        alert_count = len(report.alerts)
        correlation_count = len(report.correlations)

        alert_lines = []
        for a in report.alerts[:5]:
            alert_lines.append(f"- {a.message}")

        return AgentResponse(
            summary=(
                f"Threat landscape analysis: {alert_count} alerts, {correlation_count} correlations.\n"
                + "\n".join(alert_lines)
            ),
            intent=intent.intent,
            confidence=intent.confidence,
            details=report.model_dump(),
            follow_up_suggestions=[
                "Run a hunt: hunt for the top threat",
                "Check risk: what's our overall risk?",
            ],
        )

    def _handle_hunt_status(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.api import background as bg

        run_id = intent.entities.get("run_id", "")
        if isinstance(run_id, list):
            run_id = run_id[0]

        if not run_id:
            return AgentResponse(
                summary="No run ID found. Please provide a run ID like RUN-abc123.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="no_run_id",
            )

        status = bg.get_run_status(run_id)
        if not status:
            return AgentResponse(
                summary=f"Run {run_id} not found.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="not_found",
            )

        return AgentResponse(
            summary=(
                f"Hunt {run_id}: {status.status}. "
                f"Findings: {status.findings_count}. Events: {status.total_events}."
            ),
            intent=intent.intent,
            confidence=intent.confidence,
            run_id=run_id,
            details=status.model_dump(),
            follow_up_suggestions=[f"Generate report for {run_id}"],
        )

    def _handle_generate_report(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.api import background as bg

        run_id = intent.entities.get("run_id", "")
        if isinstance(run_id, list):
            run_id = run_id[0]

        if not run_id:
            return AgentResponse(
                summary="No run ID found. Please provide a run ID to generate a report.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="no_run_id",
            )

        status = bg.get_run_status(run_id)
        if not status:
            return AgentResponse(
                summary=f"Run {run_id} not found.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="not_found",
            )

        report = status.executive_summary or status.analyst_report or (
            f"Hunt {run_id}: {status.status}. "
            f"Findings: {status.findings_count}. Events: {status.total_events}."
        )

        return AgentResponse(
            summary=report,
            intent=intent.intent,
            confidence=intent.confidence,
            run_id=run_id,
            details={"format": "executive", "status": status.status},
        )


    def _handle_run_playbook(self, intent: ParsedIntent) -> AgentResponse:
        from mssp_hunt_agent.agent.playbooks import (
            execute_playbook, get_playbook, list_playbooks,
        )

        pb_name = intent.entities.get("playbook_name", "")

        if not pb_name:
            # List available playbooks
            playbooks = list_playbooks()
            if not playbooks:
                return AgentResponse(
                    summary="No playbooks available.",
                    intent=intent.intent,
                    confidence=intent.confidence,
                    error="no_playbooks",
                )
            names = [f"- {pb.name} ({pb.severity}): {pb.description}" for pb in playbooks]
            return AgentResponse(
                summary="Available playbooks:\n" + "\n".join(names),
                intent=intent.intent,
                confidence=intent.confidence,
                details={"playbooks": [pb.model_dump() for pb in playbooks]},
                follow_up_suggestions=[f"Run {playbooks[0].name.split()[0].lower()} playbook"],
            )

        playbook = get_playbook(pb_name)
        if not playbook:
            return AgentResponse(
                summary=f"Playbook '{pb_name}' not found. Try 'run playbook' to list available playbooks.",
                intent=intent.intent,
                confidence=intent.confidence,
                error="playbook_not_found",
            )

        return execute_playbook(playbook, self.config)


def _handle_general_question(router: ActionRouter, intent: ParsedIntent) -> AgentResponse:
    """Fallback for unrecognized intents."""
    return AgentResponse(
        summary=(
            "I can help with threat hunting, IOC sweeps, CVE assessments, "
            "telemetry profiling, detection engineering, threat modeling, "
            "risk analysis, threat landscape checks, and hunt playbooks. "
            "Try asking something like:\n"
            "- 'Hunt for lateral movement in the last 7 days'\n"
            "- 'Are we vulnerable to CVE-2025-55182?'\n"
            "- 'Check if 203.0.113.77 is in our logs'\n"
            "- 'What telemetry do we have?'\n"
            "- 'Create a detection for T1059'\n"
            "- 'What if we lose EDR?'\n"
            "- 'Run the ransomware playbook'"
        ),
        intent=intent.intent,
        confidence=intent.confidence,
        follow_up_suggestions=[
            "Hunt for lateral movement",
            "What telemetry do we have?",
            "Run the ransomware playbook",
        ],
    )


def _infer_ioc_type(value: str) -> "IOCType":
    """Infer IOC type from its value string."""
    from mssp_hunt_agent.models.ioc_models import IOCType

    parts = value.split(".")
    if len(parts) == 4 and all(
        part.isdigit() and 0 <= int(part) <= 255 for part in parts
    ):
        return IOCType.IP
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return IOCType.HASH_SHA256
    if len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower()):
        return IOCType.HASH_MD5
    if value.startswith(("http://", "https://")):
        return IOCType.URL
    if "@" in value:
        return IOCType.EMAIL
    return IOCType.DOMAIN


# Handler dispatch table
_HANDLERS: dict[AgentIntent, Any] = {
    AgentIntent.RUN_HUNT: ActionRouter._handle_run_hunt,
    AgentIntent.IOC_SWEEP: ActionRouter._handle_ioc_sweep,
    AgentIntent.CVE_CHECK: ActionRouter._handle_cve_check,
    AgentIntent.TELEMETRY_PROFILE: ActionRouter._handle_telemetry_profile,
    AgentIntent.THREAT_MODEL: ActionRouter._handle_threat_model,
    AgentIntent.RISK_ASSESSMENT: ActionRouter._handle_risk_assessment,
    AgentIntent.DETECTION_RULE: ActionRouter._handle_detection_rule,
    AgentIntent.LANDSCAPE_CHECK: ActionRouter._handle_landscape_check,
    AgentIntent.HUNT_STATUS: ActionRouter._handle_hunt_status,
    AgentIntent.GENERATE_REPORT: ActionRouter._handle_generate_report,
    AgentIntent.RUN_PLAYBOOK: ActionRouter._handle_run_playbook,
    AgentIntent.GENERAL_QUESTION: _handle_general_question,
}
