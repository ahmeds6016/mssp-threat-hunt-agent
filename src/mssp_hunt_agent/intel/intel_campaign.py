"""Intel-Driven Campaign Launcher — launches targeted hunts from threat intel events.

Takes enriched IntelEvent objects (with IOCs, TTPs, CVEs) and launches
focused campaign investigations against the client's Sentinel workspace.

Usage:
    launcher = IntelCampaignLauncher(agent_config=config, llm=llm)
    result = launcher.launch_hunt(intel_event, progress=tracker)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.hunter.campaign import CampaignOrchestrator
from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState

if TYPE_CHECKING:
    from mssp_hunt_agent.adapters.llm.base import LLMAdapter
    from mssp_hunt_agent.intel.intel_processor import IntelEvent
    from mssp_hunt_agent.persistence.progress import ProgressTracker

logger = logging.getLogger(__name__)


class IntelCampaignLauncher:
    """Launches targeted threat hunt campaigns from intel events."""

    def __init__(
        self,
        agent_config: HuntAgentConfig,
        llm: LLMAdapter,
    ) -> None:
        self._config = agent_config
        self._llm = llm

    def launch_hunt(
        self,
        intel_event: IntelEvent,
        progress: Optional[ProgressTracker] = None,
        learning_engine: Any = None,
    ) -> CampaignState:
        """Launch the appropriate hunt for an intel event.

        Routes automatically:
        - IOCs present (IPs, domains, hashes, file paths) → IOC Sweep (fast, precise)
        - TTPs only (MITRE techniques, no specific IOCs) → Campaign Hunt (hypotheses-based)

        Returns CampaignState with findings.
        """
        # Decide mode based on IOC presence
        has_actionable_iocs = self._has_actionable_iocs(intel_event)
        mode = "ioc_sweep" if has_actionable_iocs else "ttp_hunt"

        campaign_id = f"INTEL-CAMP-{uuid.uuid4().hex[:8]}"
        logger.info(
            "Launching intel %s %s for: %s (relevance=%.2f, iocs=%d, techniques=%d)",
            mode, campaign_id, intel_event.title[:80], intel_event.relevance_score,
            len(intel_event.iocs), len(intel_event.mitre_techniques),
        )

        if progress:
            progress.log(
                "intel_hunt_started",
                campaign_id=campaign_id,
                mode=mode,
                event_title=intel_event.title,
                severity=intel_event.severity,
                relevance=intel_event.relevance_score,
                techniques=intel_event.mitre_techniques[:5],
                ioc_count=len(intel_event.iocs),
            )

        if mode == "ioc_sweep":
            return self._run_ioc_sweep(intel_event, campaign_id, progress)
        else:
            return self._run_ttp_hunt(intel_event, campaign_id, progress, learning_engine)

    def _has_actionable_iocs(self, event: IntelEvent) -> bool:
        """Check if the event has IOCs worth sweeping (not just techniques)."""
        if not event.iocs:
            return False
        actionable_types = {"ip", "domain", "hash_sha256", "hash_sha1", "hash_md5",
                           "url", "filepath", "useragent", "registry"}
        return any(ioc.get("type", "") in actionable_types for ioc in event.iocs)

    def _run_ioc_sweep(
        self,
        intel_event: IntelEvent,
        campaign_id: str,
        progress: Optional[ProgressTracker] = None,
    ) -> CampaignState:
        """Fast IOC sweep — direct KQL queries for every indicator."""
        from mssp_hunt_agent.agent.tool_defs import ToolExecutor
        from mssp_hunt_agent.intel.ioc_sweep import IOCSweeper

        if progress:
            progress.log("ioc_sweep_mode", detail=f"Running direct IOC queries for {len(intel_event.iocs)} indicators + {len(intel_event.affected_software)} packages")

        # Build Sentinel adapter
        executor = ToolExecutor(self._config)
        adapter = executor._get_sentinel_adapter()

        sweeper = IOCSweeper(adapter=adapter)
        sweep_result = sweeper.run_sweep(intel_event, progress=progress)

        # Convert sweep result to CampaignState for consistent reporting
        from mssp_hunt_agent.hunter.models.finding import (
            FindingClassification, FindingSeverity, HuntFinding,
        )

        findings = []
        for hit in sweep_result.hits:
            findings.append(HuntFinding(
                finding_id=f"F-sweep-{len(findings):03d}",
                hypothesis_id="ioc-sweep",
                campaign_id=campaign_id,
                title=f"IOC match: {hit.ioc_type} {hit.ioc_value} in {hit.table}",
                description=f"{hit.ioc_context}. Found {hit.match_count} matches in {hit.table}.",
                severity=FindingSeverity.HIGH,
                classification=FindingClassification.TRUE_POSITIVE,
                confidence=0.95,
                mitre_techniques=intel_event.mitre_techniques[:3],
                affected_entities={hit.ioc_type: [hit.ioc_value]},
                recommendations=[f"Investigate {hit.match_count} events matching {hit.ioc_value} in {hit.table}"],
                detection_rule_kql=hit.query,
            ))

        # Add a summary finding for clean IOCs
        if sweep_result.misses:
            miss_summary = ", ".join(f"{m['ioc_type']}:{m['ioc_value']}" for m in sweep_result.misses[:10])
            findings.append(HuntFinding(
                finding_id="F-sweep-clear",
                hypothesis_id="ioc-sweep",
                campaign_id=campaign_id,
                title=f"No matches for {len(sweep_result.misses)} IOC(s)",
                description=f"The following IOCs were not found in any Sentinel table: {miss_summary}",
                severity=FindingSeverity.INFORMATIONAL,
                classification=FindingClassification.FALSE_POSITIVE,
                confidence=0.9,
            ))

        campaign_config = CampaignConfig(
            client_name=self._config.default_client_name or "Default",
            time_range="last 30 days",
            focus_areas=[intel_event.title[:50]],
        )

        state = CampaignState(
            campaign_id=campaign_id,
            config=campaign_config,
            status="completed",
            started_at=sweep_result.started_at,
            completed_at=sweep_result.completed_at,
            total_kql_queries=sweep_result.total_queries,
            findings=findings,
        )

        if progress:
            progress.log(
                "intel_hunt_completed",
                campaign_id=campaign_id,
                mode="ioc_sweep",
                status="completed",
                findings=len(findings),
                hits=sweep_result.total_hits,
                misses=sweep_result.total_misses,
                queries=sweep_result.total_queries,
            )

        logger.info(
            "IOC sweep %s complete: %d queries, %d hits, %d misses",
            campaign_id, sweep_result.total_queries, sweep_result.total_hits, sweep_result.total_misses,
        )
        return state

    def _run_ttp_hunt(
        self,
        intel_event: IntelEvent,
        campaign_id: str,
        progress: Optional[ProgressTracker] = None,
        learning_engine: Any = None,
    ) -> CampaignState:
        """Full campaign hunt for TTP-based threats (no specific IOCs)."""
        if progress:
            progress.log("ttp_hunt_mode", detail=f"Running hypothesis-based hunt for {len(intel_event.mitre_techniques)} techniques")

        focus_areas = self._build_focus_areas(intel_event)
        campaign_config = CampaignConfig(
            client_name=self._config.default_client_name or "Default",
            time_range="last 30 days",
            focus_areas=focus_areas,
            max_hypotheses=5,
            max_queries_per_hypothesis=15,
            max_total_queries=100,
            max_duration_minutes=15,
        )

        self._config.intel_context = self._build_intel_context(intel_event)

        orchestrator = CampaignOrchestrator(
            agent_config=self._config,
            llm=self._llm,
            campaign_config=campaign_config,
            learning_engine=learning_engine,
            progress=progress,
        )

        initial_state = CampaignState(
            campaign_id=campaign_id,
            config=campaign_config,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        state = orchestrator.run(resume_state=initial_state)

        if progress:
            progress.log(
                "intel_hunt_completed",
                campaign_id=campaign_id,
                mode="ttp_hunt",
                status=state.status,
                findings=len(state.findings),
                queries=state.total_kql_queries,
            )

        logger.info(
            "TTP hunt %s %s: %d findings, %d queries",
            campaign_id, state.status, len(state.findings), state.total_kql_queries,
        )
        return state

    def _build_focus_areas(self, event: IntelEvent) -> list[str]:
        """Build campaign focus areas from intel event."""
        areas = []

        if event.mitre_tactics:
            areas.extend(event.mitre_tactics[:3])

        if event.threat_actor:
            areas.append(f"Threat Actor: {event.threat_actor}")

        if event.cves:
            areas.append(f"CVEs: {', '.join(event.cves[:3])}")

        if event.affected_software:
            areas.append(f"Affected Software: {', '.join(event.affected_software[:3])}")

        if not areas:
            areas = [event.category, event.title[:50]]

        return areas

    def _build_intel_context(self, event: IntelEvent) -> str:
        """Build a text context block to inject into campaign prompts."""
        parts = [
            f"## Active Threat Intelligence Context",
            f"",
            f"This campaign was triggered by a threat intelligence event. Focus your hunt on indicators and TTPs from this specific threat.",
            f"",
            f"**Event:** {event.title}",
            f"**Severity:** {event.severity}",
            f"**Category:** {event.category}",
            f"**Sources:** {', '.join(event.sources)} ({event.article_count} articles)",
            f"**Summary:** {event.summary}",
        ]

        if event.threat_actor:
            parts.append(f"**Threat Actor:** {event.threat_actor}")

        if event.mitre_techniques:
            parts.append(f"**MITRE Techniques:** {', '.join(event.mitre_techniques)}")

        if event.cves:
            parts.append(f"**CVEs:** {', '.join(event.cves)}")

        if event.affected_software:
            parts.append(f"**Affected Software:** {', '.join(event.affected_software)}")

        if event.iocs:
            parts.append(f"\n**IOCs to hunt for:**")
            for ioc in event.iocs[:20]:
                parts.append(f"- [{ioc.get('type', '')}] {ioc.get('value', '')} — {ioc.get('context', '')}")

        if event.recommended_queries:
            parts.append(f"\n**Recommended KQL queries:**")
            for q in event.recommended_queries[:5]:
                parts.append(f"```kql\n{q}\n```")

        parts.append(f"\n**Hunt Objective:** Determine if this threat has impacted or could impact the client environment. Check for IOC matches, TTP indicators, and affected software presence.")

        return "\n".join(parts)
