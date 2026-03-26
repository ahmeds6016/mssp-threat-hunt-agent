"""Campaign Orchestrator — state machine driving the autonomous hunt lifecycle.

Flow:
    INDEX_REFRESH → HYPOTHESIZE → EXECUTE → CONCLUDE → DELIVER → COMPLETED

Each phase is run by a PhaseRunner. The orchestrator manages transitions,
budget tracking, error handling, and state persistence.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.agent.tool_defs import ToolExecutor
from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.hunter.budget import BudgetExhausted, BudgetTracker
from mssp_hunt_agent.hunter.context import ContextManager
from mssp_hunt_agent.hunter.index_builder import IndexBuilder
from mssp_hunt_agent.hunter.index_store import IndexStore
from mssp_hunt_agent.hunter.learning import CampaignLearningEngine
from mssp_hunt_agent.hunter.models.campaign import (
    CampaignConfig,
    CampaignPhase,
    CampaignState,
    PhaseResult,
)
from mssp_hunt_agent.hunter.phases.conclude import ConcludePhaseRunner
from mssp_hunt_agent.hunter.phases.deliver import DeliverPhaseRunner
from mssp_hunt_agent.hunter.phases.execute import ExecutePhaseRunner
from mssp_hunt_agent.hunter.phases.hypothesize import HypothesizePhaseRunner

logger = logging.getLogger(__name__)

# Phase execution order
_PHASE_ORDER = [
    CampaignPhase.INDEX_REFRESH,
    CampaignPhase.HYPOTHESIZE,
    CampaignPhase.EXECUTE,
    CampaignPhase.CONCLUDE,
    CampaignPhase.DELIVER,
]


class CampaignOrchestrator:
    """Drives autonomous hunt campaigns through the 5-phase lifecycle.

    Usage:
        config = CampaignConfig(client_name="Acme Corp")
        orchestrator = CampaignOrchestrator(agent_config, llm, config)
        state = orchestrator.run()
        # state.report contains the final deliverable
    """

    def __init__(
        self,
        agent_config: HuntAgentConfig,
        llm: LLMAdapter,
        campaign_config: CampaignConfig,
        index_store: Optional[IndexStore] = None,
        learning_engine: Optional[CampaignLearningEngine] = None,
    ) -> None:
        self._agent_config = agent_config
        self._llm = llm
        self._campaign_config = campaign_config
        self._index_store = index_store or IndexStore()
        self._tool_executor = ToolExecutor(agent_config)
        self._learning_engine = learning_engine
        self._learning_context: dict = {}

    def run(self, resume_state: Optional[CampaignState] = None) -> CampaignState:
        """Run the full campaign, or resume from a saved state."""
        if resume_state:
            state = resume_state
            logger.info("Resuming campaign %s from phase %s", state.campaign_id, state.current_phase.value)
        else:
            state = CampaignState(
                campaign_id=f"CAMP-{uuid.uuid4().hex[:8]}",
                config=self._campaign_config,
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            logger.info("Starting campaign %s for %s", state.campaign_id, state.config.client_name)

        budget = BudgetTracker(self._campaign_config)
        context_manager = ContextManager()

        # Load learning context from past campaigns
        if self._learning_engine:
            client_id = state.config.client_id or state.config.client_name.lower().replace(" ", "-")
            try:
                self._learning_context = self._learning_engine.get_learning_context(client_id)
                state.learning_context = self._learning_context
                if self._learning_context.get("past_campaigns"):
                    logger.info(
                        "Loaded learning context: %d past campaigns, %d lessons",
                        len(self._learning_context.get("past_campaigns", [])),
                        len(self._learning_context.get("lessons_learned", [])),
                    )
            except Exception as exc:
                logger.warning("Failed to load learning context: %s", exc)

        try:
            for phase in _PHASE_ORDER:
                # Skip phases we've already completed (for resume)
                if self._phase_already_done(state, phase):
                    continue

                state.current_phase = phase
                logger.info("=== Phase: %s ===", phase.value)

                # Conclude and deliver must always run — they summarize findings
                # and generate the report. Only enforce budget on earlier phases.
                if phase not in (CampaignPhase.CONCLUDE, CampaignPhase.DELIVER):
                    try:
                        budget.check_or_raise()
                    except BudgetExhausted as exc:
                        logger.warning("Budget exhausted before %s: %s", phase.value, exc)
                        state.errors.append(f"Budget exhausted before {phase.value}: {exc}")
                        # Skip to conclude — don't break the loop
                        continue

                phase_result = self._run_phase(state, phase, budget, context_manager)
                state.phase_results.append(phase_result)

                # Update budget counters on state
                state.total_kql_queries += phase_result.kql_queries_run
                state.total_tool_calls += phase_result.tool_calls
                state.total_llm_tokens += phase_result.llm_tokens_used

                if phase_result.status == "failed":
                    logger.error("Phase %s failed: %s", phase.value, phase_result.errors)
                    if phase in (CampaignPhase.INDEX_REFRESH, CampaignPhase.HYPOTHESIZE):
                        # Critical phases — can't continue
                        state.status = "failed"
                        state.errors.extend(phase_result.errors)
                        break
                    # Non-critical — continue with what we have

                # Persist state after each phase
                self._save_state(state)

            # Campaign complete
            if state.status != "failed":
                state.status = "completed"
                state.current_phase = CampaignPhase.COMPLETED

        except BudgetExhausted as exc:
            state.status = "completed"  # partial completion is still a completion
            state.errors.append(f"Campaign ended early: {exc}")
            logger.warning("Campaign ended due to budget: %s", exc)
        except Exception as exc:
            state.status = "failed"
            state.errors.append(f"Unexpected error: {exc}")
            logger.exception("Campaign %s failed", state.campaign_id)

        state.completed_at = datetime.now(timezone.utc).isoformat()
        self._save_state(state)

        # Persist campaign and extract lessons for future hunts
        if self._learning_engine:
            try:
                self._learning_engine.persist_campaign(state)
                logger.info("Campaign %s persisted with lessons extracted", state.campaign_id)
            except Exception as exc:
                logger.warning("Failed to persist campaign lessons: %s", exc)

        logger.info(
            "Campaign %s %s: %d findings, %d queries, %.1f min",
            state.campaign_id, state.status,
            len(state.findings), state.total_kql_queries, state.duration_minutes,
        )
        return state

    def _run_phase(
        self,
        state: CampaignState,
        phase: CampaignPhase,
        budget: BudgetTracker,
        context_manager: ContextManager,
    ) -> PhaseResult:
        """Dispatch to the appropriate phase runner."""

        if phase == CampaignPhase.INDEX_REFRESH:
            return self._run_index_refresh(state, budget)

        if phase == CampaignPhase.HYPOTHESIZE:
            runner = HypothesizePhaseRunner(
                llm=self._llm,
                tool_executor=self._tool_executor,
                budget=budget,
                context_manager=context_manager,
            )
        elif phase == CampaignPhase.EXECUTE:
            runner = ExecutePhaseRunner(
                llm=self._llm,
                tool_executor=self._tool_executor,
                budget=budget,
                context_manager=context_manager,
            )
        elif phase == CampaignPhase.CONCLUDE:
            # Conclude gets an unlimited budget — it must always complete
            conclude_config = CampaignConfig(
                client_name=state.config.client_name,
                max_llm_tokens=2_000_000,
                max_total_queries=9999,
                max_duration_minutes=120,
            )
            runner = ConcludePhaseRunner(
                llm=self._llm,
                tool_executor=self._tool_executor,
                budget=BudgetTracker(conclude_config),
                context_manager=context_manager,
            )
        elif phase == CampaignPhase.DELIVER:
            # Deliver gets an unlimited budget — it must always complete
            deliver_config = CampaignConfig(
                client_name=state.config.client_name,
                max_llm_tokens=2_000_000,
                max_total_queries=9999,
                max_duration_minutes=120,
            )
            runner = DeliverPhaseRunner(
                llm=self._llm,
                tool_executor=self._tool_executor,
                budget=BudgetTracker(deliver_config),
                context_manager=context_manager,
            )
        else:
            return PhaseResult(phase=phase, status="skipped", summary="Unknown phase")

        return runner.run(state)

    def _run_index_refresh(self, state: CampaignState, budget: BudgetTracker) -> PhaseResult:
        """Phase 1: Load or refresh the environment index."""
        from mssp_hunt_agent.hunter.phases.base import _now_iso

        result = PhaseResult(
            phase=CampaignPhase.INDEX_REFRESH,
            status="running",
            started_at=_now_iso(),
        )

        client_id = state.config.client_id or state.config.client_name.lower().replace(" ", "-")

        try:
            # Try to load existing index
            existing = self._index_store.load(client_id)

            if existing and not self._index_store.needs_refresh(client_id, "dynamic", max_age_hours=1):
                # Fresh enough — use as-is
                state.environment_index = existing
                result.status = "success"
                result.summary = f"Loaded cached index (v{existing.metadata.index_version})"
                logger.info("Using cached environment index for %s", client_id)
            else:
                # Build or refresh
                adapter = self._tool_executor._get_sentinel_adapter()
                builder = IndexBuilder(
                    adapter=adapter,
                    workspace_id=self._agent_config.sentinel_workspace_id,
                    client_id=client_id,
                )

                if existing:
                    # Just refresh dynamic layer
                    builder.build_dynamic(existing)
                    # Check if semi-static needs refresh (weekly)
                    if self._index_store.needs_refresh(client_id, "semi_static", max_age_hours=168):
                        builder.build_semi_static(existing)
                    state.environment_index = existing
                    result.summary = "Refreshed dynamic layer of existing index"
                else:
                    # Full build
                    index = builder.build_full()
                    state.environment_index = index
                    result.summary = f"Built full index: {len(index.telemetry.tables)} tables"

                # Save updated index
                self._index_store.save(state.environment_index)
                result.kql_queries_run = 15  # approximate

            result.status = "success"
        except Exception as exc:
            result.status = "failed"
            result.errors.append(f"Index build failed: {exc}")
            logger.exception("Index refresh failed for %s", client_id)

        result.completed_at = _now_iso()
        return result

    def _phase_already_done(self, state: CampaignState, phase: CampaignPhase) -> bool:
        """Check if a phase has already been completed (for resume)."""
        return any(
            pr.phase == phase and pr.status in ("success", "partial")
            for pr in state.phase_results
        )

    def _save_state(self, state: CampaignState) -> None:
        """Persist campaign state. Currently saves index; could extend to SQLite."""
        if state.environment_index:
            try:
                self._index_store.save(state.environment_index)
            except Exception as exc:
                logger.warning("Failed to persist index: %s", exc)
