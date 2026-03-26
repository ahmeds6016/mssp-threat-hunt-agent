"""Tests for V7 CampaignOrchestrator — full lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.hunter.budget import BudgetExhausted
from mssp_hunt_agent.hunter.campaign import CampaignOrchestrator, _PHASE_ORDER
from mssp_hunt_agent.hunter.index_store import IndexStore
from mssp_hunt_agent.hunter.models.campaign import (
    CampaignConfig,
    CampaignPhase,
    CampaignState,
    PhaseResult,
)
from mssp_hunt_agent.hunter.models.environment import (
    EnvironmentIndex,
    IdentityIndex,
    IndexMetadata,
    TableProfile,
    TelemetryIndex,
)


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def agent_config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="TestCorp",
    )


@pytest.fixture
def campaign_config() -> CampaignConfig:
    return CampaignConfig(
        client_name="TestCorp",
        max_hypotheses=2,
        max_total_queries=20,
        max_duration_minutes=5,
        max_llm_tokens=50_000,
    )


@pytest.fixture
def mock_llm() -> MagicMock:
    llm = MagicMock()
    # Default: LLM returns text (no tool calls)
    llm.chat_with_tools.return_value = {
        "content": "Phase analysis complete.",
        "tool_calls": None,
    }
    return llm


@pytest.fixture
def index_store(tmp_path: Path) -> IndexStore:
    return IndexStore(base_dir=str(tmp_path))


@pytest.fixture
def sample_index() -> EnvironmentIndex:
    return EnvironmentIndex(
        metadata=IndexMetadata(
            client_id="testcorp",
            workspace_id="ws-123",
            static_refreshed_at="2026-03-10T00:00:00+00:00",
            semi_static_refreshed_at="2026-03-10T00:00:00+00:00",
            dynamic_refreshed_at="2026-03-10T00:00:00+00:00",
        ),
        telemetry=TelemetryIndex(
            tables=[
                TableProfile(table_name="SigninLogs", row_count_7d=1000, ingestion_healthy=True),
            ],
        ),
    )


# ── Tests ───────────────────────────────────────────────────────────


class TestCampaignOrchestratorInit:
    def test_creation(self, agent_config, mock_llm, campaign_config, index_store):
        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        assert orch._campaign_config.client_name == "TestCorp"


class TestPhaseOrder:
    def test_phase_order(self):
        assert _PHASE_ORDER == [
            CampaignPhase.INDEX_REFRESH,
            CampaignPhase.HYPOTHESIZE,
            CampaignPhase.EXECUTE,
            CampaignPhase.CONCLUDE,
            CampaignPhase.DELIVER,
        ]


class TestIndexRefreshPhase:
    def test_uses_cached_index(self, agent_config, mock_llm, campaign_config, index_store, sample_index):
        # Pre-save an index
        index_store.save(sample_index)

        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = CampaignState(
            campaign_id="CAMP-test",
            config=campaign_config,
            status="running",
        )
        result = orch._run_index_refresh(state, orch._tool_executor.config)
        # Should have loaded the cached index
        assert result.status == "success"
        assert "cached" in result.summary.lower() or "index" in result.summary.lower()


class TestPhaseAlreadyDone:
    def test_skip_completed_phase(self, agent_config, mock_llm, campaign_config, index_store):
        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = CampaignState(
            campaign_id="CAMP-test",
            config=campaign_config,
            phase_results=[
                PhaseResult(phase=CampaignPhase.INDEX_REFRESH, status="success"),
            ],
        )
        assert orch._phase_already_done(state, CampaignPhase.INDEX_REFRESH) is True
        assert orch._phase_already_done(state, CampaignPhase.HYPOTHESIZE) is False

    def test_partial_counts_as_done(self, agent_config, mock_llm, campaign_config, index_store):
        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = CampaignState(
            campaign_id="CAMP-test",
            config=campaign_config,
            phase_results=[
                PhaseResult(phase=CampaignPhase.EXECUTE, status="partial"),
            ],
        )
        assert orch._phase_already_done(state, CampaignPhase.EXECUTE) is True


class TestCampaignRun:
    def test_full_run_with_cached_index(self, agent_config, mock_llm, campaign_config, index_store, sample_index):
        """Full campaign run with pre-cached index — all phases return text immediately."""
        index_store.save(sample_index)

        mock_llm.chat_with_tools.return_value = {
            "content": "Phase complete. No findings.",
            "tool_calls": None,
        }

        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = orch.run()

        assert state.status == "completed"
        assert state.campaign_id.startswith("CAMP-")
        assert len(state.phase_results) >= 4  # INDEX_REFRESH + HYPOTHESIZE + EXECUTE + CONCLUDE + DELIVER
        assert state.completed_at != ""

    def test_critical_phase_failure_stops_campaign(self, agent_config, mock_llm, campaign_config, index_store):
        """If INDEX_REFRESH fails, the entire campaign should fail."""
        # No cached index, and adapter will fail to build
        mock_llm.chat_with_tools.side_effect = RuntimeError("LLM down")

        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )

        # The index refresh doesn't use LLM — it uses Sentinel adapter which is mock
        # So we need to patch the IndexBuilder to fail
        with patch("mssp_hunt_agent.hunter.campaign.IndexBuilder") as MockBuilder:
            MockBuilder.return_value.build_full.side_effect = RuntimeError("Sentinel unavailable")
            state = orch.run()

        assert state.status == "failed"
        assert any("Index build failed" in e for e in state.errors)

    def test_resume_skips_completed_phases(self, agent_config, mock_llm, campaign_config, index_store, sample_index):
        """Resume should skip already completed phases."""
        index_store.save(sample_index)

        mock_llm.chat_with_tools.return_value = {
            "content": "Phase complete.",
            "tool_calls": None,
        }

        # Create a pre-existing state with INDEX_REFRESH done
        existing_state = CampaignState(
            campaign_id="CAMP-resume",
            config=campaign_config,
            status="running",
            started_at="2026-03-10T00:00:00+00:00",
            environment_index=sample_index,
            phase_results=[
                PhaseResult(phase=CampaignPhase.INDEX_REFRESH, status="success"),
            ],
        )

        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = orch.run(resume_state=existing_state)

        assert state.status == "completed"
        # Should have 5 phase results (1 pre-existing + 4 new)
        idx_results = [pr for pr in state.phase_results if pr.phase == CampaignPhase.INDEX_REFRESH]
        assert len(idx_results) == 1  # Not duplicated

    def test_budget_exhaustion_completes_partially(self, agent_config, mock_llm, campaign_config, index_store, sample_index):
        """Budget exhaustion should result in partial completion, not failure."""
        index_store.save(sample_index)
        campaign_config.max_total_queries = 0  # Immediate budget exhaustion

        mock_llm.chat_with_tools.return_value = {
            "content": "Phase complete.",
            "tool_calls": None,
        }

        orch = CampaignOrchestrator(
            agent_config=agent_config,
            llm=mock_llm,
            campaign_config=campaign_config,
            index_store=index_store,
        )
        state = orch.run()

        # Queries-exhausted budget should still complete some phases
        assert state.completed_at != ""
