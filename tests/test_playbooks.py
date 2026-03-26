"""Tests for the playbook engine."""

import pytest

from mssp_hunt_agent.agent.controller import AgentController
from mssp_hunt_agent.agent.models import AgentIntent
from mssp_hunt_agent.agent.playbooks import (
    Playbook,
    PlaybookStep,
    execute_playbook,
    get_playbook,
    list_playbooks,
)
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="PurpleStratus",
        agent_enabled=True,
        persist=False,
    )


@pytest.fixture
def controller(config: HuntAgentConfig) -> AgentController:
    return AgentController(config=config)


# ── Playbook loading tests ───────────────────────────────────────────


class TestPlaybookLoading:
    def test_list_playbooks(self) -> None:
        playbooks = list_playbooks()
        assert len(playbooks) >= 3
        names = [pb.name for pb in playbooks]
        assert any("Ransomware" in n for n in names)
        assert any("BEC" in n for n in names)
        assert any("Credential" in n for n in names)

    def test_get_playbook_by_name(self) -> None:
        pb = get_playbook("ransomware")
        assert pb is not None
        assert "Ransomware" in pb.name

    def test_get_playbook_partial_match(self) -> None:
        pb = get_playbook("bec")
        assert pb is not None
        assert "BEC" in pb.name

    def test_get_playbook_not_found(self) -> None:
        pb = get_playbook("nonexistent_playbook_xyz")
        assert pb is None

    def test_playbook_has_steps(self) -> None:
        pb = get_playbook("ransomware")
        assert pb is not None
        assert len(pb.steps) >= 3

    def test_playbook_severity(self) -> None:
        pb = get_playbook("ransomware")
        assert pb is not None
        assert pb.severity == "critical"


# ── Playbook execution tests ────────────────────────────────────────


class TestPlaybookExecution:
    def test_execute_ransomware_playbook(self, config: HuntAgentConfig) -> None:
        pb = get_playbook("ransomware")
        assert pb is not None
        response = execute_playbook(pb, config)
        assert response.details.get("hunts_launched", 0) > 0
        assert len(response.details.get("run_ids", [])) > 0

    def test_execute_has_thinking_trace(self, config: HuntAgentConfig) -> None:
        pb = get_playbook("bec")
        assert pb is not None
        response = execute_playbook(pb, config)
        step_types = [s.step_type for s in response.thinking_trace]
        assert "planning" in step_types
        assert "executing" in step_types
        assert "synthesizing" in step_types

    def test_execute_custom_playbook(self, config: HuntAgentConfig) -> None:
        pb = Playbook(
            name="Test Playbook",
            description="Test",
            steps=[
                PlaybookStep(
                    action="hunt",
                    hypothesis="Test hunt hypothesis",
                    techniques=["T1059"],
                    time_range="last 1 day",
                ),
            ],
        )
        response = execute_playbook(pb, config)
        assert response.details.get("hunts_launched") == 1


# ── Agent controller playbook integration ────────────────────────────


class TestPlaybookIntent:
    def test_run_ransomware_playbook(self, controller: AgentController) -> None:
        response = controller.process("Run the ransomware playbook")
        assert response.intent == AgentIntent.RUN_PLAYBOOK
        assert response.details.get("hunts_launched", 0) > 0

    def test_list_playbooks_no_name(self, controller: AgentController) -> None:
        response = controller.process("Run playbook")
        assert response.intent == AgentIntent.RUN_PLAYBOOK
        # Should list available playbooks
        assert "playbooks" in response.details or "Available" in response.summary

    def test_playbook_not_found(self, controller: AgentController) -> None:
        response = controller.process("Run the xyz123 playbook")
        assert response.intent == AgentIntent.RUN_PLAYBOOK
        assert response.error == "playbook_not_found"
