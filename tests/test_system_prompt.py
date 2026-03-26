"""Tests for the system prompt builder."""

import pytest

from mssp_hunt_agent.agent.system_prompt import build_system_prompt
from mssp_hunt_agent.config import HuntAgentConfig


@pytest.fixture
def config() -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        adapter_mode="mock",
        default_client_name="PurpleStratus",
    )


class TestSystemPrompt:
    def test_includes_client_name(self, config: HuntAgentConfig) -> None:
        prompt = build_system_prompt(config)
        assert "PurpleStratus" in prompt

    def test_includes_sentinel_tables(self, config: HuntAgentConfig) -> None:
        prompt = build_system_prompt(config)
        assert "SecurityEvent" in prompt
        assert "SigninLogs" in prompt
        assert "DeviceProcessEvents" in prompt

    def test_includes_kql_guidance(self, config: HuntAgentConfig) -> None:
        prompt = build_system_prompt(config)
        assert "ago(" in prompt
        assert "TimeGenerated" in prompt

    def test_includes_mitre_references(self, config: HuntAgentConfig) -> None:
        prompt = build_system_prompt(config)
        assert "MITRE" in prompt or "ATT&CK" in prompt or "mitre" in prompt.lower()

    def test_default_client_fallback(self) -> None:
        config = HuntAgentConfig(default_client_name="")
        prompt = build_system_prompt(config)
        assert "Unknown Client" in prompt

    def test_prompt_is_substantial(self, config: HuntAgentConfig) -> None:
        prompt = build_system_prompt(config)
        # Should be a rich prompt, not just a few words
        assert len(prompt) > 500
