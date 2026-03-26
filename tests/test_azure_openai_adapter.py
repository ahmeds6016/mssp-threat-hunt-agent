"""Tests for AzureOpenAIAdapter with mocked OpenAI client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.adapters.llm.azure_openai import AzureOpenAIAdapter


@pytest.fixture
def adapter() -> AzureOpenAIAdapter:
    return AzureOpenAIAdapter(
        endpoint="https://test.openai.azure.com",
        api_key="test-key",
        deployment="gpt-4o",
        api_version="2024-06-01",
    )


def _make_mock_response(content: dict | str) -> MagicMock:
    """Create a mock ChatCompletion response."""
    if isinstance(content, dict):
        text = json.dumps(content)
    else:
        text = content

    choice = MagicMock()
    choice.message.content = text

    response = MagicMock()
    response.choices = [choice]
    return response


VALID_RESPONSE = {
    "findings": [
        {
            "finding_id": "F-LLM-test1234",
            "title": "Test Finding",
            "description": "A finding from the LLM",
            "confidence": "medium",
            "evidence_ids": ["E-1"],
            "benign_explanations": ["Normal activity"],
            "what_would_increase_confidence": ["More logs"],
        }
    ],
    "evidence_items": [
        {
            "evidence_id": "E-LLM-test1234",
            "source": "llm_analysis",
            "observation": "Observed anomaly",
            "significance": "suspicious",
            "supporting_data": "data",
        }
    ],
    "confidence_assessment": {
        "overall_confidence": "medium",
        "rationale": "Based on available evidence",
        "limiting_factors": ["Mock data"],
        "telemetry_impact": "Adequate",
    },
}


class TestAzureOpenAIAdapter:
    def test_analyze_success(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response(
            VALID_RESPONSE
        )
        adapter._client = mock_client

        result = adapter.analyze("system prompt", "user prompt")

        assert "findings" in result
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "Test Finding"

        # Verify call args
        call_kwargs = mock_client.chat.completions.create.call_args
        assert call_kwargs.kwargs["model"] == "gpt-4o"
        msgs = call_kwargs.kwargs["messages"]
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"

    def test_analyze_empty_response(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        choice = MagicMock()
        choice.message.content = None
        response = MagicMock()
        response.choices = [choice]
        mock_client.chat.completions.create.return_value = response
        adapter._client = mock_client

        with pytest.raises(ValueError, match="empty response"):
            adapter.analyze("system", "user")

    def test_analyze_invalid_json(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response(
            "not json at all"
        )
        adapter._client = mock_client

        with pytest.raises(json.JSONDecodeError):
            adapter.analyze("system", "user")

    def test_analyze_missing_keys(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response(
            {"findings": [], "extra": "stuff"}
        )
        adapter._client = mock_client

        with pytest.raises(ValueError, match="missing required keys"):
            adapter.analyze("system", "user")

    def test_analyze_respects_params(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response(
            VALID_RESPONSE
        )
        adapter._client = mock_client

        adapter.analyze("sys", "usr", max_tokens=2048, temperature=0.5)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["max_completion_tokens"] == 2048
        assert call_kwargs["temperature"] == 0.5

    def test_test_connection_success(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response("ok")
        adapter._client = mock_client

        assert adapter.test_connection() is True

    def test_test_connection_failure(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API error")
        adapter._client = mock_client

        assert adapter.test_connection() is False

    def test_get_adapter_name(self, adapter: AzureOpenAIAdapter) -> None:
        assert adapter.get_adapter_name() == "AzureOpenAI(gpt-4o)"

    def test_lazy_client_import_error(self) -> None:
        """When openai is not installed, _get_client raises ImportError."""
        a = AzureOpenAIAdapter(
            endpoint="https://test.openai.azure.com",
            api_key="key",
        )
        with patch.dict("sys.modules", {"openai": None}):
            with pytest.raises(ImportError, match="openai package"):
                a._get_client()

    def test_analyze_api_exception(self, adapter: AzureOpenAIAdapter) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RuntimeError("Rate limited")
        adapter._client = mock_client

        with pytest.raises(RuntimeError, match="Rate limited"):
            adapter.analyze("system", "user")
