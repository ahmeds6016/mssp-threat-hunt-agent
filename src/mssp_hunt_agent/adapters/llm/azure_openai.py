"""Azure OpenAI LLM adapter — evidence-grounded reasoning via GPT-5.3-chat."""

from __future__ import annotations

import json
import logging
from typing import Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter

logger = logging.getLogger(__name__)


class AzureOpenAIAdapter(LLMAdapter):
    """Calls Azure OpenAI deployments for structured threat analysis.

    Requires the ``openai`` package (optional dependency).
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str = "gpt-5.3-chat",
        api_version: str = "2024-12-01-preview",
        *,
        max_retries: int = 3,
        timeout: int = 120,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._deployment = deployment
        self._api_version = api_version
        self._max_retries = max_retries
        self._timeout = timeout
        self._client: Any = None
        # GPT-5.x models don't support custom temperature (only default=1)
        self._supports_temperature = not deployment.startswith("gpt-5")

    # -- lazy client construction (avoids import-time failure) ----------

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from openai import AzureOpenAI  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "openai package is required for AzureOpenAIAdapter. "
                    "Install with: pip install mssp-hunt-agent[llm]"
                ) from exc

            self._client = AzureOpenAI(
                azure_endpoint=self._endpoint,
                api_key=self._api_key,
                api_version=self._api_version,
                max_retries=self._max_retries,
                timeout=self._timeout,
            )
        return self._client

    # -- LLMAdapter interface ------------------------------------------

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        client = self._get_client()

        kwargs: dict[str, Any] = {
            "model": self._deployment,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_completion_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if self._supports_temperature:
            kwargs["temperature"] = temperature

        response = client.chat.completions.create(**kwargs)

        raw_text = response.choices[0].message.content
        if not raw_text:
            raise ValueError("LLM returned empty response")

        parsed = json.loads(raw_text)

        # Validate expected top-level keys
        required = {"findings", "evidence_items", "confidence_assessment"}
        missing = required - set(parsed.keys())
        if missing:
            raise ValueError(f"LLM response missing required keys: {missing}")

        logger.info(
            "LLM analysis complete — %d findings, %d evidence items",
            len(parsed.get("findings", [])),
            len(parsed.get("evidence_items", [])),
        )
        return parsed

    def classify_intent(
        self,
        message: str,
        available_intents: list[str],
    ) -> dict[str, Any]:
        client = self._get_client()

        system_prompt = (
            "You are an MSSP threat-hunting agent intent classifier. "
            "Classify the user message into one of these intents: "
            f"{', '.join(available_intents)}. "
            "Extract relevant entities (CVE IDs, IP addresses, hashes, technique IDs, etc). "
            "Respond with JSON: {\"intent\": str, \"confidence\": float, \"entities\": dict, \"reasoning\": str}"
        )

        ci_kwargs: dict[str, Any] = {
            "model": self._deployment,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message},
            ],
            "max_completion_tokens": 512,
            "response_format": {"type": "json_object"},
        }
        if self._supports_temperature:
            ci_kwargs["temperature"] = 0.1

        response = client.chat.completions.create(**ci_kwargs)

        raw_text = response.choices[0].message.content
        if not raw_text:
            return {"intent": "general_question", "confidence": 0.5, "entities": {}, "reasoning": "Empty LLM response"}

        parsed = json.loads(raw_text)
        if parsed.get("intent") not in available_intents:
            parsed["intent"] = "general_question"
        return parsed

    def generate_response(
        self,
        context: str,
        results: dict[str, Any],
        *,
        max_tokens: int = 2048,
    ) -> str:
        client = self._get_client()

        system_prompt = (
            "You are an MSSP threat-hunting analyst assistant. "
            "Synthesize the provided analysis results into a clear, actionable response "
            "for a security analyst. Be concise but thorough. Include key findings, "
            "confidence levels, and recommended next steps."
        )

        user_prompt = f"Context: {context}\n\nResults:\n{json.dumps(results, indent=2, default=str)}"

        gr_kwargs: dict[str, Any] = {
            "model": self._deployment,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_completion_tokens": max_tokens,
        }
        if self._supports_temperature:
            gr_kwargs["temperature"] = 0.3

        response = client.chat.completions.create(**gr_kwargs)

        return response.choices[0].message.content or "Unable to generate response."

    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self._deployment,
                messages=[{"role": "user", "content": "ping"}],
                max_completion_tokens=5,
            )
            return bool(response.choices)
        except Exception as exc:
            logger.warning("LLM connection test failed: %s", exc)
            return False

    def get_adapter_name(self) -> str:
        return f"AzureOpenAI({self._deployment})"

    def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        client = self._get_client()

        kwargs: dict[str, Any] = {
            "model": self._deployment,
            "messages": messages,
            "max_completion_tokens": max_tokens,
        }
        if self._supports_temperature:
            kwargs["temperature"] = temperature
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        result: dict[str, Any] = {
            "content": choice.message.content,
            "tool_calls": None,
            "finish_reason": choice.finish_reason,
            "usage": {
                "total_tokens": getattr(response.usage, "total_tokens", 0) if response.usage else 0,
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) if response.usage else 0,
                "completion_tokens": getattr(response.usage, "completion_tokens", 0) if response.usage else 0,
            },
        }

        if choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in choice.message.tool_calls
            ]

        return result
