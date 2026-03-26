"""Abstract base class for LLM reasoning adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMAdapter(ABC):
    """Contract that every LLM reasoning backend must implement."""

    @abstractmethod
    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """Send evidence to the LLM and return structured analysis.

        Returns a dict with keys:
          - findings: list[dict]
          - evidence_items: list[dict]
          - confidence_assessment: dict
        """
        ...

    @abstractmethod
    def classify_intent(
        self,
        message: str,
        available_intents: list[str],
    ) -> dict[str, Any]:
        """Classify a user message into an intent using LLM reasoning.

        Returns a dict with keys:
          - intent: str (one of available_intents)
          - confidence: float (0-1)
          - entities: dict
          - reasoning: str
        """
        ...

    @abstractmethod
    def generate_response(
        self,
        context: str,
        results: dict[str, Any],
        *,
        max_tokens: int = 2048,
    ) -> str:
        """Generate a natural-language response from pipeline results."""
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        """Return True if the LLM backend is reachable."""
        ...

    @abstractmethod
    def get_adapter_name(self) -> str:
        """Human-readable adapter name."""
        ...

    @abstractmethod
    def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """Chat completion with function-calling tools.

        Returns a dict with keys:
          - content: str | None (text response, if any)
          - tool_calls: list[dict] | None — [{id, function: {name, arguments}}]
          - finish_reason: str ("stop" | "tool_calls")
        """
        ...
