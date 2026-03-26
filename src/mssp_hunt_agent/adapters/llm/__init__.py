"""LLM adapter package — pluggable reasoning backends."""

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter

__all__ = ["LLMAdapter", "MockLLMAdapter"]
