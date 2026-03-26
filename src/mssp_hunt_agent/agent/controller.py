"""Agent controller — top-level entry point for NL prompt processing."""

from __future__ import annotations

import logging

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.agent.action_router import ActionRouter
from mssp_hunt_agent.agent.chain_of_thought import ReasoningChain
from mssp_hunt_agent.agent.intent_parser import IntentParser
from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse, ReasoningStep
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


class AgentController:
    """Process natural-language prompts and return structured responses.

    When an LLM adapter is provided (or config.llm_enabled), routes to the
    agentic tool-calling loop (V6). Otherwise falls back to rule-based
    ReasoningChain (V5.1).
    """

    def __init__(
        self,
        config: HuntAgentConfig | None = None,
        llm: LLMAdapter | None = None,
    ) -> None:
        self.config = config or HuntAgentConfig.from_env()
        self.llm = llm
        self.parser = IntentParser()
        self.router = ActionRouter(self.config)

        # Build LLM adapter from config if enabled and not provided
        if self.llm is None and self.config.llm_enabled:
            self.llm = self._build_llm_adapter()

    def _build_llm_adapter(self) -> LLMAdapter | None:
        """Attempt to build an LLM adapter from config."""
        # Prefer real Azure OpenAI when credentials are configured
        if self.config.azure_openai_endpoint and self.config.azure_openai_key:
            try:
                from mssp_hunt_agent.adapters.llm.azure_openai import AzureOpenAIAdapter
                return AzureOpenAIAdapter(
                    endpoint=self.config.azure_openai_endpoint,
                    api_key=self.config.azure_openai_key,
                    deployment=self.config.azure_openai_deployment,
                    api_version=self.config.azure_openai_api_version,
                )
            except Exception as exc:
                logger.warning("Failed to build LLM adapter: %s", exc)

        # Fall back to mock LLM when no real credentials available
        if self.config.adapter_mode == "mock":
            from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
            return MockLLMAdapter()
        return None

    def process(self, message: str) -> AgentResponse:
        """Parse intent from message and execute the appropriate action."""
        if not message or not message.strip():
            return AgentResponse(
                summary="Please provide a message or question.",
                intent="general_question",
                confidence=0.0,
                error="empty_message",
            )

        # Agentic path: GPT-4o tool-calling loop (V6)
        if self.llm is not None:
            try:
                return self._run_agent_loop(message)
            except Exception as exc:
                logger.warning("Agent loop failed: %s", exc)
                if not self.config.agent_llm_fallback:
                    # Fallback disabled — return error, don't fall through
                    return AgentResponse(
                        summary=f"Agent loop failed: {exc}",
                        intent="general_question",
                        confidence=0.0,
                        error=str(exc),
                    )
                logger.info("Falling back to rule-based reasoning chain")

        # Fallback: rule-based ReasoningChain (V5.1)
        chain = ReasoningChain(config=self.config, llm=self.llm)
        return chain.process(message)

    def _run_agent_loop(self, message: str) -> AgentResponse:
        """Run the agentic tool-calling loop and convert result to AgentResponse."""
        from mssp_hunt_agent.agent.agent_loop import AgentLoop
        from mssp_hunt_agent.agent.system_prompt import build_system_prompt
        from mssp_hunt_agent.agent.tool_defs import ToolExecutor

        system_prompt = build_system_prompt(self.config)
        tool_executor = ToolExecutor(self.config)

        loop = AgentLoop(
            config=self.config,
            llm=self.llm,
            tool_executor=tool_executor,
            system_prompt=system_prompt,
        )

        result = loop.run(message)

        # Convert AgentLoopResult → AgentResponse
        return AgentResponse(
            summary=result.response_text,
            intent=AgentIntent.GENERAL_QUESTION,  # Agent loop handles all intents
            confidence=1.0,
            thinking_trace=result.reasoning_steps,
            data={
                "tool_calls_made": [tc.model_dump() for tc in result.tool_calls_made],
                "total_iterations": result.total_iterations,
                "agent_loop": True,
            },
        )
