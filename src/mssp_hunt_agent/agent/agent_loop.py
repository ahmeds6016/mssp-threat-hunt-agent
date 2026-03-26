"""Agent loop — iterative tool-calling loop driven by GPT-4o."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from pydantic import BaseModel, Field

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.agent.models import ReasoningStep
from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS, ToolExecutor
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


class ToolCallRecord(BaseModel):
    """Record of a single tool call made during the agent loop."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_preview: str = ""
    duration_ms: int = 0


class AgentLoopResult(BaseModel):
    """Result of an agent loop execution."""

    response_text: str
    tool_calls_made: list[ToolCallRecord] = Field(default_factory=list)
    reasoning_steps: list[ReasoningStep] = Field(default_factory=list)
    total_iterations: int = 0


class AgentLoop:
    """Iterative tool-calling agent loop.

    1. Sends user message + system prompt + tools to LLM
    2. If LLM returns tool_calls → execute → append results → loop
    3. If LLM returns text → done
    4. Max iterations cap prevents runaway loops
    """

    def __init__(
        self,
        config: HuntAgentConfig,
        llm: LLMAdapter,
        tool_executor: ToolExecutor,
        *,
        max_iterations: int | None = None,
        system_prompt: str = "",
    ) -> None:
        self.config = config
        self.llm = llm
        self.tool_executor = tool_executor
        self.max_iterations = max_iterations or config.agent_loop_max_iterations
        self.system_prompt = system_prompt

    def run(self, user_message: str) -> AgentLoopResult:
        """Execute the agent loop for a user message."""
        steps: list[ReasoningStep] = []
        tool_calls_made: list[ToolCallRecord] = []
        start_time = time.time()
        timeout = self.config.agent_loop_timeout_seconds

        # Build initial messages
        messages: list[dict[str, Any]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user_message})

        tools = AGENT_TOOLS

        for iteration in range(self.max_iterations):
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                steps.append(ReasoningStep(
                    step_type="error",
                    description=f"Agent loop timed out after {elapsed:.0f}s",
                ))
                break

            # Call LLM with tools
            try:
                response = self.llm.chat_with_tools(
                    messages=messages,
                    tools=tools,
                    max_tokens=4096,
                    temperature=0.2,
                )
            except Exception as exc:
                steps.append(ReasoningStep(
                    step_type="error",
                    description=f"LLM call failed: {exc}",
                ))
                break

            content = response.get("content")
            tool_calls = response.get("tool_calls")

            # If LLM returned text with no tool calls → done
            if content and not tool_calls:
                steps.append(ReasoningStep(
                    step_type="synthesizing",
                    description="Agent produced final response",
                    data={"iteration": iteration + 1},
                ))
                return AgentLoopResult(
                    response_text=content,
                    tool_calls_made=tool_calls_made,
                    reasoning_steps=steps,
                    total_iterations=iteration + 1,
                )

            # Process tool calls
            if tool_calls:
                # Append assistant message with tool calls
                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls,
                }
                messages.append(assistant_msg)

                for tc in tool_calls:
                    func = tc.get("function", {})
                    tool_name = func.get("name", "")
                    args_str = func.get("arguments", "{}")
                    tc_id = tc.get("id", "")

                    try:
                        args = json.loads(args_str) if isinstance(args_str, str) else args_str
                    except json.JSONDecodeError:
                        args = {}

                    # Execute tool
                    t0 = time.time()
                    result_str = self.tool_executor.execute(tool_name, args)
                    duration_ms = int((time.time() - t0) * 1000)

                    # Record
                    record = ToolCallRecord(
                        tool_name=tool_name,
                        arguments=args,
                        result_preview=result_str[:200],
                        duration_ms=duration_ms,
                    )
                    tool_calls_made.append(record)

                    steps.append(ReasoningStep(
                        step_type="tool_call",
                        description=f"Called {tool_name}({', '.join(f'{k}={v!r}' for k, v in list(args.items())[:3])})",
                        data={"tool": tool_name, "duration_ms": duration_ms},
                    ))

                    # Append tool result message (truncate large results with warning)
                    truncated = result_str[:8000]
                    if len(result_str) > 8000:
                        truncated += "\n\n[WARNING: Results truncated. Original size: {} chars. Use filters or reduce max_results for complete data.]".format(len(result_str))
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": truncated,
                    })

            # If no content and no tool calls, something went wrong
            if not content and not tool_calls:
                steps.append(ReasoningStep(
                    step_type="error",
                    description="LLM returned empty response with no tool calls",
                ))
                break

        # Max iterations reached — force a final response
        messages.append({
            "role": "system",
            "content": "HARD STOP: Maximum tool calls reached. Provide your final response NOW. Synthesize all findings gathered so far into a complete answer. If your analysis is incomplete, clearly state what was covered and what remains uninvestigated.",
        })

        try:
            final = self.llm.chat_with_tools(messages=messages, tools=[], max_tokens=4096)
            final_text = final.get("content", "I was unable to complete the analysis within the allowed number of steps.")
        except Exception:
            final_text = "I was unable to complete the analysis within the allowed number of steps."

        steps.append(ReasoningStep(
            step_type="synthesizing",
            description=f"Forced final response after {self.max_iterations} iterations",
        ))

        return AgentLoopResult(
            response_text=final_text or "Analysis incomplete.",
            tool_calls_made=tool_calls_made,
            reasoning_steps=steps,
            total_iterations=self.max_iterations,
        )
