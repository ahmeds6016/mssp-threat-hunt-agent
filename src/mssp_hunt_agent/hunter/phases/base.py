"""Base phase runner — wraps the AgentLoop pattern with phase-specific config."""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS, ToolExecutor
from mssp_hunt_agent.hunter.budget import BudgetTracker
from mssp_hunt_agent.hunter.context import ContextManager
from mssp_hunt_agent.hunter.models.campaign import CampaignState, PhaseResult, CampaignPhase

if TYPE_CHECKING:
    from mssp_hunt_agent.persistence.progress import ProgressTracker

logger = logging.getLogger(__name__)


class PhaseRunner(ABC):
    """Base class for hunt campaign phase runners.

    Each phase runner:
    1. Builds a phase-specific system prompt
    2. Selects a subset of tools relevant to that phase
    3. Runs an inner agent loop with its own iteration budget
    4. Manages context compression for long-running phases
    5. Produces a PhaseResult with artifacts
    """

    def __init__(
        self,
        llm: LLMAdapter,
        tool_executor: ToolExecutor,
        budget: BudgetTracker,
        context_manager: ContextManager | None = None,
        progress: ProgressTracker | None = None,
    ) -> None:
        self.llm = llm
        self.tool_executor = tool_executor
        self.budget = budget
        self.context_manager = context_manager or ContextManager()
        self._progress = progress

    def _log(self, event: str, **kwargs) -> None:
        """Fire a progress event if tracker is attached."""
        if self._progress:
            self._progress.log(event, **kwargs)

    @abstractmethod
    def phase_name(self) -> CampaignPhase:
        """Which phase this runner handles."""
        ...

    @abstractmethod
    def build_system_prompt(self, state: CampaignState) -> str:
        """Build the system prompt for this phase, using campaign state."""
        ...

    @abstractmethod
    def get_tools(self) -> list[dict[str, Any]]:
        """Return the tool schemas available in this phase."""
        ...

    @abstractmethod
    def get_max_iterations(self, state: CampaignState) -> int:
        """Max LLM iterations for this phase."""
        ...

    @abstractmethod
    def extract_artifacts(self, response_text: str, state: CampaignState) -> dict[str, Any]:
        """Extract structured artifacts from the LLM's final response."""
        ...

    def get_initial_user_message(self, state: CampaignState) -> str:
        """The user message to kick off this phase. Override if needed."""
        return f"Begin the {self.phase_name().value} phase now."

    def run(self, state: CampaignState) -> PhaseResult:
        """Execute this phase using an agent loop pattern."""
        phase = self.phase_name()
        max_iterations = self.get_max_iterations(state)
        timeout_minutes = state.config.phase_timeout_minutes.get(phase.value, 10)
        timeout_seconds = timeout_minutes * 60

        result = PhaseResult(
            phase=phase,
            status="running",
            started_at=_now_iso(),
        )

        # Build messages
        system_prompt = self.build_system_prompt(state)
        tools = self.get_tools()
        user_message = self.get_initial_user_message(state)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        start_time = time.monotonic()

        for iteration in range(max_iterations):
            # Check budgets
            elapsed = time.monotonic() - start_time
            if elapsed > timeout_seconds:
                result.errors.append(f"Phase timed out after {elapsed:.0f}s")
                break
            if not self.budget.can_call_llm():
                result.errors.append("LLM token budget exhausted")
                break

            # Context compression if needed
            if self.context_manager.should_compress(messages):
                summary_prompt = self.context_manager.build_compression_prompt(messages)
                try:
                    summary_resp = self.llm.chat_with_tools(
                        messages=[
                            {"role": "system", "content": "Summarize these observations concisely."},
                            {"role": "user", "content": summary_prompt},
                        ],
                        tools=[],
                        max_tokens=2048,
                    )
                    summary = summary_resp.get("content", "")
                    messages = self.context_manager.compress(messages, summary)
                except Exception as exc:
                    logger.warning("Context compression failed: %s", exc)

            # Call LLM with tools (retry up to 3 times with backoff)
            response = None
            for attempt in range(3):
                try:
                    response = self.llm.chat_with_tools(
                        messages=messages,
                        tools=tools,
                        max_tokens=4096,
                    )
                    break
                except Exception as exc:
                    if attempt < 2:
                        wait = (attempt + 1) * 5  # 5s, 10s
                        logger.warning(
                            "Phase %s LLM call failed (attempt %d/3), retrying in %ds: %s",
                            phase.value, attempt + 1, wait, exc,
                        )
                        time.sleep(wait)
                    else:
                        result.errors.append(f"LLM call failed after 3 attempts: {exc}")
                        logger.exception("Phase %s LLM call failed after retries", phase.value)
            if response is None:
                break

            content = response.get("content")
            tool_calls = response.get("tool_calls")

            # Track LLM token usage
            usage = response.get("usage", {})
            tokens_used = usage.get("total_tokens", 0)
            if tokens_used:
                self.budget.record_llm_tokens(tokens_used)
                result.llm_tokens_used += tokens_used

            # If LLM returned text with no tool calls → phase complete
            if content and not tool_calls:
                result.iterations = iteration + 1
                result.status = "success"
                result.summary = content[:2000]
                result.artifacts = self.extract_artifacts(content, state)
                self._log(
                    "phase_llm_done",
                    phase=phase.value,
                    iterations=iteration + 1,
                    detail=content[:150],
                )
                break

            # Process tool calls
            if tool_calls:
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
                        import json
                        args = json.loads(args_str) if isinstance(args_str, str) else args_str
                    except Exception:
                        args = {}

                    # Execute tool (with per-tool timeout protection)
                    t0 = time.monotonic()
                    try:
                        result_str = self.tool_executor.execute(tool_name, args)
                    except Exception as tool_exc:
                        result_str = json.dumps({"error": f"Tool {tool_name} failed: {tool_exc}"})
                        logger.warning("Tool %s execution failed: %s", tool_name, tool_exc)
                    duration_ms = int((time.monotonic() - t0) * 1000)

                    # Track budget
                    result.tool_calls += 1
                    self.budget.record_tool_call()
                    if tool_name == "run_kql_query":
                        result.kql_queries_run += 1
                        self.budget.record_query()

                    # Log progress event for every tool call
                    self._log(
                        "tool_executed",
                        phase=phase.value,
                        tool=tool_name,
                        ms=duration_ms,
                        result_len=len(result_str),
                        args_preview=str(args)[:150],
                    )

                    # Append tool result (truncate with warning)
                    truncated = result_str[:8000]
                    if len(result_str) > 8000:
                        truncated += (
                            "\n\n[WARNING: Results truncated. Original size: "
                            f"{len(result_str)} chars. Use filters or reduce "
                            "max_results for complete data.]"
                        )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": truncated,
                    })

            # Empty response
            if not content and not tool_calls:
                result.errors.append("LLM returned empty response")
                break

        else:
            # Max iterations reached — force final response
            messages.append({
                "role": "system",
                "content": (
                    "You have reached the maximum number of tool calls for this phase. "
                    "Provide your final analysis now based on everything gathered so far."
                ),
            })
            try:
                final = self.llm.chat_with_tools(messages=messages, tools=[], max_tokens=4096)
                final_text = final.get("content", "Phase completed with max iterations.")
                result.summary = final_text[:2000]
                result.artifacts = self.extract_artifacts(final_text, state)
                result.status = "partial"
            except Exception:
                result.status = "partial"
                result.summary = "Phase completed with max iterations (forced)."

        result.completed_at = _now_iso()
        result.iterations = result.iterations or max_iterations
        return result


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _get_tools_by_name(names: list[str]) -> list[dict[str, Any]]:
    """Select a subset of AGENT_TOOLS by function name."""
    return [t for t in AGENT_TOOLS if t["function"]["name"] in names]
