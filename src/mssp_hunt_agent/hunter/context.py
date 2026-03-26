"""Context window manager — compresses LLM message history during long campaigns."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Rough token estimate: 1 token ≈ 4 chars for English text
_CHARS_PER_TOKEN = 4


class ContextManager:
    """Manages the LLM message history within a phase to prevent context overflow.

    During a 20+ iteration phase, raw tool results can consume the entire
    context window. This manager:

    1. Estimates current token usage
    2. When threshold is exceeded, compresses old tool results into a summary
    3. Keeps the system prompt, recent messages, and evidence intact
    """

    def __init__(
        self,
        max_tokens: int = 100_000,
        compression_threshold: int = 60_000,
        keep_recent: int = 6,
    ) -> None:
        self.max_tokens = max_tokens
        self.compression_threshold = compression_threshold
        self.keep_recent = keep_recent  # Always keep this many recent messages

    def estimate_tokens(self, messages: list[dict[str, Any]]) -> int:
        """Rough token count estimate from message content."""
        total_chars = 0
        for msg in messages:
            content = msg.get("content") or ""
            total_chars += len(content)
            # Tool calls contribute tokens too
            if "tool_calls" in msg:
                total_chars += len(json.dumps(msg["tool_calls"]))
        return total_chars // _CHARS_PER_TOKEN

    def should_compress(self, messages: list[dict[str, Any]]) -> bool:
        return self.estimate_tokens(messages) > self.compression_threshold

    def compress(
        self,
        messages: list[dict[str, Any]],
        summary: str,
    ) -> list[dict[str, Any]]:
        """Replace old tool results with a compressed summary.

        Keeps:
        - System prompt (index 0)
        - The compression summary as a system message
        - Last N recent messages (for continuity)

        Parameters
        ----------
        messages:
            Full message history.
        summary:
            LLM-generated summary of observations so far.
        """
        if len(messages) <= self.keep_recent + 1:
            return messages  # Nothing to compress

        # Keep system prompt
        system_msgs = [m for m in messages if m.get("role") == "system"]
        system_prompt = system_msgs[0] if system_msgs else None

        # Keep recent messages, ensuring tool-call/tool-response pairs stay together.
        # Walk backward from the split point if the first kept message is an orphaned
        # tool response (which would cause an API error).
        split_idx = max(1, len(messages) - self.keep_recent)
        while split_idx > 1 and messages[split_idx].get("role") == "tool":
            split_idx -= 1
        recent = messages[split_idx:]

        # Build compressed history
        compressed: list[dict[str, Any]] = []
        if system_prompt:
            compressed.append(system_prompt)

        compressed.append({
            "role": "system",
            "content": (
                "COMPRESSED CONTEXT — The following summarizes observations "
                "from prior tool calls in this phase. Use this as your working "
                "memory:\n\n" + summary
            ),
        })
        compressed.extend(recent)

        before = self.estimate_tokens(messages)
        after = self.estimate_tokens(compressed)
        logger.info(
            "Context compressed: %d → %d tokens (%d messages → %d)",
            before, after, len(messages), len(compressed),
        )
        return compressed

    def build_compression_prompt(self, messages: list[dict[str, Any]]) -> str:
        """Build a prompt asking the LLM to summarize observations so far.

        This is called as a tool during the phase to generate the summary.
        """
        # Extract tool results from message history
        observations = []
        for msg in messages:
            if msg.get("role") == "tool":
                content = msg.get("content", "")
                # Truncate very long tool results
                if len(content) > 500:
                    content = content[:500] + "..."
                observations.append(content)
            elif msg.get("role") == "assistant" and msg.get("content"):
                observations.append(f"[Agent reasoning]: {msg['content'][:300]}")

        return (
            "Summarize the key observations from these tool results into a compact "
            "working memory. Focus on:\n"
            "1. Entities discovered (users, IPs, hosts, accounts)\n"
            "2. Suspicious patterns or anomalies found\n"
            "3. Queries that returned no results (dead ends)\n"
            "4. Evidence collected so far\n"
            "5. What still needs to be investigated\n\n"
            "Tool results:\n" + "\n---\n".join(observations[-15:])
        )
