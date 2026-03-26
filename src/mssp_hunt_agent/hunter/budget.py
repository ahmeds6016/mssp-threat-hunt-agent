"""Budget tracker — prevents runaway costs during autonomous campaigns."""

from __future__ import annotations

import logging
import time

from mssp_hunt_agent.hunter.models.campaign import CampaignConfig

logger = logging.getLogger(__name__)


class BudgetExhausted(Exception):
    """Raised when a budget limit is reached."""


class BudgetTracker:
    """Tracks KQL queries, LLM tokens, and wall-clock time.

    Enforces hard caps configured in CampaignConfig to prevent
    runaway costs during autonomous hunt campaigns.
    """

    def __init__(self, config: CampaignConfig) -> None:
        self.max_queries = config.max_total_queries
        self.max_tokens = config.max_llm_tokens
        self.max_duration_seconds = config.max_duration_minutes * 60
        self._queries_used = 0
        self._tokens_used = 0
        self._tool_calls = 0
        self._started_at = time.monotonic()

    # ── Recording ────────────────────────────────────────────────

    def record_query(self, n: int = 1) -> None:
        self._queries_used += n

    def record_llm_tokens(self, tokens: int) -> None:
        self._tokens_used += tokens

    def record_tool_call(self, n: int = 1) -> None:
        self._tool_calls += n

    # ── Checks ───────────────────────────────────────────────────

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started_at

    @property
    def queries_remaining(self) -> int:
        return max(0, self.max_queries - self._queries_used)

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.max_tokens - self._tokens_used)

    @property
    def time_remaining_seconds(self) -> float:
        return max(0.0, self.max_duration_seconds - self.elapsed_seconds)

    def can_query(self) -> bool:
        return self._queries_used < self.max_queries and not self.is_time_expired

    def can_call_llm(self, estimated_tokens: int = 4000) -> bool:
        return (
            self._tokens_used + estimated_tokens <= self.max_tokens
            and not self.is_time_expired
        )

    @property
    def is_time_expired(self) -> bool:
        return self.elapsed_seconds >= self.max_duration_seconds

    def check_or_raise(self) -> None:
        """Raise BudgetExhausted if any limit is reached."""
        if self.is_time_expired:
            raise BudgetExhausted(
                f"Time budget exhausted: {self.elapsed_seconds:.0f}s "
                f"/ {self.max_duration_seconds}s"
            )
        if self._queries_used >= self.max_queries:
            raise BudgetExhausted(
                f"Query budget exhausted: {self._queries_used} / {self.max_queries}"
            )
        if self._tokens_used >= self.max_tokens:
            raise BudgetExhausted(
                f"Token budget exhausted: {self._tokens_used} / {self.max_tokens}"
            )

    # ── Reporting ────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """Current budget status for logging / prompt injection."""
        return {
            "queries_used": self._queries_used,
            "queries_remaining": self.queries_remaining,
            "tokens_used": self._tokens_used,
            "tokens_remaining": self.tokens_remaining,
            "tool_calls": self._tool_calls,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "time_remaining_seconds": round(self.time_remaining_seconds, 1),
        }
