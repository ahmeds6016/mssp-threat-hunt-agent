"""Complexity classifier — GPT-5.3 decides chat vs campaign routing.

A single fast LLM call (~200 tokens) classifies the analyst's message into:
- "chat": quick query, 1-3 tool calls, responds in seconds
- "campaign": deep investigation, multi-phase, 5-60 minutes

Returns structured routing decision with extracted parameters (focus areas,
time range) so campaigns can start immediately without a second parse.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from mssp_hunt_agent.adapters.llm.base import LLMAdapter

logger = logging.getLogger(__name__)

_CLASSIFIER_PROMPT = """\
You are a routing classifier for an MSSP threat hunting platform. Given an analyst's message, decide the execution path.

## Routes

**chat** — Quick, synchronous queries that need 1-3 tool calls and respond in seconds:
- Single CVE lookups ("Are we vulnerable to CVE-2024-3400?")
- Specific technique questions ("What is T1059?")
- Single-topic hunts ("Check for failed logins in the last 7 days", "Hunt for defense evasion", "Hunt for credential dumping")
- Single-tactic hunts — even if they say "hunt for", if it's ONE tactic or topic, it's chat
- Detection rule requests ("Create a rule for brute force")
- Risk assessments ("What if we lose EDR?")
- Telemetry checks ("What data sources do we have?")
- General security questions
- Investigating a specific topic across one or two tables
- Health checks, connectivity checks, version questions

**campaign** — Deep, multi-phase autonomous investigations (5-60 minutes):
- Multi-vector investigations spanning 2+ ATT&CK tactics ("Investigate ransomware AND lateral movement across the environment")
- Comprehensive security assessments ("Do a full security posture review")
- Proactive hunting without a specific target ("What threats are we missing?")
- Requests that explicitly mention "comprehensive", "full hunt", "deep dive across", "posture review"
- Requests spanning multiple ATT&CK tactics or kill chain stages simultaneously

IMPORTANT: A request about a SINGLE tactic (e.g., "Hunt for defense evasion") is CHAT, not campaign. Only route to campaign when the request covers MULTIPLE tactics/vectors or asks for a comprehensive/full assessment.

## Instructions

Respond with ONLY a JSON object:
{
  "route": "chat" or "campaign",
  "confidence": 0.0-1.0,
  "reasoning": "one sentence why",
  "focus_areas": ["extracted focus areas if campaign, else empty"],
  "time_range": "extracted time range or 'last 30 days'",
  "max_hypotheses": 10
}

Default to "chat" when ambiguous — it's better to answer quickly and let the analyst escalate than to make them wait for a campaign they didn't need.\
"""


class RoutingDecision(BaseModel):
    """Result of complexity classification."""

    route: str = "chat"  # "chat" | "campaign"
    confidence: float = 0.8
    reasoning: str = ""
    focus_areas: list[str] = Field(default_factory=list)
    time_range: str = "last 30 days"
    max_hypotheses: int = 10


def classify_complexity(
    llm: LLMAdapter,
    message: str,
) -> RoutingDecision:
    """Use GPT-5.3 to classify whether a message needs chat or campaign.

    Fast call — no tools, small prompt, ~200 completion tokens.
    Falls back to "chat" on any error.
    """
    try:
        response = llm.chat_with_tools(
            messages=[
                {"role": "system", "content": _CLASSIFIER_PROMPT},
                {"role": "user", "content": message},
            ],
            tools=[],  # No tools — just structured text completion
            max_tokens=256,
        )

        content = response.get("content", "")
        if not content:
            return RoutingDecision(reasoning="Empty LLM response, defaulting to chat")

        # Parse JSON from response (handle markdown code blocks)
        json_str = content.strip()
        if json_str.startswith("```"):
            # Strip code fences
            lines = json_str.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            json_str = "\n".join(lines)

        parsed = json.loads(json_str)

        return RoutingDecision(
            route=parsed.get("route", "chat"),
            confidence=float(parsed.get("confidence", 0.8)),
            reasoning=parsed.get("reasoning", ""),
            focus_areas=parsed.get("focus_areas", []),
            time_range=parsed.get("time_range", "last 30 days"),
            max_hypotheses=int(parsed.get("max_hypotheses", 10)),
        )

    except Exception as exc:
        logger.warning("Complexity classification failed: %s — defaulting to chat", exc)
        return RoutingDecision(
            route="chat",
            confidence=0.5,
            reasoning=f"Classification error ({exc}), defaulting to chat",
        )
