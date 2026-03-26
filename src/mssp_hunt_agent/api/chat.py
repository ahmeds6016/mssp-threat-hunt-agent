"""Chat API endpoints — natural-language agent interface."""

from __future__ import annotations

import logging

from fastapi import APIRouter

from mssp_hunt_agent.agent.controller import AgentController
from mssp_hunt_agent.agent.response_formatter import format_response
from mssp_hunt_agent.api.dependencies import get_config

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/api/v1/chat")
def chat_v1(body: dict) -> dict:
    """Natural-language agent endpoint (versioned API) — returns full JSON."""
    return _process_chat(body)


@router.post("/api/chat")
def chat_flow(body: dict) -> dict:
    """Natural-language agent endpoint (Power Automate / Copilot Studio).

    Returns a simplified response with just the human-readable text.
    Uses format_response() for clean plain-text output.
    """
    result = _process_chat(body)
    return {"body": result["response"]}


def _process_chat(body: dict) -> dict:
    """Shared chat processing logic."""
    message = (body.get("message") or body.get("text") or "").strip()
    if not message:
        return {
            "response": "Please provide a message.",
            "intent": "general_question",
            "error": "empty_message",
        }

    config = get_config()
    controller = AgentController(config=config)
    response = controller.process(message)

    result: dict = {
        "response": format_response(response),
        "intent": response.intent.value if hasattr(response.intent, "value") else str(response.intent),
        "confidence": response.confidence,
    }

    if response.run_id:
        result["run_id"] = response.run_id
    if response.details:
        result["details"] = response.details
    if response.follow_up_suggestions:
        result["suggestions"] = response.follow_up_suggestions
    if response.error:
        result["error"] = response.error
    if config.agent_thinking_visible and response.thinking_trace:
        result["thinking"] = [
            {"step": s.step_type, "description": s.description}
            for s in response.thinking_trace
        ]

    return result
