"""Chain-of-thought reasoning — multi-step execution with thinking traces."""

from __future__ import annotations

import logging
from typing import Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter
from mssp_hunt_agent.agent.action_router import ActionRouter
from mssp_hunt_agent.agent.intent_parser import IntentParser
from mssp_hunt_agent.agent.models import (
    AgentIntent,
    AgentResponse,
    ParsedIntent,
    ReasoningStep,
)
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


class ReasoningChain:
    """Multi-step execution with genuine reasoning trace.

    Five-step reasoning: hypothesis -> context -> analysis -> execute -> synthesis.
    Works with or without an LLM adapter.
    """

    def __init__(
        self,
        config: HuntAgentConfig,
        llm: LLMAdapter | None = None,
    ) -> None:
        self.config = config
        self.llm = llm
        self.parser = IntentParser()
        self.router = ActionRouter(config)
        self.steps: list[ReasoningStep] = []
        self._step_count = 0

    def _add_step(
        self, step_type: str, description: str, data: dict[str, Any] | None = None
    ) -> None:
        if self._step_count >= self.config.agent_max_chain_steps:
            return
        self.steps.append(
            ReasoningStep(step_type=step_type, description=description, data=data or {})
        )
        self._step_count += 1

    def process(self, message: str) -> AgentResponse:
        """Full chain-of-thought processing of a message."""
        self.steps = []
        self._step_count = 0

        # Step 1: Hypothesis — identify what type of question this is
        intent = self._classify_intent(message)
        self._form_hypothesis(message, intent)

        # Step 2: Context — summarize extracted entities and constraints
        self._gather_context(intent)

        # Step 3: Analysis — assess confidence and ambiguity
        self._analyze_intent(intent)

        # Step 4: Execute action
        self._add_step("executing", f"Routing to {intent.intent.value} handler")
        response = self.router.execute(intent)

        # Step 5: Synthesis — evaluate result quality
        response = self._synthesize(message, intent, response)

        # Merge thinking traces
        if self.config.agent_thinking_visible:
            response.thinking_trace = self.steps + response.thinking_trace

        return response

    def _form_hypothesis(self, message: str, intent: ParsedIntent) -> None:
        """Step 1: Identify the question type and form an initial hypothesis."""
        msg_lower = message.lower()

        # Determine question type
        if any(w in msg_lower for w in ("what if", "impact", "risk if", "lose", "remove")):
            q_type = "scenario analysis"
        elif any(w in msg_lower for w in ("are we", "is our", "can we", "do we")):
            q_type = "yes/no assessment"
        elif any(w in msg_lower for w in ("create", "generate", "build", "write")):
            q_type = "action request"
        elif any(w in msg_lower for w in ("run", "execute", "start", "hunt for", "sweep")):
            q_type = "execution request"
        elif any(w in msg_lower for w in ("status", "how is", "progress")):
            q_type = "status inquiry"
        elif any(w in msg_lower for w in ("what", "which", "how", "tell me", "show")):
            q_type = "information request"
        else:
            q_type = "general request"

        self._add_step(
            "planning",
            f"Question type: {q_type}. Hypothesis: user needs {intent.intent.value} "
            f"based on {len(intent.entities)} extracted entities",
            data={"question_type": q_type, "intent": intent.intent.value},
        )

    def _gather_context(self, intent: ParsedIntent) -> None:
        """Step 2: Summarize what we know from the message."""
        context_parts = []

        if intent.entities.get("cve"):
            context_parts.append(f"CVE: {intent.entities['cve']}")
        if intent.entities.get("technique"):
            context_parts.append(f"MITRE technique: {intent.entities['technique']}")
        if intent.entities.get("ip"):
            context_parts.append(f"IP indicator: {intent.entities['ip']}")
        if intent.entities.get("hash_md5") or intent.entities.get("hash_sha256"):
            context_parts.append("File hash indicator present")
        if intent.entities.get("hypothesis"):
            context_parts.append(f"Hunt hypothesis: {intent.entities['hypothesis'][:80]}")
        if intent.entities.get("run_id"):
            context_parts.append(f"Run ID: {intent.entities['run_id']}")
        if intent.entities.get("playbook_name"):
            context_parts.append(f"Playbook: {intent.entities['playbook_name']}")
        if intent.entities.get("time_range"):
            context_parts.append(f"Time range: {intent.entities['time_range']}")

        if context_parts:
            desc = "Extracted context: " + "; ".join(context_parts)
        else:
            desc = "No specific entities extracted — using full message as context"

        self._add_step(
            "result",
            desc,
            data={"entity_count": len(intent.entities), "entities": intent.entities},
        )

    def _analyze_intent(self, intent: ParsedIntent) -> None:
        """Step 3: Assess confidence and flag ambiguity."""
        if intent.confidence >= 0.8:
            level = "high"
            assessment = f"Strong match for {intent.intent.value}"
        elif intent.confidence >= 0.5:
            level = "moderate"
            assessment = f"Reasonable match for {intent.intent.value}, some ambiguity"
        else:
            level = "low"
            assessment = f"Weak match — defaulting to {intent.intent.value}"

        clarification = ""
        if intent.needs_clarification:
            clarification = f". Clarification may help: {intent.clarification_reason}"

        self._add_step(
            "result",
            f"Confidence: {intent.confidence:.0%} ({level}). {assessment}{clarification}",
            data={
                "confidence": intent.confidence,
                "confidence_level": level,
                "needs_clarification": intent.needs_clarification,
            },
        )

    def _synthesize(
        self, message: str, intent: ParsedIntent, response: AgentResponse
    ) -> AgentResponse:
        """Step 5: Evaluate result quality and optionally enhance with LLM."""
        # Assess result quality
        has_error = bool(response.error)
        has_run_id = bool(response.run_id)
        has_details = bool(response.details)

        if has_error:
            quality = "incomplete — error occurred"
        elif has_run_id:
            quality = "action initiated — background task running"
        elif has_details:
            quality = "complete with structured results"
        else:
            quality = "complete — informational response"

        self._add_step(
            "synthesizing",
            f"Result quality: {quality}",
            data={"has_error": has_error, "has_run_id": has_run_id},
        )

        # Enhance with LLM if available
        if self.llm and self.config.agent_llm_fallback:
            response = self._enhance_with_llm(message, response)

        return response

    def _classify_intent(self, message: str) -> ParsedIntent:
        """Classify intent, using LLM if available for ambiguous cases."""
        # Always start with rule-based parsing
        rule_intent = self.parser.parse(message)

        # If confidence is high, trust the rules
        if rule_intent.confidence >= 0.8:
            return rule_intent

        # If LLM is available and rules are uncertain, ask the LLM
        if self.llm and rule_intent.confidence < 0.7:
            try:
                available = [i.value for i in AgentIntent]
                llm_result = self.llm.classify_intent(message, available)
                llm_confidence = llm_result.get("confidence", 0.5)

                self._add_step(
                    "result",
                    f"LLM classification: {llm_result.get('intent')} ({llm_confidence:.0%})",
                    data={"reasoning": llm_result.get("reasoning", "")},
                )

                # Use LLM result if it's more confident
                if llm_confidence > rule_intent.confidence:
                    llm_entities = {**rule_intent.entities, **llm_result.get("entities", {})}
                    return ParsedIntent(
                        intent=AgentIntent(llm_result["intent"]),
                        confidence=llm_confidence,
                        entities=llm_entities,
                        original_message=message,
                    )
            except Exception as exc:
                self._add_step("error", f"LLM classification failed: {exc}")
                logger.warning("LLM classification failed, using rule-based: %s", exc)

        return rule_intent

    def _enhance_with_llm(
        self, message: str, response: AgentResponse
    ) -> AgentResponse:
        """Optionally enhance the response summary with LLM-generated text."""
        if not self.llm:
            return response

        try:
            self._add_step("synthesizing", "Enhancing response with LLM reasoning")
            enhanced_summary = self.llm.generate_response(
                context=message,
                results={
                    "original_summary": response.summary,
                    "intent": response.intent.value if hasattr(response.intent, "value") else str(response.intent),
                    "details": response.details,
                },
            )
            response.summary = enhanced_summary
            self._add_step("result", "Response enhanced with LLM synthesis")
        except Exception as exc:
            self._add_step("error", f"LLM enhancement failed: {exc}")
            logger.warning("LLM enhancement failed, keeping original: %s", exc)

        return response
