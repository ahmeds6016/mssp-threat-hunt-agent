"""Rule-based intent parser — classifies NL messages into AgentIntent."""

from __future__ import annotations

import re
from typing import Any

from mssp_hunt_agent.agent.models import AgentIntent, ParsedIntent


# Valid IP regex — each octet must be 0-255
_IP_PATTERN = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"

# Pattern groups per intent, ordered by specificity (most specific first)
_INTENT_PATTERNS: dict[AgentIntent, list[str]] = {
    AgentIntent.CVE_CHECK: [
        r"cve-\d{4}-\d+",
        r"vulnerable\s+to",
        r"affected\s+by",
        r"exploit(?:ed|able)",
        r"patch(?:ed)?\s+for",
    ],
    AgentIntent.IOC_SWEEP: [
        _IP_PATTERN,
        r"\bioc\b",
        r"\bsweep\b",
        r"check\s+(?:if|whether).*(?:logs|events|telemetry)",
        r"\b[a-f0-9]{32}\b",  # MD5
        r"\b[a-f0-9]{64}\b",  # SHA256
        r"indicator.*compromise",
    ],
    AgentIntent.RUN_HUNT: [
        r"hunt\s+for",
        r"look\s+for",
        r"investigate\b",
        r"threat\s+hunt",
        r"search\s+for\s+(?:signs|evidence|traces)",
        r"lateral\s+movement",
        r"privilege\s+escalation",
        r"exfiltration",
        r"persistence\s+mechanism",
    ],
    AgentIntent.DETECTION_RULE: [
        r"(?:create|generate|write|build)\s+(?:a\s+)?detection",
        r"(?:create|generate|write|build)\s+(?:a\s+)?(?:kql\s+)?rule",
        r"kql\s+(?:for|to\s+detect)",
        r"detect\s+T\d{4}",
        r"analytic\s+rule",
    ],
    AgentIntent.RISK_ASSESSMENT: [
        r"what\s+(?:if|happens).*lose",
        r"what\s+(?:if|happens).*remove",
        r"risk\s+(?:if|assessment|scenario)",
        r"impact\s+(?:of|if|without)",
        r"coverage\s+(?:if|without|change)",
    ],
    AgentIntent.LANDSCAPE_CHECK: [
        r"active\s+threats",
        r"threat\s+landscape",
        r"blind\s+spots",
        r"can.?t\s+detect",
        r"(?:cisa|kev)\s+",
        r"currently\s+exploit",
    ],
    AgentIntent.THREAT_MODEL: [
        r"attack\s+path",
        r"threat\s+model",
        r"breach\s+sim",
        r"breach\s+scenario",
        r"simulate.*breach",
        r"attack\s+surface",
        r"entry\s+point",
    ],
    AgentIntent.TELEMETRY_PROFILE: [
        r"(?:what|which)\s+telemetry",
        r"data\s+sources",
        r"(?:what|which).*(?:logs|tables)\s+(?:do\s+we|are)",
        r"readiness",
        r"coverage\s+score",
        r"telemetry\s+profile",
    ],
    AgentIntent.HUNT_STATUS: [
        r"status\s+(?:of\s+)?RUN-",
        r"RUN-[A-Za-z0-9]+",
        r"how.*hunt\s+(?:going|doing|progressing)",
        r"is\s+(?:the|my)\s+hunt\s+(?:done|complete|finished)",
    ],
    AgentIntent.GENERATE_REPORT: [
        r"(?:generate|create|give\s+me)\s+(?:a\s+)?report",
        r"executive\s+summary",
        r"analyst\s+report",
        r"summarize\s+(?:the\s+)?(?:hunt|findings|results)",
    ],
    AgentIntent.RUN_PLAYBOOK: [
        r"(?:run|execute|start)\s+(?:the\s+)?(?:\w+\s+)?playbook",
        r"playbook\s+for\s+\w+",
        r"ransomware\s+(?:hunt|playbook)",
        r"bec\s+(?:hunt|playbook)",
        r"credential\s+(?:theft|harvest)\s+(?:hunt|playbook)",
    ],
}

# Entity extraction patterns
_ENTITY_PATTERNS: dict[str, str] = {
    "cve": r"(CVE-\d{4}-\d+)",
    "ip": f"({_IP_PATTERN})",
    "hash_md5": r"(\b[a-f0-9]{32}\b)",
    "hash_sha256": r"(\b[a-f0-9]{64}\b)",
    "run_id": r"(RUN-[A-Za-z0-9-]+)",
    "technique": r"(T\d{4}(?:\.\d{3})?)",
    "domain": r"(\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}\b)",
    "url": r"(https?://\S+)",
    "email": r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)",
    "time_range": r"(?:last|past)\s+(\d+\s+(?:hours?|days?|weeks?|months?))",
}


class IntentParser:
    """Rule-based NL intent classifier with keyword/pattern matching."""

    def parse(self, message: str) -> ParsedIntent:
        """Classify a message into an intent and extract entities."""
        if not message or not message.strip():
            return ParsedIntent(
                intent=AgentIntent.GENERAL_QUESTION,
                confidence=0.0,
                original_message=message,
            )

        lower_msg = message.lower().strip()
        entities = self._extract_entities(message)
        intent, confidence = self._classify(lower_msg, entities)

        # Flag clarification needed for low confidence
        needs_clarification = confidence < 0.5
        clarification_reason = ""
        if needs_clarification:
            clarification_reason = (
                "The request is ambiguous. Could you provide more detail "
                "about what you'd like me to do?"
            )

        return ParsedIntent(
            intent=intent,
            confidence=confidence,
            entities=entities,
            original_message=message,
            needs_clarification=needs_clarification,
            clarification_reason=clarification_reason,
        )

    def _classify(
        self, lower_msg: str, entities: dict[str, Any]
    ) -> tuple[AgentIntent, float]:
        """Score each intent and return the best match."""
        scores: dict[AgentIntent, float] = {}

        for intent, patterns in _INTENT_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, lower_msg, re.IGNORECASE):
                    match_count += 1
            if match_count > 0:
                scores[intent] = min(0.25 + match_count * 0.2, 0.95)

        # Entity-based boosting
        if entities.get("cve"):
            scores[AgentIntent.CVE_CHECK] = max(
                scores.get(AgentIntent.CVE_CHECK, 0.0), 0.9
            )
        if entities.get("run_id"):
            # Could be status or report — check context
            if any(w in lower_msg for w in ("report", "summary", "summarize")):
                scores[AgentIntent.GENERATE_REPORT] = max(
                    scores.get(AgentIntent.GENERATE_REPORT, 0.0), 0.85
                )
            else:
                scores[AgentIntent.HUNT_STATUS] = max(
                    scores.get(AgentIntent.HUNT_STATUS, 0.0), 0.85
                )
        if entities.get("ip") or entities.get("hash_md5") or entities.get("hash_sha256"):
            if AgentIntent.IOC_SWEEP not in scores:
                scores[AgentIntent.IOC_SWEEP] = 0.7
        if entities.get("technique"):
            if AgentIntent.DETECTION_RULE not in scores and AgentIntent.RUN_HUNT not in scores:
                scores[AgentIntent.RUN_HUNT] = 0.6
        # Playbook entity boosting — "playbook" keyword is very specific
        if entities.get("playbook_name") or "playbook" in lower_msg:
            scores[AgentIntent.RUN_PLAYBOOK] = max(
                scores.get(AgentIntent.RUN_PLAYBOOK, 0.0), 0.95
            )

        if not scores:
            return AgentIntent.GENERAL_QUESTION, 0.3

        best_intent = max(scores, key=lambda k: scores[k])
        return best_intent, scores[best_intent]

    def _extract_entities(self, message: str) -> dict[str, Any]:
        """Pull structured entities (CVEs, IPs, hashes, etc.) from the message."""
        entities: dict[str, Any] = {}
        for name, pattern in _ENTITY_PATTERNS.items():
            matches = re.findall(pattern, message, re.IGNORECASE)
            if matches:
                entities[name] = matches if len(matches) > 1 else matches[0]

        # Extract hypothesis (free-text after intent keywords)
        hyp_match = re.search(
            r"(?:hunt for|look for|investigate|search for)\s+(.+)",
            message,
            re.IGNORECASE,
        )
        if hyp_match:
            entities["hypothesis"] = hyp_match.group(1).strip()

        # Extract playbook name
        pb_match = re.search(
            r"(?:run|execute|start)\s+(?:the\s+)?(\w+)\s+playbook",
            message,
            re.IGNORECASE,
        )
        if pb_match:
            entities["playbook_name"] = pb_match.group(1).strip()
        elif re.search(r"playbook\s+for\s+(\w+)", message, re.IGNORECASE):
            pb_match2 = re.search(r"playbook\s+for\s+(\w+)", message, re.IGNORECASE)
            if pb_match2:
                entities["playbook_name"] = pb_match2.group(1).strip()

        return entities
