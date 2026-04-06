"""Intel Processor — correlates, scores, and extracts structured threat intel.

Phase 2 of the proactive threat intel pipeline:
1. CORRELATE: GPT-5.3 clusters related articles into unified Intel Events
2. SCORE: GPT-5.3 evaluates each Intel Event against the client's environment
3. EXTRACT: GPT-5.3 pulls structured IOCs, TTPs, CVEs from high-relevance events

Usage:
    processor = IntelProcessor(llm=llm_adapter)
    events = processor.correlate_articles(articles)
    scored = processor.score_relevance(events, env_summary)
    enriched = processor.extract_intel(scored)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter

logger = logging.getLogger(__name__)


# ── Data Models ───────────────────────────────────────────────────────

@dataclass
class IntelEvent:
    """A correlated threat intelligence event — one or more articles about the same threat."""
    event_id: str
    title: str  # GPT-generated summary title
    severity: str  # critical, high, medium, low, informational
    category: str  # apt, vulnerability, supply_chain, malware, advisory, general
    summary: str  # GPT-generated 2-3 sentence summary
    articles: list[dict] = field(default_factory=list)  # source articles
    article_count: int = 0
    sources: list[str] = field(default_factory=list)  # feed names that reported this
    relevance_score: float = 0.0  # 0-1, set by relevance scorer
    relevance_reasoning: str = ""
    # Extracted intel (populated by extract_intel)
    iocs: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    affected_software: list[str] = field(default_factory=list)
    threat_actor: str = ""
    kill_chain_phases: list[str] = field(default_factory=list)
    recommended_queries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "summary": self.summary,
            "article_count": self.article_count,
            "sources": self.sources,
            "relevance_score": self.relevance_score,
            "relevance_reasoning": self.relevance_reasoning,
            "iocs": self.iocs,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "cves": self.cves,
            "affected_software": self.affected_software,
            "threat_actor": self.threat_actor,
            "kill_chain_phases": self.kill_chain_phases,
            "recommended_queries": self.recommended_queries,
        }


# ── Prompts ───────────────────────────────────────────────────────────

CORRELATE_SYSTEM_PROMPT = """You are a senior threat intelligence analyst. Your task is to analyze a batch of security articles and group them into distinct threat events.

Multiple articles may report on the same underlying threat, vulnerability, or campaign. Group these together into a single event.

For each distinct event, provide:
- title: A concise, professional title for the event
- severity: critical, high, medium, low, or informational
- category: apt, vulnerability, supply_chain, malware, advisory, or general
- summary: 2-3 sentence summary of what happened
- article_indices: List of article index numbers (0-based) that belong to this event

Respond ONLY with valid JSON in this exact format:
{
  "events": [
    {
      "title": "...",
      "severity": "...",
      "category": "...",
      "summary": "...",
      "article_indices": [0, 3, 7]
    }
  ]
}

Rules:
- Every article must be assigned to exactly one event
- If an article is unique (not reported elsewhere), it gets its own event
- Articles from different sources about the same CVE, threat actor, campaign, or incident should be grouped
- Severity should reflect the actual threat level, not the number of articles
- Be precise with categorization — supply chain attacks are "supply_chain", not "malware"
"""

RELEVANCE_SYSTEM_PROMPT = """You are a senior MSSP threat intelligence analyst assessing whether a threat event is relevant to a specific client environment.

You will receive:
1. A threat event summary with details
2. The client's environment profile (telemetry sources, assets, users, security posture)

Score the relevance from 0.0 to 1.0:
- 1.0 = Directly affects technologies/software in the client's environment
- 0.8 = Affects the client's industry or adjacent technologies
- 0.6 = Describes TTPs that could target the client's infrastructure
- 0.4 = General threat awareness, some applicability
- 0.2 = Tangentially related, mostly informational
- 0.0 = Completely irrelevant to this client

Respond ONLY with valid JSON:
{
  "relevance_score": 0.0,
  "reasoning": "Brief explanation of why this score was assigned",
  "hunt_recommended": true/false,
  "priority_hunt_areas": ["area1", "area2"]
}

Rules:
- Be conservative — only recommend hunts (score >= 0.6) for genuinely relevant threats
- Consider what telemetry the client actually has — a threat requiring network logs is less relevant if the client only has endpoint telemetry
- Supply chain attacks affecting common packages (npm, pip) are relevant to environments with developer activity
- APT reports are relevant if the threat actor targets the client's industry or geography
- Pure news/opinion articles with no actionable intel should score low
"""

EXTRACT_SYSTEM_PROMPT = """You are a senior threat intelligence analyst. Your task is to extract EVERY indicator of compromise and TTP from a threat report.

This is CRITICAL — missing an IOC could mean missing an active compromise. Be exhaustive.

Extract ALL of the following categories. Scan the ENTIRE text including code blocks, tables, footnotes, and inline references:

1. **IOCs** — Extract EVERY instance of:
   - IP addresses (IPv4/IPv6) — type: "ip"
   - Domain names and hostnames — type: "domain"
   - File hashes (SHA256, SHA1, MD5) — type: "hash_sha256", "hash_sha1", "hash_md5"
   - URLs and URIs — type: "url"
   - Email addresses — type: "email"
   - File paths (Windows and Unix) — type: "filepath"
   - Registry keys — type: "registry"
   - User-Agent strings — type: "useragent"
   - Package/module names with versions — type: "software"

2. **MITRE ATT&CK** — Every T-code mentioned (e.g., T1195.002, T1059.001)

3. **CVEs** — Every CVE-YYYY-NNNNN mentioned

4. **Affected software** — Package names WITH exact versions

5. **Threat actor** — Primary group name and aliases

6. **Kill chain phases** — Which phases are described

7. **KQL queries** — Generate 3-5 precise queries for Microsoft Sentinel that check for the SPECIFIC IOCs extracted above

Respond ONLY with valid JSON:
{
  "iocs": [
    {"type": "ip", "value": "1.2.3.4", "context": "C2 server"},
    {"type": "domain", "value": "sfrclak.com", "context": "Payload delivery domain"},
    {"type": "hash_sha256", "value": "617b67a8e1210e...", "context": "Windows payload"},
    {"type": "filepath", "value": "/tmp/ld.py", "context": "Linux RAT payload path"},
    {"type": "filepath", "value": "/Library/Caches/com.apple.act.mond", "context": "macOS RAT payload"},
    {"type": "useragent", "value": "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)", "context": "RAT beacon User-Agent"},
    {"type": "registry", "value": "Microsoft Update", "context": "Windows persistence Run key name"},
    {"type": "software", "value": "plain-crypto-js@4.2.1", "context": "Malicious npm dependency"}
  ],
  "mitre_techniques": ["T1195.002", "T1059.001", "T1547.001"],
  "mitre_tactics": ["Initial Access", "Execution", "Persistence"],
  "cves": [],
  "affected_software": ["axios 1.14.1", "axios 0.30.4", "plain-crypto-js 4.2.1"],
  "threat_actor": "STARDUST CHOLLIMA / UNC1069",
  "kill_chain_phases": ["initial_access", "execution", "persistence", "command_and_control"],
  "recommended_queries": [
    "DeviceNetworkEvents | where TimeGenerated > ago(30d) | where RemoteIP == '142.11.206.73' or RemoteUrl has 'sfrclak.com' | project TimeGenerated, DeviceName, RemoteIP, RemoteUrl",
    "DeviceProcessEvents | where TimeGenerated > ago(30d) | where ProcessCommandLine has_any ('plain-crypto-js','axios@1.14.1','sfrclak') | project TimeGenerated, DeviceName, ProcessCommandLine"
  ]
}

CRITICAL RULES:
- Extract IOCs from code blocks, tables, pre-formatted text, and inline mentions
- Do NOT fabricate IOCs — only extract what is explicitly in the text
- Include the CONTEXT for each IOC (what role it plays in the attack)
- Defanged IOCs like sfrclak[.]com should be stored as sfrclak.com (remove brackets)
- File paths are IOCs — extract them with type "filepath"
- User-Agent strings are IOCs — extract them with type "useragent"
- Registry key names used for persistence are IOCs — extract with type "registry"
- Be EXHAUSTIVE — it is better to extract too many IOCs than to miss one
"""


# ── Intel Processor ───────────────────────────────────────────────────

class IntelProcessor:
    """Processes raw threat articles into correlated, scored, enriched Intel Events."""

    def __init__(self, llm: LLMAdapter) -> None:
        self._llm = llm

    def correlate_articles(
        self,
        articles: list[dict],
        batch_size: int = 30,
    ) -> list[IntelEvent]:
        """Cluster related articles into unified Intel Events using GPT-5.3.

        Processes articles in batches to stay within context limits.
        """
        if not articles:
            return []

        all_events: list[IntelEvent] = []
        event_counter = 0

        for batch_start in range(0, len(articles), batch_size):
            batch = articles[batch_start:batch_start + batch_size]
            logger.info(
                "Correlating articles %d-%d of %d",
                batch_start + 1, batch_start + len(batch), len(articles),
            )

            # Build article list for the prompt
            article_list = []
            for i, article in enumerate(batch):
                article_list.append(
                    f"[{i}] Source: {article.get('source', 'Unknown')}\n"
                    f"    Title: {article.get('title', 'No title')}\n"
                    f"    Published: {article.get('published', 'Unknown')}\n"
                    f"    Summary: {article.get('summary', '')[:500]}\n"
                    f"    Tags: {', '.join(article.get('tags', []))}"
                )

            user_prompt = (
                f"Analyze these {len(batch)} security articles and group related ones "
                f"into distinct threat events:\n\n"
                + "\n\n".join(article_list)
            )

            try:
                response = self._llm.chat_with_tools(
                    messages=[
                        {"role": "system", "content": CORRELATE_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    tools=[],
                    max_tokens=4096,
                )

                # Parse the response — look for JSON in findings or raw content
                events_data = self._extract_json(response)
                if not events_data or "events" not in events_data:
                    logger.warning("No events parsed from correlation response")
                    # Fallback: each article becomes its own event
                    for i, article in enumerate(batch):
                        event_counter += 1
                        all_events.append(self._article_to_event(article, event_counter))
                    continue

                for event_data in events_data["events"]:
                    event_counter += 1
                    event_id = f"INTEL-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{event_counter:04d}"

                    # Gather the source articles for this event
                    indices = event_data.get("article_indices", [])
                    event_articles = [batch[i] for i in indices if i < len(batch)]
                    sources = list(set(a.get("source", "") for a in event_articles))

                    all_events.append(IntelEvent(
                        event_id=event_id,
                        title=event_data.get("title", "Unknown Event"),
                        severity=event_data.get("severity", "informational"),
                        category=event_data.get("category", "general"),
                        summary=event_data.get("summary", ""),
                        articles=event_articles,
                        article_count=len(event_articles),
                        sources=sources,
                    ))

            except Exception as exc:
                logger.warning("Correlation failed for batch: %s", exc)
                # Fallback: each article becomes its own event
                for article in batch:
                    event_counter += 1
                    all_events.append(self._article_to_event(article, event_counter))

        logger.info(
            "Correlation complete: %d articles -> %d intel events",
            len(articles), len(all_events),
        )
        return all_events

    def score_relevance(
        self,
        events: list[IntelEvent],
        env_summary: dict[str, Any],
        threshold: float = 0.6,
    ) -> list[IntelEvent]:
        """Score each Intel Event for relevance to the client environment.

        Returns events sorted by relevance score (highest first).
        Events below threshold are still returned but marked accordingly.
        """
        if not events:
            return []

        env_context = json.dumps(env_summary, indent=2, default=str)[:3000]

        for event in events:
            logger.info("Scoring relevance: %s", event.title[:80])
            user_prompt = (
                f"## Threat Event\n"
                f"Title: {event.title}\n"
                f"Severity: {event.severity}\n"
                f"Category: {event.category}\n"
                f"Sources: {', '.join(event.sources)} ({event.article_count} articles)\n"
                f"Summary: {event.summary}\n\n"
                f"## Client Environment\n{env_context}"
            )

            try:
                response = self._llm.chat_with_tools(
                    messages=[
                        {"role": "system", "content": RELEVANCE_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    tools=[],
                    max_tokens=1024,
                )

                result = self._extract_json(response)
                if result:
                    event.relevance_score = float(result.get("relevance_score", 0))
                    event.relevance_reasoning = result.get("reasoning", "")
                    logger.info(
                        "Relevance for '%s': %.2f — %s",
                        event.title[:50], event.relevance_score, event.relevance_reasoning[:100],
                    )
                else:
                    event.relevance_score = 0.3
                    event.relevance_reasoning = "Could not score — defaulting to low"

            except Exception as exc:
                logger.warning("Relevance scoring failed for %s: %s", event.event_id, exc)
                event.relevance_score = 0.3
                event.relevance_reasoning = f"Scoring failed: {exc}"

        # Sort by relevance (highest first)
        events.sort(key=lambda e: e.relevance_score, reverse=True)
        return events

    def extract_intel(
        self,
        events: list[IntelEvent],
        min_relevance: float = 0.5,
    ) -> list[IntelEvent]:
        """Extract structured IOCs, TTPs, and CVEs from high-relevance events.

        Only processes events above min_relevance to save API costs.
        """
        extracted = []
        for event in events:
            if event.relevance_score < min_relevance:
                logger.debug("Skipping extraction for low-relevance event: %s (%.2f)", event.title[:50], event.relevance_score)
                extracted.append(event)
                continue

            logger.info("Extracting intel from: %s", event.title[:80])

            # Build full context — fetch article text from URLs if not already present
            article_text = ""
            for article in event.articles:
                full = article.get("full_text", "")
                # Fetch from URL if we don't have full text
                if not full and article.get("url"):
                    try:
                        from mssp_hunt_agent.intel.feed_monitor import fetch_article_text
                        full = fetch_article_text(article["url"])
                        article["full_text"] = full
                        logger.info("Fetched %d chars from %s", len(full), article["url"][:60])
                    except Exception as exc:
                        logger.debug("Could not fetch article text: %s", exc)

                article_text += (
                    f"\n--- Article from {article.get('source', 'Unknown')} ---\n"
                    f"Title: {article.get('title', '')}\n"
                    f"Content: {article.get('summary', '')}\n"
                    f"{full[:8000]}\n"
                )

            user_prompt = (
                f"Extract all threat intelligence from this event:\n\n"
                f"Event: {event.title}\n"
                f"Severity: {event.severity}\n"
                f"Category: {event.category}\n"
                f"Summary: {event.summary}\n\n"
                f"Source Articles:\n{article_text[:12000]}"
            )

            try:
                response = self._llm.chat_with_tools(
                    messages=[
                        {"role": "system", "content": EXTRACT_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    tools=[],
                    max_tokens=4096,
                )

                result = self._extract_json(response)
                if result:
                    event.iocs = result.get("iocs", [])
                    event.mitre_techniques = result.get("mitre_techniques", [])
                    event.mitre_tactics = result.get("mitre_tactics", [])
                    event.cves = result.get("cves", [])
                    event.affected_software = result.get("affected_software", [])
                    event.threat_actor = result.get("threat_actor", "")
                    event.kill_chain_phases = result.get("kill_chain_phases", [])
                    event.recommended_queries = result.get("recommended_queries", [])

                    logger.info(
                        "Extracted from '%s': %d IOCs, %d techniques, %d CVEs, actor=%s",
                        event.title[:50], len(event.iocs), len(event.mitre_techniques),
                        len(event.cves), event.threat_actor or "none",
                    )

            except Exception as exc:
                logger.warning("Intel extraction failed for %s: %s", event.event_id, exc)

            extracted.append(event)

        return extracted

    def process_articles(
        self,
        articles: list[dict],
        env_summary: dict[str, Any],
        relevance_threshold: float = 0.6,
    ) -> list[IntelEvent]:
        """Full pipeline: correlate -> score -> extract.

        Returns only events above the relevance threshold, fully enriched.
        """
        logger.info("Processing %d articles through intel pipeline", len(articles))

        # Step 1: Correlate
        events = self.correlate_articles(articles)
        logger.info("Correlated into %d intel events", len(events))

        # Step 2: Score relevance
        events = self.score_relevance(events, env_summary, threshold=relevance_threshold)
        relevant = [e for e in events if e.relevance_score >= relevance_threshold]
        logger.info(
            "%d events above threshold (%.1f), %d below",
            len(relevant), relevance_threshold, len(events) - len(relevant),
        )

        # Step 3: Extract intel from relevant events
        enriched = self.extract_intel(events, min_relevance=relevance_threshold)
        relevant_enriched = [e for e in enriched if e.relevance_score >= relevance_threshold]

        logger.info(
            "Intel processing complete: %d articles -> %d events -> %d relevant -> %d with IOCs",
            len(articles), len(events), len(relevant_enriched),
            sum(1 for e in relevant_enriched if e.iocs or e.mitre_techniques),
        )

        return relevant_enriched

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _article_to_event(article: dict, counter: int) -> IntelEvent:
        """Convert a single article to a standalone IntelEvent (fallback)."""
        event_id = f"INTEL-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{counter:04d}"
        return IntelEvent(
            event_id=event_id,
            title=article.get("title", "Unknown"),
            severity="informational",
            category=article.get("category", "general"),
            summary=article.get("summary", "")[:500],
            articles=[article],
            article_count=1,
            sources=[article.get("source", "Unknown")],
        )

    @staticmethod
    def _extract_json(response: dict[str, Any]) -> dict | None:
        """Extract JSON from an LLM response — handles various response formats."""
        # Try direct findings field
        findings = response.get("findings")
        if isinstance(findings, dict):
            return findings
        if isinstance(findings, list) and findings:
            return findings[0] if isinstance(findings[0], dict) else None

        # Try to find JSON in text content
        for key in ("content", "text", "response"):
            text = response.get(key, "")
            if not text:
                continue
            # Find JSON block in markdown code fences
            json_match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            # Try parsing the whole text as JSON
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
            # Try finding a JSON object in the text
            brace_match = re.search(r"\{.*\}", text, re.DOTALL)
            if brace_match:
                try:
                    return json.loads(brace_match.group(0))
                except json.JSONDecodeError:
                    pass

        return None
