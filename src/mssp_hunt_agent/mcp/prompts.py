"""MCP Prompt registry — reusable prompt templates for common workflows.

Each prompt is a named template that can be rendered with arguments.
These provide structured starting points for MCP clients (Copilot Studio,
VS Code, Claude Desktop) to invoke common analytical workflows.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, dict[str, Any]] = {
    "threat_hunt_analysis": {
        "description": (
            "Analyze a threat hunt hypothesis and recommend a hunting plan. "
            "Provide client name, hypothesis, and available data sources."
        ),
        "template": (
            "You are an expert MSSP threat hunter. Analyze the following hunt request "
            "and produce a structured hunting plan.\n\n"
            "## Hunt Request\n"
            "- **Client**: {client_name}\n"
            "- **Hypothesis**: {hypothesis}\n"
            "- **Time Range**: {time_range}\n"
            "- **Available Data Sources**: {data_sources}\n\n"
            "## Instructions\n"
            "1. Map the hypothesis to MITRE ATT&CK techniques\n"
            "2. Identify which data sources are relevant\n"
            "3. Suggest 3-5 KQL queries to test the hypothesis\n"
            "4. Note any telemetry gaps that limit the hunt\n"
            "5. Provide a triage checklist for findings\n"
            "6. Define escalation criteria\n"
        ),
    },
    "ioc_triage": {
        "description": (
            "Triage a set of IOCs — classify, prioritize, and recommend actions."
        ),
        "template": (
            "You are an MSSP intelligence analyst. Triage the following IOCs.\n\n"
            "## IOCs\n{iocs}\n\n"
            "## Client Context\n"
            "- **Client**: {client_name}\n"
            "- **Data Sources**: {data_sources}\n\n"
            "## Instructions\n"
            "1. Classify each IOC by type and confidence\n"
            "2. Check for known-benign indicators (CDNs, Microsoft IPs, etc.)\n"
            "3. Prioritize: which IOCs pose the highest risk?\n"
            "4. Recommend sweep queries for high-priority IOCs\n"
            "5. Flag any IOCs that need enrichment from external sources\n"
        ),
    },
    "executive_summary": {
        "description": (
            "Generate an executive-level summary of hunt findings for a client. "
            "Non-technical language, focused on business risk."
        ),
        "template": (
            "You are writing an executive briefing for the CISO of {client_name}.\n\n"
            "## Hunt Findings\n{findings}\n\n"
            "## Instructions\n"
            "Write a 1-page executive summary:\n"
            "1. **Situation**: What was investigated and why\n"
            "2. **Findings**: Key results in plain business language (no jargon)\n"
            "3. **Risk Assessment**: Business impact — low/medium/high/critical\n"
            "4. **Recommendations**: 3-5 actionable next steps\n"
            "5. **Timeline**: When findings occurred and urgency of response\n\n"
            "Keep the tone professional and concise. Avoid technical acronyms.\n"
        ),
    },
    "gap_analysis": {
        "description": (
            "Analyze detection gaps for a client based on their telemetry profile "
            "and recent threat landscape."
        ),
        "template": (
            "You are an MSSP security architect assessing detection coverage for "
            "{client_name}.\n\n"
            "## Current Telemetry\n{telemetry}\n\n"
            "## Recent Threat Landscape\n{threats}\n\n"
            "## Instructions\n"
            "1. Map current data sources to MITRE ATT&CK coverage\n"
            "2. Identify the top 5 detection blind spots\n"
            "3. For each gap, recommend specific data sources to add\n"
            "4. Estimate effort (low/medium/high) for each recommendation\n"
            "5. Prioritize by risk: which gaps are most exploited in the wild?\n"
            "6. Provide a 30/60/90 day improvement roadmap\n"
        ),
    },
    "detection_review": {
        "description": (
            "Review a KQL detection rule for quality, coverage, and performance."
        ),
        "template": (
            "You are a detection engineering lead reviewing a KQL detection rule.\n\n"
            "## Detection Rule\n"
            "- **Name**: {rule_name}\n"
            "- **KQL**:\n```kql\n{kql}\n```\n"
            "- **MITRE Techniques**: {techniques}\n"
            "- **Severity**: {severity}\n\n"
            "## Instructions\n"
            "1. Assess the KQL query for correctness and performance\n"
            "2. Check for common false positive scenarios\n"
            "3. Evaluate ATT&CK coverage completeness\n"
            "4. Suggest improvements to reduce noise\n"
            "5. Rate overall quality: A (production-ready) to F (needs rewrite)\n"
            "6. Provide the improved KQL if changes are needed\n"
        ),
    },
}


# ---------------------------------------------------------------------------
# Registry (exposed to MCP server)
# ---------------------------------------------------------------------------

PROMPT_REGISTRY: dict[str, dict[str, Any]] = {
    name: {
        "description": meta["description"],
        "template": meta["template"],
    }
    for name, meta in _TEMPLATES.items()
}


def render_prompt(name: str, arguments: dict) -> str:
    """Render a prompt template with the given arguments.

    Missing placeholders are replaced with '(not provided)'.
    """
    if name not in PROMPT_REGISTRY:
        return f"Unknown prompt: {name}"

    template = PROMPT_REGISTRY[name]["template"]

    # Collect all {placeholder} names from the template
    import re
    placeholders = re.findall(r"\{(\w+)\}", template)

    # Build substitution dict — fill missing with default
    subs = {}
    for ph in placeholders:
        subs[ph] = arguments.get(ph, "(not provided)")

    return template.format(**subs)
