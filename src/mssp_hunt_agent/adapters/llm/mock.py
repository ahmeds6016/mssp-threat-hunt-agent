"""Mock LLM adapter — prompt-aware mock for testing the full intelligence pipeline.

Agent loop tests: 2-iteration keyword-based tool selection (unchanged).
Campaign phase tests: detects phase from system prompt, simulates multi-iteration
hunting with structured JSON output matching what real LLM phases expect.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from mssp_hunt_agent.adapters.llm.base import LLMAdapter


# Campaign phase detection patterns — ORDER MATTERS (execute before hypothesize
# because execute prompts also contain the word "hypothesis").
_PHASE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("execute", re.compile(r"execute.*hypothesis|drill.?down|pivot|minimum.*queries", re.IGNORECASE)),
    ("conclude", re.compile(r"conclude|classify.*finding|evidence.*assessment|triage", re.IGNORECASE)),
    ("deliver", re.compile(r"deliver|generate.*report|executive.*summary|campaign.*report", re.IGNORECASE)),
    ("hypothesize", re.compile(r"hypothes[ie]|generate.*prioritized.*hunt", re.IGNORECASE)),
]


class MockLLMAdapter(LLMAdapter):
    """Prompt-aware mock that simulates campaign phase behavior for testing.

    For agent loop (non-campaign) calls: 2-iteration keyword tool selection (legacy).
    For campaign phases: multi-iteration structured responses matching phase expectations.
    """

    def __init__(self, *, should_fail: bool = False) -> None:
        self._should_fail = should_fail
        self._campaign_iteration_count: int = 0
        self._detected_phase: str = ""

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        if self._should_fail:
            raise RuntimeError("MockLLMAdapter configured to fail")

        return {
            "findings": [
                {
                    "finding_id": f"F-LLM-{uuid.uuid4().hex[:8]}",
                    "title": "LLM-Identified Suspicious Authentication Pattern",
                    "description": (
                        "Analysis of the evidence suggests an anomalous authentication "
                        "pattern consistent with credential abuse. Multiple failed logins "
                        "followed by a successful login from an unusual geographic location."
                    ),
                    "confidence": "medium",
                    "evidence_ids": [],
                    "benign_explanations": [
                        "User traveling and authenticating from a new location",
                        "VPN endpoint in an unusual geography",
                    ],
                    "what_would_increase_confidence": [
                        "Correlate with endpoint telemetry for post-auth activity",
                        "Verify geographic location against known user travel",
                        "Check for concurrent sessions from the normal location",
                    ],
                },
            ],
            "evidence_items": [
                {
                    "evidence_id": f"E-LLM-{uuid.uuid4().hex[:8]}",
                    "source": "llm_analysis",
                    "observation": (
                        "LLM analysis identified a cluster of authentication events "
                        "that deviate from the baseline pattern for this user."
                    ),
                    "significance": "suspicious",
                    "supporting_data": "Based on query results and enrichment data",
                },
            ],
            "confidence_assessment": {
                "overall_confidence": "medium",
                "rationale": (
                    "LLM analysis provides medium confidence based on available evidence. "
                    "The authentication pattern is suspicious but not conclusive without "
                    "corroborating endpoint telemetry."
                ),
                "limiting_factors": [
                    "Analysis based on mock execution data",
                    "Limited endpoint visibility to confirm post-authentication behavior",
                ],
                "telemetry_impact": "Adequate for authentication analysis but limited endpoint coverage",
            },
        }

    def classify_intent(
        self,
        message: str,
        available_intents: list[str],
    ) -> dict[str, Any]:
        if self._should_fail:
            raise RuntimeError("MockLLMAdapter configured to fail")

        # Simple deterministic classification for testing
        msg_lower = message.lower()
        intent = "general_question"
        confidence = 0.6

        if "cve" in msg_lower:
            intent = "cve_check"
            confidence = 0.95
        elif "hunt" in msg_lower or "investigate" in msg_lower:
            intent = "run_hunt"
            confidence = 0.9
        elif "sweep" in msg_lower or "ioc" in msg_lower:
            intent = "ioc_sweep"
            confidence = 0.9
        elif "detection" in msg_lower or "rule" in msg_lower:
            intent = "detection_rule"
            confidence = 0.85
        elif "risk" in msg_lower or "what if" in msg_lower:
            intent = "risk_assessment"
            confidence = 0.85
        elif "telemetry" in msg_lower or "data source" in msg_lower:
            intent = "telemetry_profile"
            confidence = 0.85

        # Ensure we return a valid intent
        if intent not in available_intents and available_intents:
            intent = available_intents[0]

        return {
            "intent": intent,
            "confidence": confidence,
            "entities": {},
            "reasoning": f"Mock classification: identified '{intent}' from keywords in message.",
        }

    def generate_response(
        self,
        context: str,
        results: dict[str, Any],
        *,
        max_tokens: int = 2048,
    ) -> str:
        if self._should_fail:
            raise RuntimeError("MockLLMAdapter configured to fail")

        return (
            "Based on my analysis of the available evidence, I identified "
            "patterns consistent with the queried activity. The evidence suggests "
            "moderate confidence in the findings. I recommend further investigation "
            "to confirm and correlating with additional data sources for higher confidence."
        )

    def test_connection(self) -> bool:
        return not self._should_fail

    def get_adapter_name(self) -> str:
        return "MockLLMAdapter"

    def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        if self._should_fail:
            raise RuntimeError("MockLLMAdapter configured to fail")

        # Detect context from system prompt
        system_prompt = ""
        for m in messages:
            if m.get("role") == "system":
                system_prompt = m.get("content", "")
                break

        # Check for complexity classifier call (no tools, classifier prompt)
        if not tools and "routing classifier" in system_prompt.lower():
            return self._classifier_response(messages)

        phase = self._detect_phase(system_prompt)

        if phase:
            return self._campaign_phase_response(phase, messages, tools)

        # --- Non-campaign (agent loop) path: legacy 2-iteration behavior ---
        return self._agent_loop_response(messages, tools)

    # ------------------------------------------------------------------
    # Campaign phase dispatch
    # ------------------------------------------------------------------

    def _detect_phase(self, system_prompt: str) -> str:
        """Detect campaign phase from system prompt keywords."""
        if not system_prompt:
            return ""
        for phase_name, pattern in _PHASE_PATTERNS:
            if pattern.search(system_prompt):
                return phase_name
        return ""

    def _campaign_phase_response(
        self,
        phase: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Route to phase-specific mock behavior."""
        if phase == "hypothesize":
            return self._hypothesize_response(messages, tools)
        if phase == "execute":
            return self._execute_response(messages, tools)
        if phase == "conclude":
            return self._conclude_response(messages, tools)
        if phase == "deliver":
            return self._deliver_response(messages, tools)
        # Fallback to agent loop behavior
        return self._agent_loop_response(messages, tools)

    # ------------------------------------------------------------------
    # Hypothesize phase: tool call → structured JSON hypothesis array
    # ------------------------------------------------------------------

    def _hypothesize_response(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tool_result_count = sum(1 for m in messages if m.get("role") == "tool")
        tool_names = {t["function"]["name"] for t in tools} if tools else set()

        # Extract environment context from system prompt
        system_prompt = ""
        for m in messages:
            if m.get("role") == "system":
                system_prompt = m.get("content", "")
                break

        # Extract available tables from the prompt
        available_tables = re.findall(r'"table"\s*:\s*"(\w+)"', system_prompt)
        if not available_tables:
            available_tables = ["SigninLogs", "AuditLogs", "SecurityEvent"]

        # Extract MITRE gaps from the prompt
        mitre_gaps = re.findall(r'T\d{4}(?:\.\d{3})?', system_prompt)

        # Iteration 1: search MITRE for coverage gaps
        if tool_result_count == 0 and "search_mitre" in tool_names:
            query = mitre_gaps[0] if mitre_gaps else "initial access"
            return self._tool_call("search_mitre", {"query": query})

        # Iteration 2: check threat landscape
        if tool_result_count == 1 and "check_landscape" in tool_names:
            return self._tool_call("check_landscape", {})

        # Iteration 3: check telemetry for table health
        if tool_result_count == 2 and "check_telemetry" in tool_names:
            return self._tool_call("check_telemetry", {})

        # Final: return structured hypotheses grounded in environment data
        primary_table = available_tables[0] if available_tables else "SigninLogs"
        secondary_table = available_tables[1] if len(available_tables) > 1 else "AuditLogs"
        third_table = available_tables[2] if len(available_tables) > 2 else "SecurityEvent"

        hypotheses = [
            {
                "hypothesis_id": f"H-{uuid.uuid4().hex[:8]}",
                "title": "Credential Abuse via Legacy Authentication Protocols",
                "description": (
                    "Adversaries may exploit legacy authentication protocols (POP3, IMAP, SMTP) "
                    "that bypass MFA to gain initial access. SigninLogs show legacy auth is still "
                    "enabled for some accounts."
                ),
                "source": "coverage_gap",
                "threat_likelihood": 0.8,
                "detection_feasibility": 0.9,
                "business_impact": 0.7,
                "mitre_techniques": ["T1078", "T1078.004"],
                "mitre_tactics": ["initial-access", "persistence"],
                "required_tables": [primary_table, secondary_table, "AADNonInteractiveUserSignInLogs"],
                "kql_approach": (
                    f"{primary_table} | where ClientAppUsed !in~ ('Browser', 'Mobile Apps and Desktop clients') "
                    f"| where ResultType == 0 | summarize by UserPrincipalName, ClientAppUsed, IPAddress"
                ),
                "expected_indicators": [
                    "Successful legacy auth sign-ins",
                    "Legacy auth from unusual IPs",
                    "Accounts with both modern and legacy auth",
                ],
                "false_positive_notes": "Service accounts may legitimately use SMTP auth for mail relay",
                "time_range": "last 30 days",
            },
            {
                "hypothesis_id": f"H-{uuid.uuid4().hex[:8]}",
                "title": "Suspicious Privileged Role Assignments in Azure AD",
                "description": (
                    "Threat actors with initial access may escalate privileges by assigning "
                    "Global Admin or other privileged roles. AuditLogs can reveal unexpected "
                    "role assignments outside normal change windows."
                ),
                "source": "posture_weakness",
                "threat_likelihood": 0.7,
                "detection_feasibility": 0.85,
                "business_impact": 0.9,
                "mitre_techniques": ["T1098", "T1098.003"],
                "mitre_tactics": ["persistence", "privilege-escalation"],
                "required_tables": [secondary_table, "IdentityInfo"],
                "kql_approach": (
                    f"{secondary_table} | where OperationName has 'Add member to role' "
                    f"| where TargetResources has 'Admin' | project TimeGenerated, "
                    f"InitiatedBy, TargetResources"
                ),
                "expected_indicators": [
                    "Role assignments outside business hours",
                    "Non-admin users initiating role changes",
                    "Rapid successive role assignments",
                ],
                "false_positive_notes": "IT admin onboarding may cause legitimate bulk role assignments",
                "time_range": "last 30 days",
            },
            {
                "hypothesis_id": f"H-{uuid.uuid4().hex[:8]}",
                "title": "Lateral Movement via Remote Desktop Protocol",
                "description": (
                    "After initial compromise, adversaries commonly use RDP for lateral movement. "
                    "DeviceLogonEvents and SecurityEvent 4624 type 10 logons reveal RDP activity "
                    "between internal hosts."
                ),
                "source": "threat_landscape",
                "threat_likelihood": 0.75,
                "detection_feasibility": 0.8,
                "business_impact": 0.8,
                "mitre_techniques": ["T1021", "T1021.001"],
                "mitre_tactics": ["lateral-movement"],
                "required_tables": [third_table, "DeviceLogonEvents", "DeviceNetworkEvents"],
                "kql_approach": (
                    f"{third_table} | where EventID == 4624 | where LogonType == 10 "
                    f"| summarize count() by TargetAccount, IpAddress, Computer "
                    f"| where count_ > 3"
                ),
                "expected_indicators": [
                    "RDP from non-admin workstations",
                    "First-time RDP connections between hosts",
                    "RDP outside business hours",
                ],
                "false_positive_notes": "IT helpdesk may use RDP legitimately for support sessions",
                "time_range": "last 14 days",
            },
        ]

        return {
            "content": "```json\n" + json.dumps(hypotheses, indent=2) + "\n```",
            "tool_calls": None,
            "finish_reason": "stop",
        }

    # ------------------------------------------------------------------
    # Execute phase: prompt-aware multi-iteration drill-down
    # ------------------------------------------------------------------

    def _execute_response(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tool_result_count = sum(1 for m in messages if m.get("role") == "tool")
        tool_names = {t["function"]["name"] for t in tools} if tools else set()

        # Extract context from system prompt to make queries grounded
        system_prompt = ""
        for m in messages:
            if m.get("role") == "system":
                system_prompt = m.get("content", "")
                break

        ctx = self._extract_execute_context(system_prompt)
        primary_table = ctx["primary_table"]
        pivot_table = ctx["pivot_table"]
        time_range = ctx["time_range"]
        target_entity = ctx["target_entity"]
        techniques = ctx["techniques"]

        # Iteration 1: broad initial query on primary table
        if tool_result_count == 0 and "run_kql_query" in tool_names:
            return self._tool_call("run_kql_query", {
                "query": (
                    f"{primary_table} | where TimeGenerated > ago({time_range}) "
                    f"| where ResultType == 0 "
                    f"| where ClientAppUsed !in~ ('Browser', 'Mobile Apps and Desktop clients') "
                    f"| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress "
                    f"| top 20 by count_"
                ),
            })

        # Iteration 2: drill down on specific entity from results
        if tool_result_count == 1 and "run_kql_query" in tool_names:
            # Extract entity from prior tool result if available
            entity = self._extract_entity_from_tool_results(messages) or target_entity
            return self._tool_call("run_kql_query", {
                "query": (
                    f"{primary_table} | where TimeGenerated > ago({time_range}) "
                    f"| where UserPrincipalName == '{entity}' "
                    f"| project TimeGenerated, IPAddress, ClientAppUsed, "
                    f"ResultType, Location, UserAgent "
                    f"| sort by TimeGenerated desc | take 50"
                ),
            })

        # Iteration 3: pivot — check same entity in another table
        if tool_result_count == 2 and "run_kql_query" in tool_names:
            entity = self._extract_entity_from_tool_results(messages) or target_entity
            entity_short = entity.split("@")[0] if "@" in entity else entity
            return self._tool_call("run_kql_query", {
                "query": (
                    f"{pivot_table} | where TimeGenerated > ago({time_range}) "
                    f"| where InitiatedBy has '{entity_short}' "
                    f"| project TimeGenerated, OperationName, "
                    f"TargetResources, Result "
                    f"| sort by TimeGenerated desc"
                ),
            })

        # Iteration 4: validate KQL for a detection rule
        if tool_result_count == 3 and "validate_kql" in tool_names:
            return self._tool_call("validate_kql", {
                "kql": (
                    f"{primary_table} | where ClientAppUsed !in~ ('Browser', 'Mobile Apps and Desktop clients') "
                    f"| where ResultType == 0 | summarize count() by UserPrincipalName"
                ),
            })

        # Iteration 5: MITRE enrichment if available
        if tool_result_count == 4 and "search_mitre" in tool_names and techniques:
            return self._tool_call("search_mitre", {"query": techniques[0]})

        # Final: structured findings JSON (grounded in extracted context)
        entity = self._extract_entity_from_tool_results(messages) or target_entity
        findings = [
            {
                "finding_id": f"F-{uuid.uuid4().hex[:8]}",
                "title": f"Active Legacy Authentication Bypassing MFA — {entity}",
                "description": (
                    f"Account {entity} is authenticating via SMTP "
                    f"legacy protocol, bypassing MFA. 847 successful sign-ins in {time_range} from "
                    f"3 distinct IPs. {pivot_table} show this account also performed 12 mailbox "
                    f"permission changes."
                ),
                "severity": "high",
                "confidence": 0.85,
                "classification": "true_positive",
                "mitre_techniques": techniques or ["T1078", "T1078.004"],
                "affected_entities": [
                    {"type": "account", "value": entity},
                    {"type": "ip", "value": "10.0.5.22"},
                    {"type": "ip", "value": "198.51.100.47"},
                ],
                "evidence_queries": [
                    f"{primary_table} legacy auth summary",
                    f"{primary_table} drill-down on {entity}",
                    f"{pivot_table} pivot on {entity}",
                    "KQL validation",
                ],
                "remediation": [
                    "Block legacy authentication via Conditional Access policy",
                    f"Rotate credentials for {entity}",
                    "Audit mailbox permission changes made by this account",
                ],
                "queries_executed": tool_result_count,
                "tables_queried": [primary_table, pivot_table],
                "entities_extracted": [entity, "10.0.5.22", "198.51.100.47"],
            },
        ]

        return {
            "content": "```json\n" + json.dumps(findings, indent=2) + "\n```",
            "tool_calls": None,
            "finish_reason": "stop",
        }

    def _extract_execute_context(self, system_prompt: str) -> dict[str, Any]:
        """Extract hypothesis tables, entities, and techniques from the execute system prompt."""
        ctx: dict[str, Any] = {
            "primary_table": "SigninLogs",
            "pivot_table": "AuditLogs",
            "time_range": "30d",
            "target_entity": "svc-mailrelay@contoso.com",
            "techniques": ["T1078", "T1078.004"],
        }

        if not system_prompt:
            return ctx

        # Extract table names from required_tables or table_profiles
        table_match = re.findall(r'"required_tables"\s*:\s*\[([^\]]+)\]', system_prompt)
        if table_match:
            tables = re.findall(r'"(\w+)"', table_match[0])
            if tables:
                ctx["primary_table"] = tables[0]
                if len(tables) > 1:
                    ctx["pivot_table"] = tables[1]

        # Also check for table names in table_profiles
        if ctx["primary_table"] == "SigninLogs":
            profile_tables = re.findall(r'"table"\s*:\s*"(\w+)"', system_prompt)
            if profile_tables:
                ctx["primary_table"] = profile_tables[0]
                if len(profile_tables) > 1:
                    ctx["pivot_table"] = profile_tables[1]

        # Extract time range
        time_match = re.search(r'(?:"time_range"|last)\s*(?::\s*")?(\d+)\s*days?"?', system_prompt, re.IGNORECASE)
        if time_match:
            ctx["time_range"] = f"{time_match.group(1)}d"

        # Extract MITRE techniques
        tech_matches = re.findall(r'T\d{4}(?:\.\d{3})?', system_prompt)
        if tech_matches:
            ctx["techniques"] = list(dict.fromkeys(tech_matches))[:5]  # dedupe, max 5

        # Extract target entity — UPN from hypothesis or env
        upn_match = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', system_prompt)
        if upn_match:
            ctx["target_entity"] = upn_match[0]

        # Extract entity from admin_users or risky_users
        admin_match = re.search(r'"upn"\s*:\s*"([^"]+)"', system_prompt)
        if admin_match:
            ctx["target_entity"] = admin_match.group(1)

        return ctx

    def _extract_entity_from_tool_results(self, messages: list[dict[str, Any]]) -> str:
        """Extract entities from prior tool results in the conversation."""
        for m in reversed(messages):
            if m.get("role") == "tool":
                content = m.get("content", "")
                # Look for UPNs in tool results
                upn_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', content)
                if upn_match:
                    return upn_match.group(0)
                # Look for IP addresses
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)
                if ip_match:
                    return ip_match.group(0)
        return ""

    # ------------------------------------------------------------------
    # Conclude phase: classification and evidence assessment
    # ------------------------------------------------------------------

    def _conclude_response(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tool_result_count = sum(1 for m in messages if m.get("role") == "tool")
        tool_names = {t["function"]["name"] for t in tools} if tools else set()

        # Extract MITRE technique from system prompt for contextual MITRE lookup
        system_prompt = ""
        for m in messages:
            if m.get("role") == "system":
                system_prompt = m.get("content", "")
                break
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', system_prompt)
        mitre_query = techniques[0] if techniques else "T1078"

        # Iteration 1: search MITRE for context
        if tool_result_count == 0 and "search_mitre" in tool_names:
            return self._tool_call("search_mitre", {"query": mitre_query})

        # Final: structured conclusion
        conclusion = {
            "findings_summary": [
                {
                    "finding_id": "F-mock-001",
                    "title": "Active Legacy Authentication Bypassing MFA",
                    "classification": "true_positive",
                    "severity": "high",
                    "confidence": 0.85,
                    "evidence_strength": "strong",
                    "rationale": (
                        "847 successful legacy auth sign-ins from svc-mailrelay in 30 days, "
                        "bypassing all MFA controls. Corroborated by AuditLogs showing "
                        "12 mailbox permission changes from the same account."
                    ),
                },
            ],
            "overall_assessment": {
                "threat_level": "elevated",
                "true_positives": 1,
                "false_positives": 0,
                "inconclusive": 0,
                "total_entities_investigated": 5,
                "total_queries_executed": 4,
            },
            "recommendations": [
                {
                    "priority": "critical",
                    "action": "Block legacy authentication protocols via Conditional Access",
                    "rationale": "Eliminates the primary attack vector for MFA bypass",
                },
                {
                    "priority": "high",
                    "action": "Rotate credentials for svc-mailrelay and audit its permissions",
                    "rationale": "Account may be compromised given unusual activity pattern",
                },
            ],
        }

        return {
            "content": "```json\n" + json.dumps(conclusion, indent=2) + "\n```",
            "tool_calls": None,
            "finish_reason": "stop",
        }

    # ------------------------------------------------------------------
    # Deliver phase: report generation
    # ------------------------------------------------------------------

    def _deliver_response(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        report = {
            "title": "Autonomous Threat Hunt Campaign Report",
            "executive_summary": (
                "This campaign investigated credential abuse, privilege escalation, and "
                "lateral movement threats. 1 true positive finding identified: active legacy "
                "authentication bypassing MFA via service account svc-mailrelay@contoso.com. "
                "Immediate action recommended to block legacy auth protocols."
            ),
            "findings_count": {"true_positive": 1, "false_positive": 0, "inconclusive": 0},
            "risk_score": 7.5,
            "top_recommendations": [
                "Block legacy authentication via Conditional Access policy",
                "Rotate svc-mailrelay credentials and audit permissions",
                "Enable MFA for all service accounts where possible",
            ],
        }

        return {
            "content": "```json\n" + json.dumps(report, indent=2) + "\n```",
            "tool_calls": None,
            "finish_reason": "stop",
        }

    # ------------------------------------------------------------------
    # Complexity classifier — keyword-based routing for mock
    # ------------------------------------------------------------------

    def _classifier_response(
        self,
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Mock complexity classification based on keywords in user message."""
        user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
                break

        msg_lower = user_msg.lower()

        # Campaign triggers
        campaign_keywords = [
            "full threat hunt", "full hunt", "comprehensive", "deep dive",
            "campaign", "proactive hunt", "run a hunt across", "full security",
            "posture review", "what threats are we missing", "hunt for all",
            "multi-phase", "autonomous hunt",
        ]

        route = "chat"
        confidence = 0.9
        reasoning = "Single-topic query suitable for real-time chat"
        focus_areas: list[str] = []

        for kw in campaign_keywords:
            if kw in msg_lower:
                route = "campaign"
                confidence = 0.95
                reasoning = f"Deep investigation triggered by '{kw}'"
                break

        # Extract focus areas from message
        focus_map = {
            "ransomware": "ransomware",
            "lateral movement": "lateral movement",
            "credential": "credential theft",
            "brute force": "credential theft",
            "phishing": "phishing",
            "bec": "business email compromise",
            "exfiltration": "data exfiltration",
            "privilege escalation": "privilege escalation",
            "persistence": "persistence",
            "initial access": "initial access",
        }
        for keyword, area in focus_map.items():
            if keyword in msg_lower:
                focus_areas.append(area)

        # Extract time range
        time_range = "last 30 days"
        if "7 day" in msg_lower or "last week" in msg_lower:
            time_range = "last 7 days"
        elif "14 day" in msg_lower or "2 week" in msg_lower:
            time_range = "last 14 days"
        elif "90 day" in msg_lower or "3 month" in msg_lower:
            time_range = "last 90 days"

        result = {
            "route": route,
            "confidence": confidence,
            "reasoning": reasoning,
            "focus_areas": focus_areas,
            "time_range": time_range,
            "max_hypotheses": 10,
        }

        return {
            "content": json.dumps(result),
            "tool_calls": None,
            "finish_reason": "stop",
        }

    # ------------------------------------------------------------------
    # Agent loop (non-campaign) — legacy 2-iteration behavior
    # ------------------------------------------------------------------

    def _agent_loop_response(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Legacy 2-iteration behavior for agent loop tests."""
        # Extract last user message
        user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
                break

        # Check if we already have tool results (iteration 2+)
        has_tool_results = any(m.get("role") == "tool" for m in messages)

        if has_tool_results:
            return {
                "content": (
                    "Based on my analysis of the security data, I found relevant "
                    "indicators that warrant further investigation. The evidence suggests "
                    "moderate confidence in the findings. I recommend correlating with "
                    "additional data sources for higher confidence."
                ),
                "tool_calls": None,
                "finish_reason": "stop",
            }

        # First iteration: decide which tool to call based on keywords
        tool_calls = self._mock_tool_selection(user_msg, tools)

        if tool_calls:
            return {
                "content": None,
                "tool_calls": tool_calls,
                "finish_reason": "tool_calls",
            }

        # No tools needed — general response
        return {
            "content": (
                "I can help with threat hunting, CVE assessments, detection "
                "engineering, risk analysis, and more. What would you like to investigate?"
            ),
            "tool_calls": None,
            "finish_reason": "stop",
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _tool_call(self, name: str, arguments: dict) -> dict[str, Any]:
        """Build a tool_calls response for a single tool."""
        return {
            "content": None,
            "tool_calls": [{
                "id": f"call_mock_{uuid.uuid4().hex[:8]}",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments),
                },
            }],
            "finish_reason": "tool_calls",
        }

    def _mock_tool_selection(
        self, message: str, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        """Deterministic tool selection based on keywords (agent loop path)."""
        msg_lower = message.lower()
        tool_names = {t["function"]["name"] for t in tools} if tools else set()

        call_id = f"call_mock_{uuid.uuid4().hex[:8]}"

        if "cve" in msg_lower and "lookup_cve" in tool_names:
            cve_match = re.search(r"CVE-\d{4}-\d+", message, re.IGNORECASE)
            cve_id = cve_match.group(0) if cve_match else "CVE-2024-0001"
            return [{
                "id": call_id,
                "function": {
                    "name": "lookup_cve",
                    "arguments": f'{{"cve_id": "{cve_id}"}}',
                },
            }]

        if ("hunt" in msg_lower or "investigate" in msg_lower) and "run_kql_query" in tool_names:
            return [{
                "id": call_id,
                "function": {
                    "name": "run_kql_query",
                    "arguments": '{"query": "SecurityEvent | where TimeGenerated > ago(7d) | where EventID == 4625 | summarize count() by Account | top 10 by count_"}',
                },
            }]

        if ("detection" in msg_lower or "rule" in msg_lower) and "search_mitre" in tool_names:
            tech_match = re.search(r"T\d{4}(?:\.\d{3})?", message)
            query = tech_match.group(0) if tech_match else "detection"
            return [{
                "id": call_id,
                "function": {
                    "name": "search_mitre",
                    "arguments": f'{{"query": "{query}"}}',
                },
            }]

        if ("risk" in msg_lower or "what if" in msg_lower) and "assess_risk" in tool_names:
            return [{
                "id": call_id,
                "function": {
                    "name": "assess_risk",
                    "arguments": '{"change_type": "remove_source", "affected_source": "EDR"}',
                },
            }]

        if ("landscape" in msg_lower or "threat" in msg_lower) and "check_landscape" in tool_names:
            return [{
                "id": call_id,
                "function": {"name": "check_landscape", "arguments": "{}"},
            }]

        return None
