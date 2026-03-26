"""Agent tool definitions — OpenAI function-calling schemas + executor."""

from __future__ import annotations

import json
import logging
from typing import Any

from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


# ── OpenAI function-calling tool schemas ─────────────────────────────

AGENT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_kql_query",
            "description": (
                "Execute a KQL query against the client's Microsoft Sentinel workspace. "
                "Always run this proactively when users ask about their environment — do not just suggest queries. "
                "Always include a time filter (e.g., ago(7d)). After getting results, analyze them and continue investigating."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The KQL query to execute. Must include a time filter (e.g., ago(7d)).",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum rows to return (default 100).",
                        "default": 100,
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_kql",
            "description": (
                "Validate a KQL query for syntax errors, performance issues, and "
                "best practices before executing it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "kql": {"type": "string", "description": "The KQL query to validate."},
                },
                "required": ["kql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": (
                "Fetch detailed CVE information from the public cvelistV5 database. "
                "Returns severity, CVSS score, affected products, CWE, and CISA KEV status. "
                "After calling this, ALWAYS follow up with run_kql_query to check if the affected "
                "technology exists in the environment, then give a VULNERABLE / NOT VULNERABLE / UNKNOWN verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID (e.g., CVE-2024-3400).",
                    },
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_mitre",
            "description": (
                "Search the full MITRE ATT&CK Enterprise dataset (770+ techniques). "
                "Search by technique ID (T1059.001) or keyword (credential dumping, lateral movement). "
                "Returns technique details, tactics, platforms, and data sources."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Technique ID (e.g., T1059) or keyword to search for.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_sentinel_rule_examples",
            "description": (
                "Fetch real community detection rules from the Azure-Sentinel GitHub repo "
                "for a given MITRE technique. Returns KQL queries, severity, tactics, and more. "
                "Always use this when generating detection rules to ground them in proven community examples."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., T1098).",
                    },
                },
                "required": ["technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_telemetry",
            "description": (
                "Check what security telemetry data sources are available, "
                "discover custom _CL tables (with exact column names and row counts), "
                "and identify ATT&CK technique coverage. "
                "ALWAYS call this first when hunting for threats to discover all available data sources."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_hunt",
            "description": (
                "Execute the full threat hunt pipeline for a hypothesis. "
                "Runs multiple queries, enriches results, and produces findings. "
                "Use for comprehensive investigations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hypothesis": {
                        "type": "string",
                        "description": "The threat hypothesis to investigate.",
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Time range (e.g., 'last 7 days').",
                        "default": "last 7 days",
                    },
                },
                "required": ["hypothesis"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_risk",
            "description": (
                "Simulate the impact of adding or removing a data source. "
                "Returns risk rating, blind spots, and recommendations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "change_type": {
                        "type": "string",
                        "enum": ["remove_source", "add_source"],
                        "description": "Type of change being assessed.",
                    },
                    "affected_source": {
                        "type": "string",
                        "description": "Data source being changed (e.g., EDR, Syslog).",
                    },
                },
                "required": ["change_type", "affected_source"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_landscape",
            "description": (
                "Cross-reference active threats from CISA KEV against detection capabilities. "
                "Returns alerts and coverage gaps."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "identify_attack_paths",
            "description": (
                "Identify likely attack paths based on data source coverage. "
                "Returns entry points, technique chains, and detection gaps."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": (
                "Enrich an IP address, domain, or file hash with threat intelligence from multiple free sources. "
                "For IPs: checks TOR exit nodes, botnet C2 (Feodo Tracker), IPsum reputation (100+ blocklists), "
                "and Shodan InternetDB (open ports, vulns, hostnames). "
                "For domains/hashes: checks Abuse.ch ThreatFox for malware family attribution. "
                "Returns a threat level (critical/high/medium/low/clean) and all source findings. "
                "ALWAYS use this when you encounter a suspicious IP, domain, or hash in query results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The IOC to enrich — IP address, domain name, or file hash (MD5/SHA256).",
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "auto"],
                        "description": "Type of indicator. Use 'auto' to detect automatically.",
                        "default": "auto",
                    },
                },
                "required": ["indicator"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_lolbas",
            "description": (
                "Check if a binary or process name is a known Living-Off-The-Land Binary (LOLBAS). "
                "Returns ATT&CK technique mapping, abuse commands, and detection guidance. "
                "Use this when you see suspicious legitimate Windows binaries in process logs "
                "(e.g., mshta.exe, regsvr32.exe, rundll32.exe, installutil.exe, certutil.exe). "
                "Also checks LOLDrivers for known vulnerable/malicious Windows drivers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_name": {
                        "type": "string",
                        "description": "Binary or driver name to check (e.g., 'mshta.exe', 'certutil').",
                    },
                },
                "required": ["binary_name"],
            },
        },
    },
]


# ── Tool Executor ────────────────────────────────────────────────────


class ToolExecutor:
    """Execute tool calls by routing to backend functions."""

    def __init__(self, config: HuntAgentConfig) -> None:
        self.config = config
        self._client_name = config.default_client_name or "Unknown"

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Route a tool call to the appropriate handler. Returns JSON string."""
        handler = _TOOL_HANDLERS.get(tool_name)
        if not handler:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        try:
            result = handler(self, arguments)
            return result if isinstance(result, str) else json.dumps(result, default=str)
        except Exception as exc:
            logger.exception("Tool '%s' failed", tool_name)
            return json.dumps({"error": f"Tool {tool_name} failed: {exc}"})

    # ── Individual handlers ──────────────────────────────────────

    def _handle_run_kql_query(self, args: dict) -> str:
        from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent

        query = args.get("query", "")
        max_results = min(args.get("max_results", 100), self.config.agent_loop_max_kql_results)

        adapter = self._get_sentinel_adapter()
        eq = ExabeamQuery(
            query_id="agent-kql-001",
            intent=QueryIntent.BASELINE,
            description="Agent-generated KQL query",
            query_text=query,
            time_range="7d",
            expected_signal="security events",
        )
        result = adapter.execute_query(eq)

        events = [e.model_dump() for e in result.events[:max_results]]
        return json.dumps({
            "total_events": result.result_count,
            "events_returned": len(events),
            "events": events,
        }, default=str)

    def _get_sentinel_adapter(self):
        """Build a Sentinel adapter — real when credentials are set, mock otherwise."""
        if self.config.adapter_mode == "real" and self.config.sentinel_workspace_id:
            from mssp_hunt_agent.adapters.sentinel.adapter import SentinelAdapter
            from mssp_hunt_agent.adapters.sentinel.api_client import SentinelQueryClient
            from mssp_hunt_agent.adapters.sentinel.auth import SentinelAuth

            auth = SentinelAuth(
                tenant_id=self.config.azure_tenant_id,
                client_id=self.config.azure_client_id,
                client_secret=self.config.azure_client_secret,
            )
            client = SentinelQueryClient(
                workspace_id=self.config.sentinel_workspace_id,
                auth=auth,
            )
            return SentinelAdapter(client=client, max_results=self.config.agent_loop_max_kql_results)

        from mssp_hunt_agent.adapters.sentinel.mock import MockSentinelAdapter
        return MockSentinelAdapter()

    def _handle_validate_kql(self, args: dict) -> str:
        from mssp_hunt_agent.detection.validator import validate_kql

        kql = args.get("kql", "")
        result = validate_kql(kql)
        return json.dumps(result.model_dump(), default=str)

    def _handle_lookup_cve(self, args: dict) -> str:
        from mssp_hunt_agent.intel.cve_lookup import CVELookup

        cve_id = args.get("cve_id", "")
        lookup = CVELookup(
            use_mock=(self.config.adapter_mode == "mock"),
            cache_dir=self.config.cve_cache_dir,
        )
        detail = lookup.fetch(cve_id)
        result = detail.model_dump()

        # Enrich with EPSS exploit probability
        try:
            from mssp_hunt_agent.intel.threat_intel import enrich_cve
            epss_data = enrich_cve(cve_id)
            result["epss_score"] = epss_data.get("epss_score")
            result["epss_percentile"] = epss_data.get("epss_percentile")
            result["exploit_probability"] = epss_data.get("exploit_probability")
        except Exception as exc:
            logger.debug("EPSS enrichment failed for %s: %s", cve_id, exc)

        return json.dumps(result, default=str)

    def _handle_search_mitre(self, args: dict) -> str:
        from mssp_hunt_agent.intel.mitre_client import MITREClient

        query = args.get("query", "")
        client = MITREClient(cache_dir=self.config.mitre_cache_dir)

        # Try exact technique ID first
        technique = client.get_technique(query)
        if technique:
            return json.dumps({"techniques": [technique.model_dump()]}, default=str)

        # Search by keyword
        results = client.search_techniques(query, max_results=10)
        return json.dumps({"techniques": [t.model_dump() for t in results]}, default=str)

    def _handle_get_sentinel_rules(self, args: dict) -> str:
        from mssp_hunt_agent.intel.sentinel_rules import SentinelRulesClient

        technique_id = args.get("technique_id", "")
        client = SentinelRulesClient(cache_dir=self.config.sentinel_rules_cache_dir)
        rules = client.get_rules_for_technique(technique_id)
        return json.dumps({"rules": [r.model_dump() for r in rules]}, default=str)

    def _handle_check_telemetry(self, args: dict) -> str:
        from mssp_hunt_agent.threat_model.asset_mapper import map_assets

        standard_tables = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
        asset_map = map_assets(self._client_name, standard_tables)

        # Discover custom _CL tables by querying Sentinel
        custom_tables: list[dict] = []
        try:
            from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent

            adapter = self._get_sentinel_adapter()

            # Use Usage table to find _CL tables (more reliable than search *)
            usage_kql = (
                "Usage "
                "| where TimeGenerated > ago(30d) "
                "| where DataType endswith '_CL' "
                "| summarize TotalMB=sum(Quantity), RowCount=sum(BillableQuantity) by DataType "
                "| order by RowCount desc "
                "| take 20"
            )
            usage_query = ExabeamQuery(
                query_id="telemetry-discover-cl",
                intent=QueryIntent.BASELINE,
                description="Discover custom _CL tables",
                query_text=usage_kql,
                time_range="30d",
                expected_signal="custom tables",
            )
            usage_result = adapter.execute_query(usage_query)

            found_tables: list[str] = []
            if usage_result and usage_result.events:
                for event in usage_result.events:
                    table_name = event.raw_event.get("DataType", "")
                    if table_name and table_name.endswith("_CL"):
                        found_tables.append(table_name)

            # For each custom table, get schema
            for table_name in found_tables:
                try:
                    schema_kql = f"{table_name} | getschema | project ColumnName, DataType | take 50"
                    schema_query = ExabeamQuery(
                        query_id=f"schema-{table_name}",
                        intent=QueryIntent.BASELINE,
                        description=f"Get schema for {table_name}",
                        query_text=schema_kql,
                        time_range="30d",
                        expected_signal="schema",
                    )
                    schema_result = adapter.execute_query(schema_query)
                    columns = [
                        {"name": e.raw_event.get("ColumnName", ""), "type": e.raw_event.get("DataType", "")}
                        for e in (schema_result.events if schema_result else [])
                        if e.raw_event.get("ColumnName")
                        and not e.raw_event["ColumnName"].startswith("_")
                        and e.raw_event["ColumnName"] not in ("TenantId", "MG", "ManagementGroupName", "RawData", "SourceSystem")
                    ]

                    # Get row count
                    count_kql = f"{table_name} | where TimeGenerated > ago(30d) | count"
                    count_query = ExabeamQuery(
                        query_id=f"count-{table_name}",
                        intent=QueryIntent.BASELINE,
                        description=f"Count rows in {table_name}",
                        query_text=count_kql,
                        time_range="30d",
                        expected_signal="count",
                    )
                    count_result = adapter.execute_query(count_query)
                    row_count = 0
                    if count_result and count_result.events:
                        row_count = count_result.events[0].raw_event.get("Count", 0)

                    custom_tables.append({
                        "table": table_name,
                        "row_count_30d": row_count,
                        "columns": columns,
                        "note": (
                            "Custom table with attack simulation data. "
                            "IMPORTANT: Use EXACT column names listed here. "
                            "Legacy API tables use _s suffix for strings, _d for numbers. "
                            "Always query this table alongside standard tables when hunting."
                        ),
                    })
                except Exception as exc:
                    logger.warning("Failed to get schema for %s: %s", table_name, exc)
                    custom_tables.append({"table": table_name, "columns": [], "note": "Schema query failed"})

        except Exception as exc:
            logger.warning("Custom table discovery failed: %s", exc)

        return json.dumps({
            "data_sources": standard_tables,
            "custom_tables": custom_tables,
            "total_assets": asset_map.total_assets,
            "coverage_summary": asset_map.coverage_summary,
            "assets": [a.model_dump() for a in asset_map.assets[:20]],
        }, default=str)

    def _handle_run_hunt(self, args: dict) -> str:
        from mssp_hunt_agent.api import background as bg
        from mssp_hunt_agent.models.input_models import HuntInput

        config = self.config.model_copy()
        config.approval_required = False

        hypothesis = args.get("hypothesis", "")
        hunt_input = HuntInput(
            client_name=self._client_name,
            hunt_objective=hypothesis,
            hunt_hypothesis=hypothesis,
            time_range=args.get("time_range", "last 7 days"),
            available_data_sources=["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"],
        )

        run_id = bg.generate_run_id("RUN")
        status = bg.launch_hunt(run_id, hunt_input, config)
        return json.dumps({"run_id": run_id, "status": status.status}, default=str)

    def _handle_assess_risk(self, args: dict) -> str:
        from mssp_hunt_agent.risk.models import RiskScenario
        from mssp_hunt_agent.risk.simulator import simulate_risk_scenario

        scenario = RiskScenario(
            client_name=self._client_name,
            change_type=args.get("change_type", "remove_source"),
            affected_source=args.get("affected_source", "EDR"),
        )
        current = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
        result = simulate_risk_scenario(scenario, current)
        return json.dumps(result.model_dump(), default=str)

    def _handle_check_landscape(self, args: dict) -> str:
        from mssp_hunt_agent.intel.landscape import ThreatLandscapeEngine

        engine = ThreatLandscapeEngine()
        client_sources = {self._client_name: ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]}
        report = engine.correlate(client_sources)
        return json.dumps({
            "alerts": len(report.alerts),
            "correlations": len(report.correlations),
            "clients_at_risk": report.clients_at_risk,
            "summary": [a.message for a in report.alerts[:5]],
        }, default=str)

    def _handle_attack_paths(self, args: dict) -> str:
        from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths

        data_sources = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
        paths = identify_attack_paths(data_sources)
        return json.dumps({
            "path_count": len(paths),
            "paths": [p.model_dump() for p in paths[:10]],
        }, default=str)

    def _handle_enrich_ioc(self, args: dict) -> str:
        from mssp_hunt_agent.intel.threat_intel import (
            enrich_domain,
            enrich_hash,
            enrich_ip,
            lookup_ioc_threatfox,
        )

        indicator = args.get("indicator", "")
        ioc_type = args.get("indicator_type", "auto")

        # Auto-detect type
        if ioc_type == "auto":
            if all(c in "0123456789." for c in indicator) and indicator.count(".") == 3:
                ioc_type = "ip"
            elif len(indicator) in (32, 64):
                ioc_type = "hash"
            else:
                ioc_type = "domain"

        if ioc_type == "ip":
            result = enrich_ip(indicator)
            return json.dumps(result, default=str)
        elif ioc_type == "hash":
            matches = enrich_hash(indicator)
            return json.dumps({
                "indicator": indicator,
                "type": "hash",
                "matches": [m.model_dump() for m in matches],
                "is_malicious": len(matches) > 0,
                "malware_families": list({m.malware for m in matches if m.malware}),
            }, default=str)
        else:
            matches = enrich_domain(indicator)
            return json.dumps({
                "indicator": indicator,
                "type": "domain",
                "matches": [m.model_dump() for m in matches],
                "is_malicious": len(matches) > 0,
                "malware_families": list({m.malware for m in matches if m.malware}),
            }, default=str)

    def _handle_check_lolbas(self, args: dict) -> str:
        from mssp_hunt_agent.intel.threat_intel import check_lolbas, get_loldrivers

        binary_name = args.get("binary_name", "")

        # Check LOLBAS
        lolbas_match = check_lolbas(binary_name)

        # Check LOLDrivers
        driver_matches = []
        name_lower = binary_name.lower().replace(".sys", "").replace(".exe", "")
        for driver in get_loldrivers():
            if name_lower in driver.get("name", "").lower():
                driver_matches.append(driver)

        result: dict[str, Any] = {
            "binary": binary_name,
            "is_lolbas": lolbas_match is not None,
            "is_loldriver": len(driver_matches) > 0,
        }

        if lolbas_match:
            result["lolbas"] = lolbas_match
            result["warning"] = (
                f"{binary_name} is a known Living-Off-The-Land Binary. "
                f"It can be abused for: {', '.join(lolbas_match.get('mitre', []))}. "
                f"Check the parent process and command line for abuse indicators."
            )

        if driver_matches:
            result["loldrivers"] = driver_matches[:3]
            result["warning"] = (
                f"{binary_name} matches a known vulnerable/malicious driver. "
                f"This could indicate a BYOVD (Bring Your Own Vulnerable Driver) attack."
            )

        if not lolbas_match and not driver_matches:
            result["note"] = f"{binary_name} is not in the LOLBAS or LOLDrivers databases."

        return json.dumps(result, default=str)


_TOOL_HANDLERS = {
    "run_kql_query": ToolExecutor._handle_run_kql_query,
    "validate_kql": ToolExecutor._handle_validate_kql,
    "lookup_cve": ToolExecutor._handle_lookup_cve,
    "search_mitre": ToolExecutor._handle_search_mitre,
    "get_sentinel_rule_examples": ToolExecutor._handle_get_sentinel_rules,
    "check_telemetry": ToolExecutor._handle_check_telemetry,
    "run_hunt": ToolExecutor._handle_run_hunt,
    "assess_risk": ToolExecutor._handle_assess_risk,
    "check_landscape": ToolExecutor._handle_check_landscape,
    "identify_attack_paths": ToolExecutor._handle_attack_paths,
    "enrich_ioc": ToolExecutor._handle_enrich_ioc,
    "check_lolbas": ToolExecutor._handle_check_lolbas,
}
