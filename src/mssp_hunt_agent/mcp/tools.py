"""MCP Tool registry — maps tool names to implementations.

Each tool has:
  - description: shown to the MCP client
  - input_schema: JSON Schema for the tool arguments
  - handler: callable(arguments) -> str
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _json_result(obj: Any) -> str:
    """Serialize a Pydantic model or dict to JSON string."""
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump(), indent=2, default=str)
    return json.dumps(obj, indent=2, default=str)


def _get_config():
    """Load a HuntAgentConfig from env (or defaults)."""
    from mssp_hunt_agent.config import HuntAgentConfig
    return HuntAgentConfig.from_env()


def _get_db():
    """Open the hunt database at the configured path."""
    from mssp_hunt_agent.persistence.database import HuntDatabase
    cfg = _get_config()
    return HuntDatabase(cfg.db_path)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def _run_hunt(arguments: dict) -> str:
    from mssp_hunt_agent.pipeline.orchestrator import run_pipeline
    from mssp_hunt_agent.models import HuntInput

    hunt_input = HuntInput(
        client_name=arguments["client_name"],
        hypothesis=arguments["hypothesis"],
        time_range=arguments.get("time_range", "last 7 days"),
        iocs=arguments.get("iocs", ""),
    )
    config = _get_config()
    result = run_pipeline(hunt_input, config)
    return _json_result(result)


def _run_ioc_sweep(arguments: dict) -> str:
    from mssp_hunt_agent.pipeline.orchestrator import run_ioc_pipeline
    from mssp_hunt_agent.models import IOCHuntInput
    from mssp_hunt_agent.intel.ioc_intake import IOCType

    raw_iocs = arguments.get("iocs", "")
    ioc_list = [v.strip() for v in raw_iocs.split(",") if v.strip()]

    parsed = []
    for value in ioc_list:
        from mssp_hunt_agent.intel.feed_ingester import detect_ioc_type
        ioc_type_str = detect_ioc_type(value) or "unknown"
        # Map to IOCType enum
        type_map = {
            "ip": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "hash_md5": IOCType.HASH_MD5,
            "hash_sha256": IOCType.HASH_SHA256,
            "url": IOCType.URL,
            "email": IOCType.EMAIL,
            "username": IOCType.USERNAME,
        }
        parsed.append({
            "value": value,
            "ioc_type": type_map.get(ioc_type_str, IOCType.IP),
        })

    ioc_input = IOCHuntInput(
        client_name=arguments["client_name"],
        iocs=parsed,
        time_range=arguments.get("time_range", "last 7 days"),
    )
    config = _get_config()
    result = run_ioc_pipeline(ioc_input, config)
    return _json_result(result)


def _run_profile(arguments: dict) -> str:
    from mssp_hunt_agent.pipeline.orchestrator import run_profile_pipeline
    from mssp_hunt_agent.models import ProfileInput

    profile_input = ProfileInput(
        client_name=arguments["client_name"],
        time_range=arguments.get("time_range", "last 30 days"),
    )
    config = _get_config()
    result = run_profile_pipeline(profile_input, config)
    return _json_result(result)


def _get_hunt_status(arguments: dict) -> str:
    db = _get_db()
    run = db.get_run(arguments["run_id"])
    if not run:
        return json.dumps({"error": f"Run {arguments['run_id']} not found"})
    return _json_result(run)


def _ingest_feed(arguments: dict) -> str:
    from mssp_hunt_agent.intel.feed_ingester import FeedIngester
    from mssp_hunt_agent.intel.feed_models import FeedSource

    ingester = FeedIngester()
    source = FeedSource(
        name=arguments.get("feed_name", "manual"),
        format=arguments.get("format", "csv"),
        url=arguments.get("url", ""),
    )
    result = ingester.ingest(source, arguments["content"])
    return _json_result(result)


def _deconflict_iocs(arguments: dict) -> str:
    from mssp_hunt_agent.intel.deconfliction import deconflict
    from mssp_hunt_agent.intel.feed_models import NormalizedIOC

    iocs = [NormalizedIOC(**i) for i in arguments["iocs"]]
    known_benign = set(arguments.get("known_benign", []))
    result = deconflict(iocs, known_benign=known_benign)
    return _json_result(result)


def _auto_sweep(arguments: dict) -> str:
    from mssp_hunt_agent.intel.auto_sweep import AutoSweepScheduler, ClientProfile
    from mssp_hunt_agent.intel.feed_models import NormalizedIOC

    iocs = [NormalizedIOC(**i) for i in arguments["iocs"]]
    profiles = [
        ClientProfile(
            client_name=p["client_name"],
            data_sources=p.get("data_sources", []),
        )
        for p in arguments["client_profiles"]
    ]
    scheduler = AutoSweepScheduler()
    config = _get_config()
    inputs = scheduler.generate_sweep_inputs(iocs, profiles, config)
    return _json_result([i.model_dump() if hasattr(i, "model_dump") else i for i in inputs])


def _get_client_kpis(arguments: dict) -> str:
    from mssp_hunt_agent.analytics.kpi_engine import KPIEngine

    db = _get_db()
    engine = KPIEngine(db)
    kpis = engine.client_kpis(
        arguments["client_name"],
        period=arguments.get("period", "all"),
    )
    if not kpis:
        return json.dumps({"error": f"No data for client {arguments['client_name']}"})
    return _json_result(kpis)


def _generate_rollup(arguments: dict) -> str:
    from mssp_hunt_agent.analytics.rollup_reports import (
        generate_weekly_rollup,
        generate_monthly_rollup,
    )

    db = _get_db()
    rollup_type = arguments.get("type", "weekly")
    period = arguments.get("period")

    if rollup_type == "monthly":
        model, markdown = generate_monthly_rollup(db, period)
    else:
        model, markdown = generate_weekly_rollup(db, period)

    return markdown


def _add_tuning_rule(arguments: dict) -> str:
    from mssp_hunt_agent.analytics.tuning import TuningStore

    db = _get_db()
    store = TuningStore(db)
    rule = store.add_rule(
        client_name=arguments["client_name"],
        rule_type=arguments.get("rule_type", "exclusion"),
        pattern=arguments["pattern"],
        reason=arguments.get("reason", ""),
    )
    return _json_result(rule)


def _search_mitre(arguments: dict) -> str:
    """Search MITRE ATT&CK technique keywords."""
    from mssp_hunt_agent.pipeline.planner import _TACTIC_KEYWORDS

    query = arguments.get("query", "").lower()
    matches = {}
    for tactic, keywords in _TACTIC_KEYWORDS.items():
        if query in tactic.lower() or any(query in kw for kw in keywords):
            matches[tactic] = keywords

    return json.dumps({"query": query, "matches": matches}, indent=2)


def _generate_detection(arguments: dict) -> str:
    from mssp_hunt_agent.detection.generator import generate_detection_rule

    rule = generate_detection_rule(
        technique_id=arguments.get("technique_id"),
        description=arguments.get("description"),
        severity=arguments.get("severity"),
    )
    return _json_result(rule)


def _validate_kql(arguments: dict) -> str:
    from mssp_hunt_agent.detection.validator import validate_kql

    result = validate_kql(arguments["kql"])
    return _json_result(result)


def _simulate_detection(arguments: dict) -> str:
    from mssp_hunt_agent.detection.generator import generate_detection_rule
    from mssp_hunt_agent.detection.scorer import score_detection_quality

    rule = generate_detection_rule(
        technique_id=arguments.get("technique_id"),
        description=arguments.get("description"),
    )
    score = score_detection_quality(rule)
    return json.dumps({
        "rule": rule.model_dump() if hasattr(rule, "model_dump") else rule,
        "quality_score": score.model_dump() if hasattr(score, "model_dump") else score,
    }, indent=2, default=str)


def _map_assets(arguments: dict) -> str:
    from mssp_hunt_agent.threat_model.asset_mapper import map_assets

    result = map_assets(
        client_name=arguments["client_name"],
        available_data_sources=arguments["data_sources"],
    )
    return _json_result(result)


def _identify_attack_paths(arguments: dict) -> str:
    from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths

    paths = identify_attack_paths(arguments["data_sources"])
    return _json_result([p.model_dump() if hasattr(p, "model_dump") else p for p in paths])


def _simulate_risk(arguments: dict) -> str:
    from mssp_hunt_agent.risk.models import RiskScenario
    from mssp_hunt_agent.risk.simulator import simulate_risk_scenario

    scenario = RiskScenario(
        client_name=arguments["client_name"],
        change_type=arguments["change_type"],
        affected_source=arguments["affected_source"],
    )
    result = simulate_risk_scenario(scenario, arguments["current_data_sources"])
    return _json_result(result)


def _correlate_landscape(arguments: dict) -> str:
    from mssp_hunt_agent.intel.landscape import ThreatLandscapeEngine

    engine = ThreatLandscapeEngine()
    if "kev_catalog" in arguments:
        engine.ingest_kev(arguments["kev_catalog"])
    report = engine.correlate(arguments["client_sources"])
    return _json_result(report)


def _portfolio_risk(arguments: dict) -> str:
    from mssp_hunt_agent.risk.portfolio import portfolio_risk_summary

    result = portfolio_risk_summary(arguments["client_sources"])
    return _json_result(result)


def _chat(arguments: dict) -> str:
    from mssp_hunt_agent.agent.controller import AgentController

    config = _get_config()
    controller = AgentController(config=config)
    response = controller.process(arguments["message"])
    return _json_result(response)


def _assess_cve(arguments: dict) -> str:
    from mssp_hunt_agent.agent.cve_assessor import CVEAssessor

    config = _get_config()
    assessor = CVEAssessor(config)
    response = assessor.assess(arguments["cve_id"])
    return _json_result(response)


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "run_hunt": {
        "description": "Run a hypothesis-driven threat hunt against Microsoft Sentinel.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "hypothesis": {"type": "string", "description": "Threat hypothesis or ATT&CK technique"},
                "time_range": {"type": "string", "description": "Time range (e.g. 'last 7 days')", "default": "last 7 days"},
                "iocs": {"type": "string", "description": "Comma-separated IOCs to pivot on", "default": ""},
            },
            "required": ["client_name", "hypothesis"],
        },
        "handler": _run_hunt,
    },
    "run_ioc_sweep": {
        "description": "Sweep a client's Sentinel workspace for specific IOCs (IPs, hashes, domains).",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "iocs": {"type": "string", "description": "Comma-separated IOC values"},
                "time_range": {"type": "string", "description": "Time range", "default": "last 7 days"},
            },
            "required": ["client_name", "iocs"],
        },
        "handler": _run_ioc_sweep,
    },
    "run_profile": {
        "description": "Profile a client's telemetry to assess hunt readiness and data source coverage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "time_range": {"type": "string", "description": "Time range", "default": "last 30 days"},
            },
            "required": ["client_name"],
        },
        "handler": _run_profile,
    },
    "get_hunt_status": {
        "description": "Get the status and results of a previous hunt run.",
        "input_schema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string", "description": "Hunt run ID"},
            },
            "required": ["run_id"],
        },
        "handler": _get_hunt_status,
    },
    "ingest_feed": {
        "description": "Ingest a threat intelligence feed (CSV, STIX, JSON) into normalized IOCs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Raw feed content"},
                "format": {"type": "string", "enum": ["csv", "stix", "json"], "description": "Feed format"},
                "feed_name": {"type": "string", "description": "Feed source name", "default": "manual"},
                "url": {"type": "string", "description": "Feed URL (metadata)", "default": ""},
            },
            "required": ["content", "format"],
        },
        "handler": _ingest_feed,
    },
    "deconflict_iocs": {
        "description": "Deduplicate and filter IOCs, suppressing known-benign entries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "iocs": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of IOC objects with 'value' and 'ioc_type' fields",
                },
                "known_benign": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known-benign values to suppress",
                    "default": [],
                },
            },
            "required": ["iocs"],
        },
        "handler": _deconflict_iocs,
    },
    "auto_sweep": {
        "description": "Automatically match new IOCs to client profiles and generate sweep inputs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "iocs": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Normalized IOC objects",
                },
                "client_profiles": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Client profiles with client_name and data_sources",
                },
            },
            "required": ["iocs", "client_profiles"],
        },
        "handler": _auto_sweep,
    },
    "get_client_kpis": {
        "description": "Compute hunt KPIs for a client (hunts run, findings, coverage).",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "period": {"type": "string", "description": "Period filter ('all', '2024-W48', '2024-12')", "default": "all"},
            },
            "required": ["client_name"],
        },
        "handler": _get_client_kpis,
    },
    "generate_rollup": {
        "description": "Generate a weekly or monthly rollup report across all clients.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["weekly", "monthly"], "description": "Rollup type", "default": "weekly"},
                "period": {"type": "string", "description": "Period (e.g. '2024-W48' or '2024-12')"},
            },
            "required": [],
        },
        "handler": _generate_rollup,
    },
    "add_tuning_rule": {
        "description": "Add a per-client tuning rule (exclusion or benign_pattern).",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "rule_type": {"type": "string", "enum": ["exclusion", "benign_pattern"], "description": "Rule type"},
                "pattern": {"type": "string", "description": "Pattern to match"},
                "reason": {"type": "string", "description": "Reason for the rule", "default": ""},
            },
            "required": ["client_name", "pattern"],
        },
        "handler": _add_tuning_rule,
    },
    "search_mitre": {
        "description": "Search MITRE ATT&CK tactics and techniques by keyword.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword"},
            },
            "required": ["query"],
        },
        "handler": _search_mitre,
    },
    "generate_detection": {
        "description": "Generate a KQL detection rule from an ATT&CK technique ID or description.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "ATT&CK technique ID (e.g. T1078)"},
                "description": {"type": "string", "description": "Natural language description of the detection"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Rule severity"},
            },
            "required": [],
        },
        "handler": _generate_detection,
    },
    "validate_kql": {
        "description": "Validate a KQL query for syntax, best practices, and performance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kql": {"type": "string", "description": "KQL query to validate"},
            },
            "required": ["kql"],
        },
        "handler": _validate_kql,
    },
    "simulate_detection": {
        "description": "Generate a detection rule and score its quality (coverage, precision, noise).",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "ATT&CK technique ID"},
                "description": {"type": "string", "description": "Detection description"},
            },
            "required": [],
        },
        "handler": _simulate_detection,
    },
    "map_assets": {
        "description": "Build a client asset inventory from available Sentinel data sources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "data_sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Available Sentinel table names",
                },
            },
            "required": ["client_name", "data_sources"],
        },
        "handler": _map_assets,
    },
    "identify_attack_paths": {
        "description": "Identify likely attack paths based on available data source coverage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data_sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Available Sentinel table names",
                },
            },
            "required": ["data_sources"],
        },
        "handler": _identify_attack_paths,
    },
    "simulate_risk": {
        "description": "Simulate the impact of adding/removing/degrading a data source on detection coverage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_name": {"type": "string", "description": "Client name"},
                "change_type": {"type": "string", "enum": ["remove_source", "add_source", "degrade_source"], "description": "Type of change"},
                "affected_source": {"type": "string", "description": "Data source being changed (e.g. 'SecurityEvent')"},
                "current_data_sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Current Sentinel table names",
                },
            },
            "required": ["client_name", "change_type", "affected_source", "current_data_sources"],
        },
        "handler": _simulate_risk,
    },
    "portfolio_risk": {
        "description": "Aggregate risk assessment across all clients in the MSSP portfolio.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_sources": {
                    "type": "object",
                    "description": "Mapping of client_name -> list of data source names",
                },
            },
            "required": ["client_sources"],
        },
        "handler": _portfolio_risk,
    },
    "correlate_landscape": {
        "description": "Cross-reference active threats (CISA KEV) against client detection capabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "client_sources": {
                    "type": "object",
                    "description": "Mapping of client_name -> list of data source names",
                },
                "kev_catalog": {
                    "type": "object",
                    "description": "Raw CISA KEV JSON catalog (optional — uses cached if omitted)",
                },
            },
            "required": ["client_sources"],
        },
        "handler": _correlate_landscape,
    },
    "chat": {
        "description": "Send a natural-language message to the agent controller. Supports: threat hunts, CVE checks, IOC sweeps, detection engineering, risk analysis, threat modeling, and more.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Natural-language prompt (e.g. 'Are we vulnerable to CVE-2025-55182?')"},
            },
            "required": ["message"],
        },
        "handler": _chat,
    },
    "assess_cve": {
        "description": "Assess vulnerability to a specific CVE — checks MITRE mapping, telemetry coverage, CISA KEV status, and generates detection recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID (e.g. CVE-2025-55182)"},
            },
            "required": ["cve_id"],
        },
        "handler": _assess_cve,
    },
}


def execute_tool(name: str, arguments: dict) -> str:
    """Execute a registered tool by name. Returns JSON string result."""
    if name not in TOOL_REGISTRY:
        return json.dumps({"error": f"Unknown tool: {name}"})

    handler: Callable = TOOL_REGISTRY[name]["handler"]
    try:
        return handler(arguments)
    except Exception as exc:
        logger.exception("Tool %s failed", name)
        return json.dumps({"error": str(exc)})
