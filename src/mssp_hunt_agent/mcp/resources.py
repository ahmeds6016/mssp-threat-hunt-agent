"""MCP Resource registry — exposes read-only data via URI schemes.

Supported URI patterns:
  clients://                  — list all clients
  clients://{name}            — single client details + stats
  hunts://                    — recent hunt runs (last 50)
  hunts://{run_id}            — single hunt run details
  intel://feeds               — feed ingestion summary
  tuning://{client_name}      — per-client tuning rules
  mitre://tactics             — ATT&CK tactic keyword map
  landscape://alerts          — latest threat landscape alerts (placeholder)
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_config():
    from mssp_hunt_agent.config import HuntAgentConfig
    return HuntAgentConfig.from_env()


def _get_db():
    from mssp_hunt_agent.persistence.database import HuntDatabase
    cfg = _get_config()
    return HuntDatabase(cfg.db_path)


def _json(obj: Any) -> str:
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump(), indent=2, default=str)
    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# Resource handlers
# ---------------------------------------------------------------------------

def _clients_list() -> str:
    db = _get_db()
    clients = db.list_clients()
    return _json([c.model_dump() if hasattr(c, "model_dump") else c for c in clients])


def _client_detail(name: str) -> str:
    db = _get_db()
    client = db.get_client(name)
    if not client:
        return json.dumps({"error": f"Client '{name}' not found"})
    stats = db.get_client_stats(name)
    result = {
        "client": client.model_dump() if hasattr(client, "model_dump") else client,
        "stats": stats.model_dump() if stats and hasattr(stats, "model_dump") else stats,
    }
    return _json(result)


def _hunts_list() -> str:
    db = _get_db()
    runs = db.get_runs(limit=50)
    return _json([r.model_dump() if hasattr(r, "model_dump") else r for r in runs])


def _hunt_detail(run_id: str) -> str:
    db = _get_db()
    run = db.get_run(run_id)
    if not run:
        return json.dumps({"error": f"Run '{run_id}' not found"})
    findings = db.get_findings(run_id)
    result = {
        "run": run.model_dump() if hasattr(run, "model_dump") else run,
        "findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings],
    }
    return _json(result)


def _intel_feeds() -> str:
    return json.dumps({
        "status": "Feed ingestion available via ingest_feed tool",
        "supported_formats": ["csv", "stix", "json"],
    }, indent=2)


def _tuning_rules(client_name: str) -> str:
    from mssp_hunt_agent.analytics.tuning import TuningStore
    db = _get_db()
    store = TuningStore(db)
    rules = store.list_rules(client_name)
    return _json([r.model_dump() if hasattr(r, "model_dump") else r for r in rules])


def _mitre_tactics() -> str:
    from mssp_hunt_agent.pipeline.planner import _TACTIC_KEYWORDS
    return json.dumps(_TACTIC_KEYWORDS, indent=2)


def _landscape_alerts() -> str:
    return json.dumps({
        "info": "Use correlate_landscape tool with client_sources to generate alerts",
        "supported_feeds": ["CISA KEV"],
    }, indent=2)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

RESOURCE_REGISTRY: dict[str, dict[str, Any]] = {
    "clients://": {
        "name": "All Clients",
        "description": "List all MSSP clients with summary data.",
        "handler": lambda: _clients_list(),
    },
    "clients://{name}": {
        "name": "Client Detail",
        "description": "Detailed client info including hunt stats and telemetry.",
        "handler": lambda name: _client_detail(name),
    },
    "hunts://": {
        "name": "Recent Hunts",
        "description": "List the 50 most recent hunt runs across all clients.",
        "handler": lambda: _hunts_list(),
    },
    "hunts://{run_id}": {
        "name": "Hunt Detail",
        "description": "Full details and findings for a specific hunt run.",
        "handler": lambda run_id: _hunt_detail(run_id),
    },
    "intel://feeds": {
        "name": "Intel Feeds",
        "description": "Threat intelligence feed status and supported formats.",
        "handler": lambda: _intel_feeds(),
    },
    "tuning://{client_name}": {
        "name": "Tuning Rules",
        "description": "Per-client tuning rules (exclusions, benign patterns).",
        "handler": lambda client_name: _tuning_rules(client_name),
    },
    "mitre://tactics": {
        "name": "MITRE ATT&CK Tactics",
        "description": "ATT&CK tactic keyword map for hunt planning.",
        "handler": lambda: _mitre_tactics(),
    },
    "landscape://alerts": {
        "name": "Threat Landscape Alerts",
        "description": "Active threat landscape correlation alerts.",
        "handler": lambda: _landscape_alerts(),
    },
}


def read_resource(uri: str) -> str:
    """Read a resource by URI. Supports parameterized URIs."""
    # Exact match first
    if uri in RESOURCE_REGISTRY:
        handler = RESOURCE_REGISTRY[uri]["handler"]
        return handler()

    # Parameterized match
    for pattern, meta in RESOURCE_REGISTRY.items():
        if "{" not in pattern:
            continue

        # Simple single-param matching
        prefix = pattern.split("{")[0]
        if uri.startswith(prefix):
            param_value = uri[len(prefix):].rstrip("/")
            if param_value:
                return meta["handler"](param_value)

    return json.dumps({"error": f"Unknown resource: {uri}"})
