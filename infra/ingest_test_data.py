#!/usr/bin/env python3
"""Ingest curated attack datasets into Microsoft Sentinel for agent testing.

This script:
1. Downloads attack datasets from GitHub repos (Mordor/OTRF, Sentinel samples)
2. Spreads timestamps across the last 30 days (so ago(7d/14d/30d) queries all work)
3. Ingests into a single AttackSimulation_CL custom table via DCR Log Ingestion API
4. The agent discovers this table via check_telemetry and queries it naturally

Prerequisites:
  - Azure CLI logged in (`az login`)
  - pip install azure-identity azure-monitor-ingestion requests

Usage:
  python infra/ingest_test_data.py --setup    # First time: create DCE, table, DCR
  python infra/ingest_test_data.py --ingest   # Download, transform, ingest data
  python infra/ingest_test_data.py --verify   # Verify data landed in Sentinel
  python infra/ingest_test_data.py --all      # Do everything

Re-run monthly when data ages out of query windows.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────

WORKSPACE_NAME = os.getenv("WORKSPACE_NAME", "adv01-eastus-logspace-1")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP", "adv01-eastus-vnet-1-rg")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID", "bb4b211f-c55c-4fae-b154-10ab473609c1")
LOCATION = os.getenv("LOCATION", "eastus")
DCE_NAME = "mssp-hunt-agent-dce"
DCR_PREFIX = "mssp-hunt-agent"

WORKSPACE_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
)

# How many days back to spread the data across
SPREAD_DAYS = 30

# ── Dataset definitions ──────────────────────────────────────────────

DATASETS = {
    # ── Credential Access ────────────────────────────────────────
    "mordor_credential_dcsync": {
        "name": "Mordor - DCSync via DRS",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "format": "zip_json",
        "tactic": "Credential Access",
        "technique": "T1003.006",
    },
    "mordor_credential_mimikatz": {
        "name": "Mordor - Mimikatz LogonPasswords",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip",
        "format": "zip_json",
        "tactic": "Credential Access",
        "technique": "T1003.001",
    },
    "mordor_credential_sam": {
        "name": "Mordor - Mimikatz SAM Access",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access.zip",
        "format": "zip_json",
        "tactic": "Credential Access",
        "technique": "T1003.002",
    },
    # ── Lateral Movement ─────────────────────────────────────────
    "mordor_lateral_wmi": {
        "name": "Mordor - WMI Lateral Movement",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/lateral_movement/host/covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers.zip",
        "format": "zip_json",
        "tactic": "Lateral Movement",
        "technique": "T1047",
    },
    "mordor_lateral_psremoting": {
        "name": "Mordor - PSRemoting Lateral Movement",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/lateral_movement/host/covenant_psremoting_grunt.zip",
        "format": "zip_json",
        "tactic": "Lateral Movement",
        "technique": "T1021.006",
    },
    "mordor_lateral_wmic": {
        "name": "Mordor - WMIC Backdoor User",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor.zip",
        "format": "zip_json",
        "tactic": "Lateral Movement",
        "technique": "T1047",
    },
    # ── Execution ────────────────────────────────────────────────
    "mordor_execution_vbs": {
        "name": "Mordor - VBS Launcher Execution",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/execution/host/empire_launcher_vbs.zip",
        "format": "zip_json",
        "tactic": "Execution",
        "technique": "T1059.005",
    },
    "mordor_execution_psh": {
        "name": "Mordor - PowerShell HTTP Listener",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/execution/host/psh_powershell_httplistener.zip",
        "format": "zip_json",
        "tactic": "Execution",
        "technique": "T1059.001",
    },
    # ── Persistence ──────────────────────────────────────────────
    "mordor_persistence_schtasks": {
        "name": "Mordor - Scheduled Task Persistence",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip",
        "format": "zip_json",
        "tactic": "Persistence",
        "technique": "T1053.005",
    },
    # ── Privilege Escalation ─────────────────────────────────────
    "mordor_privesc_uac": {
        "name": "Mordor - UAC Bypass FodHelper",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper.zip",
        "format": "zip_json",
        "tactic": "Privilege Escalation",
        "technique": "T1548.002",
    },
    "mordor_privesc_service": {
        "name": "Mordor - Service Modification",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/privilege_escalation/host/cmd_service_mod_fax.zip",
        "format": "zip_json",
        "tactic": "Privilege Escalation",
        "technique": "T1543.003",
    },
    # ── Defense Evasion ──────────────────────────────────────────
    "mordor_defense_evasion_installutil": {
        "name": "Mordor - InstallUtil Defense Evasion",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/defense_evasion/host/covenant_installutil.zip",
        "format": "zip_json",
        "tactic": "Defense Evasion",
        "technique": "T1218.004",
    },
    "mordor_defense_evasion_eventlog": {
        "name": "Mordor - Disable Event Log Service",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/defense_evasion/host/cmd_disable_eventlog_service_startuptype_modification_via_registry.zip",
        "format": "zip_json",
        "tactic": "Defense Evasion",
        "technique": "T1562.002",
    },
    "mordor_defense_evasion_lolbin": {
        "name": "Mordor - LOLBin wuauclt",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread.zip",
        "format": "zip_json",
        "tactic": "Defense Evasion",
        "technique": "T1218",
    },
    # ── Compound / Large Datasets (full attack chains) ────────────
    "mordor_apt3_day1": {
        "name": "Mordor - APT3 Simulation Day 1",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/compound/windows/apt3/apt3_host_2019-05-14201904.zip",
        "format": "zip_json",
        "tactic": "Multi-Stage",
        "technique": "APT3",
    },
    "mordor_apt3_day2": {
        "name": "Mordor - APT3 Simulation Day 2",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/compound/windows/apt3/apt3_host_2019-05-14223117.zip",
        "format": "zip_json",
        "tactic": "Multi-Stage",
        "technique": "APT3",
    },
    # ── Additional Credential Access ──────────────────────────────
    "mordor_credential_kerberoast": {
        "name": "Mordor - Kerberoasting",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/credential_access/host/empire_rubeus_asktgs_createnetonly.zip",
        "format": "zip_json",
        "tactic": "Credential Access",
        "technique": "T1558.003",
    },
    "mordor_credential_lsass_access": {
        "name": "Mordor - LSASS Process Access",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam.zip",
        "format": "zip_json",
        "tactic": "Credential Access",
        "technique": "T1003.002",
    },
    # ── Additional Lateral Movement ───────────────────────────────
    "mordor_lateral_dcom": {
        "name": "Mordor - DCOM Lateral Movement",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/lateral_movement/host/covenant_dcom_mmc20_application_executeShellCommand.zip",
        "format": "zip_json",
        "tactic": "Lateral Movement",
        "technique": "T1021.003",
    },
    "mordor_lateral_remote_service": {
        "name": "Mordor - Remote Service Creation",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip",
        "format": "zip_json",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
    },
    # ── Additional Execution ──────────────────────────────────────
    "mordor_execution_regsvr32": {
        "name": "Mordor - Regsvr32 Execution",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/execution/host/covenant_regsvr32.zip",
        "format": "zip_json",
        "tactic": "Execution",
        "technique": "T1218.010",
    },
    "mordor_execution_mshta": {
        "name": "Mordor - MSHTA Execution",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/execution/host/covenant_mshta.zip",
        "format": "zip_json",
        "tactic": "Execution",
        "technique": "T1218.005",
    },
    # ── Additional Persistence ────────────────────────────────────
    "mordor_persistence_registry": {
        "name": "Mordor - Registry Run Key Persistence",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip",
        "format": "zip_json",
        "tactic": "Persistence",
        "technique": "T1547.001",
    },
    "mordor_persistence_wmi": {
        "name": "Mordor - WMI Event Subscription Persistence",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip",
        "format": "zip_json",
        "tactic": "Persistence",
        "technique": "T1546.003",
    },
    # ── Discovery ─────────────────────────────────────────────────
    "mordor_discovery_network": {
        "name": "Mordor - Network Share Discovery",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/discovery/host/empire_find_localadmin_access.zip",
        "format": "zip_json",
        "tactic": "Discovery",
        "technique": "T1135",
    },
    "mordor_discovery_ad_recon": {
        "name": "Mordor - AD Recon via PowerView",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/discovery/host/empire_powerview_ldap_nslookup.zip",
        "format": "zip_json",
        "tactic": "Discovery",
        "technique": "T1018",
    },
    # ── Collection ────────────────────────────────────────────────
    "mordor_collection_clipboard": {
        "name": "Mordor - Clipboard Data Collection",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/collection/host/empire_clipboard_monitor.zip",
        "format": "zip_json",
        "tactic": "Collection",
        "technique": "T1115",
    },
    # ── Command and Control ───────────────────────────────────────
    "mordor_c2_http": {
        "name": "Mordor - HTTP C2 Channel",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "path": "datasets/atomic/windows/command_and_control/host/covenant_http_grunt.zip",
        "format": "zip_json",
        "tactic": "Command and Control",
        "technique": "T1071.001",
    },
}

# ── Custom table schema ──────────────────────────────────────────────

TABLE_COLUMNS = [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "SourceSystem", "type": "string"},
    {"name": "Computer", "type": "string"},
    {"name": "EventID", "type": "int"},
    {"name": "Channel", "type": "string"},
    {"name": "Provider", "type": "string"},
    {"name": "EventData", "type": "string"},
    {"name": "MitreTactic", "type": "string"},
    {"name": "MitreTechnique", "type": "string"},
    {"name": "AttackScenario", "type": "string"},
    {"name": "Severity", "type": "string"},
    {"name": "ProcessName", "type": "string"},
    {"name": "ProcessId", "type": "int"},
    {"name": "ParentProcessName", "type": "string"},
    {"name": "CommandLine", "type": "string"},
    {"name": "User", "type": "string"},
    {"name": "SourceIP", "type": "string"},
    {"name": "DestinationIP", "type": "string"},
    {"name": "DestinationPort", "type": "int"},
    {"name": "LogonType", "type": "int"},
    {"name": "RawEvent", "type": "string"},
]


# ── Azure CLI helpers ────────────────────────────────────────────────

def az(cmd: str, parse_json: bool = True, no_subscription: bool = False) -> Any:
    """Run an az CLI command and return parsed output."""
    if no_subscription:
        full_cmd = f"az {cmd} -o json"
    else:
        full_cmd = f"az {cmd} --subscription {SUBSCRIPTION_ID} -o json"
    logger.debug("Running: %s", full_cmd)
    result = subprocess.run(
        full_cmd, shell=True, capture_output=True, text=True, timeout=120,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )
    if result.returncode != 0:
        logger.error("az failed: %s\nstderr: %s", cmd, result.stderr.strip())
        raise RuntimeError(result.stderr.strip())
    if parse_json and result.stdout.strip():
        return json.loads(result.stdout)
    return result.stdout


# ── Step 1: Setup ────────────────────────────────────────────────────

def setup_dce() -> str:
    """Create or get the Data Collection Endpoint. Returns resource ID."""
    logger.info("Setting up DCE: %s", DCE_NAME)
    try:
        dce = az(
            f'monitor data-collection endpoint show '
            f'--name {DCE_NAME} --resource-group {RESOURCE_GROUP}'
        )
        logger.info("  DCE already exists")
        return dce["id"]
    except RuntimeError:
        pass

    dce = az(
        f'monitor data-collection endpoint create '
        f'--name {DCE_NAME} --resource-group {RESOURCE_GROUP} '
        f'--location {LOCATION} --public-network-access Enabled'
    )
    logger.info("  Created DCE: %s", dce["name"])
    return dce["id"]


def setup_custom_table() -> None:
    """Create AttackSimulation_CL if it doesn't exist."""
    table_name = "AttackSimulation_CL"
    logger.info("Setting up table: %s", table_name)
    try:
        az(
            f'monitor log-analytics workspace table show '
            f'--workspace-name {WORKSPACE_NAME} --resource-group {RESOURCE_GROUP} '
            f'--name {table_name}'
        )
        logger.info("  Table already exists")
        return
    except RuntimeError:
        pass

    # Build --columns arg: "col1=type1 col2=type2 ..."
    cols_str = " ".join(f'{c["name"]}={c["type"]}' for c in TABLE_COLUMNS)
    az(
        f'monitor log-analytics workspace table create '
        f'--workspace-name {WORKSPACE_NAME} --resource-group {RESOURCE_GROUP} '
        f'--name {table_name} --retention-time 90 --total-retention-time 90 '
        f'--columns {cols_str}'
    )
    logger.info("  Created table: %s", table_name)


def setup_dcr(dce_id: str) -> tuple[str, str]:
    """Create DCR via REST API. Returns (immutable_id, resource_id)."""
    dcr_name = f"{DCR_PREFIX}-attack-sim"
    logger.info("Setting up DCR: %s", dcr_name)

    try:
        dcr = az(
            f'monitor data-collection rule show '
            f'--name {dcr_name} --resource-group {RESOURCE_GROUP}'
        )
        logger.info("  DCR already exists")
        return dcr["immutableId"], dcr["id"]
    except RuntimeError:
        pass

    # Create via REST (az CLI doesn't support custom stream declarations)
    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Insights/dataCollectionRules/{dcr_name}"
        f"?api-version=2022-06-01"
    )

    body = {
        "location": LOCATION,
        "properties": {
            "dataCollectionEndpointId": dce_id,
            "streamDeclarations": {
                "Custom-AttackSimulation_CL": {
                    "columns": TABLE_COLUMNS,
                }
            },
            "dataFlows": [
                {
                    "streams": ["Custom-AttackSimulation_CL"],
                    "destinations": ["workspace"],
                    "transformKql": "source",
                    "outputStream": "Custom-AttackSimulation_CL",
                }
            ],
            "destinations": {
                "logAnalytics": [
                    {
                        "workspaceResourceId": WORKSPACE_RESOURCE_ID,
                        "name": "workspace",
                    }
                ]
            },
        },
    }

    body_file = Path(tempfile.gettempdir()) / "dcr_body.json"
    body_file.write_text(json.dumps(body))

    result = subprocess.run(
        f'az rest --method PUT --url "{url}" --body @{body_file} '
        f'--headers "Content-Type=application/json" -o json',
        shell=True, capture_output=True, text=True, timeout=120,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )
    if result.returncode != 0:
        raise RuntimeError(f"DCR creation failed: {result.stderr}")

    dcr = json.loads(result.stdout)
    immutable_id = dcr["properties"]["immutableId"]
    resource_id = dcr["id"]
    logger.info("  Created DCR: %s (immutableId: %s)", dcr_name, immutable_id)
    return immutable_id, resource_id


def setup_role_assignment(dcr_resource_id: str) -> None:
    """Grant current user Monitoring Metrics Publisher on the DCR."""
    logger.info("Setting up role assignment...")
    try:
        user = az("ad signed-in-user show", no_subscription=True)
        user_oid = user["id"]
        az(
            f'role assignment create --assignee {user_oid} '
            f'--role "Monitoring Metrics Publisher" '
            f'--scope "{dcr_resource_id}"'
        )
        logger.info("  Granted Monitoring Metrics Publisher to %s", user_oid)
    except RuntimeError as e:
        if "already exists" in str(e).lower() or "conflict" in str(e).lower():
            logger.info("  Role assignment already exists")
        else:
            logger.warning("  Role assignment failed: %s", e)


def run_setup() -> dict[str, str]:
    """Run all setup steps. Returns ingestion config."""
    dce_id = setup_dce()
    setup_custom_table()
    dcr_immutable_id, dcr_resource_id = setup_dcr(dce_id)
    setup_role_assignment(dcr_resource_id)

    # Get DCE logs ingestion endpoint
    dce = az(
        f'monitor data-collection endpoint show '
        f'--name {DCE_NAME} --resource-group {RESOURCE_GROUP}'
    )
    dce_endpoint = dce["logsIngestion"]["endpoint"]

    config = {
        "dce_endpoint": dce_endpoint,
        "dcr_immutable_id": dcr_immutable_id,
        "stream_name": "Custom-AttackSimulation_CL",
    }

    config_path = Path(__file__).parent / "ingestion_config.json"
    config_path.write_text(json.dumps(config, indent=2))
    logger.info("Saved config to %s", config_path)
    return config


# ── Step 2: Download & Transform ─────────────────────────────────────

def download_file(repo: str, branch: str, path: str, dest_dir: Path) -> Path:
    """Download a file from GitHub raw."""
    import requests

    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    logger.info("  Downloading %s", Path(path).name)
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()

    dest = dest_dir / Path(path).name
    dest.write_bytes(resp.content)
    return dest


def extract_mordor_zip(zip_path: Path) -> list[dict]:
    """Extract JSON-lines events from a Mordor zip."""
    events = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if name.endswith(".json"):
                with zf.open(name) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
    return events


def spread_timestamps(events: list[dict]) -> list[dict]:
    """Spread events across the last SPREAD_DAYS days.

    Preserves relative ordering within the dataset but maps the full
    time range of the original data onto [now - SPREAD_DAYS, now].
    Events that were close together stay close together.
    """
    if not events:
        return events

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=SPREAD_DAYS)

    # Parse original timestamps
    parsed: list[tuple[int, datetime | None]] = []
    for i, e in enumerate(events):
        ts_str = (
            e.get("@timestamp") or e.get("TimeGenerated") or
            e.get("timestamp") or e.get("EventTime")
        )
        ts = None
        if ts_str:
            try:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        parsed.append((i, ts))

    # Separate events with and without timestamps
    with_ts = [(i, ts) for i, ts in parsed if ts is not None]
    without_ts = [i for i, ts in parsed if ts is None]

    if with_ts:
        # Sort by original timestamp
        with_ts.sort(key=lambda x: x[1])  # type: ignore[arg-type]
        orig_min = with_ts[0][1]
        orig_max = with_ts[-1][1]
        orig_span = (orig_max - orig_min).total_seconds()  # type: ignore[operator]

        for idx, orig_ts in with_ts:
            if orig_span > 0:
                # Map proportionally into [start, now]
                frac = (orig_ts - orig_min).total_seconds() / orig_span  # type: ignore[operator]
                new_ts = start + timedelta(seconds=frac * SPREAD_DAYS * 86400)
            else:
                # All same timestamp — spread randomly
                new_ts = start + timedelta(seconds=random.random() * SPREAD_DAYS * 86400)
            events[idx]["TimeGenerated"] = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Events without timestamps: random spread
    for idx in without_ts:
        new_ts = start + timedelta(seconds=random.random() * SPREAD_DAYS * 86400)
        events[idx]["TimeGenerated"] = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return events


def normalize_event(event: dict, dataset: dict) -> dict:
    """Normalize a raw event into the AttackSimulation_CL schema."""
    raw = json.dumps(event, default=str)

    # Extract fields — Mordor uses various naming conventions
    def _str(val: Any, max_len: int = 200) -> str:
        if val is None:
            return ""
        if isinstance(val, dict):
            return str(val.get("name", ""))[:max_len]
        return str(val)[:max_len]

    def _int(val: Any) -> int:
        if val is None:
            return 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    return {
        "TimeGenerated": event.get("TimeGenerated", datetime.now(timezone.utc).isoformat()),
        "SourceSystem": dataset["name"],
        "Computer": _str(event.get("Computer") or event.get("Hostname") or event.get("host")),
        "EventID": _int(event.get("EventID") or event.get("event_id")),
        "Channel": _str(event.get("Channel") or event.get("log_name"), 100),
        "Provider": _str(event.get("Provider") or event.get("source_name"), 100),
        "EventData": raw[:10000],
        "MitreTactic": dataset.get("tactic", ""),
        "MitreTechnique": dataset.get("technique", ""),
        "AttackScenario": dataset["name"],
        "Severity": "Medium",
        "ProcessName": _str(event.get("ProcessName") or event.get("Image") or event.get("NewProcessName")),
        "ProcessId": _int(event.get("ProcessId") or event.get("NewProcessId")),
        "ParentProcessName": _str(event.get("ParentProcessName") or event.get("ParentImage")),
        "CommandLine": _str(event.get("CommandLine") or event.get("ParentCommandLine"), 2000),
        "User": _str(
            event.get("User") or event.get("SubjectUserName") or
            event.get("TargetUserName") or event.get("user")
        ),
        "SourceIP": _str(event.get("SourceIP") or event.get("IpAddress") or event.get("SourceAddress"), 50),
        "DestinationIP": _str(event.get("DestinationIP") or event.get("DestinationAddress"), 50),
        "DestinationPort": _int(event.get("DestinationPort")),
        "LogonType": _int(event.get("LogonType")),
        "RawEvent": raw[:30000],
    }


def download_and_transform(tmp_dir: Path) -> list[dict]:
    """Download all datasets, spread timestamps, normalize."""
    all_events: list[dict] = []

    for ds_key, ds in DATASETS.items():
        logger.info("Processing: %s", ds["name"])
        try:
            file_path = download_file(ds["repo"], ds["branch"], ds["path"], tmp_dir)

            if ds["format"] == "zip_json":
                raw_events = extract_mordor_zip(file_path)
            elif ds["format"] == "json":
                text = file_path.read_text(encoding="utf-8", errors="replace").strip()
                if text.startswith("["):
                    raw_events = json.loads(text)
                else:
                    raw_events = [json.loads(l) for l in text.split("\n") if l.strip()]
            else:
                continue

            # Spread timestamps across last 30 days
            raw_events = spread_timestamps(raw_events)

            # Normalize into table schema
            normalized = [normalize_event(e, ds) for e in raw_events]
            all_events.extend(normalized)

            logger.info("  %d events from %s", len(normalized), ds_key)

        except Exception as exc:
            logger.warning("  Failed: %s — %s", ds_key, exc)
            continue

    logger.info("Total events: %d", len(all_events))

    # Show breakdown by tactic
    tactic_counts: dict[str, int] = {}
    for e in all_events:
        t = e.get("MitreTactic", "Unknown")
        tactic_counts[t] = tactic_counts.get(t, 0) + 1
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        logger.info("  %s: %d events", tactic, count)

    return all_events


# ── Step 3: Ingest (Legacy Data Collector API) ──────────────────────

# Workspace ID and shared key for the legacy API (no role assignment needed)
WORKSPACE_ID = os.getenv("WORKSPACE_ID", "69e807f3-872b-4348-926f-16df15c02f9b")
WORKSPACE_KEY = os.getenv(
    "WORKSPACE_KEY",
    "zjtD/bg6XGoB5g9lLusIT2eWIb4o9uSvKqYMHyRM+349EwQCKOcIs9J3N7jzE7Ix2hNh0Cc6aFXxs5UAf/Mqaw==",
)
LOG_TYPE = "AttackSimulation"  # API auto-appends _CL


def _build_signature(workspace_id: str, key: str, date: str, content_length: int) -> str:
    """Build the HMAC-SHA256 authorization header for the Data Collector API."""
    import base64
    import hashlib
    import hmac

    string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def ingest_events(events: list[dict], config: dict | None = None) -> None:
    """Ingest events via the legacy Log Analytics Data Collector API.

    Uses workspace shared key — no Monitoring Metrics Publisher role needed.
    API reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api

    Key constraints:
    - Max 30 MB per POST (we keep batches under 1 MB to avoid silent drops)
    - Max 500 records per POST
    - API returns 200 even when throttling — must pace requests
    - 1 second delay between batches to avoid throttle-induced silent drops
    """
    import time

    import requests
    from email.utils import formatdate

    url = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    # Smaller batches + delay = reliable delivery
    batch_size = 200
    delay_seconds = 1.0
    total = len(events)
    ingested = 0
    failed = 0

    total_batches = (total + batch_size - 1) // batch_size
    logger.info("Ingesting %d events in %d batches (size=%d, delay=%.1fs)", total, total_batches, batch_size, delay_seconds)

    for i in range(0, total, batch_size):
        batch = events[i : i + batch_size]
        body = json.dumps(batch, default=str)
        content_length = len(body)

        # Warn if batch is unusually large
        if content_length > 5 * 1024 * 1024:
            logger.warning("  Batch %d is %.1f MB — may be silently dropped", i // batch_size + 1, content_length / 1024 / 1024)

        rfc1123_date = formatdate(timeval=None, localtime=False, usegmt=True)
        signature = _build_signature(WORKSPACE_ID, WORKSPACE_KEY, rfc1123_date, content_length)

        headers = {
            "Content-Type": "application/json",
            "Authorization": signature,
            "Log-Type": LOG_TYPE,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }

        try:
            resp = requests.post(url, data=body, headers=headers, timeout=60)
            if resp.status_code in (200, 202):
                ingested += len(batch)
                batch_num = i // batch_size + 1
                if batch_num % 50 == 0 or batch_num == total_batches:
                    pct = ingested / total * 100
                    logger.info(
                        "  Batch %d/%d — %d ingested (%.0f%%)",
                        batch_num, total_batches, ingested, pct,
                    )
            else:
                failed += len(batch)
                logger.error(
                    "  Batch %d failed: HTTP %d — %s",
                    i // batch_size + 1, resp.status_code, resp.text[:200],
                )
        except Exception as exc:
            failed += len(batch)
            logger.error("  Batch %d failed: %s", i // batch_size + 1, exc)

        # Pace requests to avoid silent throttling
        time.sleep(delay_seconds)

    logger.info("Ingested %d / %d events (%d failed)", ingested, total, failed)


# ── Step 4: Verify ───────────────────────────────────────────────────

def verify_ingestion() -> None:
    """Query AttackSimulation_CL to verify data landed."""
    logger.info("Verifying (data may take 5-10 min to appear)...")

    query = (
        "AttackSimulation_CL "
        "| summarize Count=count() by MitreTactic "
        "| order by Count desc"
    )

    try:
        result = az(
            f'monitor log-analytics query '
            f'--workspace "{WORKSPACE_RESOURCE_ID}" '
            f'--analytics-query "{query}"'
        )

        if result and result.get("tables"):
            rows = result["tables"][0].get("rows", [])
            if rows:
                logger.info("Data in AttackSimulation_CL:")
                for row in rows:
                    logger.info("  %s: %s events", row[0] or "Unknown", row[1])
                return
    except RuntimeError:
        pass

    logger.warning(
        "No data yet. Wait 5-10 min and re-run: python infra/ingest_test_data.py --verify"
    )


# ── Main ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest attack datasets into Sentinel AttackSimulation_CL"
    )
    parser.add_argument("--setup", action="store_true", help="Create DCE, table, DCR")
    parser.add_argument("--ingest", action="store_true", help="Download + transform + ingest")
    parser.add_argument("--verify", action="store_true", help="Verify data in Sentinel")
    parser.add_argument("--all", action="store_true", help="Setup + ingest + verify")
    args = parser.parse_args()

    if not any([args.setup, args.ingest, args.verify, args.all]):
        parser.print_help()
        sys.exit(0)

    config = None

    if args.all or args.setup:
        logger.info("=" * 60)
        logger.info("STEP 1: Setting up Azure resources (DCE + table + DCR)")
        logger.info("=" * 60)
        config = run_setup()

    if args.all or args.ingest:
        if config is None:
            config_path = Path(__file__).parent / "ingestion_config.json"
            if config_path.exists():
                config = json.loads(config_path.read_text())
            else:
                logger.error("No config. Run --setup first.")
                sys.exit(1)

        logger.info("=" * 60)
        logger.info("STEP 2: Downloading + transforming datasets")
        logger.info("=" * 60)
        with tempfile.TemporaryDirectory() as tmp:
            events = download_and_transform(Path(tmp))
            if events:
                logger.info("=" * 60)
                logger.info("STEP 3: Ingesting %d events", len(events))
                logger.info("=" * 60)
                ingest_events(events, config)
            else:
                logger.error("No events to ingest!")

    if args.all or args.verify:
        logger.info("=" * 60)
        logger.info("STEP 4: Verifying ingestion")
        logger.info("=" * 60)
        verify_ingestion()

    logger.info("Done!")


if __name__ == "__main__":
    main()
