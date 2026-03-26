"""FastAPI application — REST API surface for the MSSP Hunt Agent.

Start with::

    uvicorn mssp_hunt_agent.api.app:app --reload
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException

from mssp_hunt_agent.api import background as bg
from mssp_hunt_agent.api.chat import router as chat_router
from mssp_hunt_agent.api.dependencies import get_config, get_database
from mssp_hunt_agent.api.schemas import (
    ApproveRequest,
    ClientListResponse,
    HealthResponse,
    HuntRequest,
    IOCItem,
    IOCSweepRequest,
    ProfileRequest,
    RunListResponse,
    RunStatusResponse,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="MSSP Hunt Agent API",
    version="0.5.0",
    description="REST API for the MSSP threat-hunting agent pipeline",
)

# Register chat endpoints
app.include_router(chat_router)


# ── Health ───────────────────────────────────────────────────────────


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    config = get_config()
    return HealthResponse(
        status="ok",
        version="0.4.0",
        adapter_mode=config.adapter_mode,
        persist_enabled=config.persist,
        sharepoint_enabled=config.sharepoint_enabled,
    )


# ── Hypothesis hunts ─────────────────────────────────────────────────


@app.post("/api/v1/hunts", response_model=RunStatusResponse, status_code=202)
def start_hunt(req: HuntRequest) -> RunStatusResponse:
    """Start a hypothesis-driven hunt (async — returns 202)."""
    from mssp_hunt_agent.models.input_models import HuntInput, HuntType, Priority

    config = get_config()
    config.approval_required = False  # API auto-approves
    if req.allow_pivots:
        config.allow_pivots = True
    if req.persist:
        config.persist = True

    hunt_input = HuntInput(
        client_name=req.client_name,
        hunt_objective=req.hunt_objective,
        hunt_hypothesis=req.hunt_hypothesis,
        time_range=req.time_range,
        available_data_sources=req.available_data_sources,
        telemetry_gaps=req.telemetry_gaps,
        hunt_type=HuntType(req.hunt_type) if req.hunt_type in [e.value for e in HuntType] else HuntType.IDENTITY,
        industry=req.industry,
        priority=Priority(req.priority) if req.priority in [e.value for e in Priority] else Priority.MEDIUM,
        attack_techniques=req.attack_techniques,
        known_benign_patterns=req.known_benign_patterns,
        exclusions=req.exclusions,
        analyst_notes=req.analyst_notes,
    )

    run_id = bg.generate_run_id("RUN")
    status = bg.launch_hunt(run_id, hunt_input, config, plan_only=req.plan_only)
    return status


# ── IOC sweeps ───────────────────────────────────────────────────────


@app.post("/api/v1/ioc-sweeps", response_model=RunStatusResponse, status_code=202)
def start_ioc_sweep(req: IOCSweepRequest) -> RunStatusResponse:
    """Start an IOC sweep (async — returns 202)."""
    from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType

    config = get_config()
    config.approval_required = False
    if req.persist:
        config.persist = True

    ioc_entries = []
    for item in req.iocs:
        ioc_entries.append(IOCEntry(
            value=item.value,
            ioc_type=IOCType(item.ioc_type) if item.ioc_type in [e.value for e in IOCType] else IOCType.IP,
            context=item.context,
        ))

    ioc_input = IOCHuntInput(
        client_name=req.client_name,
        iocs=ioc_entries,
        time_range=req.time_range,
        available_data_sources=req.available_data_sources,
        telemetry_gaps=req.telemetry_gaps,
        sweep_objective=req.sweep_objective,
        pre_enrich=req.pre_enrich,
        analyst_notes=req.analyst_notes,
    )

    run_id = bg.generate_run_id("RUN-IOC")
    status = bg.launch_ioc_sweep(run_id, ioc_input, config, plan_only=req.plan_only)
    return status


# ── Profiles ─────────────────────────────────────────────────────────


@app.post("/api/v1/profiles", response_model=RunStatusResponse, status_code=202)
def start_profile(req: ProfileRequest) -> RunStatusResponse:
    """Start a telemetry profiling run (async — returns 202)."""
    from mssp_hunt_agent.models.input_models import HuntType
    from mssp_hunt_agent.models.profile_models import ProfileInput

    config = get_config()
    config.approval_required = False
    if req.persist:
        config.persist = True

    hunt_types = []
    for ht in req.hunt_types_of_interest:
        if ht in [e.value for e in HuntType]:
            hunt_types.append(HuntType(ht))
    if not hunt_types:
        hunt_types = list(HuntType)

    profile_input = ProfileInput(
        client_name=req.client_name,
        time_range=req.time_range,
        declared_data_sources=req.declared_data_sources,
        hunt_types_of_interest=hunt_types,
        analyst_notes=req.analyst_notes,
    )

    run_id = bg.generate_run_id("RUN-PROF")
    status = bg.launch_profile(run_id, profile_input, config, plan_only=req.plan_only)
    return status


# ── Status / polling ─────────────────────────────────────────────────


@app.get("/api/v1/hunts/{run_id}", response_model=RunStatusResponse)
def get_hunt_status(run_id: str) -> RunStatusResponse:
    """Check the status of any pipeline run."""
    status = bg.get_run_status(run_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return status


# ── Persistence queries ──────────────────────────────────────────────


@app.get("/api/v1/clients", response_model=ClientListResponse)
def list_clients() -> ClientListResponse:
    """List all managed clients from the database."""
    try:
        db = get_database()
        clients = db.list_clients()
        db.close()
        return ClientListResponse(
            clients=[c.model_dump() for c in clients]
        )
    except Exception as exc:
        logger.warning("Failed to list clients: %s", exc)
        return ClientListResponse(clients=[])


@app.get("/api/v1/runs", response_model=RunListResponse)
def list_runs(
    client: str | None = None,
    hunt_type: str | None = None,
    limit: int = 50,
) -> RunListResponse:
    """List past runs from the database."""
    try:
        db = get_database()
        runs = db.get_runs(client_name=client, hunt_type=hunt_type, limit=limit)
        db.close()
        return RunListResponse(
            runs=[r.model_dump() for r in runs]
        )
    except Exception as exc:
        logger.warning("Failed to list runs: %s", exc)
        return RunListResponse(runs=[])


# ── Flow-compatible routes (Power Automate) ─────────────────────────


@app.get("/api/health")
def flow_health() -> dict:
    return {"status": "ok", "version": "0.4.0", "adapter_mode": get_config().adapter_mode}


@app.post("/api/hunt")
def flow_hunt(body: dict) -> dict:
    """Simplified hunt endpoint for Power Automate flows."""
    from mssp_hunt_agent.models.input_models import HuntInput

    config = get_config()
    config.approval_required = False
    _dc = config.default_client_name or "Unknown"

    hunt_input = HuntInput(
        client_name=body.get("client_name", _dc),
        hunt_objective=body.get("hypothesis", "Threat hunt"),
        hunt_hypothesis=body.get("hypothesis", ""),
        time_range=body.get("time_range", "last 7 days"),
        available_data_sources=["SecurityEvent", "SigninLogs", "DeviceProcessEvents"],
        analyst_notes=body.get("iocs", "Not provided"),
    )

    run_id = bg.generate_run_id("RUN")
    status = bg.launch_hunt(run_id, hunt_input, config)
    return {"run_id": status.run_id, "status": status.status, "message": f"Hunt started for {hunt_input.client_name}"}


@app.post("/api/ioc_sweep")
def flow_ioc_sweep(body: dict) -> dict:
    """Simplified IOC sweep endpoint for Power Automate flows."""
    from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType

    config = get_config()
    config.approval_required = False
    _dc = config.default_client_name or "Unknown"

    raw_iocs = body.get("iocs", "")
    ioc_values = [v.strip() for v in raw_iocs.split(",") if v.strip()]

    ioc_entries = []
    for val in ioc_values:
        ioc_type = IOCType.IP
        if "." not in val and len(val) >= 32:
            ioc_type = IOCType.HASH_SHA256 if len(val) == 64 else IOCType.HASH_MD5
        elif "/" in val or "http" in val.lower():
            ioc_type = IOCType.URL
        elif "@" in val:
            ioc_type = IOCType.EMAIL
        elif not any(c.isdigit() for c in val.split(".")[0] if val.count(".") >= 1):
            ioc_type = IOCType.DOMAIN
        ioc_entries.append(IOCEntry(value=val, ioc_type=ioc_type))

    if not ioc_entries:
        return {"run_id": "", "status": "error", "message": "No IOCs provided"}

    ioc_input = IOCHuntInput(
        client_name=body.get("client_name", _dc),
        iocs=ioc_entries,
        time_range="last 30 days",
        available_data_sources=["SecurityEvent", "SigninLogs", "DeviceProcessEvents"],
    )

    run_id = bg.generate_run_id("RUN-IOC")
    status = bg.launch_ioc_sweep(run_id, ioc_input, config)
    return {"run_id": status.run_id, "status": status.status, "message": f"IOC sweep started for {ioc_input.client_name}"}


@app.post("/api/profile")
def flow_profile(body: dict) -> dict:
    """Simplified profile endpoint for Power Automate flows."""
    from mssp_hunt_agent.models.input_models import HuntType
    from mssp_hunt_agent.models.profile_models import ProfileInput

    config = get_config()
    config.approval_required = False
    _dc = config.default_client_name or "Unknown"

    profile_input = ProfileInput(
        client_name=body.get("client_name", _dc),
        time_range="last 30 days",
        hunt_types_of_interest=list(HuntType),
    )

    run_id = bg.generate_run_id("RUN-PROF")
    status = bg.launch_profile(run_id, profile_input, config)
    return {"run_id": status.run_id, "status": status.status, "message": f"Profile started for {profile_input.client_name}"}


@app.post("/api/status")
def flow_status(body: dict) -> dict:
    """Status check endpoint for Power Automate flows."""
    run_id = body.get("run_id", "")
    if not run_id:
        return {"status": "error", "message": "No run_id provided"}
    status = bg.get_run_status(run_id)
    if not status:
        return {"run_id": run_id, "status": "not_found", "message": f"Run {run_id} not found"}
    return status.model_dump()


@app.post("/api/report")
def flow_report(body: dict) -> dict:
    """Report generation endpoint for Power Automate flows."""
    run_id = body.get("run_id", "")
    report_format = body.get("format", "executive")
    if not run_id:
        return {"status": "error", "message": "No run_id provided"}

    status = bg.get_run_status(run_id)
    if not status:
        return {"run_id": run_id, "status": "not_found", "message": f"Run {run_id} not found"}

    result = {"run_id": run_id, "format": report_format, "status": status.status}
    if report_format == "executive" and status.executive_summary:
        result["report"] = status.executive_summary
    elif status.analyst_report:
        result["report"] = status.analyst_report
    else:
        result["report"] = f"Hunt {run_id}: {status.status}. Findings: {status.findings_count}. Events: {status.total_events}."
    return result
