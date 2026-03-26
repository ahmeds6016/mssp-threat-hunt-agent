"""Azure Function HTTP trigger — direct routing (V6.0 GPT-5.3-chat).

Handles all /api/* routes by forwarding to the internal handlers.
This avoids ASGI compatibility issues across azure-functions versions.
"""

from __future__ import annotations

import json
import logging
import os
import sys

# Ensure the wwwroot directory is on the Python path so mssp_hunt_agent is importable
_wwwroot = os.path.dirname(os.path.abspath(__file__))
if _wwwroot not in sys.path:
    sys.path.insert(0, _wwwroot)

import azure.functions as func

logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _json_response(data: dict, status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(data, default=str),
        status_code=status_code,
        mimetype="application/json",
    )


def _get_config():
    from mssp_hunt_agent.config import HuntAgentConfig
    return HuntAgentConfig.from_env()


@app.function_name("Health")
@app.route(route="api/v1/health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    config = _get_config()
    # Build LLM adapter to check what's actually being used
    llm_adapter_name = "none"
    try:
        from mssp_hunt_agent.agent.controller import AgentController
        ctrl = AgentController(config=config)
        if ctrl.llm:
            llm_adapter_name = ctrl.llm.get_adapter_name()
    except Exception as exc:
        llm_adapter_name = f"error: {exc}"
    return _json_response({
        "status": "ok",
        "version": "0.7.0",
        "adapter_mode": config.adapter_mode,
        "persist_enabled": config.persist,
        "agent_enabled": config.agent_enabled,
        "llm_enabled": config.llm_enabled,
        "llm_adapter": llm_adapter_name,
        "openai_endpoint_set": bool(config.azure_openai_endpoint),
        "openai_deployment": config.azure_openai_deployment,
    })


@app.function_name("HealthSimple")
@app.route(route="api/health", methods=["GET"])
def health_simple(req: func.HttpRequest) -> func.HttpResponse:
    config = _get_config()
    return _json_response({
        "status": "ok",
        "version": "0.7.0",
        "adapter_mode": config.adapter_mode,
    })


@app.function_name("ChatV1")
@app.route(route="api/v1/chat", methods=["POST"])
def chat_v1(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"error": "Invalid JSON body"}, 400)

    message = body.get("message", "") or body.get("text", "")
    if not message:
        return _json_response({"error": "Missing 'message' or 'text' field"}, 400)

    from mssp_hunt_agent.agent.controller import AgentController
    from mssp_hunt_agent.agent.response_formatter import format_response

    config = _get_config()
    config.agent_enabled = True
    config.agent_llm_fallback = False  # Surface errors instead of silent fallback
    controller = AgentController(config=config)
    response = controller.process(message)
    formatted = format_response(response)

    return _json_response({
        "intent": response.intent.value if hasattr(response.intent, "value") else str(response.intent),
        "confidence": response.confidence,
        "response": formatted,
        "run_id": response.run_id,
        "follow_up_suggestions": response.follow_up_suggestions,
        "data": response.data if hasattr(response, "data") else {},
        "thinking_trace": [s.description for s in (response.thinking_trace or [])],
        "error": response.error,
    })


@app.function_name("ChatSimple")
@app.route(route="api/chat", methods=["POST"])
def chat_simple(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"error": "Invalid JSON body"}, 400)

    message = body.get("message", "") or body.get("text", "")
    if not message:
        return _json_response({"error": "Missing 'message' or 'text' field"}, 400)

    from mssp_hunt_agent.agent.controller import AgentController
    from mssp_hunt_agent.agent.response_formatter import format_response

    config = _get_config()
    config.agent_enabled = True
    controller = AgentController(config=config)
    response = controller.process(message)
    formatted = format_response(response)

    return _json_response({"body": formatted})


# ── Persistence + Learning Engine ────────────────────────────────────

import threading
import uuid as _uuid

_requests_lock = threading.Lock()
_pending_requests: dict = {}  # request_id → {"status": ..., "result": ...}


def _get_hunt_db():
    """Get or create the SQLite database for campaign persistence.

    Uses /tmp/ on Azure Functions (read-only filesystem elsewhere).
    Falls back to local temp dir on Windows for dev.
    """
    import tempfile
    from pathlib import Path

    from mssp_hunt_agent.persistence.database import HuntDatabase

    # Azure Functions Linux: writable path is /tmp/
    # Local dev: use system temp directory
    tmp_dir = Path("/tmp") if os.path.isdir("/tmp") else Path(tempfile.gettempdir())
    db_path = tmp_dir / "mssp_hunt_agent.db"
    return HuntDatabase(str(db_path))


def _get_learning_engine():
    """Get a CampaignLearningEngine backed by SQLite."""
    from mssp_hunt_agent.hunter.learning import CampaignLearningEngine

    db = _get_hunt_db()
    return CampaignLearningEngine(db)


# ── Unified Entry Point — fully async, return 202 immediately ────────


@app.function_name("AskAgent")
@app.route(route="api/v1/ask", methods=["POST"])
def ask_agent(req: func.HttpRequest) -> func.HttpResponse:
    """Fully async entry point — returns 202 immediately, poll for result.

    GPT-5.3 classifies complexity in the background:
    - Chat queries: result ready in 15-60s
    - Campaign queries: result contains campaign_id to poll separately

    Poll GET /api/v1/ask/{request_id} for the result.
    """
    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"error": "Invalid JSON body"}, 400)

    message = body.get("message", "") or body.get("text", "")
    if not message:
        return _json_response({"error": "Missing 'message' or 'text' field"}, 400)

    request_id = f"REQ-{_uuid.uuid4().hex[:8]}"

    with _requests_lock:
        _pending_requests[request_id] = {
            "request_id": request_id,
            "status": "processing",
            "message": message,
        }

    # Run everything in a background thread
    thread = threading.Thread(
        target=_process_ask_request,
        args=(request_id, message),
        daemon=True,
    )
    thread.start()

    return _json_response({
        "request_id": request_id,
        "status": "processing",
        "message": f"Request accepted. Poll GET /api/v1/ask/{request_id} for the result.",
    }, 202)


@app.function_name("GetAskResult")
@app.route(route="api/v1/ask/{request_id}", methods=["GET"])
def get_ask_result(req: func.HttpRequest) -> func.HttpResponse:
    """Poll for the result of an async /ask request."""
    request_id = req.route_params.get("request_id", "")

    with _requests_lock:
        entry = _pending_requests.get(request_id)

    if not entry:
        return _json_response({"error": f"Request {request_id} not found"}, 404)

    return _json_response(entry)


def _process_ask_request(request_id: str, message: str) -> None:
    """Background worker — classify, route, execute, store result."""
    try:
        from mssp_hunt_agent.agent.complexity_classifier import classify_complexity
        from mssp_hunt_agent.agent.controller import AgentController
        from mssp_hunt_agent.agent.response_formatter import format_response

        config = _get_config()
        config.agent_enabled = True
        config.agent_llm_fallback = False
        controller = AgentController(config=config)

        if not controller.llm:
            with _requests_lock:
                _pending_requests[request_id] = {
                    "request_id": request_id,
                    "status": "error",
                    "error": "LLM not available",
                }
            return

        # Step 1: GPT-5.3 classifies complexity
        routing = classify_complexity(controller.llm, message)
        logger.info(
            "Routing [%s]: %s (%.2f) — %s",
            request_id, routing.route, routing.confidence, routing.reasoning,
        )

        # Step 2: Route based on classification
        if routing.route == "campaign":
            _start_campaign_for_request(request_id, config, controller, routing)
            return

        # Chat path — run agent loop
        response = controller.process(message)
        formatted = format_response(response)

        with _requests_lock:
            _pending_requests[request_id] = {
                "request_id": request_id,
                "status": "completed",
                "route": "chat",
                "response": formatted,
                "error": response.error or "",
            }

    except Exception as exc:
        logger.exception("Request %s failed", request_id)
        with _requests_lock:
            _pending_requests[request_id] = {
                "request_id": request_id,
                "status": "error",
                "error": str(exc),
            }


def _start_campaign_for_request(request_id, config, controller, routing):
    """Start a campaign and store the campaign_id in the request result."""
    from datetime import datetime, timezone

    from mssp_hunt_agent.hunter.campaign import CampaignOrchestrator
    from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState

    client_name = config.default_client_name or "Default"
    campaign_config = CampaignConfig(
        client_name=client_name,
        time_range=routing.time_range,
        focus_areas=routing.focus_areas,
        max_hypotheses=routing.max_hypotheses,
    )

    campaign_id = f"CAMP-{_uuid.uuid4().hex[:8]}"

    # Initialize learning engine for this campaign
    learning_status = "unknown"
    try:
        learning_engine = _get_learning_engine()
        learning_status = "active"
        logger.info("Learning engine initialized for campaign %s", campaign_id)
    except Exception as exc:
        logger.warning("Learning engine init failed (campaigns will run without learning): %s", exc)
        learning_engine = None
        learning_status = f"failed: {exc}"

    def _run(camp_config, cid, llm, agent_config, learn_engine):
        try:
            orchestrator = CampaignOrchestrator(
                agent_config=agent_config,
                llm=llm,
                campaign_config=camp_config,
                learning_engine=learn_engine,
            )
            initial_state = CampaignState(
                campaign_id=cid,
                config=camp_config,
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            state = orchestrator.run(resume_state=initial_state)
            with _campaigns_lock:
                _active_campaigns[cid] = state
        except Exception as exc:
            logger.exception("Campaign %s failed", cid)
            with _campaigns_lock:
                _active_campaigns[cid] = {
                    "campaign_id": cid, "status": "failed",
                    "client_name": camp_config.client_name,
                    "error": str(exc),
                }

    with _campaigns_lock:
        _active_campaigns[campaign_id] = {
            "campaign_id": campaign_id,
            "status": "starting",
            "client_name": client_name,
        }

    campaign_thread = threading.Thread(
        target=_run,
        args=(campaign_config, campaign_id, controller.llm, config, learning_engine),
        daemon=True,
    )
    campaign_thread.start()

    # Mark the ask request as completed with the campaign_id
    with _requests_lock:
        _pending_requests[request_id] = {
            "request_id": request_id,
            "status": "completed",
            "route": "campaign",
            "campaign_id": campaign_id,
            "response": f"Deep investigation started. Campaign {campaign_id} is running. Use getCampaign to check progress.",
            "focus_areas": routing.focus_areas,
            "time_range": routing.time_range,
            "learning_status": learning_status,
            "error": "",
        }


# ── V7 Autonomous Hunt Campaign Endpoints ────────────────────────────

# In-memory campaign state (reuses threading import from above)
_campaigns_lock = threading.Lock()
_active_campaigns: dict = {}


@app.function_name("CampaignsEndpoint")
@app.route(route="api/v1/campaigns", methods=["GET", "POST"])
def campaigns_endpoint(req: func.HttpRequest) -> func.HttpResponse:
    """POST: Start a campaign. GET: List campaigns."""
    if req.method == "GET":
        return _list_campaigns()
    return _start_campaign(req)


def _list_campaigns() -> func.HttpResponse:
    """List all campaigns."""
    with _campaigns_lock:
        snapshot = dict(_active_campaigns)
    campaigns = []
    for cid, state in snapshot.items():
        if isinstance(state, dict):
            campaigns.append(state)
        elif hasattr(state, "campaign_id"):
            campaigns.append({
                "campaign_id": state.campaign_id,
                "status": state.status,
                "current_phase": state.current_phase.value,
                "client_name": state.config.client_name,
                "findings_count": len(state.findings),
                "started_at": state.started_at,
            })
    return _json_response({"campaigns": campaigns})


def _start_campaign(req: func.HttpRequest) -> func.HttpResponse:
    """Start an autonomous threat hunt campaign. Returns campaign_id immediately."""
    try:
        body = req.get_json()
    except ValueError:
        body = {}

    client_name = body.get("client_name", "")
    if not client_name:
        config = _get_config()
        client_name = config.default_client_name or "Default"

    from mssp_hunt_agent.hunter.models.campaign import CampaignConfig

    campaign_config = CampaignConfig(
        client_name=client_name,
        time_range=body.get("time_range", "last 30 days"),
        focus_areas=body.get("focus_areas", []),
        max_hypotheses=body.get("max_hypotheses", 10),
        max_total_queries=body.get("max_total_queries", 200),
        max_duration_minutes=body.get("max_duration_minutes", 60),
    )

    # Generate campaign ID upfront
    import uuid
    campaign_id = f"CAMP-{uuid.uuid4().hex[:8]}"

    def _run_campaign(camp_config, cid):
        from mssp_hunt_agent.agent.controller import AgentController
        from mssp_hunt_agent.hunter.campaign import CampaignOrchestrator
        from mssp_hunt_agent.hunter.models.campaign import CampaignState
        from datetime import datetime, timezone

        try:
            agent_config = _get_config()
            agent_config.agent_enabled = True
            agent_config.agent_llm_fallback = False

            ctrl = AgentController(config=agent_config)
            if not ctrl.llm:
                with _campaigns_lock:
                    _active_campaigns[cid] = {
                        "campaign_id": cid, "status": "failed",
                        "client_name": camp_config.client_name,
                        "error": "LLM not available",
                    }
                return

            orchestrator = CampaignOrchestrator(
                agent_config=agent_config,
                llm=ctrl.llm,
                campaign_config=camp_config,
            )
            # Pass a pre-built state with the known campaign_id
            initial_state = CampaignState(
                campaign_id=cid,
                config=camp_config,
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            state = orchestrator.run(resume_state=initial_state)
            with _campaigns_lock:
                _active_campaigns[cid] = state
        except Exception as exc:
            logger.exception("Campaign %s failed", cid)
            with _campaigns_lock:
                _active_campaigns[cid] = {
                    "campaign_id": cid, "status": "failed",
                    "client_name": camp_config.client_name,
                    "error": str(exc),
                }

    # Store a placeholder
    with _campaigns_lock:
        _active_campaigns[campaign_id] = {
            "campaign_id": campaign_id,
            "status": "starting",
            "client_name": client_name,
        }

    # Run in background thread
    thread = threading.Thread(target=_run_campaign, args=(campaign_config, campaign_id), daemon=True)
    thread.start()

    return _json_response({
        "campaign_id": campaign_id,
        "status": "starting",
        "client_name": client_name,
        "message": "Campaign started. Poll /api/v1/campaigns/{campaign_id} for status.",
    }, 202)


@app.function_name("GetCampaign")
@app.route(route="api/v1/campaigns/{campaign_id}", methods=["GET"])
def get_campaign(req: func.HttpRequest) -> func.HttpResponse:
    """Get campaign status and progress."""
    campaign_id = req.route_params.get("campaign_id", "")

    # Search active campaigns (thread-safe snapshot)
    with _campaigns_lock:
        state = _active_campaigns.get(campaign_id)
    if not state:
        with _campaigns_lock:
            snapshot = dict(_active_campaigns)
        for cid, s in snapshot.items():
            if isinstance(s, dict) and s.get("campaign_id") == campaign_id:
                return _json_response(s)
            elif hasattr(s, "campaign_id") and s.campaign_id == campaign_id:
                state = s
                break
        if not state:
            return _json_response({"error": "Campaign not found"}, 404)

    if isinstance(state, dict):
        return _json_response(state)

    # CampaignState object
    return _json_response({
        "campaign_id": state.campaign_id,
        "status": state.status,
        "current_phase": state.current_phase.value,
        "client_name": state.config.client_name,
        "hypotheses_count": len(state.hypotheses),
        "findings_count": len(state.findings),
        "total_kql_queries": state.total_kql_queries,
        "started_at": state.started_at,
        "completed_at": state.completed_at,
        "errors": state.errors,
        "phase_results": [
            {"phase": pr.phase.value, "status": pr.status, "summary": pr.summary}
            for pr in state.phase_results
        ],
    })


@app.function_name("GetCampaignReport")
@app.route(route="api/v1/campaigns/{campaign_id}/report", methods=["GET"])
def get_campaign_report(req: func.HttpRequest) -> func.HttpResponse:
    """Get the final campaign report (available after DELIVER phase)."""
    campaign_id = req.route_params.get("campaign_id", "")

    # Find campaign state (direct key lookup first, then scan)
    with _campaigns_lock:
        state = _active_campaigns.get(campaign_id)
    if not state:
        with _campaigns_lock:
            snapshot = dict(_active_campaigns)
        for cid, s in snapshot.items():
            if hasattr(s, "campaign_id") and s.campaign_id == campaign_id:
                state = s
                break

    if not state or isinstance(state, dict):
        return _json_response({"error": "Report not available yet"}, 404)

    # If report object exists, return it
    if hasattr(state, "report") and state.report:
        fmt = req.params.get("format", "json")
        if fmt == "markdown" and hasattr(state.report, "markdown"):
            return func.HttpResponse(
                state.report.markdown,
                mimetype="text/markdown",
            )
        return _json_response(state.report.model_dump(mode="json"))

    # Fallback: build report from deliver phase summary + phase_results
    deliver_summary = ""
    for pr in getattr(state, "phase_results", []):
        if pr.phase.value == "deliver" and pr.summary:
            deliver_summary = pr.summary
            break

    if deliver_summary:
        return _json_response({
            "campaign_id": state.campaign_id,
            "client_name": state.config.client_name,
            "report_markdown": deliver_summary,
            "findings_count": len(state.findings),
            "hypotheses_count": len(state.hypotheses),
            "total_kql_queries": state.total_kql_queries,
        })

    return _json_response({"error": "Campaign has not completed the deliver phase"}, 404)




@app.function_name("OpenAPISpec")
@app.route(route="api/openapi.json", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def openapi_spec(req: func.HttpRequest) -> func.HttpResponse:
    spec_path = os.path.join(_wwwroot, "openapi.json")
    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            return func.HttpResponse(f.read(), mimetype="application/json")
    except FileNotFoundError:
        return _json_response({"error": "OpenAPI spec not found"}, 404)
