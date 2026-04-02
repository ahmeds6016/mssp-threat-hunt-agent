"""Azure Function HTTP trigger — direct routing (V7.2 GPT-5.3-chat).

Handles all /api/* routes by forwarding to the internal handlers.
This avoids ASGI compatibility issues across azure-functions versions.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time as _time

# Ensure the wwwroot directory is on the Python path so mssp_hunt_agent is importable
_wwwroot = os.path.dirname(os.path.abspath(__file__))
if _wwwroot not in sys.path:
    sys.path.insert(0, _wwwroot)

import azure.functions as func

logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# ── Input validation limits ──────────────────────────────────────────
_MAX_MESSAGE_LENGTH = 4000  # chars — longest reasonable analyst prompt
_MAX_CLIENT_NAME_LENGTH = 100
_MAX_FOCUS_AREAS = 10
_MAX_FOCUS_AREA_LENGTH = 200
_MAX_HYPOTHESES = 50
_MAX_TOTAL_QUERIES = 500
_MAX_DURATION_MINUTES = 120


def _json_response(
    data: dict, status_code: int = 200, *, request_id: str = "",
) -> func.HttpResponse:
    if request_id:
        data.setdefault("request_id", request_id)
    return func.HttpResponse(
        json.dumps(data, default=str),
        status_code=status_code,
        mimetype="application/json",
    )


def _get_config():
    from mssp_hunt_agent.config import HuntAgentConfig
    return HuntAgentConfig.from_env()


def _extract_message(body: dict) -> tuple[str | None, str | None]:
    """Extract and validate the message field. Returns (message, error)."""
    message = body.get("message", "") or body.get("text", "")
    if not message:
        return None, "Missing 'message' or 'text' field"
    if not isinstance(message, str):
        return None, "'message' must be a string"
    if len(message) > _MAX_MESSAGE_LENGTH:
        return None, f"Message too long ({len(message)} chars). Maximum is {_MAX_MESSAGE_LENGTH}."
    return message.strip(), None


def _validate_campaign_body(body: dict) -> str | None:
    """Validate campaign start request fields. Returns error string or None."""
    client_name = body.get("client_name", "")
    if client_name and len(str(client_name)) > _MAX_CLIENT_NAME_LENGTH:
        return f"client_name too long. Maximum is {_MAX_CLIENT_NAME_LENGTH} chars."

    focus_areas = body.get("focus_areas", [])
    if not isinstance(focus_areas, list):
        return "focus_areas must be a list of strings"
    if len(focus_areas) > _MAX_FOCUS_AREAS:
        return f"Too many focus_areas ({len(focus_areas)}). Maximum is {_MAX_FOCUS_AREAS}."
    for fa in focus_areas:
        if not isinstance(fa, str) or len(fa) > _MAX_FOCUS_AREA_LENGTH:
            return f"Each focus_area must be a string under {_MAX_FOCUS_AREA_LENGTH} chars."

    max_hyp = body.get("max_hypotheses", 10)
    if not isinstance(max_hyp, int) or max_hyp < 1 or max_hyp > _MAX_HYPOTHESES:
        return f"max_hypotheses must be 1-{_MAX_HYPOTHESES}"

    max_q = body.get("max_total_queries", 200)
    if not isinstance(max_q, int) or max_q < 1 or max_q > _MAX_TOTAL_QUERIES:
        return f"max_total_queries must be 1-{_MAX_TOTAL_QUERIES}"

    max_dur = body.get("max_duration_minutes", 60)
    if not isinstance(max_dur, int) or max_dur < 1 or max_dur > _MAX_DURATION_MINUTES:
        return f"max_duration_minutes must be 1-{_MAX_DURATION_MINUTES}"

    return None


@app.function_name("Health")
@app.route(route="api/v1/health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return _json_response({
        "status": "ok",
        "version": "0.7.2",
    })


@app.function_name("HealthSimple")
@app.route(route="api/health", methods=["GET"])
def health_simple(req: func.HttpRequest) -> func.HttpResponse:
    return _json_response({
        "status": "ok",
        "version": "0.7.2",
    })


@app.function_name("ChatV1")
@app.route(route="api/v1/chat", methods=["POST"])
def chat_v1(req: func.HttpRequest) -> func.HttpResponse:
    import uuid as _uuid_mod
    rid = f"CHAT-{_uuid_mod.uuid4().hex[:8]}"

    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"error": "Invalid JSON body"}, 400, request_id=rid)

    message, err = _extract_message(body)
    if err:
        return _json_response({"error": err}, 400, request_id=rid)

    logger.info("[%s] chat_v1 start | len=%d", rid, len(message))
    t0 = _time.time()

    from mssp_hunt_agent.agent.controller import AgentController
    from mssp_hunt_agent.agent.response_formatter import format_response

    config = _get_config()
    config.agent_enabled = True
    config.agent_llm_fallback = False
    controller = AgentController(config=config, request_id=rid)
    response = controller.process(message)
    formatted = format_response(response)

    elapsed_ms = int((_time.time() - t0) * 1000)
    logger.info("[%s] chat_v1 done | %dms | intent=%s", rid, elapsed_ms, response.intent)

    return _json_response({
        "request_id": rid,
        "intent": response.intent.value if hasattr(response.intent, "value") else str(response.intent),
        "confidence": response.confidence,
        "response": formatted,
        "run_id": response.run_id,
        "follow_up_suggestions": response.follow_up_suggestions,
        "data": response.data if hasattr(response, "data") else {},
        "error": response.error,
    })


@app.function_name("ChatSimple")
@app.route(route="api/chat", methods=["POST"])
def chat_simple(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"error": "Invalid JSON body"}, 400)

    message, err = _extract_message(body)
    if err:
        return _json_response({"error": err}, 400)

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

_state_lock = threading.Lock()


def _get_state_store():
    """Lazy-init singleton BlobStateStore. Falls back to memory-only if no connection string."""
    global _state_store_singleton
    if "_state_store_singleton" not in globals() or _state_store_singleton is None:
        from mssp_hunt_agent.persistence.blob_store import BlobStateStore
        config = _get_config()
        _state_store_singleton = BlobStateStore(
            connection_string=config.blob_connection_string,
            container_name=config.blob_container_name,
        )
        mode = "blob" if _state_store_singleton.blob_enabled else "memory-only"
        logger.info("State store initialized: %s", mode)
    return _state_store_singleton


_state_store_singleton = None

# ── Progress tracking for live campaign updates ──────────────────────
_progress_trackers: dict = {}  # campaign_id → ProgressTracker
_progress_lock = threading.Lock()


def _create_progress_tracker(campaign_id: str):
    """Create a ProgressTracker for a campaign and wire blob persistence."""
    from mssp_hunt_agent.persistence.progress import ProgressTracker

    tracker = ProgressTracker(campaign_id)
    store = _get_state_store()

    def _flush(cid, events):
        """Persist progress log to blob after each event."""
        try:
            store._upload_json(f"progress/{cid}.json", {
                "campaign_id": cid,
                "events": events,
            })
        except Exception:
            pass  # non-critical, logged inside _upload_json

    tracker.set_flush_callback(_flush)

    with _progress_lock:
        _progress_trackers[campaign_id] = tracker

    return tracker


def _get_progress_tracker(campaign_id: str):
    """Get an existing ProgressTracker, or try loading from blob."""
    with _progress_lock:
        tracker = _progress_trackers.get(campaign_id)
    if tracker:
        return tracker

    # Try loading from blob
    store = _get_state_store()
    blob_data = store._download_json(f"progress/{campaign_id}.json")
    if blob_data and blob_data.get("events"):
        from mssp_hunt_agent.persistence.progress import ProgressTracker
        tracker = ProgressTracker(campaign_id)
        tracker._events = blob_data["events"]
        with _progress_lock:
            _progress_trackers[campaign_id] = tracker
        return tracker

    return None


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

    message, err = _extract_message(body)
    if err:
        return _json_response({"error": err}, 400)

    request_id = f"REQ-{_uuid.uuid4().hex[:8]}"
    logger.info("[%s] ask_agent accepted | len=%d", request_id, len(message))

    store = _get_state_store()
    with _state_lock:
        store.save_request(request_id, {
            "request_id": request_id,
            "status": "processing",
            "message": message,
        })

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

    store = _get_state_store()
    with _state_lock:
        entry = store.get_request(request_id)

    if not entry:
        return _json_response({"error": f"Request {request_id} not found"}, 404)

    return _json_response(entry)


def _process_ask_request(request_id: str, message: str) -> None:
    """Background worker — classify, route, execute, store result."""
    t0 = _time.time()
    store = _get_state_store()
    try:
        from mssp_hunt_agent.agent.complexity_classifier import classify_complexity
        from mssp_hunt_agent.agent.controller import AgentController
        from mssp_hunt_agent.agent.response_formatter import format_response

        config = _get_config()
        config.agent_enabled = True
        config.agent_llm_fallback = False
        controller = AgentController(config=config, request_id=request_id)

        if not controller.llm:
            logger.error("[%s] LLM not available", request_id)
            with _state_lock:
                store.save_request(request_id, {
                    "request_id": request_id,
                    "status": "error",
                    "error": "LLM not available",
                })
            return

        # Step 1: GPT-5.3 classifies complexity
        classify_t0 = _time.time()
        routing = classify_complexity(controller.llm, message)
        classify_ms = int((_time.time() - classify_t0) * 1000)
        logger.info(
            "[%s] classified | route=%s conf=%.2f | %dms | %s",
            request_id, routing.route, routing.confidence, classify_ms, routing.reasoning,
        )

        # Step 2: Route based on classification
        if routing.route == "campaign":
            _start_campaign_for_request(request_id, config, controller, routing)
            return

        # Chat path — run agent loop
        chat_t0 = _time.time()
        response = controller.process(message)
        chat_ms = int((_time.time() - chat_t0) * 1000)
        formatted = format_response(response)

        total_ms = int((_time.time() - t0) * 1000)
        tool_count = len(response.thinking_trace or [])
        logger.info(
            "[%s] chat complete | %dms total (%dms classify, %dms agent) | tools=%d | intent=%s",
            request_id, total_ms, classify_ms, chat_ms, tool_count, response.intent,
        )

        with _state_lock:
            store.save_request(request_id, {
                "request_id": request_id,
                "status": "completed",
                "route": "chat",
                "response": formatted,
                "error": response.error or "",
            })

    except Exception as exc:
        total_ms = int((_time.time() - t0) * 1000)
        logger.exception("[%s] failed after %dms", request_id, total_ms)
        with _state_lock:
            store.save_request(request_id, {
                "request_id": request_id,
                "status": "error",
                "error": "Internal processing error. Check server logs for details.",
            })


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
    logger.info(
        "[%s] campaign starting | campaign=%s | client=%s | focus=%s | hypotheses=%d",
        request_id, campaign_id, client_name, routing.focus_areas, routing.max_hypotheses,
    )

    # Initialize learning engine for this campaign
    learning_status = "unknown"
    try:
        learning_engine = _get_learning_engine()
        learning_status = "active"
        logger.info("[%s] learning engine active for %s", request_id, campaign_id)
    except Exception as exc:
        logger.warning("[%s] learning engine init failed: %s", request_id, exc)
        learning_engine = None
        learning_status = f"failed: {exc}"

    store = _get_state_store()
    progress = _create_progress_tracker(campaign_id)

    def _run(camp_config, cid, llm, agent_config, learn_engine):
        camp_t0 = _time.time()
        try:
            orchestrator = CampaignOrchestrator(
                agent_config=agent_config,
                llm=llm,
                campaign_config=camp_config,
                learning_engine=learn_engine,
                progress=progress,
            )
            initial_state = CampaignState(
                campaign_id=cid,
                config=camp_config,
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            state = orchestrator.run(resume_state=initial_state)
            elapsed_s = int(_time.time() - camp_t0)
            logger.info(
                "[%s] campaign complete | campaign=%s | %ds | hypotheses=%d queries=%d findings=%d",
                request_id, cid, elapsed_s,
                len(state.hypotheses), state.total_kql_queries, len(state.findings),
            )
            with _state_lock:
                store.save_campaign(cid, state)
        except Exception as exc:
            elapsed_s = int(_time.time() - camp_t0)
            logger.exception("[%s] campaign %s failed after %ds", request_id, cid, elapsed_s)
            with _state_lock:
                store.save_campaign(cid, {
                    "campaign_id": cid, "status": "failed",
                    "client_name": camp_config.client_name,
                    "error": "Campaign execution failed. Check server logs for details.",
                })

    with _state_lock:
        store.save_campaign(campaign_id, {
            "campaign_id": campaign_id,
            "status": "starting",
            "client_name": client_name,
        })

    campaign_thread = threading.Thread(
        target=_run,
        args=(campaign_config, campaign_id, controller.llm, config, learning_engine),
        daemon=True,
    )
    campaign_thread.start()

    # Mark the ask request as completed with the campaign_id
    with _state_lock:
        store.save_request(request_id, {
            "request_id": request_id,
            "status": "completed",
            "route": "campaign",
            "campaign_id": campaign_id,
            "response": f"Deep investigation started. Campaign {campaign_id} is running. Use getCampaign to check progress.",
            "focus_areas": routing.focus_areas,
            "time_range": routing.time_range,
            "learning_status": learning_status,
            "error": "",
        })


# ── V7 Autonomous Hunt Campaign Endpoints ────────────────────────────


@app.function_name("CampaignsEndpoint")
@app.route(route="api/v1/campaigns", methods=["GET", "POST"])
def campaigns_endpoint(req: func.HttpRequest) -> func.HttpResponse:
    """POST: Start a campaign. GET: List campaigns."""
    if req.method == "GET":
        return _list_campaigns()
    return _start_campaign(req)


def _list_campaigns() -> func.HttpResponse:
    """List all campaigns."""
    store = _get_state_store()
    with _state_lock:
        snapshot = store.list_campaigns()
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

    # Validate campaign request body
    validation_err = _validate_campaign_body(body)
    if validation_err:
        return _json_response({"error": validation_err}, 400)

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
    logger.info(
        "[%s] campaign start (direct) | client=%s | hypotheses=%d | queries=%d",
        campaign_id, client_name,
        campaign_config.max_hypotheses, campaign_config.max_total_queries,
    )

    store = _get_state_store()
    progress = _create_progress_tracker(campaign_id)

    def _run_campaign(camp_config, cid):
        from mssp_hunt_agent.agent.controller import AgentController
        from mssp_hunt_agent.hunter.campaign import CampaignOrchestrator
        from mssp_hunt_agent.hunter.models.campaign import CampaignState
        from datetime import datetime, timezone

        camp_t0 = _time.time()
        try:
            agent_config = _get_config()
            agent_config.agent_enabled = True
            agent_config.agent_llm_fallback = False

            ctrl = AgentController(config=agent_config)
            if not ctrl.llm:
                logger.error("[%s] LLM not available for campaign", cid)
                with _state_lock:
                    store.save_campaign(cid, {
                        "campaign_id": cid, "status": "failed",
                        "client_name": camp_config.client_name,
                        "error": "LLM not available",
                    })
                return

            orchestrator = CampaignOrchestrator(
                agent_config=agent_config,
                llm=ctrl.llm,
                campaign_config=camp_config,
                progress=progress,
            )
            initial_state = CampaignState(
                campaign_id=cid,
                config=camp_config,
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            state = orchestrator.run(resume_state=initial_state)
            elapsed_s = int(_time.time() - camp_t0)
            logger.info(
                "[%s] campaign complete (direct) | %ds | hypotheses=%d queries=%d findings=%d",
                cid, elapsed_s,
                len(state.hypotheses), state.total_kql_queries, len(state.findings),
            )
            with _state_lock:
                store.save_campaign(cid, state)
        except Exception as exc:
            elapsed_s = int(_time.time() - camp_t0)
            logger.exception("[%s] campaign failed after %ds", cid, elapsed_s)
            with _state_lock:
                store.save_campaign(cid, {
                    "campaign_id": cid, "status": "failed",
                    "client_name": camp_config.client_name,
                    "error": "Campaign execution failed. Check server logs for details.",
                })

    # Store a placeholder
    with _state_lock:
        store.save_campaign(campaign_id, {
            "campaign_id": campaign_id,
            "status": "starting",
            "client_name": client_name,
        })

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

    store = _get_state_store()
    with _state_lock:
        state = store.get_campaign(campaign_id)

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

    store = _get_state_store()
    with _state_lock:
        state = store.get_campaign(campaign_id)

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


@app.function_name("GetCampaignProgress")
@app.route(route="api/v1/campaigns/{campaign_id}/progress", methods=["GET"])
def get_campaign_progress(req: func.HttpRequest) -> func.HttpResponse:
    """Live progress feed for a running campaign.

    Query params:
        since: int — return only events after this sequence number (default 0 = all)

    Returns:
        campaign_id, summary (compact status), events (list of timestamped events)
    """
    campaign_id = req.route_params.get("campaign_id", "")
    since = int(req.params.get("since", "0"))

    tracker = _get_progress_tracker(campaign_id)
    if not tracker:
        return _json_response({
            "campaign_id": campaign_id,
            "summary": {"phase": "unknown", "events_count": 0},
            "events": [],
            "total_events": 0,
        })

    events = tracker.get_events(since=since)
    summary = tracker.summary()

    return _json_response({
        "campaign_id": campaign_id,
        "summary": summary,
        "events": events,
        "total_events": tracker.count,
        "since": since,
    })



@app.function_name("OpenAPISpec")
@app.route(route="api/openapi.json", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def openapi_spec(req: func.HttpRequest) -> func.HttpResponse:
    spec_path = os.path.join(_wwwroot, "openapi.json")
    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            return func.HttpResponse(f.read(), mimetype="application/json")
    except FileNotFoundError:
        return _json_response({"error": "OpenAPI spec not found"}, 404)
