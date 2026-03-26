"""Background task runner for async pipeline execution.

Pipelines run synchronously but can be long-running.  This module wraps
them in a thread so the API can return ``202 Accepted`` immediately and
let the caller poll for status.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from mssp_hunt_agent.api.schemas import RunStatusResponse
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)

# In-memory status store — keyed by run_id
_run_store: dict[str, RunStatusResponse] = {}
_lock = threading.Lock()


def get_run_status(run_id: str) -> RunStatusResponse | None:
    """Retrieve the current status of a run."""
    with _lock:
        return _run_store.get(run_id)


def list_all_runs() -> list[RunStatusResponse]:
    """Return all tracked runs (most recent first)."""
    with _lock:
        return sorted(
            _run_store.values(),
            key=lambda r: r.started_at,
            reverse=True,
        )


def _update_status(run_id: str, **kwargs: Any) -> None:
    with _lock:
        if run_id in _run_store:
            current = _run_store[run_id]
            _run_store[run_id] = current.model_copy(update=kwargs)


# ── Hypothesis hunt ──────────────────────────────────────────────────


def launch_hunt(
    run_id: str,
    hunt_input,
    config: HuntAgentConfig,
    plan_only: bool = False,
) -> RunStatusResponse:
    """Launch a hypothesis hunt in a background thread."""
    now = datetime.now(timezone.utc).isoformat()
    status = RunStatusResponse(
        run_id=run_id,
        status="queued",
        hunt_type="hypothesis",
        client_name=hunt_input.client_name,
        started_at=now,
    )
    with _lock:
        _run_store[run_id] = status

    thread = threading.Thread(
        target=_run_hypothesis,
        args=(run_id, hunt_input, config, plan_only),
        daemon=True,
    )
    thread.start()
    return status


def _run_hypothesis(run_id: str, hunt_input, config: HuntAgentConfig, plan_only: bool) -> None:
    try:
        _update_status(run_id, status="running")
        from mssp_hunt_agent.pipeline.orchestrator import run_pipeline

        result = run_pipeline(
            hunt_input=hunt_input,
            config=config,
            approval_callback=None,  # API auto-approves
            plan_only=plan_only,
        )

        _update_status(
            run_id,
            status="completed" if not result.stopped_at else "stopped",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=result.stopped_at or "Pipeline completed successfully",
            output_dir=str(result.output_dir) if result.output_dir else "",
            findings_count=len(result.analyst_report.findings) if result.analyst_report else 0,
            queries_executed=len(result.query_results),
            total_events=sum(qr.result_count for qr in result.query_results),
            errors=result.errors,
        )
    except Exception as exc:
        logger.exception("Hunt %s failed", run_id)
        _update_status(
            run_id,
            status="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=str(exc),
            errors=[str(exc)],
        )


# ── IOC sweep ────────────────────────────────────────────────────────


def launch_ioc_sweep(
    run_id: str,
    ioc_input,
    config: HuntAgentConfig,
    plan_only: bool = False,
) -> RunStatusResponse:
    """Launch an IOC sweep in a background thread."""
    now = datetime.now(timezone.utc).isoformat()
    status = RunStatusResponse(
        run_id=run_id,
        status="queued",
        hunt_type="ioc_sweep",
        client_name=ioc_input.client_name,
        started_at=now,
    )
    with _lock:
        _run_store[run_id] = status

    thread = threading.Thread(
        target=_run_ioc_sweep,
        args=(run_id, ioc_input, config, plan_only),
        daemon=True,
    )
    thread.start()
    return status


def _run_ioc_sweep(run_id: str, ioc_input, config: HuntAgentConfig, plan_only: bool) -> None:
    try:
        _update_status(run_id, status="running")
        from mssp_hunt_agent.pipeline.orchestrator import run_ioc_pipeline

        result = run_ioc_pipeline(
            ioc_input=ioc_input,
            config=config,
            approval_callback=None,
            plan_only=plan_only,
        )

        hits = result.sweep_result.total_hits if result.sweep_result else 0
        _update_status(
            run_id,
            status="completed" if not result.stopped_at else "stopped",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=result.stopped_at or f"Sweep completed — {hits} hits",
            output_dir=str(result.output_dir) if result.output_dir else "",
            findings_count=hits,
            queries_executed=len(result.query_results),
            total_events=sum(qr.result_count for qr in result.query_results),
            errors=result.errors,
        )
    except Exception as exc:
        logger.exception("IOC sweep %s failed", run_id)
        _update_status(
            run_id,
            status="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=str(exc),
            errors=[str(exc)],
        )


# ── Profile ──────────────────────────────────────────────────────────


def launch_profile(
    run_id: str,
    profile_input,
    config: HuntAgentConfig,
    plan_only: bool = False,
) -> RunStatusResponse:
    """Launch a profiling run in a background thread."""
    now = datetime.now(timezone.utc).isoformat()
    status = RunStatusResponse(
        run_id=run_id,
        status="queued",
        hunt_type="profile",
        client_name=profile_input.client_name,
        started_at=now,
    )
    with _lock:
        _run_store[run_id] = status

    thread = threading.Thread(
        target=_run_profile,
        args=(run_id, profile_input, config, plan_only),
        daemon=True,
    )
    thread.start()
    return status


def _run_profile(run_id: str, profile_input, config: HuntAgentConfig, plan_only: bool) -> None:
    try:
        _update_status(run_id, status="running")
        from mssp_hunt_agent.pipeline.orchestrator import run_profile_pipeline

        result = run_profile_pipeline(
            profile_input=profile_input,
            config=config,
            approval_callback=None,
            plan_only=plan_only,
        )

        _update_status(
            run_id,
            status="completed" if not result.stopped_at else "stopped",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=result.stopped_at or "Profile completed",
            output_dir=str(result.output_dir) if result.output_dir else "",
            queries_executed=len(result.query_results),
            total_events=sum(qr.result_count for qr in result.query_results),
            errors=result.errors,
        )
    except Exception as exc:
        logger.exception("Profile %s failed", run_id)
        _update_status(
            run_id,
            status="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message=str(exc),
            errors=[str(exc)],
        )


def generate_run_id(prefix: str = "RUN") -> str:
    """Generate a unique run ID."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
