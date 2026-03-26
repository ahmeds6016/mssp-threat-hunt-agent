"""Playbook engine — load and execute predefined hunt sequences."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse, ReasoningStep
from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)

# Default playbook directory
_PLAYBOOK_DIR = Path(__file__).parent.parent / "data" / "playbooks"


class PlaybookStep(BaseModel):
    """A single step in a hunt playbook."""

    action: str  # hunt | ioc_sweep | detection
    hypothesis: str = ""
    description: str = ""
    techniques: list[str] = Field(default_factory=list)
    time_range: str = "last 7 days"
    iocs: list[str] = Field(default_factory=list)


class Playbook(BaseModel):
    """A predefined hunt playbook."""

    name: str
    description: str = ""
    severity: str = "medium"
    techniques: list[str] = Field(default_factory=list)
    steps: list[PlaybookStep] = Field(default_factory=list)


def list_playbooks(playbook_dir: Path | None = None) -> list[Playbook]:
    """List all available playbooks."""
    directory = playbook_dir or _PLAYBOOK_DIR
    playbooks: list[Playbook] = []

    if not directory.exists():
        return playbooks

    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data:
                playbooks.append(Playbook(**data))
        except Exception as exc:
            logger.warning("Failed to load playbook %s: %s", path, exc)

    return playbooks


def get_playbook(name: str, playbook_dir: Path | None = None) -> Playbook | None:
    """Get a playbook by name (case-insensitive partial match)."""
    for pb in list_playbooks(playbook_dir):
        if name.lower() in pb.name.lower():
            return pb
    return None


def execute_playbook(
    playbook: Playbook, config: HuntAgentConfig
) -> AgentResponse:
    """Execute a playbook — runs each step sequentially and collects results."""
    from mssp_hunt_agent.api import background as bg
    from mssp_hunt_agent.models.input_models import HuntInput

    client_name = config.default_client_name or "Unknown"
    steps: list[ReasoningStep] = []
    run_ids: list[str] = []

    steps.append(ReasoningStep(
        step_type="planning",
        description=f"Executing playbook: {playbook.name} ({len(playbook.steps)} steps)",
        data={"severity": playbook.severity, "techniques": playbook.techniques},
    ))

    config_copy = config.model_copy()
    config_copy.approval_required = False

    for i, step in enumerate(playbook.steps):
        step_num = i + 1
        steps.append(ReasoningStep(
            step_type="executing",
            description=f"Step {step_num}/{len(playbook.steps)}: {step.action} — {step.hypothesis or step.description}",
        ))

        try:
            if step.action == "hunt":
                hunt_input = HuntInput(
                    client_name=client_name,
                    hunt_objective=step.hypothesis,
                    hunt_hypothesis=step.hypothesis,
                    time_range=step.time_range,
                    available_data_sources=["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"],
                    attack_techniques=step.techniques,
                )
                run_id = bg.generate_run_id("RUN")
                bg.launch_hunt(run_id, hunt_input, config_copy)
                run_ids.append(run_id)
                steps.append(ReasoningStep(
                    step_type="result",
                    description=f"Step {step_num}: Hunt launched as {run_id}",
                    data={"run_id": run_id},
                ))

            elif step.action == "ioc_sweep" and step.iocs:
                from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType
                entries = [IOCEntry(value=ioc, ioc_type=IOCType.IP) for ioc in step.iocs]
                ioc_input = IOCHuntInput(
                    client_name=client_name,
                    iocs=entries,
                    time_range=step.time_range,
                    available_data_sources=["SecurityEvent", "SigninLogs"],
                )
                run_id = bg.generate_run_id("RUN-IOC")
                bg.launch_ioc_sweep(run_id, ioc_input, config_copy)
                run_ids.append(run_id)
                steps.append(ReasoningStep(
                    step_type="result",
                    description=f"Step {step_num}: IOC sweep launched as {run_id}",
                    data={"run_id": run_id},
                ))
            else:
                steps.append(ReasoningStep(
                    step_type="result",
                    description=f"Step {step_num}: Skipped (no IOCs for sweep or unrecognized action)",
                ))

        except Exception as exc:
            steps.append(ReasoningStep(
                step_type="error",
                description=f"Step {step_num} failed: {exc}",
            ))

    steps.append(ReasoningStep(
        step_type="synthesizing",
        description=f"Playbook complete. Launched {len(run_ids)} hunts.",
    ))

    return AgentResponse(
        summary=(
            f"Playbook '{playbook.name}' executed: {len(run_ids)} hunts launched.\n"
            f"Run IDs: {', '.join(run_ids)}\n"
            f"Check status of each hunt to view results."
        ),
        intent=AgentIntent.RUN_PLAYBOOK,
        confidence=0.95,
        details={
            "playbook": playbook.name,
            "steps_total": len(playbook.steps),
            "hunts_launched": len(run_ids),
            "run_ids": run_ids,
        },
        thinking_trace=steps,
        follow_up_suggestions=[
            f"Check status of {run_ids[0]}" if run_ids else "List available playbooks",
        ],
    )
