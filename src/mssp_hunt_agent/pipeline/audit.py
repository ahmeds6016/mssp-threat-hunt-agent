"""Audit / trace module — persist all run artefacts to timestamped folders."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mssp_hunt_agent.models.report_models import RunAuditRecord


def save_run(
    audit: RunAuditRecord,
    executive_md: str,
    analyst_md: str,
    evidence_md: str,
    output_dir: Path,
) -> Path:
    """Write all artefacts into a timestamped run folder and return its path."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_client = audit.client_name.replace(" ", "_").lower()
    run_folder = output_dir / f"{ts}_{safe_client}"
    run_folder.mkdir(parents=True, exist_ok=True)

    # Markdown reports
    (run_folder / "executive_summary.md").write_text(executive_md, encoding="utf-8")
    (run_folder / "analyst_report.md").write_text(analyst_md, encoding="utf-8")
    (run_folder / "evidence_table.md").write_text(evidence_md, encoding="utf-8")

    # Full audit trace as JSON
    (run_folder / "run_trace.json").write_text(
        audit.model_dump_json(indent=2), encoding="utf-8"
    )

    # Convenience copies
    (run_folder / "input_payload.json").write_text(
        json.dumps(audit.input_payload, indent=2), encoding="utf-8"
    )
    (run_folder / "hunt_plan.json").write_text(
        json.dumps(audit.hunt_plan, indent=2), encoding="utf-8"
    )

    return run_folder
