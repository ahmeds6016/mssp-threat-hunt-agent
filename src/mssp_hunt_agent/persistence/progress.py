"""Live progress tracker for campaign execution.

Maintains a timestamped event log that can be polled for real-time updates.
Events cover phase transitions, tool calls, hypothesis generation, finding
discovery, budget usage, and LLM reasoning steps.

Usage:
    tracker = ProgressTracker("CAMP-abc123")
    tracker.log("phase_started", phase="index_refresh")
    tracker.log("query_executed", query="SecurityEvent | take 100", results=47, ms=1200)
    tracker.log("finding_discovered", severity="high", title="12 failed logons")

    # Poll for updates (with cursor for incremental reads)
    events = tracker.get_events(since=15)  # events after index 15
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Thread-safe, append-only event log for campaign progress."""

    def __init__(self, campaign_id: str) -> None:
        self.campaign_id = campaign_id
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._flush_callback: Any | None = None  # set by function_app to persist

    def set_flush_callback(self, callback) -> None:
        """Set a callback(campaign_id, events) called after each event."""
        self._flush_callback = callback

    @staticmethod
    def _clean_title(title: str) -> str:
        """Strip LLM preamble and numbering from hypothesis titles."""
        import re
        # Remove "HYPOTHESIS N —" or "HYPOTHESIS N:" prefix
        title = re.sub(r"^HYPOTHESIS\s+\d+\s*[—:\-]+\s*", "", title, flags=re.IGNORECASE)
        # Remove "Below are N prioritized..." preamble
        if title.lower().startswith("below are") or title.lower().startswith("if you'd like"):
            return ""
        # Remove leading numbering like "1." or "1)"
        title = re.sub(r"^\d+[.)]\s*", "", title)
        return title.strip()

    def log(self, event: str, **kwargs: Any) -> None:
        """Append a timestamped event to the log."""
        # Clean hypothesis titles before storing
        if "title" in kwargs and kwargs.get("title"):
            kwargs["title"] = self._clean_title(str(kwargs["title"]))

        cleaned = dict(kwargs)

        entry = {
            "seq": len(self._events),
            "t": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **cleaned,
        }
        with self._lock:
            self._events.append(entry)

        logger.debug("[%s] progress: %s %s", self.campaign_id, event, kwargs)

        # Fire flush callback (non-blocking, swallow errors)
        if self._flush_callback:
            try:
                self._flush_callback(self.campaign_id, self._events)
            except Exception as exc:
                logger.debug("Progress flush failed: %s", exc)

    def get_events(self, since: int = 0) -> list[dict[str, Any]]:
        """Get events after sequence number `since`. Returns all if since=0."""
        with self._lock:
            return list(self._events[since:])

    def get_all(self) -> list[dict[str, Any]]:
        """Get the full event log."""
        with self._lock:
            return list(self._events)

    @property
    def count(self) -> int:
        return len(self._events)

    def summary(self) -> dict[str, Any]:
        """Build a compact status summary from the event log."""
        with self._lock:
            events = list(self._events)

        if not events:
            return {"phase": "pending", "detail": "Waiting to start"}

        # Find current phase
        current_phase = "starting"
        phases_completed: list[str] = []
        total_queries = 0
        total_findings = 0
        hypotheses_count = 0
        last_detail = ""

        current_hypothesis_queries = 0
        hypotheses_tested = 0

        for e in events:
            evt = e["event"]

            if evt == "phase_started":
                current_phase = e.get("phase", current_phase)
                if current_phase == "index_refresh":
                    last_detail = "Discovering environment telemetry and building workspace index."
                elif current_phase == "hypothesize":
                    last_detail = "Analyzing threat landscape and generating prioritized hunt hypotheses."
                elif current_phase == "execute":
                    last_detail = "Executing hunt queries against Sentinel. Testing each hypothesis with targeted KQL."
                elif current_phase == "conclude":
                    last_detail = "Classifying findings by severity and correlating evidence across hypotheses."
                elif current_phase == "deliver":
                    last_detail = "Compiling executive report with findings, MITRE mappings, and recommendations."
                else:
                    last_detail = f"Phase {current_phase} initiated."

            elif evt == "phase_completed":
                phases_completed.append(e.get("phase", ""))
                p = e.get("phase", "")
                detail = e.get("detail", "")
                if p == "index_refresh":
                    last_detail = f"Environment indexed. {detail}" if detail else "Environment index built."
                elif p == "hypothesize":
                    last_detail = f"Hypothesis generation complete. {hypotheses_count} hypotheses prioritized for investigation."
                elif p == "execute":
                    last_detail = f"Execution complete. {total_queries} KQL queries across {hypotheses_count} hypotheses. {total_findings} findings identified."
                elif p == "conclude":
                    last_detail = f"Analysis complete. {total_findings} findings classified and severity-rated."
                elif p == "deliver":
                    last_detail = "Report generated. Full findings and recommendations available."

            elif evt == "query_executed":
                total_queries += 1
                current_hypothesis_queries += 1

            elif evt == "finding_discovered":
                total_findings += 1
                sev = e.get("severity", "").upper()
                title = e.get("title", "")
                last_detail = f"Finding [{sev}]: {title}"

            elif evt == "hypothesis_generated":
                hypotheses_count += 1

            elif evt == "hypothesis_started":
                idx = e.get("index", "")
                total = e.get("total", "")
                title = e.get("title", "")
                techs = e.get("techniques", [])
                tech_str = f" [{', '.join(techs)}]" if techs else ""
                current_hypothesis_queries = 0
                if title:
                    last_detail = f"Investigating hypothesis {idx}/{total}: {title}{tech_str}"
                else:
                    last_detail = f"Investigating hypothesis {idx}/{total}{tech_str}"

            elif evt == "hypothesis_completed":
                idx = e.get("index", "")
                f_count = e.get("findings", 0)
                q_count = e.get("queries", 0)
                hypotheses_tested += 1
                if f_count > 0:
                    last_detail = f"Hypothesis {idx} complete. {q_count} queries executed, {f_count} finding(s) confirmed."
                else:
                    last_detail = f"Hypothesis {idx} complete. {q_count} queries executed, no findings."

            elif evt == "campaign_completed":
                current_phase = "completed"
                findings = e.get("findings", total_findings)
                queries = e.get("queries", total_queries)
                duration = e.get("duration_min", "")
                dur_str = f" Duration: {duration} minutes." if duration else ""
                last_detail = f"Investigation complete. {findings} findings across {queries} queries.{dur_str}"

            elif evt == "campaign_failed":
                current_phase = "failed"
                last_detail = f"Investigation terminated. {e.get('detail', 'Unexpected error encountered.')}"

            elif evt == "budget_update":
                if current_phase == "execute" and hypotheses_tested > 0:
                    last_detail = f"Progress: {hypotheses_tested}/{hypotheses_count} hypotheses tested. {total_queries} queries run, {total_findings} finding(s) so far."

            elif evt == "tool_executed":
                if current_phase not in ("execute",):
                    tool = e.get("tool", "")
                    ms = e.get("ms", 0)
                    if tool == "search_mitre":
                        last_detail = "Querying MITRE ATT&CK knowledge base."
                    elif tool == "check_telemetry":
                        last_detail = "Assessing available telemetry sources."
                    elif tool == "check_landscape":
                        last_detail = "Evaluating current threat landscape."
                    elif tool == "assess_risk":
                        last_detail = "Running risk assessment model."
                    elif tool == "get_sentinel_rule_examples":
                        last_detail = "Retrieving Sentinel detection rule templates."
                    elif tool == "lookup_cve":
                        last_detail = "Looking up CVE vulnerability data."
                    elif tool == "identify_attack_paths":
                        last_detail = "Mapping potential attack paths."
                    else:
                        last_detail = f"Executing {tool}."

        # Build the status line
        phase_label = current_phase.upper().replace("_", " ")
        status_line = f"[{phase_label}] {last_detail}"

        return {
            "phase": current_phase,
            "phases_completed": phases_completed,
            "total_queries": total_queries,
            "total_findings": total_findings,
            "hypotheses": hypotheses_count,
            "events_count": len(events),
            "last_event": events[-1]["event"] if events else "",
            "last_detail": last_detail,
            "status_line": status_line,
        }
