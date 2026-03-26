"""Phase 3: Hunt Execution — runs KQL hunts for each hypothesis with pivoting."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from mssp_hunt_agent.agent.tool_defs import AGENT_TOOLS
from mssp_hunt_agent.hunter.models.campaign import CampaignPhase, CampaignState, PhaseResult
from mssp_hunt_agent.hunter.models.finding import (
    EvidenceChain,
    EvidenceLink,
    FindingClassification,
    FindingSeverity,
    HuntFinding,
)
from mssp_hunt_agent.hunter.models.hypothesis import AutonomousHypothesis
from mssp_hunt_agent.hunter.phases.base import PhaseRunner, _now_iso
from mssp_hunt_agent.hunter.prompts.phase_prompts import build_execute_prompt

logger = logging.getLogger(__name__)


class ExecutePhaseRunner(PhaseRunner):
    """Execute hunts for each hypothesis with pivoting and drill-down.

    This phase runs a nested loop:
    - Outer: iterate over hypotheses (highest priority first)
    - Inner: agent loop per hypothesis (run queries, pivot, correlate)
    """

    def phase_name(self) -> CampaignPhase:
        return CampaignPhase.EXECUTE

    def build_system_prompt(self, state: CampaignState) -> str:
        # This is overridden per-hypothesis in run()
        return ""

    def get_tools(self) -> list[dict[str, Any]]:
        allowed = {"run_kql_query", "validate_kql", "search_mitre", "lookup_cve", "assess_risk", "identify_attack_paths"}
        return [t for t in AGENT_TOOLS if t["function"]["name"] in allowed]

    def get_max_iterations(self, state: CampaignState) -> int:
        return state.config.phase_max_iterations.get("execute", 20)

    def extract_artifacts(self, response_text: str, state: CampaignState) -> dict[str, Any]:
        return {"raw_response": response_text[:2000]}

    def run(self, state: CampaignState) -> PhaseResult:
        """Override base run() to implement nested hypothesis loop."""
        import time

        phase = self.phase_name()
        timeout_minutes = state.config.phase_timeout_minutes.get("execute", 30)
        timeout_seconds = timeout_minutes * 60
        max_iter_per_hypothesis = state.config.phase_max_iterations.get("execute", 20)

        result = PhaseResult(
            phase=phase,
            status="running",
            started_at=_now_iso(),
        )

        all_findings: list[HuntFinding] = []
        start_time = time.monotonic()
        env_summary = state.environment_index.rich_summary() if state.environment_index else {}

        for h_idx, hypothesis in enumerate(state.hypotheses):
            # Check overall budget
            elapsed = time.monotonic() - start_time
            if elapsed > timeout_seconds:
                result.errors.append(f"Execute phase timed out after {elapsed:.0f}s")
                break
            if not self.budget.can_query():
                result.errors.append("Query budget exhausted")
                break

            logger.info(
                "Executing hypothesis %d/%d: %s (priority=%.2f)",
                h_idx + 1, len(state.hypotheses), hypothesis.title, hypothesis.priority_score,
            )
            hypothesis.status = "in_progress"

            # Build per-hypothesis prompt
            prior_summary = ""
            if all_findings:
                prior_summary = "\n".join(
                    f"- [{f.severity.value}] {f.title}: {f.classification.value}"
                    for f in all_findings
                )

            system_prompt = build_execute_prompt(
                client_name=state.config.client_name,
                hypothesis=hypothesis.model_dump(exclude={"status", "reason_skipped"}),
                env_summary=env_summary,
                budget=self.budget.snapshot(),
                prior_findings_summary=prior_summary,
                auto_pivot=state.config.auto_pivot,
                max_pivot_depth=state.config.max_pivot_depth,
                learning_context=state.learning_context or None,
            )

            user_message = (
                f"Execute the hunt for hypothesis: {hypothesis.title}\n\n"
                f"Description: {hypothesis.description}\n"
                f"KQL approach: {hypothesis.kql_approach}\n"
                f"Available tables: {', '.join(hypothesis.available_tables)}\n"
                f"Time range: {hypothesis.time_range}\n\n"
                f"Start hunting. Run queries, analyze results, pivot on findings, "
                f"and provide your final assessment."
            )

            messages: list[dict[str, Any]] = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ]

            tools = self.get_tools()
            hypothesis_findings: list[HuntFinding] = []

            for iteration in range(max_iter_per_hypothesis):
                elapsed = time.monotonic() - start_time
                if elapsed > timeout_seconds or not self.budget.can_call_llm():
                    break

                # Context compression
                if self.context_manager.should_compress(messages):
                    try:
                        summary_resp = self.llm.chat_with_tools(
                            messages=[
                                {"role": "system", "content": "Summarize observations concisely."},
                                {"role": "user", "content": self.context_manager.build_compression_prompt(messages)},
                            ],
                            tools=[], max_tokens=2048,
                        )
                        messages = self.context_manager.compress(
                            messages, summary_resp.get("content", "")
                        )
                    except Exception:
                        pass

                # LLM call (retry up to 3 times with backoff)
                response = None
                for attempt in range(3):
                    try:
                        response = self.llm.chat_with_tools(
                            messages=messages, tools=tools,
                            max_tokens=4096,
                        )
                        break
                    except Exception as exc:
                        if attempt < 2:
                            import time as _time
                            wait = (attempt + 1) * 5
                            logger.warning(
                                "LLM call failed for %s (attempt %d/3), retrying in %ds: %s",
                                hypothesis.hypothesis_id, attempt + 1, wait, exc,
                            )
                            _time.sleep(wait)
                        else:
                            result.errors.append(
                                f"LLM failed on hypothesis {hypothesis.hypothesis_id} after 3 attempts: {exc}"
                            )
                if response is None:
                    break

                content = response.get("content")
                tool_calls = response.get("tool_calls")

                # Track LLM token usage
                usage = response.get("usage", {})
                tokens_used = usage.get("total_tokens", 0)
                if tokens_used:
                    self.budget.record_llm_tokens(tokens_used)
                    result.llm_tokens_used += tokens_used

                # Final response — extract findings
                if content and not tool_calls:
                    findings = _extract_findings_from_response(
                        content, hypothesis, state.campaign_id,
                    )
                    hypothesis_findings.extend(findings)
                    result.iterations += iteration + 1
                    break

                # Process tool calls
                if tool_calls:
                    messages.append({
                        "role": "assistant",
                        "content": content,
                        "tool_calls": tool_calls,
                    })
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        tool_name = func.get("name", "")
                        args_str = func.get("arguments", "{}")
                        tc_id = tc.get("id", "")
                        try:
                            args = json.loads(args_str) if isinstance(args_str, str) else args_str
                        except Exception:
                            args = {}

                        t0 = time.monotonic()
                        try:
                            result_str = self.tool_executor.execute(tool_name, args)
                        except Exception as tool_exc:
                            result_str = json.dumps({"error": f"Tool {tool_name} failed: {tool_exc}"})
                            logger.warning("Tool %s execution failed: %s", tool_name, tool_exc)

                        result.tool_calls += 1
                        self.budget.record_tool_call()
                        if tool_name == "run_kql_query":
                            result.kql_queries_run += 1
                            hypothesis.queries_executed += 1
                            self.budget.record_query()

                        # Truncate with warning
                        truncated = result_str[:8000]
                        if len(result_str) > 8000:
                            truncated += (
                                "\n\n[WARNING: Results truncated. Original size: "
                                f"{len(result_str)} chars. Use filters or reduce "
                                "max_results for complete data.]"
                            )
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": truncated,
                        })

                if not content and not tool_calls:
                    break

            else:
                # Max iterations reached — force a final response
                messages.append({
                    "role": "system",
                    "content": (
                        "Maximum tool calls reached for this hypothesis. "
                        "Provide your final assessment now: classification, "
                        "confidence, and key evidence found."
                    ),
                })
                try:
                    final = self.llm.chat_with_tools(messages=messages, tools=[], max_tokens=4096)
                    final_text = final.get("content", "")
                    if final_text:
                        findings = _extract_findings_from_response(
                            final_text, hypothesis, state.campaign_id,
                        )
                        hypothesis_findings.extend(findings)
                except Exception:
                    pass

            # Wrap up hypothesis
            hypothesis.status = "completed"
            hypothesis.findings_count = len(hypothesis_findings)
            all_findings.extend(hypothesis_findings)

        # Store findings on campaign state
        state.findings.extend(all_findings)

        result.status = "success" if not result.errors else "partial"
        result.completed_at = _now_iso()
        result.summary = (
            f"Executed {len(state.hypotheses)} hypotheses, "
            f"found {len(all_findings)} findings "
            f"({result.kql_queries_run} KQL queries)"
        )
        result.artifacts = {
            "findings_count": len(all_findings),
            "hypotheses_executed": sum(1 for h in state.hypotheses if h.status == "completed"),
        }
        return result


def _extract_findings_from_response(
    text: str,
    hypothesis: AutonomousHypothesis,
    campaign_id: str,
) -> list[HuntFinding]:
    """Extract findings from the LLM's final hunt response.

    Tries structured JSON extraction first (from ```json blocks),
    then falls back to regex-based extraction from free text.
    """
    import re

    # --- Attempt 1: Structured JSON extraction ---
    parsed = _try_parse_finding_json(text)
    if parsed:
        return [_build_finding_from_json(parsed, hypothesis, campaign_id, text)]

    # --- Attempt 2: Regex-based fallback ---
    text_lower = text.lower()

    # Classification — use word boundary matching to avoid false matches
    classification = FindingClassification.INCONCLUSIVE
    for pattern, cls in [
        (r"\brequires?[_ ]escalation\b", FindingClassification.REQUIRES_ESCALATION),
        (r"\btrue[_ ]positive\b", FindingClassification.TRUE_POSITIVE),
        (r"\bfalse[_ ]positive\b", FindingClassification.FALSE_POSITIVE),
    ]:
        if re.search(pattern, text_lower):
            classification = cls
            break

    # Severity — require proximity to severity-related context
    severity = FindingSeverity.INFORMATIONAL
    severity_match = re.search(
        r"severity[:\s]*[\"']?(critical|high|medium|low|informational)",
        text_lower,
    )
    if severity_match:
        severity = FindingSeverity(severity_match.group(1))
    elif "critical" in text_lower and classification == FindingClassification.TRUE_POSITIVE:
        severity = FindingSeverity.CRITICAL

    # Confidence — extract numeric value after "confidence" keyword
    confidence = 0.5
    conf_match = re.search(r"confidence[:\s]+(\d+\.?\d*)\s*%?", text_lower)
    if conf_match:
        val = float(conf_match.group(1))
        confidence = val / 100.0 if val > 1.0 else val
        confidence = min(1.0, max(0.0, confidence))

    # Extract MITRE techniques from text (supplement hypothesis techniques)
    text_techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
    all_techniques = list(dict.fromkeys(hypothesis.mitre_techniques + text_techniques))

    # Always create a finding (even for false positives — they're useful in reports)
    evidence_chain = EvidenceChain(
        chain_id=f"EC-{uuid.uuid4().hex[:8]}",
        narrative=text[:3000],
    )

    findings = [HuntFinding(
        finding_id=f"F-{uuid.uuid4().hex[:8]}",
        hypothesis_id=hypothesis.hypothesis_id,
        campaign_id=campaign_id,
        title=f"Hunt result: {hypothesis.title}",
        description=text[:2000],
        classification=classification,
        severity=severity,
        confidence=confidence,
        created_at=_now_iso(),
        mitre_techniques=all_techniques,
        mitre_tactics=hypothesis.mitre_tactics,
        evidence_chain=evidence_chain,
    )]

    return findings


def _try_parse_finding_json(text: str) -> dict | None:
    """Try to extract a structured finding JSON from ```json blocks or raw JSON."""
    import re

    # Look for ```json blocks
    json_blocks = re.findall(r"```json\s*\n(.*?)```", text, re.DOTALL)
    for block in json_blocks:
        try:
            data = json.loads(block.strip())
            if isinstance(data, dict) and "classification" in data:
                return data
        except json.JSONDecodeError:
            continue

    # Try parsing last JSON-like block in text
    brace_blocks = re.findall(r"\{[^{}]*\"classification\"[^{}]*\}", text, re.DOTALL)
    for block in reversed(brace_blocks):
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            continue

    return None


def _build_finding_from_json(
    data: dict,
    hypothesis: AutonomousHypothesis,
    campaign_id: str,
    full_text: str,
) -> HuntFinding:
    """Build a HuntFinding from structured JSON data."""
    # Classification
    cls_str = data.get("classification", "inconclusive").lower().replace(" ", "_")
    try:
        classification = FindingClassification(cls_str)
    except ValueError:
        classification = FindingClassification.INCONCLUSIVE

    # Severity
    sev_str = data.get("severity", "informational").lower()
    try:
        severity = FindingSeverity(sev_str)
    except ValueError:
        severity = FindingSeverity.INFORMATIONAL

    # Confidence
    confidence = float(data.get("confidence", 0.5))
    if confidence > 1.0:
        confidence = confidence / 100.0
    confidence = min(1.0, max(0.0, confidence))

    # MITRE techniques — merge from JSON + hypothesis
    json_techniques = data.get("mitre_techniques", [])
    all_techniques = list(dict.fromkeys(hypothesis.mitre_techniques + json_techniques))

    # Build evidence chain with structured links
    evidence_steps = data.get("evidence_steps", [])
    links: list[EvidenceLink] = []
    for step in evidence_steps:
        links.append(EvidenceLink(
            evidence_id=f"EL-{uuid.uuid4().hex[:6]}",
            source_type="kql_query",
            query_text=str(step.get("query_or_action", "")),
            result_summary=step.get("result_summary", ""),
            key_observations=[
                obs for obs in [
                    step.get("result_summary", ""),
                    step.get("significance", ""),
                ] if obs
            ],
        ))

    narrative = data.get("narrative", full_text[:3000])
    evidence_chain = EvidenceChain(
        chain_id=f"EC-{uuid.uuid4().hex[:8]}",
        narrative=narrative,
        links=links,
    )

    title = data.get("title", f"Hunt result: {hypothesis.title}")

    # affected_entities: model expects dict[str, list[str]], JSON may provide list[str]
    raw_affected = data.get("affected_entities", {})
    if isinstance(raw_affected, list):
        affected = {"entities": raw_affected}
    elif isinstance(raw_affected, dict):
        affected = raw_affected
    else:
        affected = {}

    return HuntFinding(
        finding_id=f"F-{uuid.uuid4().hex[:8]}",
        hypothesis_id=hypothesis.hypothesis_id,
        campaign_id=campaign_id,
        title=title,
        description=full_text[:2000],
        classification=classification,
        severity=severity,
        confidence=confidence,
        created_at=_now_iso(),
        mitre_techniques=all_techniques,
        mitre_tactics=hypothesis.mitre_tactics,
        affected_entities=affected,
        recommendations=data.get("recommendations", []),
        evidence_chain=evidence_chain,
    )
