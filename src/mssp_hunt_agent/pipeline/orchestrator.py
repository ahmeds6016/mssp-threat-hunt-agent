"""Orchestrator — coordinate the full pipeline from intake to audit."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mssp_hunt_agent.adapters.base import SIEMAdapter
from mssp_hunt_agent.adapters.sentinel.mock import MockSentinelAdapter
from mssp_hunt_agent.adapters.intel.base import ThreatIntelAdapter
from mssp_hunt_agent.adapters.intel.cache import CachedIntelAdapter
from mssp_hunt_agent.adapters.intel.factory import build_intel_adapter
from mssp_hunt_agent.adapters.intel.mock import MockThreatIntelAdapter
from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, HuntPlan
from mssp_hunt_agent.models.input_models import HuntInput
from mssp_hunt_agent.models.ioc_models import IOCBatch, IOCHuntInput, IOCSweepReport, IOCSweepResult
from mssp_hunt_agent.models.profile_models import ClientTelemetryProfile, ProfileInput
from mssp_hunt_agent.models.report_models import (
    AnalystReport,
    ConfidenceAssessment,
    ExecutiveSummary,
    RunAuditRecord,
)
from mssp_hunt_agent.models.result_models import EnrichmentRecord, QueryResult
from mssp_hunt_agent.pipeline import (
    audit as audit_mod,
    enrichment as enrichment_mod,
    executor as executor_mod,
    intake as intake_mod,
    planner as planner_mod,
    query_safety as safety_mod,
    reasoning as reasoning_mod,
    reporting as reporting_mod,
)
from mssp_hunt_agent.pipeline import ioc_intake as ioc_intake_mod
from mssp_hunt_agent.pipeline import ioc_planner as ioc_planner_mod
from mssp_hunt_agent.pipeline import ioc_analyzer as ioc_analyzer_mod
from mssp_hunt_agent.pipeline import profile_engine as profile_engine_mod
from mssp_hunt_agent.policy.models import ActionCategory, PolicyAction
from mssp_hunt_agent.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class PipelineResult:
    """Bag of all artefacts produced by a pipeline run."""

    def __init__(self) -> None:
        self.hunt_input: HuntInput | None = None
        self.hunt_plan: HuntPlan | None = None
        self.query_results: list[QueryResult] = []
        self.enrichments: list[EnrichmentRecord] = []
        self.executive_summary: ExecutiveSummary | None = None
        self.analyst_report: AnalystReport | None = None
        self.output_dir: Path | None = None
        self.stopped_at: str | None = None  # which stage the user stopped at
        self.errors: list[str] = []
        self.pipeline_steps: list[dict] = []

    def _log_step(self, name: str, status: str = "completed") -> None:
        self.pipeline_steps.append({
            "step": name,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


ApprovalCallback = Callable[[HuntPlan], bool]
"""Callable that presents the plan to the analyst and returns True to proceed."""


def run_pipeline(
    hunt_input: HuntInput,
    config: HuntAgentConfig,
    approval_callback: ApprovalCallback | None = None,
    plan_only: bool = False,
    client_profile: ClientTelemetryProfile | None = None,
) -> PipelineResult:
    """Execute the full (or partial) hunt pipeline."""
    result = PipelineResult()
    result.hunt_input = hunt_input
    run_id = f"RUN-{uuid.uuid4().hex[:8]}"
    execution_mode = "mock" if config.mock_mode else "live"

    # ── 1. Intake ─────────────────────────────────────────────────────
    logger.info("[1/7] Intake — validating inputs")
    hunt_input = intake_mod.validate_and_normalise(hunt_input)
    telemetry = intake_mod.classify_telemetry(hunt_input)
    result._log_step("intake")

    # ── 2. Plan ───────────────────────────────────────────────────────
    logger.info("[2/7] Planning — generating hunt plan")
    plan = planner_mod.generate_plan(hunt_input, telemetry, client_profile=client_profile)
    result.hunt_plan = plan
    result._log_step("planning")

    # ── 2b. Policy check ──────────────────────────────────────────────
    if config.policy_engine_enabled:
        policy = PolicyEngine(config)
        query_count = sum(len(s.queries) for s in plan.hunt_steps)
        policy_decision = policy.evaluate_plan(
            client_name=plan.client_name,
            query_count=query_count,
            hunt_type=plan.hunt_type,
        )
        result._log_step("policy_check", policy_decision.action)
        if policy_decision.action == PolicyAction.AUTO_DENY.value:
            result.stopped_at = "policy_denied"
            result.errors.append(f"Policy denied: {policy_decision.reason}")
            result._log_step("policy_denied")
            return result
        if policy_decision.action == PolicyAction.AUTO_APPROVE.value:
            config = config.model_copy(update={"approval_required": False})

    # ── 3. Query safety ───────────────────────────────────────────────
    logger.info("[3/7] Query safety — checking guardrails")
    for step in plan.hunt_steps:
        for query in step.queries:
            flags = safety_mod.check_query(query)
            query.safety_flags = flags
    result._log_step("query_safety")

    if plan_only:
        result.stopped_at = "plan_only"
        result._log_step("plan_only_stop")
        _build_reports_and_save(result, plan, [], [], config, run_id, execution_mode, hunt_input)
        return result

    # ── 4. Approval ───────────────────────────────────────────────────
    if config.approval_required:
        logger.info("[4/7] Approval — awaiting analyst decision")
        if approval_callback and not approval_callback(plan):
            result.stopped_at = "approval_denied"
            result._log_step("approval", "denied")
            _build_reports_and_save(result, plan, [], [], config, run_id, execution_mode, hunt_input)
            return result
        # Auto-approve all queries that passed safety (no errors)
        _auto_approve_safe_queries(plan)
        result._log_step("approval")
    else:
        _auto_approve_safe_queries(plan)
        result._log_step("approval", "auto")

    # ── 5. Execute ────────────────────────────────────────────────────
    logger.info("[5/8] Execution — running approved queries")
    adapter: SIEMAdapter = _get_siem_adapter(config)
    query_results = executor_mod.execute_approved_queries(plan, adapter)
    result.query_results = query_results
    result._log_step("execution")

    # ── 6. Enrichment ─────────────────────────────────────────────────
    logger.info("[6/8] Enrichment — extracting and enriching entities")
    entities = enrichment_mod.extract_entities(query_results)
    ti_provider: ThreatIntelAdapter = _get_ti_provider(config)
    enrichments = enrichment_mod.enrich_entities(entities, ti_provider)
    result.enrichments = enrichments
    result._log_step("enrichment")

    # ── 7. Pivots (optional) ──────────────────────────────────────────
    if config.allow_pivots:
        # Policy check for pivots
        if config.policy_engine_enabled:
            pivot_policy = PolicyEngine(config)
            pivot_decision = pivot_policy.evaluate_autonomous_action(
                ActionCategory.PIVOT_QUERY.value,
                client_name=plan.client_name,
                context={"query_count": config.max_pivot_queries},
            )
            if pivot_decision.action == PolicyAction.AUTO_DENY.value:
                result._log_step("pivot_execution", "policy_denied")
                config = config.model_copy(update={"allow_pivots": False})

        logger.info("[7/8] Pivots — generating follow-up queries")
        from mssp_hunt_agent.pipeline.pivot_engine import PivotEngine
        from mssp_hunt_agent.models.hunt_models import HuntStep

        engine = PivotEngine(max_pivots=config.max_pivot_queries)
        pivot_queries = engine.generate_pivots(plan, query_results, enrichments)
        if pivot_queries:
            for pq in pivot_queries:
                pq.approved = True
            pivot_step = HuntStep(
                step_number=len(plan.hunt_steps) + 1,
                description="Pivot queries (auto-generated)",
                queries=pivot_queries,
                success_criteria="Pivot context gathered",
                next_if_positive="Incorporate into findings",
                next_if_negative="Close pivot",
            )
            pivot_plan = plan.model_copy(update={"hunt_steps": [pivot_step]})
            pivot_results = executor_mod.execute_approved_queries(pivot_plan, adapter)
            query_results.extend(pivot_results)
            result.query_results = query_results

            # Re-enrich with pivot results
            pivot_entities = enrichment_mod.extract_entities(pivot_results)
            pivot_enrichments = enrichment_mod.enrich_entities(pivot_entities, ti_provider)
            enrichments.extend(pivot_enrichments)
            result.enrichments = enrichments
            result._log_step("pivot_execution")
        else:
            result._log_step("pivot_execution", "no_pivots_generated")
    else:
        result._log_step("pivot_execution", "disabled")

    # ── 8. Reasoning & reporting ──────────────────────────────────────
    logger.info("[8/8] Reasoning & reporting")
    _build_reports_and_save(result, plan, query_results, enrichments, config, run_id, execution_mode, hunt_input)

    return result


# ── helpers ───────────────────────────────────────────────────────────

def _auto_approve_safe_queries(plan: HuntPlan) -> None:
    for step in plan.hunt_steps:
        for q in step.queries:
            if not safety_mod.has_errors(q.safety_flags):
                q.approved = True


def _get_real_sentinel_adapter(config: HuntAgentConfig) -> SIEMAdapter:
    from mssp_hunt_agent.adapters.sentinel.auth import SentinelAuth
    from mssp_hunt_agent.adapters.sentinel.api_client import SentinelQueryClient
    from mssp_hunt_agent.adapters.sentinel.adapter import SentinelAdapter

    auth = SentinelAuth(
        tenant_id=config.azure_tenant_id,
        client_id=config.azure_client_id,
        client_secret=config.azure_client_secret,
    )
    client = SentinelQueryClient(
        workspace_id=config.sentinel_workspace_id,
        auth=auth,
        timeout=config.query_timeout_seconds,
    )
    return SentinelAdapter(client, max_results=config.max_query_results)


def _get_siem_adapter(config: HuntAgentConfig) -> SIEMAdapter:
    """Build the appropriate SIEM adapter (Sentinel real or mock)."""
    if config.adapter_mode == "real":
        adapter = _get_real_sentinel_adapter(config)
        if not adapter.test_connection():
            raise RuntimeError(
                "Cannot connect to Microsoft Sentinel / Log Analytics. "
                "Check AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, "
                "and SENTINEL_WORKSPACE_ID."
            )
        return adapter
    return MockSentinelAdapter()


def _get_ti_provider(config: HuntAgentConfig) -> ThreatIntelAdapter:
    """Build the appropriate threat-intel adapter from config."""
    return build_intel_adapter(config)


def _get_llm_adapter(config: HuntAgentConfig):
    """Build the appropriate LLM adapter from config."""
    from mssp_hunt_agent.adapters.llm.base import LLMAdapter

    if config.azure_openai_endpoint and config.azure_openai_key:
        from mssp_hunt_agent.adapters.llm.azure_openai import AzureOpenAIAdapter
        return AzureOpenAIAdapter(
            endpoint=config.azure_openai_endpoint,
            api_key=config.azure_openai_key,
            deployment=config.azure_openai_deployment,
            api_version=config.azure_openai_api_version,
        )
    # Fallback to mock when LLM is enabled but no Azure credentials
    from mssp_hunt_agent.adapters.llm.mock import MockLLMAdapter
    logger.warning("LLM enabled but no Azure OpenAI credentials; using MockLLMAdapter")
    return MockLLMAdapter()


def _build_reports_and_save(
    result: PipelineResult,
    plan: HuntPlan,
    query_results: list[QueryResult],
    enrichments: list[EnrichmentRecord],
    config: HuntAgentConfig,
    run_id: str,
    execution_mode: str,
    hunt_input: HuntInput,
) -> None:
    """Build executive + analyst reports, render markdown, save artefacts."""
    if config.llm_enabled:
        from mssp_hunt_agent.pipeline import llm_reasoning as llm_mod
        llm_adapter = _get_llm_adapter(config)
        findings, evidence_items, confidence = llm_mod.llm_analyse(
            plan, query_results, enrichments, llm_adapter,
        )
    else:
        findings, evidence_items, confidence = reasoning_mod.analyse(plan, query_results, enrichments)

    exec_summary = ExecutiveSummary(
        client_name=plan.client_name,
        hunt_objective=plan.objective,
        hunt_type=plan.hunt_type,
        time_range=hunt_input.time_range,
        execution_mode=execution_mode,
        scope_summary=(
            f"{plan.hunt_type.capitalize()} hunt for {plan.client_name} "
            f"covering {hunt_input.time_range}. "
            f"Telemetry readiness: {plan.telemetry_assessment.readiness.value}."
        ),
        key_findings=[f.title for f in findings] or ["No high-confidence findings at this stage"],
        risk_assessment=confidence.rationale,
        recommended_next_steps=_recommend_next_steps(findings, plan),
        limitations=confidence.limiting_factors,
    )

    attack_mapping = []
    for hyp in plan.hypotheses:
        attack_mapping.append({
            "hypothesis": hyp.description,
            "tactics": hyp.attack_tactics,
            "techniques": hyp.attack_techniques,
            "source": hyp.technique_source,
        })

    analyst_report = AnalystReport(
        client_name=plan.client_name,
        hunt_type=plan.hunt_type,
        plan_id=plan.plan_id,
        execution_mode=execution_mode,
        hunt_objective=plan.objective,
        hunt_hypothesis=plan.hypotheses[0].description if plan.hypotheses else "Not specified",
        time_range=hunt_input.time_range,
        data_sources=list(hunt_input.available_data_sources),
        telemetry_gaps=list(hunt_input.telemetry_gaps),
        attack_mapping=attack_mapping,
        telemetry_readiness=plan.telemetry_assessment.readiness.value,
        telemetry_rationale=plan.telemetry_assessment.rationale,
        findings=findings,
        evidence_items=evidence_items,
        confidence_assessment=confidence,
        escalation_recommendation=_escalation_recommendation(findings),
        detection_engineering_followups=_detection_followups(plan, findings),
        additional_hunt_pivots=_additional_pivots(plan),
        gaps=plan.telemetry_assessment.missing_sources,
        analyst_notes=hunt_input.analyst_notes,
    )

    result.executive_summary = exec_summary
    result.analyst_report = analyst_report

    # Render markdown
    exec_md = reporting_mod.render_executive_summary(exec_summary)
    analyst_md = reporting_mod.render_analyst_report(analyst_report)
    evidence_md = reporting_mod.render_evidence_table(analyst_report)

    # Build audit record
    audit_record = RunAuditRecord(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        client_name=plan.client_name,
        hunt_type=plan.hunt_type,
        execution_mode=execution_mode,
        input_payload=hunt_input.model_dump(),
        hunt_plan=plan.model_dump(),
        approved_queries=[
            q.model_dump()
            for step in plan.hunt_steps
            for q in step.queries
            if q.approved
        ],
        query_results=[qr.model_dump() for qr in query_results],
        enrichment_results=[e.model_dump() for e in enrichments],
        executive_summary=exec_summary.model_dump(),
        analyst_report=analyst_report.model_dump(),
        errors=result.errors,
        pipeline_steps=result.pipeline_steps,
    )

    run_folder = audit_mod.save_run(audit_record, exec_md, analyst_md, evidence_md, config.output_dir)
    result.output_dir = run_folder
    result._log_step("reporting_and_audit")
    logger.info("Run artefacts saved to %s", run_folder)

    # ── Persistence ──────────────────────────────────────────────────
    if config.persist:
        _persist_hypothesis_run(
            config, run_id, plan, findings, query_results, execution_mode,
            str(run_folder),
        )
    if config.sharepoint_enabled:
        _upload_reports_to_sharepoint(config, plan.client_name, exec_md, analyst_md)


def _recommend_next_steps(findings: list, plan: HuntPlan) -> list[str]:
    steps = []
    for f in findings:
        if f.confidence in ("medium", "high"):
            steps.append(f"Triage finding: {f.title}")
    if plan.telemetry_assessment.readiness.value != "Green":
        steps.append("Address telemetry gaps before next hunt iteration")
    steps.append("Review detection engineering follow-up recommendations")
    steps.append("Schedule follow-up hunt within 30 days")
    return steps


def _escalation_recommendation(findings: list) -> str:
    high = [f for f in findings if f.confidence == "high"]
    medium = [f for f in findings if f.confidence == "medium"]
    if high:
        return (
            f"ESCALATE IMMEDIATELY — {len(high)} high-confidence finding(s). "
            "Engage incident response and notify client."
        )
    if medium:
        return (
            f"ESCALATE TO SENIOR ANALYST — {len(medium)} medium-confidence finding(s) "
            "require further investigation within 24 hours."
        )
    return "No immediate escalation required. Document results and schedule follow-up."


def _detection_followups(plan: HuntPlan, findings: list) -> list[str]:
    followups = []
    for hyp in plan.hypotheses:
        for tactic in hyp.attack_tactics:
            followups.append(
                f"Create or tune detection rule covering {tactic} "
                f"based on hunt hypothesis '{hyp.description[:60]}...'"
            )
    followups.append("Review and update correlation rules based on observed false positives")
    followups.append("Document new IOCs from this hunt in the detection rule backlog")
    return followups


def _additional_pivots(plan: HuntPlan) -> list[str]:
    pivots = [
        "Cross-reference flagged users with HR/termination lists",
        "Check flagged IPs against historical baseline for this client",
        "Run follow-up hunt with expanded time window if initial results are borderline",
    ]
    if plan.telemetry_assessment.missing_sources:
        pivots.append(
            f"Re-hunt after onboarding missing sources: "
            f"{', '.join(plan.telemetry_assessment.missing_sources[:3])}"
        )
    return pivots


# =====================================================================
# IOC SWEEP PIPELINE
# =====================================================================


class IOCPipelineResult:
    """Bag of artefacts produced by an IOC sweep run."""

    def __init__(self) -> None:
        self.ioc_input: IOCHuntInput | None = None
        self.ioc_batch: IOCBatch | None = None
        self.hunt_plan: HuntPlan | None = None
        self.pre_enrichments: list[EnrichmentRecord] = []
        self.query_results: list[QueryResult] = []
        self.sweep_result: IOCSweepResult | None = None
        self.ioc_report: IOCSweepReport | None = None
        self.output_dir: Path | None = None
        self.stopped_at: str | None = None
        self.errors: list[str] = []
        self.pipeline_steps: list[dict] = []

    def _log_step(self, name: str, status: str = "completed") -> None:
        self.pipeline_steps.append({
            "step": name,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


def run_ioc_pipeline(
    ioc_input: IOCHuntInput,
    config: HuntAgentConfig,
    approval_callback: ApprovalCallback | None = None,
    plan_only: bool = False,
) -> IOCPipelineResult:
    """Execute the IOC sweep pipeline."""
    result = IOCPipelineResult()
    result.ioc_input = ioc_input
    run_id = f"RUN-IOC-{uuid.uuid4().hex[:8]}"
    execution_mode = "mock" if config.mock_mode else "live"

    # ── 1. IOC Intake — validate, normalize, dedupe ───────────────────
    logger.info("[1/7] IOC Intake — validating and normalizing indicators")
    ioc_batch = ioc_intake_mod.process_iocs(ioc_input.iocs)
    result.ioc_batch = ioc_batch
    result._log_step("ioc_intake")

    if not ioc_batch.valid:
        logger.warning("No valid IOCs after validation. Aborting.")
        result.stopped_at = "no_valid_iocs"
        result.errors.append(f"All {len(ioc_batch.invalid)} IOCs failed validation")
        result._log_step("ioc_intake", "no_valid_iocs")
        return result

    logger.info(
        "IOC intake: %d valid, %d invalid, %d deduped",
        len(ioc_batch.valid), len(ioc_batch.invalid), ioc_batch.dedup_removed,
    )

    # ── 2. Telemetry classification (reuse hypothesis intake) ─────────
    # Build a temporary HuntInput to classify telemetry
    temp_input = HuntInput(
        client_name=ioc_input.client_name,
        hunt_objective=ioc_input.sweep_objective,
        hunt_hypothesis="IOC sweep",
        time_range=ioc_input.time_range,
        available_data_sources=ioc_input.available_data_sources,
        telemetry_gaps=ioc_input.telemetry_gaps,
        hunt_type=ioc_input.hunt_type,
    )
    telemetry = intake_mod.classify_telemetry(temp_input)
    result._log_step("telemetry_classification")

    # ── 3. Optional pre-enrichment ────────────────────────────────────
    pre_enrichments: list[EnrichmentRecord] = []
    if ioc_input.pre_enrich:
        logger.info("[2/7] Pre-enrichment — enriching IOCs before sweep")
        ti_provider = _get_ti_provider(config)
        pre_enrichments = _enrich_ioc_batch(ioc_batch, ti_provider)
        result.pre_enrichments = pre_enrichments
        result._log_step("pre_enrichment")
    else:
        result._log_step("pre_enrichment", "skipped")

    # ── 4. IOC Plan generation ────────────────────────────────────────
    logger.info("[3/7] IOC Planning — generating sweep queries")
    plan = ioc_planner_mod.generate_ioc_plan(ioc_input, ioc_batch, telemetry)
    result.hunt_plan = plan
    result._log_step("ioc_planning")

    # ── 4b. Policy check ─────────────────────────────────────────────
    if config.policy_engine_enabled:
        policy = PolicyEngine(config)
        query_count = sum(len(s.queries) for s in plan.hunt_steps)
        policy_decision = policy.evaluate_plan(
            client_name=ioc_input.client_name,
            query_count=query_count,
            ioc_count=len(ioc_batch.valid),
            hunt_type="ioc_sweep",
        )
        result._log_step("policy_check", policy_decision.action)
        if policy_decision.action == PolicyAction.AUTO_DENY.value:
            result.stopped_at = "policy_denied"
            result.errors.append(f"Policy denied: {policy_decision.reason}")
            result._log_step("policy_denied")
            return result
        if policy_decision.action == PolicyAction.AUTO_APPROVE.value:
            config = config.model_copy(update={"approval_required": False})

    # ── 5. Query safety ───────────────────────────────────────────────
    logger.info("[4/7] Query safety — checking guardrails")
    for step in plan.hunt_steps:
        for query in step.queries:
            flags = safety_mod.check_query(query)
            query.safety_flags = flags
    result._log_step("query_safety")

    if plan_only:
        result.stopped_at = "plan_only"
        result._log_step("plan_only_stop")
        _build_ioc_reports_and_save(
            result, plan, ioc_input, ioc_batch, [], IOCSweepResult(),
            pre_enrichments, config, run_id, execution_mode, telemetry,
        )
        return result

    # ── 6. Approval ───────────────────────────────────────────────────
    if config.approval_required:
        logger.info("[5/7] Approval — awaiting analyst decision")
        if approval_callback and not approval_callback(plan):
            result.stopped_at = "approval_denied"
            result._log_step("approval", "denied")
            _build_ioc_reports_and_save(
                result, plan, ioc_input, ioc_batch, [], IOCSweepResult(),
                pre_enrichments, config, run_id, execution_mode, telemetry,
            )
            return result
        _auto_approve_safe_queries(plan)
        result._log_step("approval")
    else:
        _auto_approve_safe_queries(plan)
        result._log_step("approval", "auto")

    # ── 7. Execute ────────────────────────────────────────────────────
    logger.info("[6/7] Execution — running IOC sweep queries")
    adapter: SIEMAdapter = _get_siem_adapter(config)
    query_results = executor_mod.execute_approved_queries(plan, adapter)
    result.query_results = query_results
    result._log_step("execution")

    # ── 8. Hit analysis ───────────────────────────────────────────────
    logger.info("[7/7] Hit analysis & reporting")
    sweep_result = ioc_analyzer_mod.analyze_sweep_results(
        ioc_batch, query_results, mock_mode=config.mock_mode,
    )
    result.sweep_result = sweep_result

    _build_ioc_reports_and_save(
        result, plan, ioc_input, ioc_batch, query_results, sweep_result,
        pre_enrichments, config, run_id, execution_mode, telemetry,
    )

    return result


# ── IOC helpers ───────────────────────────────────────────────────────


def _enrich_ioc_batch(
    batch: IOCBatch,
    provider: ThreatIntelAdapter,
) -> list[EnrichmentRecord]:
    """Enrich valid IOCs before sweep."""
    records: list[EnrichmentRecord] = []
    dispatch = {
        "ip": provider.enrich_ip,
        "domain": provider.enrich_domain,
        "hash_md5": provider.enrich_hash,
        "hash_sha1": provider.enrich_hash,
        "hash_sha256": provider.enrich_hash,
        "user_agent": provider.enrich_user_agent,
    }
    for ioc in batch.valid:
        fn = dispatch.get(ioc.ioc_type.value)
        if fn:
            try:
                records.append(fn(ioc.normalized_value))
            except Exception as exc:
                logger.warning("Pre-enrichment failed for %s: %s", ioc.normalized_value, exc)
    return records


def _build_ioc_reports_and_save(
    result: IOCPipelineResult,
    plan: HuntPlan,
    ioc_input: IOCHuntInput,
    ioc_batch: IOCBatch,
    query_results: list[QueryResult],
    sweep_result: IOCSweepResult,
    pre_enrichments: list[EnrichmentRecord],
    config: HuntAgentConfig,
    run_id: str,
    execution_mode: str,
    telemetry,
) -> None:
    """Build IOC-specific reports, render, and save artefacts."""
    report = IOCSweepReport(
        client_name=ioc_input.client_name,
        plan_id=plan.plan_id,
        execution_mode=execution_mode,
        sweep_objective=ioc_input.sweep_objective,
        total_iocs_submitted=len(ioc_input.iocs),
        valid_iocs=len(ioc_batch.valid),
        invalid_iocs=len(ioc_batch.invalid),
        dedup_removed=ioc_batch.dedup_removed,
        type_breakdown=ioc_batch.type_counts,
        pre_enrichment_results=pre_enrichments,
        sweep_result=sweep_result,
        time_range=ioc_input.time_range,
        data_sources=list(ioc_input.available_data_sources),
        telemetry_gaps=list(ioc_input.telemetry_gaps),
        telemetry_readiness=plan.telemetry_assessment.readiness.value,
        telemetry_rationale=plan.telemetry_assessment.rationale,
        escalation_recommendation=_ioc_escalation(sweep_result, pre_enrichments),
        benign_explanations=plan.expected_false_positives,
        detection_engineering_followups=_ioc_detection_followups(sweep_result),
        gaps=plan.telemetry_assessment.missing_sources,
        analyst_notes=ioc_input.analyst_notes,
        invalid_ioc_details=[
            {"value": inv.original_value, "ioc_type": inv.ioc_type.value, "reason": inv.validation_note}
            for inv in ioc_batch.invalid
        ],
    )

    result.ioc_report = report

    exec_md = reporting_mod.render_ioc_executive_summary(report)
    analyst_md = reporting_mod.render_ioc_analyst_report(report)

    audit_record = RunAuditRecord(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        client_name=ioc_input.client_name,
        hunt_type=f"ioc_sweep ({ioc_input.hunt_type.value})",
        execution_mode=execution_mode,
        input_payload=ioc_input.model_dump(),
        hunt_plan=plan.model_dump(),
        approved_queries=[
            q.model_dump()
            for step in plan.hunt_steps
            for q in step.queries
            if q.approved
        ],
        query_results=[qr.model_dump() for qr in query_results],
        enrichment_results=[e.model_dump() for e in pre_enrichments],
        executive_summary=report.model_dump(),
        analyst_report=report.model_dump(),
        errors=result.errors,
        pipeline_steps=result.pipeline_steps,
    )

    run_folder = audit_mod.save_run(
        audit_record, exec_md, analyst_md, "", config.output_dir,
    )
    result.output_dir = run_folder
    result._log_step("reporting_and_audit")
    logger.info("IOC sweep artefacts saved to %s", run_folder)

    # ── Persistence ──────────────────────────────────────────────────
    if config.persist:
        _persist_ioc_run(
            config, run_id, ioc_input, ioc_batch, sweep_result,
            query_results, execution_mode, str(run_folder),
        )
    if config.sharepoint_enabled:
        _upload_reports_to_sharepoint(
            config, ioc_input.client_name, exec_md, analyst_md,
        )


def _ioc_escalation(sweep: IOCSweepResult, enrichments: list[EnrichmentRecord]) -> str:
    mal_enriched = [e for e in enrichments if e.verdict == "malicious"]
    hits_with_mal = [h for h in sweep.hits if h.ioc_value in {e.entity_value for e in mal_enriched}]

    if hits_with_mal:
        return (
            f"ESCALATE IMMEDIATELY — {len(hits_with_mal)} IOC(s) with confirmed malicious TI verdict "
            f"found active in the environment. Initiate incident response."
        )
    if sweep.total_hits > 0:
        return (
            f"ESCALATE TO SENIOR ANALYST — {sweep.total_hits} IOC hit(s) detected. "
            f"Triage required within 24 hours."
        )
    return "No IOC hits detected. Document sweep results and monitor for future appearances."


def _ioc_detection_followups(sweep: IOCSweepResult) -> list[str]:
    followups = []
    if sweep.hits:
        followups.append("Add hit IOCs to real-time detection watchlists / blocklists")
        followups.append("Create correlation rules for affected users and hosts")
        for hit in sweep.hits[:3]:
            followups.append(
                f"Investigate {hit.ioc_type} '{hit.ioc_value}' — "
                f"{hit.hit_count} hits across {len(hit.affected_hosts)} host(s)"
            )
    followups.append("Schedule follow-up sweep in 7-14 days for IOCs that had no hits")
    followups.append("Feed confirmed malicious IOCs into SIEM correlation and EDR block rules")
    return followups


# =====================================================================
# CLIENT TELEMETRY PROFILING PIPELINE
# =====================================================================


class ProfilePipelineResult:
    """Bag of artefacts produced by a profile run."""

    def __init__(self) -> None:
        self.profile_input: ProfileInput | None = None
        self.hunt_plan: HuntPlan | None = None
        self.query_results: list[QueryResult] = []
        self.client_profile: ClientTelemetryProfile | None = None
        self.output_dir: Path | None = None
        self.stopped_at: str | None = None
        self.errors: list[str] = []
        self.pipeline_steps: list[dict] = []

    def _log_step(self, name: str, status: str = "completed") -> None:
        self.pipeline_steps.append({
            "step": name,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


def run_profile_pipeline(
    profile_input: ProfileInput,
    config: HuntAgentConfig,
    approval_callback: ApprovalCallback | None = None,
    plan_only: bool = False,
) -> ProfilePipelineResult:
    """Execute the client telemetry profiling pipeline."""
    result = ProfilePipelineResult()
    result.profile_input = profile_input
    run_id = f"RUN-PROF-{uuid.uuid4().hex[:8]}"
    execution_mode = "mock" if config.mock_mode else "live"

    # ── 1. Generate profiling plan ────────────────────────────────────
    logger.info("[1/5] Profile Planning — generating profiling queries")
    plan = profile_engine_mod.generate_profile_plan(profile_input)
    result.hunt_plan = plan
    result._log_step("profile_planning")

    # ── 2. Query safety ───────────────────────────────────────────────
    logger.info("[2/5] Query safety — checking guardrails")
    for step in plan.hunt_steps:
        for query in step.queries:
            flags = safety_mod.check_query(query)
            query.safety_flags = flags
    result._log_step("query_safety")

    if plan_only:
        result.stopped_at = "plan_only"
        result._log_step("plan_only_stop")
        return result

    # ── 3. Approval ───────────────────────────────────────────────────
    if config.approval_required:
        logger.info("[3/5] Approval — awaiting analyst decision")
        if approval_callback and not approval_callback(plan):
            result.stopped_at = "approval_denied"
            result._log_step("approval", "denied")
            return result
        _auto_approve_safe_queries(plan)
        result._log_step("approval")
    else:
        _auto_approve_safe_queries(plan)
        result._log_step("approval", "auto")

    # ── 4. Execute ────────────────────────────────────────────────────
    logger.info("[4/5] Execution — running profiling queries")
    adapter: SIEMAdapter = _get_siem_adapter(config)
    query_results = executor_mod.execute_approved_queries(plan, adapter)
    result.query_results = query_results
    result._log_step("execution")

    # ── 5. Profile assembly ───────────────────────────────────────────
    logger.info("[5/5] Profile assembly — building client telemetry profile")
    discovered_sources = profile_engine_mod.parse_profile_results(
        query_results, profile_input, mock_mode=config.mock_mode,
    )
    capabilities = profile_engine_mod.classify_capabilities(
        discovered_sources, profile_input.hunt_types_of_interest,
    )
    profile = profile_engine_mod.build_profile(
        profile_input, discovered_sources, capabilities, execution_mode,
    )
    result.client_profile = profile
    result._log_step("profile_assembly")

    # ── Save artefacts ────────────────────────────────────────────────
    _save_profile_artefacts(result, profile, profile_input, config, run_id, execution_mode)

    return result


def _save_profile_artefacts(
    result: ProfilePipelineResult,
    profile: ClientTelemetryProfile,
    profile_input: ProfileInput,
    config: HuntAgentConfig,
    run_id: str,
    execution_mode: str,
) -> None:
    """Render and save profile artefacts."""
    import json as _json

    profile_md = reporting_mod.render_profile_report(profile)

    audit_record = RunAuditRecord(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        client_name=profile_input.client_name,
        hunt_type="profile",
        execution_mode=execution_mode,
        input_payload=profile_input.model_dump(),
        hunt_plan=result.hunt_plan.model_dump() if result.hunt_plan else {},
        approved_queries=[
            q.model_dump()
            for step in (result.hunt_plan.hunt_steps if result.hunt_plan else [])
            for q in step.queries
            if q.approved
        ],
        query_results=[qr.model_dump() for qr in result.query_results],
        enrichment_results=[],
        executive_summary={},
        analyst_report={},
        errors=result.errors,
        pipeline_steps=result.pipeline_steps,
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_client = profile_input.client_name.replace(" ", "_").lower()
    run_folder = config.output_dir / f"{ts}_{safe_client}_profile"
    run_folder.mkdir(parents=True, exist_ok=True)

    (run_folder / "client_telemetry_profile.json").write_text(
        profile.model_dump_json(indent=2), encoding="utf-8"
    )
    (run_folder / "client_telemetry_profile.md").write_text(
        profile_md, encoding="utf-8"
    )
    (run_folder / "run_trace.json").write_text(
        audit_record.model_dump_json(indent=2), encoding="utf-8"
    )
    (run_folder / "input_payload.json").write_text(
        _json.dumps(profile_input.model_dump(), indent=2), encoding="utf-8"
    )
    if result.hunt_plan:
        (run_folder / "profile_plan.json").write_text(
            _json.dumps(result.hunt_plan.model_dump(), indent=2), encoding="utf-8"
        )

    result.output_dir = run_folder
    result._log_step("reporting_and_audit")
    logger.info("Profile artefacts saved to %s", run_folder)

    # ── Persistence ──────────────────────────────────────────────────
    if config.persist:
        _persist_profile_run(
            config, run_id, profile_input, profile,
            result.query_results, execution_mode, str(run_folder),
        )
    if config.sharepoint_enabled:
        _upload_reports_to_sharepoint(
            config, profile_input.client_name, profile_md, "",
        )


# =====================================================================
# PERSISTENCE HELPERS
# =====================================================================


def _get_database(config: HuntAgentConfig):
    """Lazily construct a HuntDatabase from config."""
    from mssp_hunt_agent.persistence.database import HuntDatabase
    return HuntDatabase(config.db_path)


def _persist_hypothesis_run(
    config: HuntAgentConfig,
    run_id: str,
    plan: HuntPlan,
    findings: list,
    query_results: list[QueryResult],
    execution_mode: str,
    output_dir: str,
) -> None:
    """Save a hypothesis pipeline run to the SQLite database."""
    try:
        from mssp_hunt_agent.persistence.models import FindingRecord, RunRecord

        db = _get_database(config)
        client = db.ensure_client(plan.client_name)
        now = datetime.now(timezone.utc).isoformat()

        high_conf = sum(1 for f in findings if f.confidence == "high")
        total_events = sum(qr.result_count for qr in query_results)

        run = RunRecord(
            run_id=run_id,
            client_id=client.client_id,
            client_name=plan.client_name,
            hunt_type="hypothesis",
            execution_mode=execution_mode,
            started_at=now,
            completed_at=now,
            status="completed",
            findings_count=len(findings),
            high_confidence_count=high_conf,
            queries_executed=len(query_results),
            total_events=total_events,
            output_dir=output_dir,
            summary=plan.objective,
        )
        db.save_run(run)

        for f in findings:
            db.save_finding(FindingRecord(
                finding_id=f.finding_id,
                run_id=run_id,
                client_id=client.client_id,
                title=f.title,
                description=f.description,
                confidence=f.confidence,
                evidence_count=len(f.evidence),
                created_at=now,
            ))

        db.close()
        logger.info("Persisted hypothesis run %s to database", run_id)
    except Exception as exc:
        logger.warning("Failed to persist hypothesis run: %s", exc)


def _persist_ioc_run(
    config: HuntAgentConfig,
    run_id: str,
    ioc_input,
    ioc_batch,
    sweep_result,
    query_results: list[QueryResult],
    execution_mode: str,
    output_dir: str,
) -> None:
    """Save an IOC sweep run to the SQLite database."""
    try:
        from mssp_hunt_agent.persistence.models import IOCSweepRecord, RunRecord

        db = _get_database(config)
        client = db.ensure_client(ioc_input.client_name)
        now = datetime.now(timezone.utc).isoformat()

        total_events = sum(qr.result_count for qr in query_results)

        run = RunRecord(
            run_id=run_id,
            client_id=client.client_id,
            client_name=ioc_input.client_name,
            hunt_type="ioc_sweep",
            execution_mode=execution_mode,
            started_at=now,
            completed_at=now,
            status="completed",
            findings_count=sweep_result.total_hits,
            queries_executed=len(query_results),
            total_events=total_events,
            output_dir=output_dir,
            summary=ioc_input.sweep_objective,
        )
        db.save_run(run)

        sweep_id = f"SWEEP-{uuid.uuid4().hex[:8]}"
        db.save_ioc_sweep(IOCSweepRecord(
            sweep_id=sweep_id,
            run_id=run_id,
            client_id=client.client_id,
            total_iocs=len(ioc_input.iocs),
            valid_iocs=len(ioc_batch.valid),
            total_hits=sweep_result.total_hits,
            total_misses=sweep_result.total_misses,
            hit_iocs=[h.ioc_value for h in sweep_result.hits],
            created_at=now,
        ))

        db.close()
        logger.info("Persisted IOC sweep run %s to database", run_id)
    except Exception as exc:
        logger.warning("Failed to persist IOC sweep run: %s", exc)


def _persist_profile_run(
    config: HuntAgentConfig,
    run_id: str,
    profile_input,
    profile,
    query_results: list[QueryResult],
    execution_mode: str,
    output_dir: str,
) -> None:
    """Save a profile pipeline run to the SQLite database."""
    try:
        from mssp_hunt_agent.persistence.models import ProfileVersion, RunRecord

        db = _get_database(config)
        client = db.ensure_client(profile_input.client_name)
        now = datetime.now(timezone.utc).isoformat()

        total_events = sum(qr.result_count for qr in query_results)

        run = RunRecord(
            run_id=run_id,
            client_id=client.client_id,
            client_name=profile_input.client_name,
            hunt_type="profile",
            execution_mode=execution_mode,
            started_at=now,
            completed_at=now,
            status="completed",
            queries_executed=len(query_results),
            total_events=total_events,
            output_dir=output_dir,
            summary=f"Telemetry profile for {profile_input.client_name}",
        )
        db.save_run(run)

        version_num = db.get_next_profile_version(client.client_id)
        pv = ProfileVersion(
            version_id=f"PV-{uuid.uuid4().hex[:8]}",
            client_id=client.client_id,
            version_number=version_num,
            profile_data=profile.model_dump(),
            created_at=now,
            source_count=profile.source_count,
            total_event_count=profile.total_event_count,
            execution_mode=execution_mode,
        )
        db.save_profile(pv)

        db.close()
        logger.info("Persisted profile run %s (v%d) to database", run_id, version_num)
    except Exception as exc:
        logger.warning("Failed to persist profile run: %s", exc)


def _upload_reports_to_sharepoint(
    config: HuntAgentConfig,
    client_name: str,
    executive_md: str,
    analyst_md: str,
) -> None:
    """Upload rendered report markdown files to SharePoint."""
    try:
        from mssp_hunt_agent.persistence.sharepoint import SharePointUploader

        uploader = SharePointUploader(
            tenant_id=config.sharepoint_tenant_id,
            client_id=config.sharepoint_client_id,
            client_secret=config.sharepoint_client_secret,
            site_id=config.sharepoint_site_id,
            drive_id=config.sharepoint_drive_id,
        )
        safe_client = client_name.replace(" ", "_").lower()
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        folder = f"HuntReports/{safe_client}/{ts}"

        uploader.ensure_folder(folder)
        if executive_md:
            uploader.upload_artifact(folder, "executive_summary.md", executive_md)
        if analyst_md:
            uploader.upload_artifact(folder, "analyst_report.md", analyst_md)

        logger.info("Uploaded reports to SharePoint: %s", folder)
    except Exception as exc:
        logger.warning("SharePoint upload failed: %s", exc)
