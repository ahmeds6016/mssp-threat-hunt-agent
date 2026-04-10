"""CISA KEV scan pipeline — proactive vulnerability exposure detection.

Orchestrates the full KEV workflow as a single ``run_scan`` call:

    1. KEVMonitor.check_catalog()           → list[KEVAlert]   (only new entries)
    2. _enrich_alert(alert)                  → adds CVSS, EPSS, description, MITRE
    3. _assess_exposure(alert, env_index)    → runs targeted KQL queries
    4. _build_intel_event(alert)             → IntelEvent (so existing builders work)
    5. _build_campaign_state(alert, assess)  → CampaignState (ditto)
    6. ExecutiveReportBuilder.build_report() → IntelReport
    7. EmailSender.send_intel_report()       → email + persistence

The pipeline reuses every downstream module from the V7.4 threat-intel
pipeline (``IntelEvent``, ``ExecutiveReportBuilder``, ``EmailSender``,
``BlobStateStore``) so the operator gets the same email format, the same
report shape, and the same blob layout — just with KEV semantics on top.

Why exposure assessment is local (not delegated to ``IntelCampaignLauncher``):

* A KEV entry doesn't have IPs/domains/hashes — those would route through
  IOCSweeper but find nothing because there's nothing to sweep.
* It also doesn't have GPT-extracted TTPs — most KEV entries have empty
  ``mitre_techniques`` fields, so the campaign-orchestrator hypothesis path
  has nothing to seed itself with.
* What KEV *does* have is a vendor + product. The right hunt is "is this
  software in my tenant?" — answered by ``DeviceTvmSoftwareInventory`` if MDE
  is wired up, with ``DeviceProcessEvents`` and ``DeviceFileEvents`` as
  fallbacks. That's 3 deterministic queries per CVE, not a 5-phase campaign.

Verdict logic:

* DeviceTvmSoftwareInventory hit              → TRUE_POSITIVE (high confidence)
* Process or file event hit (no MDE inventory) → INCONCLUSIVE (medium confidence)
* All telemetry sources missing                → REQUIRES_ESCALATION (gap)
* Nothing found, telemetry healthy             → FALSE_POSITIVE (not exposed)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from mssp_hunt_agent.intel.executive_report import ExecutiveReportBuilder, IntelReport
from mssp_hunt_agent.intel.intel_processor import IntelEvent
from mssp_hunt_agent.intel.kev_monitor import KEVAlert, KEVMonitor

logger = logging.getLogger(__name__)


# Bound the number of CVEs we enrich + hunt per scan. CISA can publish many
# entries on a single day; running 50+ enrichment + KQL passes in one Function
# invocation risks the 10-minute limit. Newest first, oldest get deferred to
# the next scan (they remain in dedup state, NOT marked as seen).
DEFAULT_MAX_ALERTS_PER_SCAN = 25


# ── Data Models ───────────────────────────────────────────────────────


@dataclass
class ExposureAssessment:
    """Result of the per-CVE exposure check."""

    cve_id: str
    has_definitive_exposure: bool = False  # software inventory match
    has_circumstantial_evidence: bool = False  # process / file match
    telemetry_available: bool = False  # at least one inferred source has recent data
    queries_run: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    missing_telemetry: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.has_definitive_exposure:
            return "true_positive"
        if self.has_circumstantial_evidence:
            return "inconclusive"
        if not self.telemetry_available:
            return "requires_escalation"
        return "false_positive"


@dataclass
class KEVScanResult:
    """End-to-end result of a KEV scan run."""

    scan_id: str
    started_at: str
    completed_at: str = ""
    alerts_discovered: int = 0
    alerts_processed: int = 0
    alerts_deferred: int = 0
    exposed_count: int = 0
    inconclusive_count: int = 0
    not_exposed_count: int = 0
    escalation_count: int = 0
    emails_sent: int = 0
    reports: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "alerts_discovered": self.alerts_discovered,
            "alerts_processed": self.alerts_processed,
            "alerts_deferred": self.alerts_deferred,
            "exposed_count": self.exposed_count,
            "inconclusive_count": self.inconclusive_count,
            "not_exposed_count": self.not_exposed_count,
            "escalation_count": self.escalation_count,
            "emails_sent": self.emails_sent,
            "reports": self.reports,
            "errors": self.errors,
            "dry_run": self.dry_run,
        }


# ── Exposure Matcher ──────────────────────────────────────────────────


class KEVExposureMatcher:
    """Runs targeted KQL queries to detect tenant exposure to a KEV CVE.

    Each ``assess`` call runs at most 3 queries:

    1. ``DeviceTvmSoftwareInventory`` — gold standard. If MDE-TVM is wired up
       this tells us definitively whether the vulnerable product is installed.
    2. ``DeviceProcessEvents`` — fallback. Looks for the product name in
       process executables observed in the last 30 days.
    3. ``DeviceFileEvents`` — fallback. Looks for the product name in file
       paths over the last 30 days (catches installer drops, .exe presence).

    The matcher is conservative with KQL escaping — vendor/product names are
    sanitized before being interpolated into queries to avoid injection or
    syntax errors from special characters in vendor names.
    """

    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter

    def assess(self, alert: KEVAlert) -> ExposureAssessment:
        from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent

        assessment = ExposureAssessment(cve_id=alert.cve_id)
        product_token = _kql_safe_token(alert.product)
        vendor_token = _kql_safe_token(alert.vendor)

        if not product_token:
            # Can't search without a product name — flag as escalation gap
            assessment.errors.append("KEV entry has empty product field; cannot build exposure query")
            assessment.missing_telemetry.append("DeviceTvmSoftwareInventory")
            return assessment

        # Build a list of (label, table, kql, classification_on_hit) tuples.
        # classification_on_hit = "definitive" or "circumstantial".
        queries: list[tuple[str, str, str, str]] = [
            (
                "Software inventory",
                "DeviceTvmSoftwareInventory",
                (
                    "DeviceTvmSoftwareInventory "
                    f"| where SoftwareName has '{product_token}'"
                    f"{(' or SoftwareVendor has ' + repr(vendor_token)) if vendor_token else ''} "
                    "| summarize Devices=dcount(DeviceName), Versions=make_set(SoftwareVersion, 20) "
                    "by SoftwareName, SoftwareVendor "
                    "| take 25"
                ),
                "definitive",
            ),
            (
                "Process events",
                "DeviceProcessEvents",
                (
                    "DeviceProcessEvents "
                    "| where TimeGenerated > ago(30d) "
                    f"| where FileName has '{product_token}' or InitiatingProcessFileName has '{product_token}' "
                    "| summarize Hits=count(), Devices=dcount(DeviceName) by FileName "
                    "| top 25 by Hits"
                ),
                "circumstantial",
            ),
            (
                "File events",
                "DeviceFileEvents",
                (
                    "DeviceFileEvents "
                    "| where TimeGenerated > ago(30d) "
                    f"| where FileName has '{product_token}' or FolderPath has '{product_token}' "
                    "| summarize Hits=count(), Devices=dcount(DeviceName) by FileName "
                    "| top 25 by Hits"
                ),
                "circumstantial",
            ),
        ]

        for label, table, kql, classification in queries:
            assessment.queries_run += 1
            try:
                t0 = time.time()
                eq = ExabeamQuery(
                    query_id=f"kev-{alert.cve_id.lower()}-{table.lower()}",
                    intent=QueryIntent.IOC_HUNT,
                    description=f"KEV exposure check: {alert.cve_id} via {table}",
                    query_text=kql,
                    time_range="30d",
                    expected_signal=f"presence of {alert.product}",
                )
                qr = self._adapter.execute_query(eq)
                duration_ms = int((time.time() - t0) * 1000)

                if qr.result_count > 0:
                    assessment.telemetry_available = True
                    if classification == "definitive":
                        assessment.has_definitive_exposure = True
                    else:
                        assessment.has_circumstantial_evidence = True
                    assessment.evidence.append({
                        "label": label,
                        "table": table,
                        "result_count": qr.result_count,
                        "query": kql,
                        "duration_ms": duration_ms,
                        "classification": classification,
                        "sample": [e.model_dump() for e in qr.events[:3]] if hasattr(qr, "events") else [],
                    })
                    logger.info(
                        "KEV %s: HIT %s in %s — %d results (%dms)",
                        alert.cve_id, label, table, qr.result_count, duration_ms,
                    )
                else:
                    # Even an empty result set tells us the table exists and is queryable —
                    # a real telemetry gap raises an exception below.
                    assessment.telemetry_available = True
                    logger.debug(
                        "KEV %s: MISS %s in %s (%dms)",
                        alert.cve_id, label, table, duration_ms,
                    )
            except Exception as exc:
                msg = str(exc).lower()
                # Treat "table doesn't exist" specifically as a telemetry gap; everything
                # else is a real query error.
                if "could not be found" in msg or "unknown function" in msg or "semantic error" in msg:
                    assessment.missing_telemetry.append(table)
                    logger.info("KEV %s: telemetry gap — %s not in workspace", alert.cve_id, table)
                else:
                    assessment.errors.append(f"{table}: {exc}")
                    logger.warning("KEV %s: query failed against %s: %s", alert.cve_id, table, exc)

        return assessment


def _kql_safe_token(raw: str) -> str:
    """Sanitize a vendor/product name for safe interpolation into KQL.

    KQL string literals use single quotes; the only character we strictly
    must escape is the single quote. Stripping non-alphanumerics (other than
    dot, hyphen, space, underscore) is a defensive belt-and-suspenders
    measure since vendor names rarely contain anything exotic.
    """
    if not raw:
        return ""
    cleaned = "".join(c for c in raw if c.isalnum() or c in " .-_")
    return cleaned.strip().replace("'", "")[:80]


# ── Pipeline ──────────────────────────────────────────────────────────


class KEVPipeline:
    """Orchestrates the end-to-end KEV scan workflow."""

    def __init__(
        self,
        config: Any,
        adapter: Any,
        llm: Any | None = None,
        blob_store: Any | None = None,
        email_sender: Any | None = None,
        monitor: KEVMonitor | None = None,
        report_builder: ExecutiveReportBuilder | None = None,
        max_alerts_per_scan: int = DEFAULT_MAX_ALERTS_PER_SCAN,
    ) -> None:
        self._config = config
        self._adapter = adapter
        self._llm = llm
        self._blob = blob_store
        self._email = email_sender
        self._monitor = monitor or KEVMonitor(blob_store=blob_store)
        self._matcher = KEVExposureMatcher(adapter=adapter)
        self._report_builder = report_builder or ExecutiveReportBuilder()
        self._max_alerts = max(1, max_alerts_per_scan)

    # ── Public entry point ────────────────────────────────────────────

    def run_scan(
        self,
        recipients: list[str] | None = None,
        dry_run: bool = False,
    ) -> KEVScanResult:
        """Execute one full scan cycle."""
        scan_id = f"KEV-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"
        result = KEVScanResult(
            scan_id=scan_id,
            started_at=datetime.now(timezone.utc).isoformat(),
            dry_run=dry_run,
        )
        logger.info("KEVPipeline %s: starting (dry_run=%s)", scan_id, dry_run)

        # Step 1: pull new entries from the catalog
        try:
            new_alerts = self._monitor.check_catalog()
        except Exception as exc:
            logger.exception("KEVPipeline %s: catalog check failed", scan_id)
            result.errors.append(f"catalog check failed: {exc}")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_scan(result)
            return result

        result.alerts_discovered = len(new_alerts)
        if not new_alerts:
            logger.info("KEVPipeline %s: no new KEV entries", scan_id)
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_scan(result)
            return result

        # Cap to the per-scan budget. Newest first (already sorted by check_catalog).
        to_process = new_alerts[: self._max_alerts]
        result.alerts_deferred = len(new_alerts) - len(to_process)
        if result.alerts_deferred:
            logger.info(
                "KEVPipeline %s: %d alerts exceed budget — deferring oldest %d",
                scan_id, result.alerts_deferred, result.alerts_deferred,
            )

        if dry_run:
            for alert in to_process:
                result.reports.append({
                    "cve_id": alert.cve_id,
                    "vendor": alert.vendor,
                    "product": alert.product,
                    "vulnerability_name": alert.vulnerability_name,
                    "date_added": alert.date_added,
                })
            result.alerts_processed = len(to_process)
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_scan(result)
            return result

        # Step 2-7: enrich, assess, build report, email — per alert
        for alert in to_process:
            try:
                self._enrich_alert(alert)
                assessment = self._matcher.assess(alert)
                report = self._build_and_persist_report(alert, assessment)
                self._tally(result, assessment)

                result.reports.append({
                    "cve_id": alert.cve_id,
                    "report_id": report.report_id,
                    "verdict": report.verdict,
                    "risk_level": report.risk_level,
                    "queries_run": assessment.queries_run,
                })
                result.alerts_processed += 1

                if recipients and self._email and report.verdict in ("exposed", "partially_exposed"):
                    if self._send_report(report, alert, recipients):
                        result.emails_sent += 1
            except Exception as exc:
                logger.exception("KEVPipeline %s: failed to process %s", scan_id, alert.cve_id)
                result.errors.append(f"{alert.cve_id}: {exc}")

        result.completed_at = datetime.now(timezone.utc).isoformat()
        self._persist_scan(result)
        logger.info(
            "KEVPipeline %s: complete — processed=%d exposed=%d inconclusive=%d "
            "not_exposed=%d escalation=%d emails=%d errors=%d",
            scan_id, result.alerts_processed, result.exposed_count,
            result.inconclusive_count, result.not_exposed_count,
            result.escalation_count, result.emails_sent, len(result.errors),
        )
        return result

    # ── Internals ─────────────────────────────────────────────────────

    def _enrich_alert(self, alert: KEVAlert) -> None:
        """Pull CVSS / EPSS / description / MITRE techniques onto the alert.

        Best-effort: any failure leaves the alert with the raw KEV fields,
        which is enough to still produce a useful report.
        """
        try:
            from mssp_hunt_agent.intel.cve_lookup import CVELookup
            lookup = CVELookup(
                use_mock=(getattr(self._config, "adapter_mode", "") == "mock"),
                cache_dir=getattr(self._config, "cve_cache_dir", None),
            )
            detail = lookup.fetch(alert.cve_id)
            data = detail.model_dump() if hasattr(detail, "model_dump") else {}
            alert.cvss_score = float(data.get("cvss_score") or 0.0)
            alert.severity = data.get("severity", alert.severity) or alert.severity
            alert.description = data.get("description", "") or alert.short_description
            alert.references = list(data.get("references", []) or [])
            alert.cwe_ids = list(data.get("cwe_ids", []) or [])
            new_techniques = list(data.get("techniques", []) or [])
            if new_techniques:
                # Merge with whatever the KEV entry already had
                merged = list(dict.fromkeys(alert.mitre_techniques + new_techniques))
                alert.mitre_techniques = merged
        except Exception as exc:
            logger.debug("KEV %s: cve_lookup enrichment skipped (%s)", alert.cve_id, exc)

        try:
            from mssp_hunt_agent.intel.threat_intel import enrich_cve
            epss = enrich_cve(alert.cve_id)
            alert.epss_score = float(epss.get("epss_score") or 0.0)
            alert.epss_percentile = float(epss.get("epss_percentile") or 0.0)
        except Exception as exc:
            logger.debug("KEV %s: epss enrichment skipped (%s)", alert.cve_id, exc)

    def _build_and_persist_report(
        self,
        alert: KEVAlert,
        assessment: ExposureAssessment,
    ) -> IntelReport:
        intel_event = self._build_intel_event(alert)
        campaign_state = self._build_campaign_state(alert, assessment)
        report = self._report_builder.build_report(intel_event, campaign_state)
        # Override report severity / verdict with what's actually appropriate
        # for KEV given the CVSS / EPSS / ransomware-use signals.
        report.intel_event_severity = self._derive_severity(alert)
        if alert.known_ransomware_use.lower() == "known":
            report.recommendations.insert(
                0,
                "PRIORITY: This CVE is actively used in ransomware campaigns. "
                "Treat any exposure finding as critical.",
            )
        self._persist_report(report)
        return report

    def _build_intel_event(self, alert: KEVAlert) -> IntelEvent:
        """Adapt a KEVAlert into the IntelEvent shape so existing builders work."""
        title = f"CISA KEV: {alert.vulnerability_name or alert.cve_id}"
        summary_parts = [
            f"{alert.vendor} {alert.product}".strip(),
            f"CVE: {alert.cve_id}",
        ]
        if alert.cvss_score:
            summary_parts.append(f"CVSS {alert.cvss_score}")
        if alert.epss_score:
            summary_parts.append(f"EPSS {alert.epss_score:.3f}")
        if alert.known_ransomware_use.lower() == "known":
            summary_parts.append("KNOWN RANSOMWARE USE")
        prefix = " | ".join(p for p in summary_parts if p)
        body = alert.description or alert.short_description
        summary = f"{prefix}. {body}".strip()

        return IntelEvent(
            event_id=f"KEV-{alert.cve_id}",
            title=title,
            severity=self._derive_severity(alert),
            category="vulnerability",
            summary=summary,
            articles=[],
            article_count=0,
            sources=["CISA Known Exploited Vulnerabilities Catalog"],
            relevance_score=1.0,  # KEV is inherently relevant — every entry is in-the-wild
            relevance_reasoning="CISA KEV entries are confirmed actively exploited",
            iocs=[],
            mitre_techniques=list(alert.mitre_techniques),
            mitre_tactics=[],
            cves=[alert.cve_id],
            affected_software=[f"{alert.vendor} {alert.product}".strip()],
            threat_actor="",
            kill_chain_phases=[],
            recommended_queries=[],
        )

    def _build_campaign_state(
        self,
        alert: KEVAlert,
        assessment: ExposureAssessment,
    ) -> Any:
        """Build a minimal CampaignState carrying the assessment as findings.

        Returns a real ``CampaignState`` (not a duck-type) so any future
        downstream consumer that introspects fields beyond what
        ``ExecutiveReportBuilder`` reads still works.
        """
        from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState
        from mssp_hunt_agent.hunter.models.finding import (
            FindingClassification,
            FindingSeverity,
            HuntFinding,
        )

        client_name = getattr(self._config, "client_name", "Client") or "Client"
        state = CampaignState(
            campaign_id=f"KEV-CAMP-{alert.cve_id}",
            config=CampaignConfig(client_name=client_name),
            status="completed",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_kql_queries=assessment.queries_run,
        )

        # Map assessment to findings.
        if assessment.has_definitive_exposure:
            sev = FindingSeverity.CRITICAL if alert.known_ransomware_use.lower() == "known" else FindingSeverity.HIGH
            for ev in assessment.evidence:
                if ev.get("classification") != "definitive":
                    continue
                state.findings.append(
                    HuntFinding(
                        finding_id=f"KEV-{alert.cve_id}-DEF",
                        hypothesis_id="kev-exposure",
                        title=f"{alert.product} found in software inventory",
                        description=(
                            f"{ev.get('label')}: {ev.get('result_count')} matches in "
                            f"{ev.get('table')}. Vulnerable software is installed in the environment "
                            f"and CVE {alert.cve_id} is known to be actively exploited."
                        ),
                        classification=FindingClassification.TRUE_POSITIVE,
                        severity=sev,
                        confidence=0.95,
                        mitre_techniques=list(alert.mitre_techniques),
                    )
                )
        elif assessment.has_circumstantial_evidence:
            for ev in assessment.evidence:
                if ev.get("classification") != "circumstantial":
                    continue
                state.findings.append(
                    HuntFinding(
                        finding_id=f"KEV-{alert.cve_id}-CIRC-{ev.get('table','')}",
                        hypothesis_id="kev-exposure",
                        title=f"{alert.product} observed in {ev.get('table')}",
                        description=(
                            f"{ev.get('label')}: {ev.get('result_count')} matches in "
                            f"{ev.get('table')} over the last 30 days. Software inventory unavailable "
                            "or did not return a definitive match — manual verification recommended."
                        ),
                        classification=FindingClassification.INCONCLUSIVE,
                        severity=FindingSeverity.MEDIUM,
                        confidence=0.55,
                        mitre_techniques=list(alert.mitre_techniques),
                    )
                )
        elif assessment.missing_telemetry and not assessment.telemetry_available:
            state.findings.append(
                HuntFinding(
                    finding_id=f"KEV-{alert.cve_id}-GAP",
                    hypothesis_id="kev-exposure",
                    title=f"Telemetry gap — cannot assess {alert.cve_id}",
                    description=(
                        "None of the inferred detection sources are available in the workspace: "
                        + ", ".join(sorted(set(assessment.missing_telemetry)))
                        + ". Exposure cannot be confirmed or ruled out from telemetry alone."
                    ),
                    classification=FindingClassification.REQUIRES_ESCALATION,
                    severity=FindingSeverity.MEDIUM,
                    confidence=0.0,
                )
            )
        else:
            state.findings.append(
                HuntFinding(
                    finding_id=f"KEV-{alert.cve_id}-CLEAN",
                    hypothesis_id="kev-exposure",
                    title=f"No exposure detected for {alert.cve_id}",
                    description=(
                        f"Ran {assessment.queries_run} exposure check(s) against "
                        f"{alert.vendor} {alert.product} — no software inventory, process, or file "
                        "event matches found in the last 30 days."
                    ),
                    classification=FindingClassification.FALSE_POSITIVE,
                    severity=FindingSeverity.INFORMATIONAL,
                    confidence=0.85,
                )
            )

        return state

    def _derive_severity(self, alert: KEVAlert) -> str:
        """Map CVSS / EPSS / ransomware signals to a severity bucket."""
        if alert.known_ransomware_use.lower() == "known":
            return "critical"
        if alert.cvss_score >= 9.0 or alert.epss_score >= 0.7:
            return "critical"
        if alert.cvss_score >= 7.0 or alert.epss_score >= 0.3:
            return "high"
        if alert.cvss_score >= 4.0:
            return "medium"
        return alert.severity or "high"  # KEV entries default to high

    def _tally(self, result: KEVScanResult, assessment: ExposureAssessment) -> None:
        verdict = assessment.verdict
        if verdict == "true_positive":
            result.exposed_count += 1
        elif verdict == "inconclusive":
            result.inconclusive_count += 1
        elif verdict == "requires_escalation":
            result.escalation_count += 1
        else:
            result.not_exposed_count += 1

    # ── Persistence + Email ───────────────────────────────────────────

    def _persist_report(self, report: IntelReport) -> None:
        if not self._blob:
            return
        try:
            self._blob._upload_json(f"kev-reports/{report.report_id}.json", report.to_dict())
            md = self._report_builder.to_markdown(report)
            try:
                self._blob.container_client.get_blob_client(f"kev-reports/{report.report_id}.md").upload_blob(
                    md.encode("utf-8"), overwrite=True,
                )
            except Exception:
                # Markdown upload is best-effort. JSON is the canonical record.
                pass
        except Exception as exc:
            logger.warning("KEVPipeline: failed to persist report %s: %s", report.report_id, exc)

    def _persist_scan(self, result: KEVScanResult) -> None:
        if not self._blob:
            return
        try:
            self._blob._upload_json(f"kev-scans/{result.scan_id}.json", result.to_dict())
        except Exception as exc:
            logger.warning("KEVPipeline: failed to persist scan %s: %s", result.scan_id, exc)

    def _send_report(
        self,
        report: IntelReport,
        alert: KEVAlert,
        recipients: list[str],
    ) -> bool:
        try:
            html = self._report_builder.to_html(report)
            subject = (
                f"[CISA KEV] {alert.cve_id} {alert.vendor} {alert.product} — "
                f"{report.verdict.replace('_', ' ').title()} ({report.risk_level.upper()})"
            )
            return bool(self._email.send_report(
                to=recipients,
                subject=subject,
                html_body=html,
                importance="high" if report.risk_level in ("critical", "high") else "normal",
            ))
        except Exception as exc:
            logger.warning("KEVPipeline: email send failed for %s: %s", report.report_id, exc)
            return False
