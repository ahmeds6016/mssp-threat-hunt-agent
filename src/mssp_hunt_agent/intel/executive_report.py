"""Executive Report Builder — synthesizes intel events + hunt results into formatted reports.

Produces both markdown (for blob/SharePoint) and HTML (for email delivery).

Usage:
    builder = ExecutiveReportBuilder()
    report = builder.build_report(intel_event, campaign_state)
    html = builder.to_html(report)
    markdown = builder.to_markdown(report)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IntelReport:
    """A complete intel-driven threat assessment report."""
    report_id: str
    generated_at: str
    intel_event_title: str
    intel_event_severity: str
    intel_event_summary: str
    sources: list[str]
    article_count: int
    threat_actor: str
    mitre_techniques: list[str]
    cves: list[str]
    affected_software: list[str]
    ioc_count: int
    # Hunt results
    campaign_id: str
    campaign_status: str
    hunt_findings_count: int
    hunt_queries_count: int
    hunt_hypotheses_count: int
    hunt_duration_min: float
    # Verdict
    verdict: str  # "exposed", "not_exposed", "partially_exposed", "inconclusive"
    risk_level: str  # "critical", "high", "medium", "low", "informational"
    verdict_summary: str
    # Details
    findings_summary: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    detection_gaps: list[str] = field(default_factory=list)
    hunt_timeline: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


class ExecutiveReportBuilder:
    """Builds executive-quality intel assessment reports."""

    def build_report(
        self,
        intel_event: Any,
        campaign_state: Any,
        hunt_timeline: str = "",
    ) -> IntelReport:
        """Build a report from an intel event and campaign results."""
        # Determine verdict
        findings = getattr(campaign_state, "findings", [])
        true_positives = [f for f in findings if hasattr(f, "classification") and
                         str(getattr(f.classification, "value", f.classification)) == "true_positive"]
        inconclusive = [f for f in findings if hasattr(f, "classification") and
                       str(getattr(f.classification, "value", f.classification)) == "inconclusive"]

        if true_positives:
            verdict = "exposed"
            risk_level = "high"
            verdict_summary = (
                f"Active indicators of compromise detected. {len(true_positives)} confirmed finding(s) "
                f"match the threat profile. Immediate investigation recommended."
            )
        elif inconclusive:
            verdict = "partially_exposed"
            risk_level = "medium"
            verdict_summary = (
                f"Potential exposure identified. {len(inconclusive)} inconclusive finding(s) require "
                f"further investigation to confirm or rule out compromise."
            )
        elif findings:
            verdict = "not_exposed"
            risk_level = "low"
            verdict_summary = (
                f"No indicators of compromise detected. {len(findings)} finding(s) were analyzed "
                f"and classified as false positives or informational."
            )
        else:
            verdict = "not_exposed"
            risk_level = "low"
            verdict_summary = (
                "No indicators of compromise detected in the monitored environment. "
                "Hunt queries returned no matches for the threat indicators."
            )

        findings_summary = []
        for f in findings:
            findings_summary.append({
                "title": getattr(f, "title", "Unknown"),
                "severity": str(getattr(getattr(f, "severity", ""), "value", "informational")),
                "classification": str(getattr(getattr(f, "classification", ""), "value", "unknown")),
                "description": getattr(f, "description", "")[:300],
            })

        recommendations = self._build_recommendations(intel_event, campaign_state, verdict)
        detection_gaps = self._identify_gaps(intel_event, campaign_state)

        return IntelReport(
            report_id=f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            intel_event_title=intel_event.title,
            intel_event_severity=intel_event.severity,
            intel_event_summary=intel_event.summary,
            sources=intel_event.sources,
            article_count=intel_event.article_count,
            threat_actor=intel_event.threat_actor,
            mitre_techniques=intel_event.mitre_techniques,
            cves=intel_event.cves,
            affected_software=intel_event.affected_software,
            ioc_count=len(intel_event.iocs),
            campaign_id=campaign_state.campaign_id,
            campaign_status=campaign_state.status,
            hunt_findings_count=len(findings),
            hunt_queries_count=campaign_state.total_kql_queries,
            hunt_hypotheses_count=len(campaign_state.hypotheses),
            hunt_duration_min=round(campaign_state.duration_minutes, 1),
            verdict=verdict,
            risk_level=risk_level,
            verdict_summary=verdict_summary,
            findings_summary=findings_summary,
            recommendations=recommendations,
            detection_gaps=detection_gaps,
            hunt_timeline=hunt_timeline,
        )

    def to_markdown(self, report: IntelReport) -> str:
        """Render report as markdown."""
        severity_badge = report.risk_level.upper()
        lines = [
            f"# Threat Intelligence Assessment: {report.intel_event_title}",
            f"",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {report.generated_at}",
            f"**Risk Level:** {severity_badge}",
            f"**Verdict:** {report.verdict.replace('_', ' ').title()}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"{report.verdict_summary}",
            f"",
            f"---",
            f"",
            f"## Threat Intelligence",
            f"",
            f"**Event:** {report.intel_event_title}",
            f"**Severity:** {report.intel_event_severity.upper()}",
            f"**Sources:** {', '.join(report.sources)} ({report.article_count} articles)",
            f"",
            f"{report.intel_event_summary}",
            f"",
        ]

        if report.threat_actor:
            lines.append(f"**Threat Actor:** {report.threat_actor}")
        if report.mitre_techniques:
            lines.append(f"**MITRE ATT&CK:** {', '.join(report.mitre_techniques)}")
        if report.cves:
            lines.append(f"**CVEs:** {', '.join(report.cves)}")
        if report.affected_software:
            lines.append(f"**Affected Software:** {', '.join(report.affected_software)}")
        if report.ioc_count:
            lines.append(f"**IOCs Analyzed:** {report.ioc_count}")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Hunt Results",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Campaign ID | {report.campaign_id} |",
            f"| Status | {report.campaign_status} |",
            f"| Hypotheses Tested | {report.hunt_hypotheses_count} |",
            f"| KQL Queries Executed | {report.hunt_queries_count} |",
            f"| Findings | {report.hunt_findings_count} |",
            f"| Duration | {report.hunt_duration_min} minutes |",
            f"",
        ])

        if report.findings_summary:
            lines.extend([
                f"### Findings Detail",
                f"",
                f"| # | Finding | Severity | Classification |",
                f"|---|---------|----------|---------------|",
            ])
            for i, f in enumerate(report.findings_summary, 1):
                lines.append(f"| {i} | {f['title'][:60]} | {f['severity'].upper()} | {f['classification']} |")
            lines.append("")

        if report.detection_gaps:
            lines.extend([
                f"---",
                f"",
                f"## Detection Gaps",
                f"",
            ])
            for gap in report.detection_gaps:
                lines.append(f"- {gap}")
            lines.append("")

        if report.recommendations:
            lines.extend([
                f"---",
                f"",
                f"## Recommendations",
                f"",
            ])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.extend([
            f"---",
            f"",
            f"*This assessment was generated autonomously by the MSSP Threat Hunt Agent.*",
            f"*Campaign: {report.campaign_id} | Report: {report.report_id}*",
        ])

        return "\n".join(lines)

    def to_html(self, report: IntelReport) -> str:
        """Render report as HTML email."""
        verdict_color = {
            "exposed": "#dc3545",
            "partially_exposed": "#fd7e14",
            "not_exposed": "#28a745",
            "inconclusive": "#6c757d",
        }.get(report.verdict, "#6c757d")

        risk_color = {
            "critical": "#dc3545",
            "high": "#dc3545",
            "medium": "#fd7e14",
            "low": "#28a745",
            "informational": "#17a2b8",
        }.get(report.risk_level, "#6c757d")

        findings_rows = ""
        for i, f in enumerate(report.findings_summary, 1):
            sev_color = {"critical": "#dc3545", "high": "#dc3545", "medium": "#fd7e14", "low": "#28a745"}.get(f["severity"], "#6c757d")
            findings_rows += f"""
            <tr>
                <td style="padding:8px;border-bottom:1px solid #e0e0e0;">{i}</td>
                <td style="padding:8px;border-bottom:1px solid #e0e0e0;">{f['title'][:80]}</td>
                <td style="padding:8px;border-bottom:1px solid #e0e0e0;"><span style="color:{sev_color};font-weight:bold;">{f['severity'].upper()}</span></td>
                <td style="padding:8px;border-bottom:1px solid #e0e0e0;">{f['classification']}</td>
            </tr>"""

        recommendations_html = ""
        for i, rec in enumerate(report.recommendations, 1):
            recommendations_html += f"<li style='margin-bottom:8px;'>{rec}</li>"

        gaps_html = ""
        for gap in report.detection_gaps:
            gaps_html += f"<li style='margin-bottom:4px;'>{gap}</li>"

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,Arial,sans-serif;color:#333;max-width:800px;margin:0 auto;padding:20px;">

<div style="background:#1a1a2e;color:white;padding:24px;border-radius:8px 8px 0 0;">
    <h1 style="margin:0;font-size:20px;">THREAT INTELLIGENCE ASSESSMENT</h1>
    <p style="margin:8px 0 0;opacity:0.8;">{report.generated_at[:10]} | {report.report_id}</p>
</div>

<div style="background:#f8f9fa;padding:20px;border:1px solid #dee2e6;">
    <h2 style="margin:0 0 12px;font-size:18px;">{report.intel_event_title}</h2>
    <table style="width:100%;">
        <tr>
            <td style="padding:4px 16px 4px 0;"><strong>Risk Level:</strong></td>
            <td><span style="background:{risk_color};color:white;padding:4px 12px;border-radius:4px;font-weight:bold;">{report.risk_level.upper()}</span></td>
        </tr>
        <tr>
            <td style="padding:4px 16px 4px 0;"><strong>Verdict:</strong></td>
            <td><span style="color:{verdict_color};font-weight:bold;">{report.verdict.replace('_', ' ').upper()}</span></td>
        </tr>
        <tr>
            <td style="padding:4px 16px 4px 0;"><strong>Sources:</strong></td>
            <td>{', '.join(report.sources)} ({report.article_count} articles)</td>
        </tr>
        {"<tr><td style='padding:4px 16px 4px 0;'><strong>Threat Actor:</strong></td><td>" + report.threat_actor + "</td></tr>" if report.threat_actor else ""}
        {"<tr><td style='padding:4px 16px 4px 0;'><strong>MITRE ATT&CK:</strong></td><td>" + ', '.join(report.mitre_techniques) + "</td></tr>" if report.mitre_techniques else ""}
        {"<tr><td style='padding:4px 16px 4px 0;'><strong>CVEs:</strong></td><td>" + ', '.join(report.cves) + "</td></tr>" if report.cves else ""}
    </table>
</div>

<div style="padding:20px;border:1px solid #dee2e6;border-top:none;">
    <h3 style="margin:0 0 12px;">Executive Summary</h3>
    <p>{report.verdict_summary}</p>
    <p style="color:#666;">{report.intel_event_summary}</p>
</div>

<div style="padding:20px;border:1px solid #dee2e6;border-top:none;">
    <h3 style="margin:0 0 12px;">Hunt Results</h3>
    <table style="width:100%;border-collapse:collapse;">
        <tr style="background:#f1f3f5;">
            <td style="padding:8px;"><strong>Campaign</strong></td>
            <td style="padding:8px;">{report.campaign_id}</td>
            <td style="padding:8px;"><strong>Status</strong></td>
            <td style="padding:8px;">{report.campaign_status}</td>
        </tr>
        <tr>
            <td style="padding:8px;"><strong>Hypotheses</strong></td>
            <td style="padding:8px;">{report.hunt_hypotheses_count}</td>
            <td style="padding:8px;"><strong>KQL Queries</strong></td>
            <td style="padding:8px;">{report.hunt_queries_count}</td>
        </tr>
        <tr style="background:#f1f3f5;">
            <td style="padding:8px;"><strong>Findings</strong></td>
            <td style="padding:8px;">{report.hunt_findings_count}</td>
            <td style="padding:8px;"><strong>Duration</strong></td>
            <td style="padding:8px;">{report.hunt_duration_min} min</td>
        </tr>
    </table>
</div>

{"<div style='padding:20px;border:1px solid #dee2e6;border-top:none;'><h3 style='margin:0 0 12px;'>Findings</h3><table style='width:100%;border-collapse:collapse;'><tr style='background:#1a1a2e;color:white;'><th style='padding:8px;text-align:left;'>#</th><th style='padding:8px;text-align:left;'>Finding</th><th style='padding:8px;text-align:left;'>Severity</th><th style='padding:8px;text-align:left;'>Classification</th></tr>" + findings_rows + "</table></div>" if findings_rows else ""}

{"<div style='padding:20px;border:1px solid #dee2e6;border-top:none;'><h3 style='margin:0 0 12px;'>Detection Gaps</h3><ul style='margin:0;padding-left:20px;'>" + gaps_html + "</ul></div>" if gaps_html else ""}

{"<div style='padding:20px;border:1px solid #dee2e6;border-top:none;'><h3 style='margin:0 0 12px;'>Recommendations</h3><ol style='margin:0;padding-left:20px;'>" + recommendations_html + "</ol></div>" if recommendations_html else ""}

<div style="background:#1a1a2e;color:white;padding:16px;border-radius:0 0 8px 8px;text-align:center;font-size:12px;">
    <p style="margin:0;">Generated by MSSP Threat Hunt Agent | Campaign: {report.campaign_id} | Report: {report.report_id}</p>
</div>

</body>
</html>"""
        return html

    def _build_recommendations(self, intel_event: Any, campaign_state: Any, verdict: str) -> list[str]:
        """Build actionable recommendations based on verdict and findings."""
        recs = []

        if verdict == "exposed":
            recs.append("IMMEDIATE: Initiate incident response procedures for confirmed indicators of compromise.")
            recs.append("Isolate affected systems and preserve evidence for forensic analysis.")
            recs.append("Reset credentials for any accounts associated with confirmed findings.")

        if intel_event.iocs:
            recs.append(f"Add {len(intel_event.iocs)} IOCs from this threat report to your blocklist and TI watchlist.")

        if intel_event.mitre_techniques:
            techniques = ", ".join(intel_event.mitre_techniques[:5])
            recs.append(f"Deploy Sentinel analytic rules covering: {techniques}")

        if intel_event.cves:
            cves = ", ".join(intel_event.cves[:3])
            recs.append(f"Verify patch status for: {cves}")

        if intel_event.affected_software:
            sw = ", ".join(intel_event.affected_software[:3])
            recs.append(f"Audit systems for presence of: {sw}")

        if verdict == "not_exposed":
            recs.append("Continue monitoring — deploy detection rules for the TTPs described in this report.")
            recs.append("Schedule a follow-up hunt in 7 days to catch delayed indicators.")

        return recs

    def _identify_gaps(self, intel_event: Any, campaign_state: Any) -> list[str]:
        """Identify detection coverage gaps relevant to this threat."""
        gaps = []

        # Check what tables the campaign queried vs what the threat needs
        if intel_event.kill_chain_phases:
            phase_map = {
                "initial_access": "Network and email telemetry (DeviceNetworkEvents, OfficeActivity)",
                "execution": "Process creation telemetry (DeviceProcessEvents, SecurityEvent 4688)",
                "persistence": "Registry and scheduled task telemetry (DeviceRegistryEvents, SecurityEvent 4698/7045)",
                "command_and_control": "Network connection telemetry (DeviceNetworkEvents, firewall logs)",
                "exfiltration": "Data transfer telemetry (DeviceNetworkEvents, DLP events)",
            }
            for phase in intel_event.kill_chain_phases:
                if phase in phase_map:
                    gaps.append(f"{phase.replace('_', ' ').title()}: Requires {phase_map[phase]}")

        if not gaps:
            gaps.append("Review telemetry coverage for the MITRE techniques referenced in this report.")

        return gaps
