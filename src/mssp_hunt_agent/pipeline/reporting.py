"""Reporting stage — render Jinja2 templates into markdown files."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from mssp_hunt_agent.models.ioc_models import IOCSweepReport
from mssp_hunt_agent.models.profile_models import ClientTelemetryProfile
from mssp_hunt_agent.models.report_models import AnalystReport, ExecutiveSummary

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_executive_summary(summary: ExecutiveSummary) -> str:
    """Render the client-facing executive summary to markdown."""
    env = _env()
    tmpl = env.get_template("executive_summary.md.j2")
    return tmpl.render(s=summary)


def render_analyst_report(report: AnalystReport) -> str:
    """Render the full analyst technical report to markdown."""
    env = _env()
    tmpl = env.get_template("analyst_report.md.j2")
    return tmpl.render(r=report)


def render_evidence_table(report: AnalystReport) -> str:
    """Render a standalone evidence table."""
    env = _env()
    tmpl = env.get_template("evidence_table.md.j2")
    return tmpl.render(evidence=report.evidence_items, findings=report.findings)


def render_ioc_executive_summary(report: IOCSweepReport) -> str:
    """Render the client-facing IOC sweep summary."""
    env = _env()
    tmpl = env.get_template("ioc_executive_summary.md.j2")
    return tmpl.render(s=report)


def render_ioc_analyst_report(report: IOCSweepReport) -> str:
    """Render the full IOC sweep analyst report."""
    env = _env()
    tmpl = env.get_template("ioc_analyst_report.md.j2")
    return tmpl.render(r=report)


def render_profile_report(profile: ClientTelemetryProfile) -> str:
    """Render the client telemetry profile to markdown."""
    env = _env()
    tmpl = env.get_template("client_telemetry_profile.md.j2")
    return tmpl.render(p=profile)
