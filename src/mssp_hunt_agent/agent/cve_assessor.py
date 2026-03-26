"""CVE assessor — orchestrates CVE lookup, MITRE mapping, telemetry check."""

from __future__ import annotations

import logging
from typing import Any

from mssp_hunt_agent.agent.models import AgentIntent, AgentResponse, ReasoningStep
from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.intel.cve_lookup import CVEDetail, CVELookup

logger = logging.getLogger(__name__)


class CVEAssessor:
    """Full CVE assessment pipeline.

    Steps:
    1. Fetch CVE details (severity, techniques, affected products)
    2. Map to ATT&CK techniques
    3. Check telemetry coverage for those techniques
    4. Check CISA KEV for active exploitation
    5. Generate detection recommendations for gaps
    6. Synthesize verdict
    """

    def __init__(self, config: HuntAgentConfig) -> None:
        self.config = config
        self._client_name = config.default_client_name or "Unknown"
        self._lookup = CVELookup(use_mock=config.adapter_mode == "mock")

    def assess(self, cve_id: str) -> AgentResponse:
        """Run full CVE assessment pipeline."""
        steps: list[ReasoningStep] = []
        steps.append(ReasoningStep(
            step_type="planning",
            description=f"Starting CVE assessment for {cve_id}",
        ))

        # Step 1: Fetch CVE details
        cve = self._lookup.fetch(cve_id)
        steps.append(ReasoningStep(
            step_type="result",
            description=(
                f"CVE Details: severity={cve.severity}, CVSS={cve.cvss_score}, "
                f"techniques={cve.techniques}, "
                f"actively_exploited={cve.actively_exploited}"
            ),
            data=cve.model_dump(),
        ))

        # Step 2: Check telemetry coverage
        coverage, gaps = self._check_coverage(cve.techniques)
        steps.append(ReasoningStep(
            step_type="result",
            description=f"Coverage: {len(coverage) - len(gaps)}/{len(coverage)} techniques covered",
            data={"coverage": coverage, "gaps": gaps},
        ))

        # Step 3: Check CISA KEV
        in_kev = self._check_kev(cve_id)
        steps.append(ReasoningStep(
            step_type="result",
            description=f"CISA KEV: {'ACTIVE exploitation' if in_kev else 'Not listed'}",
            data={"in_kev": in_kev},
        ))

        # Step 4: Generate detection recommendations
        recommendations = self._generate_recommendations(cve, gaps)
        if recommendations:
            steps.append(ReasoningStep(
                step_type="result",
                description=f"Generated {len(recommendations)} detection recommendations",
                data={"recommendations": recommendations},
            ))

        # Step 5: Synthesize
        steps.append(ReasoningStep(step_type="synthesizing", description="Compiling assessment"))
        verdict, summary = self._synthesize(cve, coverage, gaps, in_kev, recommendations)

        return AgentResponse(
            summary=summary,
            intent=AgentIntent.CVE_CHECK,
            confidence=0.9 if cve.description else 0.6,
            details={
                "cve_id": cve_id,
                "verdict": verdict,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "techniques": cve.techniques,
                "affected_products": cve.affected_products,
                "in_cisa_kev": in_kev or cve.actively_exploited,
                "coverage": coverage,
                "gaps": gaps,
                "recommendations": recommendations,
            },
            thinking_trace=steps,
            follow_up_suggestions=[
                f"Hunt for {cve_id}: hunt for exploitation of {cve_id}",
                "Check telemetry: what telemetry do we have?",
                "Check landscape: any active threats we can't detect?",
            ],
        )

    def _check_coverage(self, techniques: list[str]) -> tuple[dict[str, str], list[str]]:
        """Check which techniques are covered by current telemetry."""
        coverage: dict[str, str] = {}
        gaps: list[str] = []

        try:
            from mssp_hunt_agent.threat_model.attack_paths import identify_attack_paths
            data_sources = ["SecurityEvent", "SigninLogs", "Syslog", "DeviceProcessEvents"]
            paths = identify_attack_paths(data_sources)
            covered_set: set[str] = set()
            for path in paths:
                covered_set.update(path.techniques)

            for tech in techniques:
                if tech in covered_set:
                    coverage[tech] = "covered"
                else:
                    coverage[tech] = "gap"
                    gaps.append(tech)
        except Exception as exc:
            logger.warning("Coverage check failed: %s", exc)
            for tech in techniques:
                coverage[tech] = "unknown"

        return coverage, gaps

    def _check_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog."""
        try:
            from mssp_hunt_agent.intel.landscape import ThreatLandscapeEngine
            engine = ThreatLandscapeEngine()
            for entry in engine.kev_entries:
                if entry.cve_id.upper() == cve_id.upper():
                    return True
        except Exception as exc:
            logger.warning("KEV check failed: %s", exc)
        return False

    def _generate_recommendations(
        self, cve: CVEDetail, gaps: list[str]
    ) -> list[str]:
        """Generate detection recommendations for coverage gaps."""
        recommendations: list[str] = []

        if not gaps:
            return recommendations

        try:
            from mssp_hunt_agent.detection.generator import generate_detection_rule
            for tech in gaps[:3]:
                rule = generate_detection_rule(technique_id=tech)
                recommendations.append(
                    f"Deploy detection rule '{rule.name}' to cover {tech}"
                )
        except Exception as exc:
            logger.warning("Detection generation failed: %s", exc)
            for tech in gaps[:3]:
                recommendations.append(f"Create KQL detection rule for {tech}")

        return recommendations

    def _synthesize(
        self,
        cve: CVEDetail,
        coverage: dict[str, str],
        gaps: list[str],
        in_kev: bool,
        recommendations: list[str],
    ) -> tuple[str, str]:
        """Build verdict and summary."""
        covered_count = sum(1 for v in coverage.values() if v == "covered")
        total = len(coverage)

        if gaps:
            verdict = "PARTIALLY VULNERABLE"
            summary = (
                f"{verdict}: {cve.cve_id} (CVSS {cve.cvss_score}, {cve.severity}) "
                f"maps to {total} ATT&CK techniques. You have detection coverage for "
                f"{covered_count}/{total}. Gaps: {', '.join(gaps)}. "
            )
        elif total > 0:
            verdict = "COVERED"
            summary = (
                f"{verdict}: {cve.cve_id} (CVSS {cve.cvss_score}, {cve.severity}) "
                f"— your telemetry covers all {total} related ATT&CK techniques. "
            )
        else:
            verdict = "ASSESSMENT INCOMPLETE"
            summary = (
                f"{verdict}: {cve.cve_id} — unable to map to ATT&CK techniques. "
                f"Run a telemetry profile to improve analysis. "
            )

        if in_kev or cve.actively_exploited:
            summary += "WARNING: This CVE is ACTIVELY EXPLOITED. "

        if recommendations:
            summary += "Recommendations: " + "; ".join(recommendations[:3]) + "."

        return verdict, summary
