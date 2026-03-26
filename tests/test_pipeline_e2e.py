"""End-to-end pipeline test using mock adapters."""

from __future__ import annotations

import tempfile
from pathlib import Path

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.models.input_models import HuntInput, HuntType
from mssp_hunt_agent.pipeline.orchestrator import run_pipeline


def _make_config(output_dir: Path) -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        approval_required=False,
        output_dir=output_dir,
        enrichment_cache_dir=output_dir / ".cache",
    )


class TestPipelineE2E:
    def test_full_mock_pipeline(self, identity_input: HuntInput) -> None:
        """Run the entire pipeline in mock mode and verify artefacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_pipeline(identity_input, config, plan_only=False)

            # Pipeline completed
            assert result.stopped_at is None
            assert result.output_dir is not None
            assert result.output_dir.exists()

            # Artefacts written
            assert (result.output_dir / "executive_summary.md").exists()
            assert (result.output_dir / "analyst_report.md").exists()
            assert (result.output_dir / "evidence_table.md").exists()
            assert (result.output_dir / "run_trace.json").exists()
            assert (result.output_dir / "input_payload.json").exists()
            assert (result.output_dir / "hunt_plan.json").exists()

            # Reports populated
            assert result.executive_summary is not None
            assert result.analyst_report is not None
            assert len(result.query_results) > 0
            assert len(result.enrichments) > 0

    def test_plan_only_mode(self, identity_input: HuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_pipeline(identity_input, config, plan_only=True)

            assert result.stopped_at == "plan_only"
            assert result.hunt_plan is not None
            assert len(result.query_results) == 0  # not executed
            assert result.output_dir is not None
            assert (result.output_dir / "executive_summary.md").exists()

    def test_approval_denied(self, identity_input: HuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            config.approval_required = True

            result = run_pipeline(
                identity_input,
                config,
                approval_callback=lambda _plan: False,
            )

            assert result.stopped_at == "approval_denied"
            assert len(result.query_results) == 0

    def test_report_contains_required_sections(self, identity_input: HuntInput) -> None:
        """Verify the analyst report markdown contains all required headings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_pipeline(identity_input, config, plan_only=False)

            report_md = (result.output_dir / "analyst_report.md").read_text()

            required_headings = [
                "Hunt Overview",
                "Confirmed Inputs",
                "Assumptions and Hypotheses",
                "ATT&CK Mapping",
                "Required / Available Data Sources",
                "Telemetry Readiness Assessment",
                "Findings",
                "Confidence Assessment",
                "Escalation Recommendation",
                "Detection Engineering Follow-Up",
                "Additional Hunt Pivots",
                "Gaps / Missing Information",
                "Analyst Notes",
            ]
            for heading in required_headings:
                assert heading in report_md, f"Missing heading: {heading}"

    def test_executive_summary_mock_disclaimer(self, identity_input: HuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_pipeline(identity_input, config, plan_only=False)

            summary_md = (result.output_dir / "executive_summary.md").read_text()
            assert "mock" in summary_md.lower() or "MOCK" in summary_md

    def test_endpoint_hunt_type(self, endpoint_input: HuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_pipeline(endpoint_input, config, plan_only=False)

            assert result.analyst_report is not None
            assert result.analyst_report.hunt_type == "endpoint"

    def test_telemetry_readiness_classification(self) -> None:
        """Verify telemetry readiness for different data source coverage."""
        from mssp_hunt_agent.pipeline.intake import classify_telemetry

        # Green — 4 of 5 expected identity sources
        green_input = HuntInput(
            client_name="Green",
            hunt_objective="test",
            hunt_hypothesis="test",
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=[
                "Azure AD sign-in logs",
                "VPN logs",
                "MFA logs",
                "Active Directory event logs",
            ],
            hunt_type=HuntType.IDENTITY,
        )
        assert classify_telemetry(green_input).readiness.value == "Green"

        # Yellow — 2 of 5 expected
        yellow_input = HuntInput(
            client_name="Yellow",
            hunt_objective="test",
            hunt_hypothesis="test",
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=["Azure AD sign-in logs", "VPN logs"],
            hunt_type=HuntType.IDENTITY,
        )
        assert classify_telemetry(yellow_input).readiness.value == "Yellow"

        # Red — 0 of 5 expected
        red_input = HuntInput(
            client_name="Red",
            hunt_objective="test",
            hunt_hypothesis="test",
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=["Some random log source"],
            hunt_type=HuntType.IDENTITY,
        )
        assert classify_telemetry(red_input).readiness.value == "Red"
