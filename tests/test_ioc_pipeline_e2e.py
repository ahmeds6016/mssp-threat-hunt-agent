"""End-to-end tests for the IOC sweep pipeline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType
from mssp_hunt_agent.pipeline.orchestrator import run_ioc_pipeline


def _make_config(output_dir: Path) -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        approval_required=False,
        output_dir=output_dir,
        enrichment_cache_dir=output_dir / ".cache",
    )


@pytest.fixture
def ioc_input() -> IOCHuntInput:
    return IOCHuntInput(
        client_name="TestCorp",
        iocs=[
            IOCEntry(value="185.220.101.34", ioc_type=IOCType.IP, context="C2 callback"),
            IOCEntry(value="91.219.236.12", ioc_type=IOCType.IP, context="Secondary C2"),
            IOCEntry(value="evil-finance-login.com", ioc_type=IOCType.DOMAIN, context="Phishing domain"),
            IOCEntry(value="e99a18c428cb38d5f260853678922e03", ioc_type=IOCType.HASH_MD5, context="Malicious PDF"),
            IOCEntry(value="python-requests/2.31.0", ioc_type=IOCType.USER_AGENT, context="Dropper UA"),
            IOCEntry(value="not-a-valid-ip", ioc_type=IOCType.IP, context="Invalid"),
            IOCEntry(value="185.220.101.34", ioc_type=IOCType.IP, context="Duplicate"),
        ],
        time_range="2024-10-01 to 2024-11-30",
        available_data_sources=["Azure AD sign-in logs", "Firewall logs", "DNS logs"],
        telemetry_gaps=["Email gateway logs not available"],
        pre_enrich=True,
        analyst_notes="IOCs from FS-ISAC alert.",
    )


class TestIOCPipelineE2E:
    def test_full_ioc_sweep(self, ioc_input: IOCHuntInput) -> None:
        """Run the full IOC sweep in mock mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(ioc_input, config)

            assert result.stopped_at is None
            assert result.output_dir is not None
            assert result.output_dir.exists()

            # Artefacts written
            assert (result.output_dir / "executive_summary.md").exists()
            assert (result.output_dir / "analyst_report.md").exists()
            assert (result.output_dir / "run_trace.json").exists()

            # IOC batch processed
            assert result.ioc_batch is not None
            assert len(result.ioc_batch.valid) == 5  # 7 submitted - 1 invalid - 1 dedup
            assert len(result.ioc_batch.invalid) == 1
            assert result.ioc_batch.dedup_removed == 1

            # Sweep executed
            assert result.sweep_result is not None
            assert result.sweep_result.total_iocs_searched == 5
            assert result.sweep_result.total_hits + result.sweep_result.total_misses == 5

            # Pre-enrichment ran
            assert len(result.pre_enrichments) > 0

    def test_ioc_plan_only(self, ioc_input: IOCHuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(ioc_input, config, plan_only=True)

            assert result.stopped_at == "plan_only"
            assert result.hunt_plan is not None
            assert len(result.query_results) == 0

    def test_ioc_approval_denied(self, ioc_input: IOCHuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            config.approval_required = True
            result = run_ioc_pipeline(
                ioc_input, config, approval_callback=lambda _: False,
            )
            assert result.stopped_at == "approval_denied"

    def test_all_invalid_iocs(self) -> None:
        """If every IOC is invalid, pipeline stops early."""
        bad_input = IOCHuntInput(
            client_name="BadCorp",
            iocs=[
                IOCEntry(value="not-valid", ioc_type=IOCType.IP),
                IOCEntry(value="also-bad", ioc_type=IOCType.IP),
            ],
            time_range="2024-01-01 to 2024-01-31",
            available_data_sources=["Firewall logs"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(bad_input, config)
            assert result.stopped_at == "no_valid_iocs"

    def test_ioc_report_sections(self, ioc_input: IOCHuntInput) -> None:
        """Verify IOC report contains required sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(ioc_input, config)

            report_md = (result.output_dir / "analyst_report.md").read_text()
            required = [
                "Sweep Overview",
                "IOC Validation & Normalization",
                "Pre-Search Threat Intel Assessment",
                "IOC Sweep Results by Type",
                "Indicators with Hits",
                "Indicators with No Hits",
                "Telemetry Readiness Assessment",
                "Alternative Benign Explanations",
                "Escalation Recommendations",
                "Detection Engineering Follow-Up",
                "Gaps / Missing Information",
                "Analyst Notes",
            ]
            for heading in required:
                assert heading in report_md, f"Missing section: {heading}"

    def test_ioc_executive_summary_labels_mock(self, ioc_input: IOCHuntInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(ioc_input, config)

            summary_md = (result.output_dir / "executive_summary.md").read_text()
            assert "IOC Sweep" in summary_md
            assert "MOCK" in summary_md

    def test_from_json_file(self) -> None:
        """Load the sample IOC JSON and run the pipeline."""
        sample_path = Path(__file__).parent.parent / "examples" / "client_inputs" / "ioc_sweep_retro.json"
        if not sample_path.exists():
            pytest.skip("Sample IOC file not found")

        data = json.loads(sample_path.read_text())
        ioc_input = IOCHuntInput(**data)

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_ioc_pipeline(ioc_input, config)

            assert result.stopped_at is None
            assert result.ioc_batch is not None
            assert result.sweep_result is not None
            # The sample has 1 invalid + 1 duplicate out of 12
            assert len(result.ioc_batch.invalid) >= 1
            assert result.ioc_batch.dedup_removed >= 1
