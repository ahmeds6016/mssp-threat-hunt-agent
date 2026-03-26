"""End-to-end tests for the profile pipeline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.models.profile_models import ClientTelemetryProfile, ProfileInput
from mssp_hunt_agent.pipeline.orchestrator import run_profile_pipeline


def _make_config(output_dir: Path) -> HuntAgentConfig:
    return HuntAgentConfig(
        mock_mode=True,
        approval_required=False,
        output_dir=output_dir,
        enrichment_cache_dir=output_dir / ".cache",
    )


class TestProfilePipelineE2E:
    def test_full_mock_profile(self, profile_input: ProfileInput) -> None:
        """Run profile pipeline end-to-end in mock mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config)

            assert result.stopped_at is None
            assert result.output_dir is not None
            assert result.output_dir.exists()

            # Artefacts written
            assert (result.output_dir / "client_telemetry_profile.json").exists()
            assert (result.output_dir / "client_telemetry_profile.md").exists()
            assert (result.output_dir / "run_trace.json").exists()
            assert (result.output_dir / "input_payload.json").exists()
            assert (result.output_dir / "profile_plan.json").exists()

            # Profile populated
            assert result.client_profile is not None
            assert result.client_profile.source_count > 0
            assert len(result.client_profile.capabilities) == 4

    def test_plan_only_mode(self, profile_input: ProfileInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config, plan_only=True)

            assert result.stopped_at == "plan_only"
            assert result.hunt_plan is not None
            assert result.client_profile is None
            assert len(result.query_results) == 0

    def test_approval_denied(self, profile_input: ProfileInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            config.approval_required = True
            result = run_profile_pipeline(
                profile_input, config, approval_callback=lambda _: False,
            )
            assert result.stopped_at == "approval_denied"

    def test_profile_json_roundtrip(self, profile_input: ProfileInput) -> None:
        """client_telemetry_profile.json roundtrips through the model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config)

            json_path = result.output_dir / "client_telemetry_profile.json"
            data = json.loads(json_path.read_text(encoding="utf-8"))
            restored = ClientTelemetryProfile(**data)

            assert restored.profile_id == result.client_profile.profile_id
            assert restored.source_count == result.client_profile.source_count
            assert len(restored.capabilities) == len(result.client_profile.capabilities)

    def test_profile_md_has_required_sections(self, profile_input: ProfileInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config)

            md = (result.output_dir / "client_telemetry_profile.md").read_text()
            required_headings = [
                "Profile Summary",
                "Hunt Readiness by Type",
                "Discovered Data Sources",
                "Declared vs. Discovered Gaps",
                "Recency Warnings",
                "Caveats",
                "Analyst Notes",
            ]
            for heading in required_headings:
                assert heading in md, f"Missing heading: {heading}"

    def test_mock_disclaimer_present(self, profile_input: ProfileInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config)

            md = (result.output_dir / "client_telemetry_profile.md").read_text()
            assert "SIMULATED" in md

    def test_from_json_file(self) -> None:
        """Load the sample profile JSON and run the pipeline."""
        sample = Path(__file__).parent.parent / "examples" / "client_inputs" / "profile_telemetry.json"
        if not sample.exists():
            pytest.skip("Sample profile file not found")

        data = json.loads(sample.read_text())
        pi = ProfileInput(**data)

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(pi, config)

            assert result.stopped_at is None
            assert result.client_profile is not None
            assert result.client_profile.client_name == "Contoso Financial"

    def test_output_folder_name_has_profile_suffix(self, profile_input: ProfileInput) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(Path(tmpdir))
            result = run_profile_pipeline(profile_input, config)

            assert result.output_dir is not None
            assert result.output_dir.name.endswith("_profile")
