"""Tests for the CISA KEV pipeline (matcher + orchestrator)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.intel.kev_monitor import KEVAlert
from mssp_hunt_agent.intel.kev_pipeline import (
    DEFAULT_MAX_ALERTS_PER_SCAN,
    ExposureAssessment,
    KEVExposureMatcher,
    KEVPipeline,
    KEVScanResult,
    _kql_safe_token,
)
from mssp_hunt_agent.models.result_models import QueryResult


# ── Fixtures ──────────────────────────────────────────────────────────


def _make_alert(cve_id: str = "CVE-2026-0001", **overrides) -> KEVAlert:
    base = dict(
        alert_id="abc1234567890def",
        cve_id=cve_id,
        vendor="Acme",
        product="WebPortal",
        vulnerability_name="Acme WebPortal RCE",
        short_description="auth bypass to RCE",
        date_added="2026-04-10",
        due_date="2026-04-30",
        known_ransomware_use="Unknown",
        inferred_detection_sources=["DeviceProcessEvents", "DeviceFileEvents"],
    )
    base.update(overrides)
    return KEVAlert(**base)


def _adapter_returning(*counts: int) -> MagicMock:
    """Build a mock adapter where execute_query returns QueryResults
    with the given result_count values, in order. Extra calls return 0."""
    queue = list(counts)

    def _execute(query):
        n = queue.pop(0) if queue else 0
        return QueryResult(
            query_id=query.query_id,
            query_text=query.query_text,
            status="success",
            result_count=n,
            events=[],
            execution_time_ms=10,
        )

    adapter = MagicMock()
    adapter.execute_query.side_effect = _execute
    return adapter


def _adapter_raising(*errors: Exception) -> MagicMock:
    """Mock adapter where each execute_query call raises the next exception."""
    queue = list(errors)

    def _execute(query):
        if not queue:
            return QueryResult(
                query_id=query.query_id, query_text=query.query_text,
                status="success", result_count=0, events=[],
            )
        raise queue.pop(0)

    adapter = MagicMock()
    adapter.execute_query.side_effect = _execute
    return adapter


def _mock_blob() -> MagicMock:
    state: dict = {}
    blob = MagicMock()
    blob._download_json.side_effect = lambda k: state.get(k)
    blob._upload_json.side_effect = lambda k, v: state.update({k: v})
    blob._state = state
    return blob


# ── _kql_safe_token ───────────────────────────────────────────────────


class TestKqlSafeToken:
    def test_passes_alphanumeric(self):
        assert _kql_safe_token("Exchange Server") == "Exchange Server"

    def test_strips_single_quote(self):
        assert "'" not in _kql_safe_token("Don't")

    def test_strips_special_chars(self):
        assert _kql_safe_token("Acme; DROP TABLE") == "Acme DROP TABLE"

    def test_keeps_dot_and_hyphen(self):
        assert _kql_safe_token("v1.2-rc") == "v1.2-rc"

    def test_caps_length(self):
        long = "x" * 200
        assert len(_kql_safe_token(long)) == 80

    def test_handles_empty(self):
        assert _kql_safe_token("") == ""
        assert _kql_safe_token("   ") == ""


# ── KEVExposureMatcher ────────────────────────────────────────────────


class TestKEVExposureMatcher:
    def test_definitive_when_software_inventory_hits(self):
        # First query is DeviceTvmSoftwareInventory — return 5 matches
        adapter = _adapter_returning(5, 0, 0)
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.has_definitive_exposure is True
        assert assessment.has_circumstantial_evidence is False
        assert assessment.verdict == "true_positive"
        assert assessment.queries_run == 3
        assert any(e["table"] == "DeviceTvmSoftwareInventory" for e in assessment.evidence)

    def test_circumstantial_when_only_process_events_hit(self):
        adapter = _adapter_returning(0, 12, 0)
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.has_definitive_exposure is False
        assert assessment.has_circumstantial_evidence is True
        assert assessment.verdict == "inconclusive"

    def test_circumstantial_when_only_file_events_hit(self):
        adapter = _adapter_returning(0, 0, 7)
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.has_circumstantial_evidence is True
        assert assessment.verdict == "inconclusive"

    def test_definitive_overrides_circumstantial(self):
        # Both definitive AND circumstantial fire — should still be true_positive
        adapter = _adapter_returning(5, 12, 7)
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())
        assert assessment.verdict == "true_positive"

    def test_false_positive_when_all_queries_clean(self):
        adapter = _adapter_returning(0, 0, 0)
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.has_definitive_exposure is False
        assert assessment.has_circumstantial_evidence is False
        assert assessment.telemetry_available is True
        assert assessment.verdict == "false_positive"

    def test_escalation_when_all_tables_missing(self):
        # Every query raises a "could not be found" error → telemetry gap
        adapter = _adapter_raising(
            RuntimeError("Table 'DeviceTvmSoftwareInventory' could not be found"),
            RuntimeError("Table 'DeviceProcessEvents' could not be found"),
            RuntimeError("Table 'DeviceFileEvents' could not be found"),
        )
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.telemetry_available is False
        assert len(assessment.missing_telemetry) == 3
        assert assessment.verdict == "requires_escalation"

    def test_real_query_error_recorded_separately(self):
        adapter = _adapter_raising(
            RuntimeError("upstream timeout 504"),  # not a "table not found" error
            RuntimeError("upstream timeout 504"),
            RuntimeError("upstream timeout 504"),
        )
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert())

        assert assessment.telemetry_available is False
        assert len(assessment.errors) == 3
        assert len(assessment.missing_telemetry) == 0

    def test_empty_product_field_short_circuits(self):
        adapter = _adapter_returning()
        matcher = KEVExposureMatcher(adapter=adapter)

        assessment = matcher.assess(_make_alert(product=""))

        assert assessment.queries_run == 0
        assert assessment.errors  # logged the empty product issue
        adapter.execute_query.assert_not_called()


# ── KEVPipeline.run_scan (orchestration) ──────────────────────────────


def _config() -> HuntAgentConfig:
    cfg = HuntAgentConfig.from_env()
    cfg.adapter_mode = "mock"
    return cfg


class TestKEVPipelineRunScan:
    def test_returns_empty_when_no_new_alerts(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = []
        adapter = _adapter_returning()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
        )
        result = pipeline.run_scan()

        assert result.alerts_discovered == 0
        assert result.alerts_processed == 0
        assert result.exposed_count == 0
        adapter.execute_query.assert_not_called()

    def test_dry_run_skips_assessment(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert(), _make_alert(cve_id="CVE-2026-0002")]
        adapter = _adapter_returning()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
        )
        result = pipeline.run_scan(dry_run=True)

        assert result.alerts_discovered == 2
        assert result.alerts_processed == 2
        assert result.dry_run is True
        assert len(result.reports) == 2
        assert all("cve_id" in r for r in result.reports)
        adapter.execute_query.assert_not_called()

    def test_processes_alerts_and_tallies_verdicts(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [
            _make_alert(cve_id="CVE-2026-0001"),  # exposed
            _make_alert(cve_id="CVE-2026-0002"),  # not exposed
        ]
        # Alert 1: definitive hit on first query, then 2 zeros
        # Alert 2: 3 zeros
        adapter = _adapter_returning(5, 0, 0, 0, 0, 0)

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
        )
        result = pipeline.run_scan()

        assert result.alerts_processed == 2
        assert result.exposed_count == 1
        assert result.not_exposed_count == 1
        assert result.inconclusive_count == 0
        # 3 queries × 2 alerts
        assert adapter.execute_query.call_count == 6

    def test_caps_alerts_to_max_and_defers_excess(self):
        monitor = MagicMock()
        # 10 alerts, max 3 → 3 processed, 7 deferred
        monitor.check_catalog.return_value = [
            _make_alert(cve_id=f"CVE-2026-{i:04d}") for i in range(10)
        ]
        adapter = _adapter_returning()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
            max_alerts_per_scan=3,
        )
        result = pipeline.run_scan()

        assert result.alerts_discovered == 10
        assert result.alerts_processed == 3
        assert result.alerts_deferred == 7

    def test_max_alerts_default_constant(self):
        # Sanity: we expose the constant publicly
        assert DEFAULT_MAX_ALERTS_PER_SCAN >= 1

    def test_persists_scan_result_to_blob(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = []
        adapter = _adapter_returning()
        blob = _mock_blob()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=blob,
            monitor=monitor,
        )
        pipeline.run_scan()

        scan_keys = [k for k in blob._state if k.startswith("kev-scans/KEV-")]
        assert len(scan_keys) == 1

    def test_persists_report_per_processed_alert(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert()]
        adapter = _adapter_returning(5, 0, 0)
        blob = _mock_blob()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=blob,
            monitor=monitor,
        )
        result = pipeline.run_scan()

        assert result.alerts_processed == 1
        report_keys = [k for k in blob._state if k.startswith("kev-reports/RPT-")]
        assert len(report_keys) == 1

    def test_email_only_sent_for_exposed_or_partially_exposed(self):
        monitor = MagicMock()
        # Alert 1: exposed (definitive hit)
        # Alert 2: not exposed (all zeros)
        monitor.check_catalog.return_value = [
            _make_alert(cve_id="CVE-2026-0001"),
            _make_alert(cve_id="CVE-2026-0002"),
        ]
        adapter = _adapter_returning(5, 0, 0, 0, 0, 0)
        email = MagicMock()
        email.send_report.return_value = True

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            email_sender=email,
            monitor=monitor,
        )
        result = pipeline.run_scan(recipients=["test@example.com"])

        assert result.exposed_count == 1
        assert result.not_exposed_count == 1
        assert result.emails_sent == 1
        email.send_report.assert_called_once()

    def test_email_subject_includes_cve_and_verdict(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert(cve_id="CVE-2026-0001")]
        adapter = _adapter_returning(5, 0, 0)
        email = MagicMock()
        email.send_report.return_value = True

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            email_sender=email,
            monitor=monitor,
        )
        pipeline.run_scan(recipients=["a@b.com"])

        call_kwargs = email.send_report.call_args.kwargs
        subject = call_kwargs["subject"]
        assert "CVE-2026-0001" in subject
        assert "[CISA KEV]" in subject

    def test_no_email_when_recipients_empty(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert()]
        adapter = _adapter_returning(5, 0, 0)
        email = MagicMock()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            email_sender=email,
            monitor=monitor,
        )
        result = pipeline.run_scan(recipients=None)

        assert result.exposed_count == 1
        assert result.emails_sent == 0
        email.send_report.assert_not_called()

    def test_alert_processing_failure_does_not_abort_scan(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [
            _make_alert(cve_id="CVE-2026-0001"),
            _make_alert(cve_id="CVE-2026-0002"),
        ]
        adapter = MagicMock()
        # First alert raises mid-processing, second succeeds
        adapter.execute_query.side_effect = [
            RuntimeError("boom"),
            RuntimeError("boom"),
            RuntimeError("boom"),
            QueryResult(query_id="x", query_text="y", status="success",
                        result_count=0, events=[], execution_time_ms=1),
            QueryResult(query_id="x", query_text="y", status="success",
                        result_count=0, events=[], execution_time_ms=1),
            QueryResult(query_id="x", query_text="y", status="success",
                        result_count=0, events=[], execution_time_ms=1),
        ]

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
        )
        result = pipeline.run_scan()

        # First alert failed during exposure check (real errors, not telemetry gaps)
        # → falls into not_exposed bucket since telemetry_available stayed False but
        # ALL three calls were errors-with-no-table-msg, so we land in escalation.
        # The key assertion is the loop didn't crash and the second alert ran.
        assert result.alerts_processed == 2

    def test_catalog_fetch_failure_returns_partial_result(self):
        monitor = MagicMock()
        monitor.check_catalog.side_effect = RuntimeError("CISA down")
        adapter = _adapter_returning()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=_mock_blob(),
            monitor=monitor,
        )
        result = pipeline.run_scan()

        assert result.alerts_discovered == 0
        assert result.errors
        assert "catalog check failed" in result.errors[0]


# ── KEVPipeline._build_intel_event ────────────────────────────────────


class TestBuildIntelEvent:
    def test_marks_kev_inherently_relevant(self):
        pipeline = KEVPipeline(
            config=_config(),
            adapter=_adapter_returning(),
            blob_store=_mock_blob(),
            monitor=MagicMock(),
        )
        event = pipeline._build_intel_event(_make_alert())

        assert event.relevance_score == 1.0
        assert event.category == "vulnerability"
        assert event.cves == ["CVE-2026-0001"]
        assert "Acme WebPortal" in event.affected_software[0]

    def test_severity_critical_for_known_ransomware(self):
        pipeline = KEVPipeline(
            config=_config(),
            adapter=_adapter_returning(),
            blob_store=_mock_blob(),
            monitor=MagicMock(),
        )
        alert = _make_alert(known_ransomware_use="Known")
        event = pipeline._build_intel_event(alert)

        assert event.severity == "critical"

    def test_severity_uses_cvss_for_non_ransomware(self):
        pipeline = KEVPipeline(
            config=_config(),
            adapter=_adapter_returning(),
            blob_store=_mock_blob(),
            monitor=MagicMock(),
        )

        alert = _make_alert(cvss_score=9.5, known_ransomware_use="Unknown")
        assert pipeline._build_intel_event(alert).severity == "critical"

        alert = _make_alert(cvss_score=7.5, known_ransomware_use="Unknown")
        assert pipeline._build_intel_event(alert).severity == "high"

        alert = _make_alert(cvss_score=5.0, known_ransomware_use="Unknown")
        assert pipeline._build_intel_event(alert).severity == "medium"


# ── End-to-end report verdict ─────────────────────────────────────────


class TestEndToEndReport:
    def test_exposed_alert_produces_high_risk_report(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert()]
        adapter = _adapter_returning(5, 0, 0)
        blob = _mock_blob()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=blob,
            monitor=monitor,
        )
        result = pipeline.run_scan()

        report_keys = [k for k in blob._state if k.startswith("kev-reports/RPT-")]
        assert len(report_keys) == 1
        report = blob._state[report_keys[0]]
        assert report["verdict"] == "exposed"
        assert report["risk_level"] == "high"
        assert "CVE-2026-0001" in report["cves"]

    def test_not_exposed_alert_produces_low_risk_report(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert()]
        adapter = _adapter_returning(0, 0, 0)
        blob = _mock_blob()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=blob,
            monitor=monitor,
        )
        pipeline.run_scan()

        report_keys = [k for k in blob._state if k.startswith("kev-reports/RPT-")]
        report = blob._state[report_keys[0]]
        assert report["verdict"] == "not_exposed"
        assert report["risk_level"] == "low"

    def test_ransomware_alert_adds_priority_recommendation(self):
        monitor = MagicMock()
        monitor.check_catalog.return_value = [_make_alert(known_ransomware_use="Known")]
        adapter = _adapter_returning(5, 0, 0)
        blob = _mock_blob()

        pipeline = KEVPipeline(
            config=_config(),
            adapter=adapter,
            blob_store=blob,
            monitor=monitor,
        )
        pipeline.run_scan()

        report = blob._state[next(k for k in blob._state if k.startswith("kev-reports/RPT-"))]
        # Priority recommendation should be inserted at the top
        assert "ransomware" in report["recommendations"][0].lower()
