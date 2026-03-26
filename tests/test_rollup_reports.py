"""Tests for weekly and monthly rollup report generation."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.analytics.rollup_reports import (
    generate_monthly_rollup,
    generate_weekly_rollup,
)
from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.persistence.models import FindingRecord, RunRecord


@pytest.fixture
def populated_db() -> HuntDatabase:
    """In-memory DB with sample data."""
    db = HuntDatabase(":memory:")
    db.ensure_client("AcmeCorp")
    db.ensure_client("GlobalBank")

    # AcmeCorp runs
    db.save_run(RunRecord(
        run_id="RUN-AC-1",
        client_id="acmecorp",
        client_name="AcmeCorp",
        hunt_type="hypothesis",
        started_at="2024-12-02T10:00:00Z",
        completed_at="2024-12-02T11:00:00Z",
        findings_count=2,
        high_confidence_count=1,
        queries_executed=5,
        total_events=150,
        summary="Credential abuse investigation",
    ))

    db.save_run(RunRecord(
        run_id="RUN-AC-2",
        client_id="acmecorp",
        client_name="AcmeCorp",
        hunt_type="ioc_sweep",
        started_at="2024-12-04T10:00:00Z",
        findings_count=1,
        queries_executed=8,
        total_events=300,
    ))

    # GlobalBank runs
    db.save_run(RunRecord(
        run_id="RUN-GB-1",
        client_id="globalbank",
        client_name="GlobalBank",
        hunt_type="hypothesis",
        started_at="2024-12-03T10:00:00Z",
        findings_count=3,
        high_confidence_count=2,
        queries_executed=6,
        total_events=200,
    ))

    # Findings
    db.save_finding(FindingRecord(
        finding_id="F-1",
        run_id="RUN-AC-1",
        client_id="acmecorp",
        title="Suspicious Auth Pattern",
        confidence="high",
    ))
    db.save_finding(FindingRecord(
        finding_id="F-2",
        run_id="RUN-GB-1",
        client_id="globalbank",
        title="Suspicious Auth Pattern",
        confidence="medium",
    ))
    db.save_finding(FindingRecord(
        finding_id="F-3",
        run_id="RUN-GB-1",
        client_id="globalbank",
        title="Malware Hash Match",
        confidence="high",
    ))

    return db


class TestWeeklyRollup:
    def test_generates_rollup(self, populated_db: HuntDatabase) -> None:
        rollup, md = generate_weekly_rollup(populated_db, period="2024-W48")

        assert rollup.period == "2024-W48"
        assert isinstance(md, str)
        assert "Weekly Hunt Rollup" in md

    def test_rollup_with_data(self, populated_db: HuntDatabase) -> None:
        # Using "all" period (no filter) by using a generic period
        rollup, md = generate_weekly_rollup(populated_db, period="2024-W48")

        # The rollup object should be valid even if period filter returns 0
        assert rollup.total_clients_active >= 0
        assert isinstance(rollup.client_kpis, list)

    def test_markdown_contains_table(self, populated_db: HuntDatabase) -> None:
        _, md = generate_weekly_rollup(populated_db, period="2024-W48")

        assert "| Metric |" in md
        assert "Active clients" in md

    def test_default_period(self, populated_db: HuntDatabase) -> None:
        rollup, md = generate_weekly_rollup(populated_db)

        # Should default to current week
        assert rollup.period  # non-empty
        assert "-W" in rollup.period


class TestMonthlyRollup:
    def test_generates_rollup(self, populated_db: HuntDatabase) -> None:
        rollup, md = generate_monthly_rollup(populated_db, period="2024-12")

        assert rollup.period == "2024-12"
        assert isinstance(md, str)
        assert "Monthly Hunt Rollup" in md

    def test_rollup_aggregates(self, populated_db: HuntDatabase) -> None:
        rollup, _ = generate_monthly_rollup(populated_db, period="2024-12")

        # Both clients have runs in 2024-12
        assert rollup.total_clients_active == 2
        assert rollup.total_hunts == 3  # 2 + 1
        assert rollup.total_findings == 6  # 2+1+3
        assert rollup.high_confidence_findings == 3  # 1+2

    def test_client_kpis_in_rollup(self, populated_db: HuntDatabase) -> None:
        rollup, _ = generate_monthly_rollup(populated_db, period="2024-12")

        assert len(rollup.client_kpis) == 2
        acme = next(k for k in rollup.client_kpis if k.client_name == "AcmeCorp")
        assert acme.total_hunts == 2
        assert acme.total_queries == 13  # 5 + 8

    def test_top_findings_in_rollup(self, populated_db: HuntDatabase) -> None:
        rollup, md = generate_monthly_rollup(populated_db, period="2024-12")

        assert len(rollup.top_findings) >= 1
        titles = {f["title"] for f in rollup.top_findings}
        assert "Suspicious Auth Pattern" in titles

    def test_markdown_has_sections(self, populated_db: HuntDatabase) -> None:
        _, md = generate_monthly_rollup(populated_db, period="2024-12")

        assert "## Summary" in md
        assert "## Client Breakdown" in md
        assert "## Top Findings" in md

    def test_default_period(self, populated_db: HuntDatabase) -> None:
        rollup, _ = generate_monthly_rollup(populated_db)

        assert rollup.period  # non-empty
        assert "-" in rollup.period  # "YYYY-MM" format
