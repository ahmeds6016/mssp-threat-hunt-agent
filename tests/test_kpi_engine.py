"""Tests for the KPI engine — compute metrics from pre-populated SQLite."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.analytics.kpi_engine import KPIEngine
from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.persistence.models import FindingRecord, RunRecord


@pytest.fixture
def populated_db() -> HuntDatabase:
    """In-memory DB pre-populated with sample run data."""
    db = HuntDatabase(":memory:")

    # Create two clients
    db.ensure_client("ClientA")
    db.ensure_client("ClientB")

    # ClientA: 3 hypothesis runs, 1 IOC sweep
    for i in range(3):
        db.save_run(RunRecord(
            run_id=f"RUN-A-{i}",
            client_id="clienta",
            client_name="ClientA",
            hunt_type="hypothesis",
            started_at=f"2024-12-0{i+1}T10:00:00Z",
            completed_at=f"2024-12-0{i+1}T11:00:00Z",
            findings_count=2,
            high_confidence_count=1 if i == 0 else 0,
            queries_executed=5,
            total_events=100,
        ))

    db.save_run(RunRecord(
        run_id="RUN-A-IOC",
        client_id="clienta",
        client_name="ClientA",
        hunt_type="ioc_sweep",
        started_at="2024-12-05T10:00:00Z",
        completed_at="2024-12-05T11:00:00Z",
        findings_count=3,
        queries_executed=10,
        total_events=500,
    ))

    # ClientB: 1 hypothesis, 1 profile
    db.save_run(RunRecord(
        run_id="RUN-B-0",
        client_id="clientb",
        client_name="ClientB",
        hunt_type="hypothesis",
        started_at="2024-12-02T10:00:00Z",
        completed_at="2024-12-02T11:00:00Z",
        findings_count=1,
        queries_executed=3,
        total_events=50,
    ))

    db.save_run(RunRecord(
        run_id="RUN-B-PROF",
        client_id="clientb",
        client_name="ClientB",
        hunt_type="profile",
        started_at="2024-12-03T10:00:00Z",
        completed_at="2024-12-03T11:00:00Z",
        queries_executed=8,
        total_events=200,
    ))

    # Add some findings
    for i in range(3):
        db.save_finding(FindingRecord(
            finding_id=f"F-A-{i}",
            run_id="RUN-A-0",
            client_id="clienta",
            title="Suspicious Auth Pattern" if i < 2 else "Malware Hash Match",
            confidence="high" if i == 0 else "medium",
            evidence_count=2,
            created_at="2024-12-01T10:30:00Z",
        ))

    db.save_finding(FindingRecord(
        finding_id="F-B-0",
        run_id="RUN-B-0",
        client_id="clientb",
        title="Suspicious Auth Pattern",
        confidence="low",
        evidence_count=1,
        created_at="2024-12-02T10:30:00Z",
    ))

    return db


class TestClientKPIs:
    def test_basic_kpis(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        kpis = engine.client_kpis("ClientA")

        assert kpis is not None
        assert kpis.client_name == "ClientA"
        assert kpis.total_hunts == 4
        assert kpis.hypothesis_hunts == 3
        assert kpis.ioc_sweeps == 1
        assert kpis.profile_runs == 0
        assert kpis.total_findings == 9  # 2*3 + 3
        assert kpis.high_confidence_findings == 1
        assert kpis.total_queries == 25  # 5*3 + 10
        assert kpis.total_events == 800  # 100*3 + 500

    def test_hit_rate(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        kpis = engine.client_kpis("ClientA")

        assert kpis is not None
        assert kpis.hit_rate == round(9 / 4, 3)

    def test_mean_queries(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        kpis = engine.client_kpis("ClientA")

        assert kpis is not None
        assert kpis.mean_queries_per_hunt == round(25 / 4, 1)

    def test_nonexistent_client(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        assert engine.client_kpis("NoSuchClient") is None

    def test_clientb_kpis(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        kpis = engine.client_kpis("ClientB")

        assert kpis is not None
        assert kpis.total_hunts == 2
        assert kpis.hypothesis_hunts == 1
        assert kpis.profile_runs == 1
        assert kpis.total_queries == 11


class TestAllClientKPIs:
    def test_all_clients(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        all_kpis = engine.all_client_kpis()

        assert len(all_kpis) == 2
        names = {k.client_name for k in all_kpis}
        assert names == {"ClientA", "ClientB"}

    def test_period_filter(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        kpis = engine.all_client_kpis(period="2024-12")

        # All runs are in 2024-12 so should return both clients
        assert len(kpis) >= 1


class TestTopFindings:
    def test_top_findings(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        top = engine.top_findings(limit=5)

        assert len(top) >= 1
        # Findings are grouped by (title, confidence), so verify our titles appear
        titles = {f["title"] for f in top}
        assert "Suspicious Auth Pattern" in titles


class TestRecurringGaps:
    def test_recurring_gaps(self, populated_db: HuntDatabase) -> None:
        engine = KPIEngine(populated_db)
        gaps = engine.recurring_gaps(limit=5)

        # All runs have empty summary by default (summary="" except what we set)
        # This test just verifies the function runs without error
        assert isinstance(gaps, list)
