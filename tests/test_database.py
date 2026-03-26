"""Tests for the SQLite persistence layer."""

from __future__ import annotations

import json

import pytest

from mssp_hunt_agent.persistence.database import HuntDatabase, _slug
from mssp_hunt_agent.persistence.models import (
    ClientRecord,
    FindingRecord,
    IOCSweepRecord,
    ProfileVersion,
    RunRecord,
)


@pytest.fixture()
def db() -> HuntDatabase:
    """Fresh in-memory database for each test."""
    return HuntDatabase(":memory:")


# ── slug helper ──────────────────────────────────────────────────────


class TestSlug:
    def test_basic(self) -> None:
        assert _slug("Acme Corp") == "acme-corp"

    def test_underscores(self) -> None:
        assert _slug("my_client") == "my-client"

    def test_whitespace(self) -> None:
        assert _slug("  Big  Bank  ") == "big--bank"


# ── clients ──────────────────────────────────────────────────────────


class TestClients:
    def test_ensure_client_creates(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme Corp", industry="Finance")
        assert client.client_name == "Acme Corp"
        assert client.client_id == "acme-corp"
        assert client.industry == "Finance"

    def test_ensure_client_idempotent(self, db: HuntDatabase) -> None:
        c1 = db.ensure_client("Acme Corp")
        c2 = db.ensure_client("Acme Corp")
        assert c1.client_id == c2.client_id

    def test_get_client_missing(self, db: HuntDatabase) -> None:
        assert db.get_client("Nonexistent") is None

    def test_list_clients(self, db: HuntDatabase) -> None:
        db.ensure_client("Alpha")
        db.ensure_client("Beta")
        db.ensure_client("Gamma")
        clients = db.list_clients()
        assert len(clients) == 3
        assert [c.client_name for c in clients] == ["Alpha", "Beta", "Gamma"]

    def test_custom_client_id(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme", client_id="custom-id")
        assert client.client_id == "custom-id"


# ── hunt runs ────────────────────────────────────────────────────────


class TestRuns:
    def _seed_client(self, db: HuntDatabase) -> ClientRecord:
        return db.ensure_client("TestClient")

    def test_save_and_get_run(self, db: HuntDatabase) -> None:
        client = self._seed_client(db)
        run = RunRecord(
            run_id="RUN-001",
            client_id=client.client_id,
            client_name="TestClient",
            hunt_type="hypothesis",
            execution_mode="mock",
            started_at="2024-01-15T10:00:00Z",
            completed_at="2024-01-15T10:05:00Z",
            findings_count=2,
            high_confidence_count=1,
            queries_executed=3,
            total_events=150,
            output_dir="/output/run1",
            summary="Found suspicious activity",
        )
        db.save_run(run)

        got = db.get_run("RUN-001")
        assert got is not None
        assert got.run_id == "RUN-001"
        assert got.hunt_type == "hypothesis"
        assert got.findings_count == 2
        assert got.high_confidence_count == 1

    def test_get_run_missing(self, db: HuntDatabase) -> None:
        assert db.get_run("NOPE") is None

    def test_get_runs_filter_by_client(self, db: HuntDatabase) -> None:
        c1 = db.ensure_client("ClientA")
        c2 = db.ensure_client("ClientB")

        for i in range(3):
            db.save_run(RunRecord(
                run_id=f"RUN-A{i}", client_id=c1.client_id,
                client_name="ClientA", hunt_type="hypothesis",
                started_at=f"2024-01-{10+i}T00:00:00Z",
            ))
        db.save_run(RunRecord(
            run_id="RUN-B0", client_id=c2.client_id,
            client_name="ClientB", hunt_type="ioc_sweep",
        ))

        a_runs = db.get_runs(client_name="ClientA")
        assert len(a_runs) == 3
        b_runs = db.get_runs(client_name="ClientB")
        assert len(b_runs) == 1

    def test_get_runs_filter_by_type(self, db: HuntDatabase) -> None:
        client = self._seed_client(db)
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="TestClient", hunt_type="hypothesis",
        ))
        db.save_run(RunRecord(
            run_id="R2", client_id=client.client_id,
            client_name="TestClient", hunt_type="ioc_sweep",
        ))
        db.save_run(RunRecord(
            run_id="R3", client_id=client.client_id,
            client_name="TestClient", hunt_type="hypothesis",
        ))

        hyp = db.get_runs(hunt_type="hypothesis")
        assert len(hyp) == 2
        ioc = db.get_runs(hunt_type="ioc_sweep")
        assert len(ioc) == 1

    def test_get_runs_limit(self, db: HuntDatabase) -> None:
        client = self._seed_client(db)
        for i in range(10):
            db.save_run(RunRecord(
                run_id=f"R{i}", client_id=client.client_id,
                client_name="TestClient", hunt_type="hypothesis",
            ))
        runs = db.get_runs(limit=3)
        assert len(runs) == 3

    def test_run_errors_serialized(self, db: HuntDatabase) -> None:
        client = self._seed_client(db)
        run = RunRecord(
            run_id="R-ERR", client_id=client.client_id,
            client_name="TestClient", hunt_type="hypothesis",
            errors=["timeout at step 3", "enrichment failed"],
        )
        db.save_run(run)
        got = db.get_run("R-ERR")
        assert got is not None
        assert got.errors == ["timeout at step 3", "enrichment failed"]

    def test_save_run_upsert(self, db: HuntDatabase) -> None:
        client = self._seed_client(db)
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="TestClient", hunt_type="hypothesis",
            status="running",
        ))
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="TestClient", hunt_type="hypothesis",
            status="completed", findings_count=5,
        ))
        got = db.get_run("R1")
        assert got is not None
        assert got.status == "completed"
        assert got.findings_count == 5


# ── profiles ─────────────────────────────────────────────────────────


class TestProfiles:
    def test_save_and_get_latest(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        db.save_profile(ProfileVersion(
            version_id="PV-1", client_id=client.client_id,
            version_number=1, source_count=5, total_event_count=1000,
            profile_data={"sources": ["Azure AD"]},
        ))
        db.save_profile(ProfileVersion(
            version_id="PV-2", client_id=client.client_id,
            version_number=2, source_count=8, total_event_count=5000,
            profile_data={"sources": ["Azure AD", "Okta", "CrowdStrike"]},
        ))

        latest = db.get_latest_profile(client.client_id)
        assert latest is not None
        assert latest.version_number == 2
        assert latest.source_count == 8

    def test_list_versions(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        for i in range(1, 4):
            db.save_profile(ProfileVersion(
                version_id=f"PV-{i}", client_id=client.client_id,
                version_number=i, source_count=i * 3,
            ))
        versions = db.list_profile_versions(client.client_id)
        assert len(versions) == 3
        assert [v.version_number for v in versions] == [1, 2, 3]

    def test_get_next_version(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        assert db.get_next_profile_version(client.client_id) == 1
        db.save_profile(ProfileVersion(
            version_id="PV-1", client_id=client.client_id,
            version_number=1,
        ))
        assert db.get_next_profile_version(client.client_id) == 2

    def test_compare_profiles(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        db.save_profile(ProfileVersion(
            version_id="PV-1", client_id=client.client_id,
            version_number=1, source_count=3, total_event_count=1000,
            profile_data={"sources": ["A", "B", "C"]},
        ))
        db.save_profile(ProfileVersion(
            version_id="PV-2", client_id=client.client_id,
            version_number=2, source_count=5, total_event_count=3000,
            profile_data={"sources": ["A", "B", "C", "D", "E"]},
        ))

        diff = db.compare_profiles(client.client_id, 1, 2)
        assert diff["source_count_delta"] == 2
        assert diff["event_count_delta"] == 2000

    def test_compare_missing_version(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        diff = db.compare_profiles(client.client_id, 1, 99)
        assert "error" in diff

    def test_latest_profile_empty(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        assert db.get_latest_profile(client.client_id) is None


# ── findings ─────────────────────────────────────────────────────────


class TestFindings:
    def test_save_and_get_findings(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="Acme", hunt_type="hypothesis",
        ))
        db.save_finding(FindingRecord(
            finding_id="F1", run_id="R1", client_id=client.client_id,
            title="Suspicious auth", confidence="high", evidence_count=3,
        ))
        db.save_finding(FindingRecord(
            finding_id="F2", run_id="R1", client_id=client.client_id,
            title="Lateral movement", confidence="medium", evidence_count=1,
        ))
        findings = db.get_findings("R1")
        assert len(findings) == 2
        assert findings[0].title == "Suspicious auth"

    def test_findings_empty(self, db: HuntDatabase) -> None:
        assert db.get_findings("NOPE") == []


# ── IOC sweeps ───────────────────────────────────────────────────────


class TestIOCSweeps:
    def test_save_and_get_sweeps(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="Acme", hunt_type="ioc_sweep",
        ))
        db.save_ioc_sweep(IOCSweepRecord(
            sweep_id="S1", run_id="R1", client_id=client.client_id,
            total_iocs=10, valid_iocs=8, total_hits=3, total_misses=5,
            hit_iocs=["1.2.3.4", "evil.com", "abc123"],
        ))
        sweeps = db.get_ioc_sweeps(client.client_id)
        assert len(sweeps) == 1
        assert sweeps[0].hit_iocs == ["1.2.3.4", "evil.com", "abc123"]

    def test_sweeps_empty(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        assert db.get_ioc_sweeps(client.client_id) == []


# ── client stats ─────────────────────────────────────────────────────


class TestClientStats:
    def test_stats_with_data(self, db: HuntDatabase) -> None:
        client = db.ensure_client("Acme")
        db.save_run(RunRecord(
            run_id="R1", client_id=client.client_id,
            client_name="Acme", hunt_type="hypothesis",
            started_at="2024-01-10T00:00:00Z",
        ))
        db.save_run(RunRecord(
            run_id="R2", client_id=client.client_id,
            client_name="Acme", hunt_type="hypothesis",
            started_at="2024-01-15T00:00:00Z",
        ))
        db.save_run(RunRecord(
            run_id="R3", client_id=client.client_id,
            client_name="Acme", hunt_type="ioc_sweep",
        ))
        db.save_finding(FindingRecord(
            finding_id="F1", run_id="R1", client_id=client.client_id,
            title="Test", confidence="high",
        ))
        db.save_finding(FindingRecord(
            finding_id="F2", run_id="R1", client_id=client.client_id,
            title="Test2", confidence="low",
        ))

        stats = db.get_client_stats("Acme")
        assert stats is not None
        assert stats.total_runs == 3
        assert stats.hypothesis_runs == 2
        assert stats.ioc_runs == 1
        assert stats.total_findings == 2
        assert stats.high_confidence_findings == 1

    def test_stats_missing_client(self, db: HuntDatabase) -> None:
        assert db.get_client_stats("Nonexistent") is None

    def test_stats_no_runs(self, db: HuntDatabase) -> None:
        db.ensure_client("Empty")
        stats = db.get_client_stats("Empty")
        assert stats is not None
        assert stats.total_runs == 0
