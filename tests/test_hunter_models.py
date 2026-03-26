"""Tests for V7 hunter data models — environment, hypothesis, finding, campaign, report."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from mssp_hunt_agent.hunter.models.environment import (
    AssetIndex,
    AssetProfile,
    EnvironmentIndex,
    IdentityIndex,
    IndexMetadata,
    IndexRefreshLayer,
    IngestionBaseline,
    NetworkContext,
    OrgContext,
    SecurityPosture,
    TableProfile,
    TelemetryIndex,
    UserProfile,
)
from mssp_hunt_agent.hunter.models.hypothesis import (
    AutonomousHypothesis,
    HypothesisPriority,
    HypothesisSource,
)
from mssp_hunt_agent.hunter.models.finding import (
    EvidenceChain,
    EvidenceLink,
    FindingClassification,
    FindingSeverity,
    HuntFinding,
)
from mssp_hunt_agent.hunter.models.campaign import (
    CampaignConfig,
    CampaignPhase,
    CampaignState,
    PhaseResult,
)
from mssp_hunt_agent.hunter.models.report import (
    CampaignReport,
    DetectionSuggestion,
    MITREHeatmapEntry,
    ReportSection,
)


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def table_profile() -> TableProfile:
    return TableProfile(
        table_name="SigninLogs",
        columns=["TimeGenerated", "UserPrincipalName", "IPAddress", "ResultType"],
        column_types={"TimeGenerated": "datetime", "UserPrincipalName": "string"},
        mitre_techniques_covered=["T1078"],
        avg_daily_events=5000.0,
        row_count_7d=35000,
        row_count_30d=150000,
        ingestion_healthy=True,
    )


@pytest.fixture
def env_index() -> EnvironmentIndex:
    return EnvironmentIndex(
        metadata=IndexMetadata(
            client_id="test-client",
            workspace_id="ws-123",
            index_version=1,
            total_tables=3,
            total_users=10,
            total_assets=5,
        ),
        telemetry=TelemetryIndex(
            tables=[
                TableProfile(table_name="SigninLogs", columns=["TimeGenerated"], row_count_7d=1000, ingestion_healthy=True),
                TableProfile(table_name="SecurityEvent", columns=["TimeGenerated"], row_count_7d=5000, ingestion_healthy=True),
                TableProfile(table_name="Heartbeat", columns=["TimeGenerated"], row_count_7d=0, ingestion_healthy=False),
            ],
        ),
        identity=IdentityIndex(
            users=[
                UserProfile(user_principal_name="admin@test.com", is_admin=True, mfa_enforced=True),
                UserProfile(user_principal_name="user@test.com", is_admin=False),
                UserProfile(user_principal_name="svc-app@test.com", is_service_account=True),
            ],
            total_users=3,
            admin_count=1,
            service_account_count=1,
        ),
        assets=AssetIndex(
            assets=[
                AssetProfile(hostname="DC01", is_domain_controller=True, os_type="Windows"),
                AssetProfile(hostname="WEB01", is_server=True, os_type="Linux"),
            ],
            total_assets=2,
            domain_controllers=["DC01"],
            edr_coverage_pct=50.0,
        ),
        posture=SecurityPosture(open_incidents=2, incidents_last_90d=15),
        org=OrgContext(industry="Finance", domains=["test.com"]),
    )


@pytest.fixture
def hypothesis() -> AutonomousHypothesis:
    return AutonomousHypothesis(
        hypothesis_id="H-001",
        title="Credential Stuffing via Legacy Auth",
        description="Attackers may use legacy protocols to bypass MFA.",
        source=HypothesisSource.COVERAGE_GAP,
        threat_likelihood=0.8,
        detection_feasibility=0.9,
        business_impact=0.7,
        required_tables=["SigninLogs", "AuditLogs"],
        available_tables=["SigninLogs"],
        missing_tables=["AuditLogs"],
        mitre_techniques=["T1078"],
    )


@pytest.fixture
def finding() -> HuntFinding:
    return HuntFinding(
        finding_id="F-001",
        hypothesis_id="H-001",
        campaign_id="CAMP-abc123",
        title="Legacy auth from suspicious IP",
        description="Multiple failed sign-ins via IMAP from 185.x.x.x",
        classification=FindingClassification.TRUE_POSITIVE,
        severity=FindingSeverity.HIGH,
        confidence=0.85,
        mitre_techniques=["T1078"],
        recommendations=["Block legacy auth", "Enforce MFA"],
        evidence_chain=EvidenceChain(
            chain_id="EC-001",
            links=[
                EvidenceLink(
                    evidence_id="EL-001",
                    source_type="kql_result",
                    query_text="SigninLogs | where ClientAppUsed !in~ ('Browser', 'Mobile Apps')",
                    result_count=42,
                    entities_involved={"ip": ["185.1.2.3"], "user": ["user@test.com"]},
                ),
            ],
        ),
    )


@pytest.fixture
def campaign_config() -> CampaignConfig:
    return CampaignConfig(
        client_name="TestCorp",
        max_hypotheses=5,
        max_total_queries=100,
        max_duration_minutes=30,
        max_llm_tokens=200_000,
    )


# ── Environment Model Tests ────────────────────────────────────────


class TestEnvironmentModels:
    def test_table_profile_creation(self, table_profile: TableProfile):
        assert table_profile.table_name == "SigninLogs"
        assert len(table_profile.columns) == 4
        assert table_profile.ingestion_healthy is True
        assert table_profile.row_count_7d == 35000

    def test_telemetry_index_table_names(self, env_index: EnvironmentIndex):
        assert "SigninLogs" in env_index.telemetry.table_names
        assert "SecurityEvent" in env_index.telemetry.table_names

    def test_telemetry_get_table(self, env_index: EnvironmentIndex):
        t = env_index.telemetry.get_table("signinlogs")  # case-insensitive
        assert t is not None
        assert t.table_name == "SigninLogs"

    def test_telemetry_get_table_missing(self, env_index: EnvironmentIndex):
        assert env_index.telemetry.get_table("NonExistent") is None

    def test_telemetry_healthy_tables(self, env_index: EnvironmentIndex):
        healthy = env_index.telemetry.healthy_tables
        assert "SigninLogs" in healthy
        assert "SecurityEvent" in healthy
        assert "Heartbeat" not in healthy  # row_count_7d=0

    def test_identity_admin_accounts(self, env_index: EnvironmentIndex):
        admins = env_index.identity.admin_accounts
        assert admins == ["admin@test.com"]

    def test_identity_service_accounts(self, env_index: EnvironmentIndex):
        svc = env_index.identity.service_accounts
        assert svc == ["svc-app@test.com"]

    def test_env_index_summary(self, env_index: EnvironmentIndex):
        s = env_index.summary()
        assert s["tables"] == 3
        assert s["total_users"] == 3
        assert s["admin_count"] == 1
        assert s["open_incidents"] == 2
        assert s["industry"] == "Finance"
        assert "SigninLogs" in s["healthy_tables"]

    def test_index_metadata_defaults(self):
        m = IndexMetadata(client_id="x")
        assert m.index_version == 1
        assert m.static_refreshed_at == ""

    def test_index_refresh_layer_enum(self):
        assert IndexRefreshLayer.STATIC.value == "static"
        assert IndexRefreshLayer.SEMI_STATIC.value == "semi_static"
        assert IndexRefreshLayer.DYNAMIC.value == "dynamic"

    def test_user_profile_defaults(self):
        u = UserProfile(user_principal_name="a@b.com")
        assert u.is_admin is False
        assert u.is_service_account is False
        assert u.mfa_enforced is False

    def test_asset_profile_defaults(self):
        a = AssetProfile(hostname="SRV01")
        assert a.is_domain_controller is False
        assert a.edr_enrolled is False

    def test_ingestion_baseline(self):
        b = IngestionBaseline(table_name="SigninLogs", avg_daily_mb=100.5, stddev_daily_mb=10.0)
        assert b.baseline_period_days == 30

    def test_env_index_serialization(self, env_index: EnvironmentIndex):
        data = env_index.model_dump(mode="json")
        reloaded = EnvironmentIndex.model_validate(data)
        assert reloaded.metadata.client_id == "test-client"
        assert len(reloaded.telemetry.tables) == 3
        assert len(reloaded.identity.users) == 3


# ── Hypothesis Model Tests ─────────────────────────────────────────


class TestHypothesisModels:
    def test_hypothesis_creation(self, hypothesis: AutonomousHypothesis):
        assert hypothesis.hypothesis_id == "H-001"
        assert hypothesis.source == HypothesisSource.COVERAGE_GAP
        assert "T1078" in hypothesis.mitre_techniques

    def test_compute_priority_score_critical(self, hypothesis: AutonomousHypothesis):
        score = hypothesis.compute_priority_score()
        # 0.8 * 0.9 * 0.7 = 0.504
        assert score == pytest.approx(0.504, rel=0.01)
        assert hypothesis.priority == HypothesisPriority.HIGH

    def test_compute_priority_score_critical_threshold(self):
        h = AutonomousHypothesis(
            hypothesis_id="H-X",
            title="Test",
            description="Test",
            source=HypothesisSource.THREAT_LANDSCAPE,
            threat_likelihood=0.9,
            detection_feasibility=0.9,
            business_impact=0.9,
        )
        score = h.compute_priority_score()
        assert score >= 0.6
        assert h.priority == HypothesisPriority.CRITICAL

    def test_compute_priority_score_low(self):
        h = AutonomousHypothesis(
            hypothesis_id="H-L",
            title="Low",
            description="Low priority",
            source=HypothesisSource.ANALYST_INPUT,
            threat_likelihood=0.1,
            detection_feasibility=0.3,
            business_impact=0.2,
        )
        score = h.compute_priority_score()
        assert score < 0.2
        assert h.priority == HypothesisPriority.LOW

    def test_is_feasible_true(self, hypothesis: AutonomousHypothesis):
        assert hypothesis.is_feasible is True

    def test_is_feasible_false_no_tables(self):
        h = AutonomousHypothesis(
            hypothesis_id="H-NF",
            title="No Tables",
            description="Nothing available",
            source=HypothesisSource.COVERAGE_GAP,
            available_tables=[],
            detection_feasibility=0.5,
        )
        assert h.is_feasible is False

    def test_is_feasible_false_low_feasibility(self):
        h = AutonomousHypothesis(
            hypothesis_id="H-LF",
            title="Low Feasibility",
            description="Too hard",
            source=HypothesisSource.COVERAGE_GAP,
            available_tables=["SomeTable"],
            detection_feasibility=0.05,
        )
        assert h.is_feasible is False

    def test_hypothesis_source_values(self):
        assert len(HypothesisSource) == 8
        assert HypothesisSource.CISA_KEV.value == "cisa_kev"


# ── Finding Model Tests ────────────────────────────────────────────


class TestFindingModels:
    def test_finding_creation(self, finding: HuntFinding):
        assert finding.finding_id == "F-001"
        assert finding.classification == FindingClassification.TRUE_POSITIVE
        assert finding.severity == FindingSeverity.HIGH

    def test_finding_is_actionable_tp(self, finding: HuntFinding):
        assert finding.is_actionable is True

    def test_finding_is_actionable_escalation(self):
        f = HuntFinding(
            finding_id="F-ESC",
            hypothesis_id="H-001",
            title="Needs escalation",
            description="Unclear",
            classification=FindingClassification.REQUIRES_ESCALATION,
            severity=FindingSeverity.MEDIUM,
        )
        assert f.is_actionable is True

    def test_finding_not_actionable_fp(self):
        f = HuntFinding(
            finding_id="F-FP",
            hypothesis_id="H-001",
            title="False positive",
            description="Benign",
            classification=FindingClassification.FALSE_POSITIVE,
            severity=FindingSeverity.LOW,
        )
        assert f.is_actionable is False

    def test_finding_not_actionable_inconclusive(self):
        f = HuntFinding(
            finding_id="F-INC",
            hypothesis_id="H-001",
            title="Inconclusive",
            description="Not enough data",
            classification=FindingClassification.INCONCLUSIVE,
            severity=FindingSeverity.MEDIUM,
        )
        assert f.is_actionable is False

    def test_evidence_chain_total_events(self, finding: HuntFinding):
        assert finding.evidence_chain.total_events_analyzed == 42

    def test_evidence_chain_all_entities(self, finding: HuntFinding):
        entities = finding.evidence_chain.all_entities
        assert "ip" in entities
        assert "185.1.2.3" in entities["ip"]
        assert "user@test.com" in entities["user"]

    def test_evidence_chain_multiple_links(self):
        chain = EvidenceChain(
            chain_id="EC-M",
            links=[
                EvidenceLink(evidence_id="E1", source_type="kql_result", result_count=10,
                             entities_involved={"ip": ["1.2.3.4"]}),
                EvidenceLink(evidence_id="E2", source_type="pivot", result_count=5,
                             entities_involved={"ip": ["1.2.3.4", "5.6.7.8"], "host": ["DC01"]}),
            ],
        )
        assert chain.total_events_analyzed == 15
        all_e = chain.all_entities
        assert len(all_e["ip"]) == 2  # deduplicated
        assert "DC01" in all_e["host"]


# ── Campaign Model Tests ───────────────────────────────────────────


class TestCampaignModels:
    def test_campaign_phase_enum(self):
        assert CampaignPhase.INDEX_REFRESH.value == "index_refresh"
        assert CampaignPhase.COMPLETED.value == "completed"
        assert len(CampaignPhase) == 8

    def test_campaign_config_defaults(self, campaign_config: CampaignConfig):
        assert campaign_config.max_hypotheses == 5
        assert campaign_config.max_total_queries == 100
        assert campaign_config.auto_pivot is True
        assert campaign_config.priority_threshold == 0.2

    def test_campaign_config_phase_limits(self, campaign_config: CampaignConfig):
        assert "hypothesize" in campaign_config.phase_max_iterations
        assert campaign_config.phase_max_iterations["execute"] == 20

    def test_phase_result_defaults(self):
        pr = PhaseResult(phase=CampaignPhase.HYPOTHESIZE)
        assert pr.status == "pending"
        assert pr.tool_calls == 0
        assert pr.kql_queries_run == 0
        assert pr.errors == []

    def test_campaign_state_creation(self, campaign_config: CampaignConfig):
        state = CampaignState(
            campaign_id="CAMP-test",
            config=campaign_config,
            status="running",
            started_at="2026-03-10T00:00:00+00:00",
        )
        assert state.campaign_id == "CAMP-test"
        assert state.current_phase == CampaignPhase.INDEX_REFRESH
        assert state.findings == []

    def test_campaign_state_duration(self, campaign_config: CampaignConfig):
        state = CampaignState(
            campaign_id="CAMP-dur",
            config=campaign_config,
            started_at="2026-03-10T00:00:00+00:00",
            completed_at="2026-03-10T00:30:00+00:00",
        )
        assert state.duration_minutes == pytest.approx(30.0)

    def test_campaign_state_duration_not_completed(self, campaign_config: CampaignConfig):
        state = CampaignState(campaign_id="CAMP-x", config=campaign_config)
        assert state.duration_minutes == 0.0

    def test_campaign_state_true_positives(self, campaign_config: CampaignConfig, finding: HuntFinding):
        state = CampaignState(
            campaign_id="CAMP-tp",
            config=campaign_config,
            findings=[finding],
        )
        assert len(state.true_positives) == 1

    def test_campaign_state_actionable_findings(self, campaign_config: CampaignConfig, finding: HuntFinding):
        fp = HuntFinding(
            finding_id="F-FP",
            hypothesis_id="H-001",
            title="FP",
            description="False positive",
            classification=FindingClassification.FALSE_POSITIVE,
            severity=FindingSeverity.LOW,
        )
        state = CampaignState(
            campaign_id="CAMP-af",
            config=campaign_config,
            findings=[finding, fp],
        )
        assert len(state.actionable_findings) == 1

    def test_campaign_state_get_phase_result(self, campaign_config: CampaignConfig):
        pr = PhaseResult(phase=CampaignPhase.HYPOTHESIZE, status="success")
        state = CampaignState(
            campaign_id="CAMP-gpr",
            config=campaign_config,
            phase_results=[pr],
        )
        assert state.get_phase_result(CampaignPhase.HYPOTHESIZE) is pr
        assert state.get_phase_result(CampaignPhase.EXECUTE) is None


# ── Report Model Tests ─────────────────────────────────────────────


class TestReportModels:
    def test_report_creation(self):
        r = CampaignReport(campaign_id="CAMP-rpt", client_name="TestCorp")
        assert r.total_findings == 0
        assert r.markdown == ""

    def test_report_section(self):
        s = ReportSection(title="Executive Summary", content="All good.", order=1)
        assert s.order == 1

    def test_mitre_heatmap_entry(self):
        e = MITREHeatmapEntry(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="initial-access",
            status="finding",
            finding_id="F-001",
        )
        assert e.status == "finding"

    def test_detection_suggestion(self):
        d = DetectionSuggestion(
            title="Detect legacy auth",
            description="Flag legacy protocol usage",
            kql_query="SigninLogs | where ClientAppUsed !in~ ('Browser', 'Mobile Apps')",
            severity="high",
            mitre_techniques=["T1078"],
        )
        assert "SigninLogs" in d.kql_query

    def test_report_serialization(self):
        r = CampaignReport(
            campaign_id="CAMP-ser",
            client_name="TestCorp",
            total_findings=3,
            true_positives=2,
            markdown="# Report\n\nFindings here.",
            detection_suggestions=[
                DetectionSuggestion(
                    title="Rule 1",
                    description="Desc",
                    kql_query="SigninLogs | take 10",
                ),
            ],
        )
        data = r.model_dump(mode="json")
        reloaded = CampaignReport.model_validate(data)
        assert reloaded.total_findings == 3
        assert len(reloaded.detection_suggestions) == 1
