"""Tests for campaign persistence and recursive learning engine."""

from __future__ import annotations

import json
import uuid

import pytest

from mssp_hunt_agent.hunter.learning import CampaignLearningEngine
from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState
from mssp_hunt_agent.hunter.models.finding import (
    EvidenceChain,
    EvidenceLink,
    FindingClassification,
    FindingSeverity,
    HuntFinding,
)
from mssp_hunt_agent.hunter.models.hypothesis import (
    AutonomousHypothesis,
    HypothesisPriority,
    HypothesisSource,
)
from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.persistence.models import (
    CampaignFindingRecord,
    CampaignHypothesisRecord,
    CampaignRecord,
    HuntLessonRecord,
)


@pytest.fixture
def db():
    return HuntDatabase(":memory:")


@pytest.fixture
def engine(db):
    return CampaignLearningEngine(db)


def _make_campaign_state(
    findings: list[HuntFinding] | None = None,
    hypotheses: list[AutonomousHypothesis] | None = None,
) -> CampaignState:
    """Create a test campaign state."""
    return CampaignState(
        campaign_id=f"CAMP-{uuid.uuid4().hex[:8]}",
        config=CampaignConfig(
            client_name="Test Corp",
            client_id="test-corp",
        ),
        status="completed",
        started_at="2026-03-10T10:00:00+00:00",
        completed_at="2026-03-10T10:30:00+00:00",
        findings=findings or [],
        hypotheses=hypotheses or [],
        total_kql_queries=25,
        total_llm_tokens=50000,
    )


def _make_finding(
    classification: FindingClassification = FindingClassification.TRUE_POSITIVE,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: float = 0.85,
    title: str = "Suspicious brute-force on admin account",
    hypothesis_id: str = "H-test001",
    techniques: list[str] | None = None,
) -> HuntFinding:
    return HuntFinding(
        finding_id=f"F-{uuid.uuid4().hex[:8]}",
        hypothesis_id=hypothesis_id,
        campaign_id="CAMP-test",
        title=title,
        description="Test finding description",
        classification=classification,
        severity=severity,
        confidence=confidence,
        mitre_techniques=techniques or ["T1110.003"],
        mitre_tactics=["credential-access"],
        affected_entities={"users": ["admin@test.com"], "ips": ["10.0.0.5"]},
        evidence_chain=EvidenceChain(
            chain_id="EC-test",
            narrative="Found suspicious activity.",
            links=[
                EvidenceLink(
                    evidence_id="EL-001",
                    source_type="kql_result",
                    query_text="SigninLogs | where ResultType != 0",
                    result_count=342,
                    result_summary="342 failed sign-ins",
                ),
            ],
        ),
        recommendations=["Enable MFA", "Block IP"],
    )


def _make_hypothesis(
    hypothesis_id: str = "H-test001",
    title: str = "Hunt for brute-force attacks",
    findings_count: int = 1,
) -> AutonomousHypothesis:
    return AutonomousHypothesis(
        hypothesis_id=hypothesis_id,
        title=title,
        description="Look for credential-based attacks",
        source=HypothesisSource.COVERAGE_GAP,
        priority_score=0.7,
        priority=HypothesisPriority.HIGH,
        threat_likelihood=0.8,
        detection_feasibility=0.9,
        business_impact=0.7,
        mitre_techniques=["T1110.003"],
        available_tables=["SigninLogs", "AuditLogs"],
        status="completed",
        findings_count=findings_count,
        queries_executed=5,
    )


# ── Campaign persistence ──────────────────────────────────────────────


class TestCampaignPersistence:

    def test_save_and_load_campaign(self, db):
        record = CampaignRecord(
            campaign_id="CAMP-abc123",
            client_id="test-corp",
            client_name="Test Corp",
            status="completed",
            started_at="2026-03-10T10:00:00+00:00",
            total_hypotheses=5,
            total_findings=3,
            true_positives=1,
            false_positives=2,
        )
        db.save_campaign(record)
        loaded = db.get_campaign("CAMP-abc123")
        assert loaded is not None
        assert loaded.campaign_id == "CAMP-abc123"
        assert loaded.true_positives == 1

    def test_list_campaigns_by_client(self, db):
        for i in range(3):
            db.save_campaign(CampaignRecord(
                campaign_id=f"CAMP-{i}",
                client_id="test-corp",
                client_name="Test Corp",
                status="completed",
                started_at=f"2026-03-{10+i}T10:00:00+00:00",
            ))
        db.save_campaign(CampaignRecord(
            campaign_id="CAMP-other",
            client_id="other-corp",
            client_name="Other Corp",
            status="completed",
        ))
        campaigns = db.get_campaigns(client_id="test-corp")
        assert len(campaigns) == 3
        assert all(c.client_id == "test-corp" for c in campaigns)

    def test_save_campaign_finding(self, db):
        db.save_campaign(CampaignRecord(
            campaign_id="CAMP-x", client_id="c1", client_name="C1", status="completed",
        ))
        db.save_campaign_finding(CampaignFindingRecord(
            finding_id="F-001", campaign_id="CAMP-x", client_id="c1",
            title="Test Finding", classification="true_positive",
            severity="high", confidence=0.9,
        ))
        findings = db.get_campaign_findings("c1", classification="true_positive")
        assert len(findings) == 1
        assert findings[0].classification == "true_positive"

    def test_save_campaign_hypothesis(self, db):
        db.save_campaign(CampaignRecord(
            campaign_id="CAMP-x", client_id="c1", client_name="C1", status="completed",
        ))
        db.save_campaign_hypothesis(CampaignHypothesisRecord(
            hypothesis_id="H-001", campaign_id="CAMP-x", client_id="c1",
            title="Test Hypothesis", priority_score=0.8,
        ))


# ── Hunt lessons ──────────────────────────────────────────────────────


class TestHuntLessons:

    def test_save_and_get_lesson(self, db):
        db.save_lesson(HuntLessonRecord(
            lesson_id="HL-001", client_id="c1", campaign_id="CAMP-1",
            lesson_type="productive_hypothesis",
            title="Productive: Brute-force hunt",
            description="This hypothesis found true positives.",
            confidence=0.9, times_confirmed=1,
            created_at="2026-03-10T10:00:00+00:00",
            updated_at="2026-03-10T10:00:00+00:00",
        ))
        lessons = db.get_lessons("c1")
        assert len(lessons) == 1
        assert lessons[0].lesson_type == "productive_hypothesis"

    def test_increment_lesson(self, db):
        db.save_lesson(HuntLessonRecord(
            lesson_id="HL-001", client_id="c1", campaign_id="CAMP-1",
            lesson_type="technique_relevance",
            title="Active technique: T1110",
            confidence=0.7, times_confirmed=1,
            created_at="2026-03-10T10:00:00+00:00",
            updated_at="2026-03-10T10:00:00+00:00",
        ))
        db.increment_lesson("HL-001")
        db.increment_lesson("HL-001")
        lessons = db.get_lessons("c1")
        assert lessons[0].times_confirmed == 3

    def test_filter_lessons_by_type(self, db):
        for lt in ["productive_hypothesis", "false_positive_pattern", "technique_relevance"]:
            db.save_lesson(HuntLessonRecord(
                lesson_id=f"HL-{lt}", client_id="c1", campaign_id="CAMP-1",
                lesson_type=lt, title=f"Lesson: {lt}",
                created_at="2026-03-10T10:00:00+00:00",
                updated_at="2026-03-10T10:00:00+00:00",
            ))
        fp_only = db.get_lessons("c1", lesson_type="false_positive_pattern")
        assert len(fp_only) == 1
        assert fp_only[0].lesson_type == "false_positive_pattern"


# ── Learning engine ───────────────────────────────────────────────────


class TestCampaignLearningEngine:

    def test_persist_campaign_creates_records(self, engine, db):
        finding = _make_finding()
        hypothesis = _make_hypothesis()
        state = _make_campaign_state(findings=[finding], hypotheses=[hypothesis])

        engine.persist_campaign(state)

        campaigns = db.get_campaigns(client_id="test-corp")
        assert len(campaigns) == 1
        assert campaigns[0].total_findings == 1

        findings = db.get_campaign_findings("test-corp")
        assert len(findings) == 1

    def test_persist_extracts_productive_hypothesis_lesson(self, engine, db):
        hypothesis = _make_hypothesis(hypothesis_id="H-prod", findings_count=1)
        finding = _make_finding(hypothesis_id="H-prod")
        state = _make_campaign_state(findings=[finding], hypotheses=[hypothesis])

        engine.persist_campaign(state)

        lessons = db.get_lessons("test-corp", lesson_type="productive_hypothesis")
        assert len(lessons) == 1
        assert "Productive:" in lessons[0].title

    def test_persist_extracts_false_positive_lesson(self, engine, db):
        finding = _make_finding(
            classification=FindingClassification.FALSE_POSITIVE,
            title="Benign admin activity",
        )
        state = _make_campaign_state(findings=[finding])

        engine.persist_campaign(state)

        lessons = db.get_lessons("test-corp", lesson_type="false_positive_pattern")
        assert len(lessons) == 1
        assert "FP Pattern:" in lessons[0].title

    def test_persist_extracts_technique_relevance_lesson(self, engine, db):
        finding = _make_finding(techniques=["T1078", "T1110.003"])
        state = _make_campaign_state(findings=[finding])

        engine.persist_campaign(state)

        lessons = db.get_lessons("test-corp", lesson_type="technique_relevance")
        assert len(lessons) == 2  # One per technique

    def test_persist_extracts_effective_query_lesson(self, engine, db):
        finding = _make_finding(confidence=0.9)
        state = _make_campaign_state(findings=[finding])

        engine.persist_campaign(state)

        lessons = db.get_lessons("test-corp", lesson_type="effective_query")
        assert len(lessons) == 1

    def test_reinforcement_increments_existing_lesson(self, engine, db):
        """Running two campaigns with similar findings should reinforce lessons."""
        for i in range(2):
            finding = _make_finding(
                classification=FindingClassification.FALSE_POSITIVE,
                title="Benign admin activity",
            )
            state = _make_campaign_state(findings=[finding])
            state.campaign_id = f"CAMP-{i}"
            engine.persist_campaign(state)

        lessons = db.get_lessons("test-corp", lesson_type="false_positive_pattern")
        assert len(lessons) == 1  # Only one lesson, not two
        assert lessons[0].times_confirmed == 2  # Reinforced

    def test_get_learning_context_empty(self, engine):
        ctx = engine.get_learning_context("nonexistent-client")
        assert ctx == {}

    def test_get_learning_context_with_data(self, engine, db):
        finding = _make_finding()
        hypothesis = _make_hypothesis()
        state = _make_campaign_state(findings=[finding], hypotheses=[hypothesis])
        engine.persist_campaign(state)

        ctx = engine.get_learning_context("test-corp")
        assert "past_campaigns" in ctx
        assert len(ctx["past_campaigns"]) == 1
        assert "past_true_positives" in ctx
        assert len(ctx["past_true_positives"]) == 1
        assert "lessons_learned" in ctx
        assert len(ctx["lessons_learned"]) > 0

    def test_get_learning_context_known_false_positives(self, engine, db):
        fp_finding = _make_finding(
            classification=FindingClassification.FALSE_POSITIVE,
            title="Benign scheduled task",
        )
        state = _make_campaign_state(findings=[fp_finding])
        engine.persist_campaign(state)

        ctx = engine.get_learning_context("test-corp")
        assert len(ctx["known_false_positives"]) == 1
        assert ctx["known_false_positives"][0]["title"] == "Benign scheduled task"


# ── Lesson similarity ─────────────────────────────────────────────────


class TestLessonSimilarity:

    def test_exact_match(self):
        assert CampaignLearningEngine._lessons_similar(
            "Productive: Brute-force hunt",
            "Productive: Brute-force hunt",
        )

    def test_substring_match(self):
        assert CampaignLearningEngine._lessons_similar(
            "FP Pattern: Admin role assignment",
            "FP Pattern: Admin role assignment via PIM",
        )

    def test_word_overlap_match(self):
        assert CampaignLearningEngine._lessons_similar(
            "Productive: Hunt for brute-force attacks on admin",
            "Productive: Hunt for brute-force attacks on admin accounts",
        )

    def test_dissimilar(self):
        assert not CampaignLearningEngine._lessons_similar(
            "Productive: Brute-force hunt",
            "FP Pattern: Benign scheduled task",
        )


# ── Rich environment summary ─────────────────────────────────────────


class TestRichSummary:

    def test_rich_summary_includes_table_profiles(self):
        from mssp_hunt_agent.hunter.models.environment import (
            EnvironmentIndex,
            IdentityIndex,
            IndexMetadata,
            TableProfile,
            TelemetryIndex,
        )

        index = EnvironmentIndex(
            metadata=IndexMetadata(client_id="test"),
            telemetry=TelemetryIndex(tables=[
                TableProfile(
                    table_name="SigninLogs",
                    key_fields=["UserPrincipalName", "IPAddress", "ResultType"],
                    mitre_techniques_covered=["T1078"],
                    row_count_7d=50000,
                    row_count_30d=200000,
                    ingestion_healthy=True,
                ),
            ]),
        )

        summary = index.rich_summary()
        assert "table_profiles" in summary
        assert len(summary["table_profiles"]) == 1
        assert summary["table_profiles"][0]["table"] == "SigninLogs"
        assert "columns" in summary["table_profiles"][0]

    def test_rich_summary_includes_admin_users(self):
        from mssp_hunt_agent.hunter.models.environment import (
            EnvironmentIndex,
            IdentityIndex,
            IndexMetadata,
            UserProfile,
        )

        index = EnvironmentIndex(
            metadata=IndexMetadata(client_id="test"),
            identity=IdentityIndex(
                users=[
                    UserProfile(
                        user_principal_name="admin@test.com",
                        is_admin=True,
                        admin_roles=["Global Administrator"],
                        mfa_enforced=False,
                        risk_level="high",
                    ),
                ],
                total_users=100,
                admin_count=1,
            ),
        )

        summary = index.rich_summary()
        assert len(summary["identity"]["admin_users"]) == 1
        assert summary["identity"]["admin_users"][0]["upn"] == "admin@test.com"

    def test_rich_summary_vs_compact_summary(self):
        from mssp_hunt_agent.hunter.models.environment import (
            EnvironmentIndex,
            IndexMetadata,
        )

        index = EnvironmentIndex(metadata=IndexMetadata(client_id="test"))
        compact = index.summary()
        rich = index.rich_summary()

        # Rich has more structured data
        assert "table_profiles" in rich
        assert "identity" in rich
        assert isinstance(rich["identity"], dict)
        # Compact just has counts
        assert isinstance(compact.get("tables"), int)


# ── Phase prompt learning integration ─────────────────────────────────


class TestPromptLearningIntegration:

    def test_hypothesize_prompt_includes_learning(self):
        from mssp_hunt_agent.hunter.prompts.phase_prompts import build_hypothesize_prompt

        learning_ctx = {
            "past_campaigns": [
                {"campaign_id": "CAMP-001", "date": "2026-03-01", "true_positives": 2, "false_positives": 1, "findings": 3},
            ],
            "past_true_positives": [
                {"title": "Brute-force on admin", "severity": "high", "mitre_techniques": '["T1110"]', "confidence": 0.9},
            ],
            "known_false_positives": [
                {"title": "Benign PIM activation", "evidence_summary": "Admin activated role via PIM"},
            ],
            "lessons_learned": [
                {"type": "productive_hypothesis", "title": "Productive: Credential hunt", "description": "Found TPs", "times_confirmed": 3, "confidence": 0.9},
            ],
        }

        prompt = build_hypothesize_prompt(
            client_name="Test Corp",
            env_summary={"workspace_id": "ws1"},
            budget={"queries_remaining": 100},
            learning_context=learning_ctx,
        )

        assert "Past Campaigns" in prompt or "past_campaigns" in prompt.lower()
        assert "Brute-force on admin" in prompt
        assert "Benign PIM activation" in prompt
        assert "Credential hunt" in prompt

    def test_hypothesize_prompt_without_learning(self):
        from mssp_hunt_agent.hunter.prompts.phase_prompts import build_hypothesize_prompt

        prompt = build_hypothesize_prompt(
            client_name="Test Corp",
            env_summary={"workspace_id": "ws1"},
            budget={"queries_remaining": 100},
        )
        # Should not contain learning sections
        assert "Past Campaigns" not in prompt

    def test_execute_prompt_includes_learning(self):
        from mssp_hunt_agent.hunter.prompts.phase_prompts import build_execute_prompt

        learning_ctx = {
            "known_false_positives": [
                {"title": "Benign PIM activation"},
            ],
            "past_true_positives": [
                {"title": "Lateral movement via RDP", "severity": "high", "affected_entities": '{"hosts": ["DC01"]}'},
            ],
            "lessons_learned": [
                {"type": "effective_query", "description": "SigninLogs | where ResultType != 0 | summarize..."},
            ],
        }

        prompt = build_execute_prompt(
            client_name="Test Corp",
            hypothesis={"title": "Test Hunt"},
            env_summary={},
            budget={"queries_remaining": 20},
            learning_context=learning_ctx,
        )

        assert "Benign PIM activation" in prompt
        assert "Lateral movement via RDP" in prompt
        assert "Query Patterns That Worked Before" in prompt
