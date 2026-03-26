"""Recursive learning engine — extracts lessons from campaign outcomes.

After each campaign completes, this module:
1. Persists campaign state (findings, hypotheses, metadata) to SQLite
2. Extracts lessons learned (productive hypotheses, false positive patterns, etc.)
3. Builds contextual summaries from past campaigns for future prompts
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from mssp_hunt_agent.hunter.models.campaign import CampaignState
from mssp_hunt_agent.hunter.models.finding import FindingClassification
from mssp_hunt_agent.persistence.database import HuntDatabase
from mssp_hunt_agent.persistence.models import (
    CampaignFindingRecord,
    CampaignHypothesisRecord,
    CampaignRecord,
    HuntLessonRecord,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignLearningEngine:
    """Extracts and persists lessons from completed campaigns.

    Usage:
        engine = CampaignLearningEngine(db)
        engine.persist_campaign(state)  # saves campaign + extracts lessons
        context = engine.get_learning_context(client_id)  # for next campaign
    """

    def __init__(self, db: HuntDatabase) -> None:
        self._db = db

    def persist_campaign(self, state: CampaignState) -> None:
        """Persist full campaign state to SQLite and extract lessons."""
        client_id = state.config.client_id or state.config.client_name.lower().replace(" ", "-")

        # 1. Save campaign record
        self._save_campaign_record(state, client_id)

        # 2. Save findings
        for finding in state.findings:
            self._save_finding(finding, state.campaign_id, client_id)

        # 3. Save hypotheses
        for hypothesis in state.hypotheses:
            self._save_hypothesis(hypothesis, state.campaign_id, client_id)

        # 4. Extract and save lessons
        self._extract_lessons(state, client_id)

        logger.info(
            "Persisted campaign %s: %d findings, %d hypotheses, lessons extracted",
            state.campaign_id, len(state.findings), len(state.hypotheses),
        )

    def get_learning_context(self, client_id: str) -> dict[str, Any]:
        """Build learning context from past campaigns for injection into prompts.

        Returns a dict with past campaign summaries, confirmed findings,
        known false positive patterns, and accumulated lessons.
        """
        return self._db.get_past_campaign_context(client_id)

    # ── internal: persistence ──────────────────────────────────────────

    def _save_campaign_record(self, state: CampaignState, client_id: str) -> None:
        from mssp_hunt_agent.hunter.models.finding import FindingClassification

        tp = sum(1 for f in state.findings if f.classification == FindingClassification.TRUE_POSITIVE)
        fp = sum(1 for f in state.findings if f.classification == FindingClassification.FALSE_POSITIVE)
        inc = sum(1 for f in state.findings if f.classification == FindingClassification.INCONCLUSIVE)
        esc = sum(1 for f in state.findings if f.classification == FindingClassification.REQUIRES_ESCALATION)

        record = CampaignRecord(
            campaign_id=state.campaign_id,
            client_id=client_id,
            client_name=state.config.client_name,
            status=state.status,
            started_at=state.started_at,
            completed_at=state.completed_at,
            total_hypotheses=len(state.hypotheses),
            total_findings=len(state.findings),
            true_positives=tp,
            false_positives=fp,
            inconclusive=inc,
            escalations=esc,
            total_kql_queries=state.total_kql_queries,
            total_llm_tokens=state.total_llm_tokens,
            duration_minutes=state.duration_minutes,
            focus_areas=json.dumps(state.config.focus_areas),
            config_json=state.config.model_dump_json(),
            summary=state.report.executive_summary[:2000] if state.report else "",
            errors=json.dumps(state.errors),
        )
        self._db.save_campaign(record)

    def _save_finding(self, finding: Any, campaign_id: str, client_id: str) -> None:
        record = CampaignFindingRecord(
            finding_id=finding.finding_id,
            campaign_id=campaign_id,
            client_id=client_id,
            hypothesis_id=finding.hypothesis_id,
            title=finding.title,
            classification=finding.classification.value,
            severity=finding.severity.value,
            confidence=finding.confidence,
            mitre_techniques=json.dumps(finding.mitre_techniques),
            mitre_tactics=json.dumps(finding.mitre_tactics),
            affected_entities=json.dumps(finding.affected_entities),
            evidence_summary=finding.evidence_chain.narrative[:2000] if finding.evidence_chain else "",
            recommendations=json.dumps(finding.recommendations),
            detection_rule_kql=finding.detection_rule_kql,
            created_at=finding.created_at or _now_iso(),
        )
        self._db.save_campaign_finding(record)

    def _save_hypothesis(self, hypothesis: Any, campaign_id: str, client_id: str) -> None:
        record = CampaignHypothesisRecord(
            hypothesis_id=hypothesis.hypothesis_id,
            campaign_id=campaign_id,
            client_id=client_id,
            title=hypothesis.title,
            description=hypothesis.description[:2000],
            source=hypothesis.source.value if hasattr(hypothesis.source, 'value') else str(hypothesis.source),
            priority_score=hypothesis.priority_score,
            status=hypothesis.status,
            mitre_techniques=json.dumps(hypothesis.mitre_techniques),
            available_tables=json.dumps(hypothesis.available_tables),
            findings_count=hypothesis.findings_count,
            queries_executed=hypothesis.queries_executed,
            created_at=_now_iso(),
        )
        self._db.save_campaign_hypothesis(record)

    # ── internal: lesson extraction ────────────────────────────────────

    def _extract_lessons(self, state: CampaignState, client_id: str) -> None:
        """Extract actionable lessons from a completed campaign."""
        now = _now_iso()

        # Lesson 1: Productive hypotheses (found true positives)
        for hypothesis in state.hypotheses:
            tp_findings = [
                f for f in state.findings
                if f.hypothesis_id == hypothesis.hypothesis_id
                and f.classification == FindingClassification.TRUE_POSITIVE
            ]
            if tp_findings:
                self._save_or_reinforce_lesson(
                    client_id=client_id,
                    campaign_id=state.campaign_id,
                    lesson_type="productive_hypothesis",
                    title=f"Productive: {hypothesis.title}",
                    description=(
                        f"Hypothesis '{hypothesis.title}' found {len(tp_findings)} true positive(s). "
                        f"Source: {hypothesis.source.value if hasattr(hypothesis.source, 'value') else hypothesis.source}. "
                        f"Tables used: {', '.join(hypothesis.available_tables)}. "
                        f"Queries executed: {hypothesis.queries_executed}. "
                        f"Prioritize similar hypotheses in future hunts."
                    ),
                    mitre_techniques=hypothesis.mitre_techniques,
                    tables_involved=hypothesis.available_tables,
                    confidence=max(f.confidence for f in tp_findings),
                    now=now,
                )

        # Lesson 2: False positive patterns (avoid re-investigating)
        for finding in state.findings:
            if finding.classification == FindingClassification.FALSE_POSITIVE:
                self._save_or_reinforce_lesson(
                    client_id=client_id,
                    campaign_id=state.campaign_id,
                    lesson_type="false_positive_pattern",
                    title=f"FP Pattern: {finding.title}",
                    description=(
                        f"'{finding.title}' was classified as false positive (confidence {finding.confidence:.0%}). "
                        f"Evidence: {finding.evidence_chain.narrative[:500] if finding.evidence_chain else 'N/A'}. "
                        f"Affected entities: {json.dumps(finding.affected_entities)}. "
                        f"In future hunts, consider this known benign pattern before escalating."
                    ),
                    mitre_techniques=finding.mitre_techniques,
                    tables_involved=[],
                    confidence=finding.confidence,
                    now=now,
                )

        # Lesson 3: Technique relevance for this client
        technique_hits: dict[str, int] = {}
        for finding in state.findings:
            if finding.classification in (FindingClassification.TRUE_POSITIVE, FindingClassification.REQUIRES_ESCALATION):
                for tech in finding.mitre_techniques:
                    technique_hits[tech] = technique_hits.get(tech, 0) + 1

        for technique, count in technique_hits.items():
            self._save_or_reinforce_lesson(
                client_id=client_id,
                campaign_id=state.campaign_id,
                lesson_type="technique_relevance",
                title=f"Active technique: {technique}",
                description=(
                    f"MITRE technique {technique} had {count} confirmed finding(s) in this campaign. "
                    f"This technique is actively relevant for this client and should be prioritized."
                ),
                mitre_techniques=[technique],
                tables_involved=[],
                confidence=min(0.9, 0.5 + count * 0.1),
                now=now,
            )

        # Lesson 4: Effective query patterns (from high-confidence findings)
        for finding in state.findings:
            if finding.confidence >= 0.7 and finding.evidence_chain and finding.evidence_chain.links:
                queries = [
                    link.query_text for link in finding.evidence_chain.links
                    if link.query_text and link.result_count > 0
                ]
                if queries:
                    self._save_or_reinforce_lesson(
                        client_id=client_id,
                        campaign_id=state.campaign_id,
                        lesson_type="effective_query",
                        title=f"Effective queries for: {finding.title[:80]}",
                        description=(
                            f"These queries produced results for '{finding.title}': "
                            + " | ".join(q[:200] for q in queries[:3])
                        ),
                        mitre_techniques=finding.mitre_techniques,
                        tables_involved=[],
                        confidence=finding.confidence,
                        now=now,
                    )

    def _save_or_reinforce_lesson(
        self,
        client_id: str,
        campaign_id: str,
        lesson_type: str,
        title: str,
        description: str,
        mitre_techniques: list[str],
        tables_involved: list[str],
        confidence: float,
        now: str,
    ) -> None:
        """Save a new lesson, or reinforce an existing one if similar."""
        # Check for existing similar lesson (same type + similar title)
        existing = self._db.get_lessons(client_id, lesson_type=lesson_type, limit=50)
        for lesson in existing:
            if self._lessons_similar(lesson.title, title):
                # Reinforce existing lesson
                self._db.increment_lesson(lesson.lesson_id)
                logger.debug("Reinforced lesson %s: %s", lesson.lesson_id, title)
                return

        # New lesson
        lesson = HuntLessonRecord(
            lesson_id=f"HL-{uuid.uuid4().hex[:8]}",
            client_id=client_id,
            campaign_id=campaign_id,
            lesson_type=lesson_type,
            title=title,
            description=description,
            mitre_techniques=json.dumps(mitre_techniques),
            tables_involved=json.dumps(tables_involved),
            confidence=confidence,
            times_confirmed=1,
            created_at=now,
            updated_at=now,
        )
        self._db.save_lesson(lesson)

    @staticmethod
    def _lessons_similar(title_a: str, title_b: str) -> bool:
        """Check if two lesson titles are similar enough to merge."""
        # Strip the prefix (e.g., "Productive: ", "FP Pattern: ")
        a = title_a.split(": ", 1)[-1].lower().strip()
        b = title_b.split(": ", 1)[-1].lower().strip()

        # Simple containment check — if one is a substring of the other
        if a in b or b in a:
            return True

        # Word overlap — if >70% of words match
        words_a = set(a.split())
        words_b = set(b.split())
        if not words_a or not words_b:
            return False
        overlap = len(words_a & words_b) / max(len(words_a), len(words_b))
        return overlap > 0.7
