"""Intel Pipeline — full autonomous threat intel scan and hunt orchestration.

Ties together all intel components into a single pipeline:
1. Monitor feeds for new articles
2. Correlate and score articles via GPT-5.3
3. Launch targeted hunts for high-relevance events
4. Build executive reports
5. Deliver via email and blob storage

Usage:
    pipeline = IntelPipeline(config=agent_config, llm=llm, blob_store=store)
    results = pipeline.run_scan(recipients=["analyst@company.com"])
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)


class IntelScanResult:
    """Result of a complete intel scan cycle."""

    def __init__(self) -> None:
        self.scan_id: str = ""
        self.started_at: str = ""
        self.completed_at: str = ""
        self.articles_found: int = 0
        self.events_correlated: int = 0
        self.events_relevant: int = 0
        self.hunts_launched: int = 0
        self.hunts_completed: int = 0
        self.total_findings: int = 0
        self.emails_sent: int = 0
        self.reports: list[dict] = []
        self.errors: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


class IntelPipeline:
    """Full autonomous threat intel scanning and hunting pipeline."""

    def __init__(
        self,
        config: HuntAgentConfig,
        llm: Any,
        blob_store: Any = None,
        email_sender: Any = None,
    ) -> None:
        self._config = config
        self._llm = llm
        self._blob = blob_store
        self._email = email_sender

    def run_scan(
        self,
        recipients: list[str] | None = None,
        relevance_threshold: float = 0.6,
        fetch_full_text: bool = True,
        dry_run: bool = False,
    ) -> IntelScanResult:
        """Execute a full intel scan cycle.

        Args:
            recipients: Email addresses for report delivery (None = no email)
            relevance_threshold: Minimum relevance score to trigger a hunt (0-1)
            fetch_full_text: Whether to fetch full article text for better LLM context
            dry_run: If True, skip hunt execution and email delivery

        Returns:
            IntelScanResult with full metrics
        """
        from mssp_hunt_agent.intel.executive_report import ExecutiveReportBuilder
        from mssp_hunt_agent.intel.feed_monitor import FeedMonitor
        from mssp_hunt_agent.intel.intel_campaign import IntelCampaignLauncher
        from mssp_hunt_agent.intel.intel_processor import IntelProcessor
        from mssp_hunt_agent.persistence.progress import ProgressTracker

        result = IntelScanResult()
        result.scan_id = f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M')}"
        result.started_at = datetime.now(timezone.utc).isoformat()

        logger.info("Starting intel scan %s", result.scan_id)

        # Step 1: Check feeds for new articles
        logger.info("[1/5] Checking threat intel feeds...")
        try:
            monitor = FeedMonitor(blob_store=self._blob)
            articles = monitor.check_all_feeds(fetch_full_text=fetch_full_text)
            result.articles_found = len(articles)
            logger.info("Found %d new articles", len(articles))
        except Exception as exc:
            result.errors.append(f"Feed monitoring failed: {exc}")
            logger.exception("Feed monitoring failed")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        if not articles:
            logger.info("No new articles found — scan complete")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_result(result)
            return result

        # Step 2: Correlate and score articles
        logger.info("[2/5] Correlating and scoring %d articles...", len(articles))
        try:
            processor = IntelProcessor(llm=self._llm)
            article_dicts = [a.to_dict() for a in articles]

            # Get environment summary for relevance scoring
            env_summary = self._get_env_summary()

            events = processor.process_articles(
                article_dicts, env_summary, relevance_threshold=relevance_threshold,
            )
            result.events_correlated = len(events)
            result.events_relevant = len([e for e in events if e.relevance_score >= relevance_threshold])
            logger.info(
                "Correlated into %d events, %d above threshold",
                result.events_correlated, result.events_relevant,
            )
        except Exception as exc:
            result.errors.append(f"Intel processing failed: {exc}")
            logger.exception("Intel processing failed")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_result(result)
            return result

        relevant_events = [e for e in events if e.relevance_score >= relevance_threshold]

        if not relevant_events:
            logger.info("No relevant events above threshold — scan complete")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._persist_result(result)
            return result

        # Step 3: Launch targeted hunts for relevant events
        logger.info("[3/5] Launching hunts for %d relevant events...", len(relevant_events))
        launcher = IntelCampaignLauncher(agent_config=self._config, llm=self._llm)
        report_builder = ExecutiveReportBuilder()

        for event in relevant_events:
            if dry_run:
                logger.info("DRY RUN: Would launch hunt for: %s", event.title[:80])
                result.hunts_launched += 1
                continue

            try:
                progress = ProgressTracker(f"intel-{event.event_id}")
                if self._blob:
                    progress.set_flush_callback(
                        lambda cid, evts: self._blob._upload_json(f"progress/{cid}.json", {"events": evts})
                    )

                campaign_state = launcher.launch_hunt(event, progress=progress)
                result.hunts_launched += 1

                if campaign_state.status in ("completed", "partial"):
                    result.hunts_completed += 1
                    result.total_findings += len(campaign_state.findings)

                    # Step 4: Build executive report
                    logger.info("[4/5] Building report for: %s", event.title[:80])
                    timeline = "\n".join(
                        f"[{e.get('t', '')}] {e.get('event', '')}"
                        for e in progress.get_all()[-20:]
                    )
                    report = report_builder.build_report(event, campaign_state, hunt_timeline=timeline)
                    markdown = report_builder.to_markdown(report)
                    html = report_builder.to_html(report)

                    # Persist report to blob
                    if self._blob:
                        self._blob._upload_json(
                            f"intel-reports/{report.report_id}.json",
                            report.to_dict(),
                        )
                        self._blob._upload_json(
                            f"intel-reports/{report.report_id}.md",
                            {"content": markdown},
                        )

                    # Save campaign state to blob
                    if self._blob:
                        self._blob.save_campaign(campaign_state.campaign_id, campaign_state)

                    result.reports.append({
                        "report_id": report.report_id,
                        "event_title": event.title,
                        "verdict": report.verdict,
                        "risk_level": report.risk_level,
                        "findings": report.hunt_findings_count,
                        "campaign_id": report.campaign_id,
                    })

                    # Step 5: Send email
                    if recipients and self._email:
                        logger.info("[5/5] Sending email report to %s", recipients)
                        try:
                            sent = self._email.send_intel_report(
                                to=recipients, report=report, html_body=html,
                            )
                            if sent:
                                result.emails_sent += 1
                        except Exception as exc:
                            result.errors.append(f"Email delivery failed for {event.event_id}: {exc}")
                            logger.warning("Email delivery failed: %s", exc)

                else:
                    result.errors.append(f"Hunt failed for {event.event_id}: {campaign_state.status}")

            except Exception as exc:
                result.errors.append(f"Hunt failed for {event.event_id}: {exc}")
                logger.exception("Hunt failed for %s", event.event_id)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        self._persist_result(result)

        logger.info(
            "Intel scan %s complete: %d articles, %d events, %d hunts, %d findings, %d emails",
            result.scan_id, result.articles_found, result.events_correlated,
            result.hunts_completed, result.total_findings, result.emails_sent,
        )
        return result

    def _get_env_summary(self) -> dict[str, Any]:
        """Get the client environment summary for relevance scoring."""
        try:
            from mssp_hunt_agent.agent.tool_defs import ToolExecutor
            executor = ToolExecutor(self._config)
            adapter = executor._get_sentinel_adapter()
            # Try to get a basic environment profile
            return {
                "client_name": self._config.default_client_name or "Default",
                "adapter_mode": self._config.adapter_mode,
                "tables": ["SecurityEvent", "SigninLogs", "DeviceProcessEvents", "Syslog"],
                "workspace_configured": bool(self._config.sentinel_workspace_id),
            }
        except Exception:
            return {
                "client_name": self._config.default_client_name or "Default",
                "adapter_mode": self._config.adapter_mode,
            }

    def _persist_result(self, result: IntelScanResult) -> None:
        """Save scan result to blob storage."""
        if self._blob:
            try:
                self._blob._upload_json(
                    f"intel-scans/{result.scan_id}.json",
                    result.to_dict(),
                )
            except Exception as exc:
                logger.warning("Failed to persist scan result: %s", exc)
