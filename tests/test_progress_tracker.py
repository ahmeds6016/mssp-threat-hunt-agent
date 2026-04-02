"""Tests for ProgressTracker — live campaign event logging."""

from __future__ import annotations

from mssp_hunt_agent.persistence.progress import ProgressTracker


class TestProgressTracker:
    def test_log_and_get_events(self) -> None:
        tracker = ProgressTracker("CAMP-001")
        tracker.log("campaign_started", detail="Test campaign")
        tracker.log("phase_started", phase="index_refresh")
        tracker.log("phase_completed", phase="index_refresh", status="success")

        events = tracker.get_all()
        assert len(events) == 3
        assert events[0]["event"] == "campaign_started"
        assert events[1]["phase"] == "index_refresh"
        assert events[2]["status"] == "success"

    def test_sequence_numbers(self) -> None:
        tracker = ProgressTracker("CAMP-002")
        tracker.log("a")
        tracker.log("b")
        tracker.log("c")

        assert tracker.get_all()[0]["seq"] == 0
        assert tracker.get_all()[2]["seq"] == 2

    def test_get_events_since(self) -> None:
        tracker = ProgressTracker("CAMP-003")
        for i in range(10):
            tracker.log(f"event_{i}")

        events = tracker.get_events(since=7)
        assert len(events) == 3
        assert events[0]["event"] == "event_7"

    def test_summary(self) -> None:
        tracker = ProgressTracker("CAMP-004")
        tracker.log("campaign_started", detail="Test")
        tracker.log("phase_started", phase="hypothesize")
        tracker.log("hypothesis_generated", title="H1")
        tracker.log("hypothesis_generated", title="H2")
        tracker.log("phase_completed", phase="hypothesize")
        tracker.log("phase_started", phase="execute")
        tracker.log("query_executed", query="test")
        tracker.log("query_executed", query="test2")
        tracker.log("finding_discovered", severity="high", title="Bad stuff")

        summary = tracker.summary()
        assert summary["phase"] == "execute"
        assert summary["total_queries"] == 2
        assert summary["total_findings"] == 1
        assert summary["hypotheses"] == 2
        assert "hypothesize" in summary["phases_completed"]

    def test_empty_summary(self) -> None:
        tracker = ProgressTracker("CAMP-005")
        summary = tracker.summary()
        assert summary["phase"] == "pending"

    def test_flush_callback(self) -> None:
        tracker = ProgressTracker("CAMP-006")
        flushed = []
        tracker.set_flush_callback(lambda cid, events: flushed.append((cid, len(events))))

        tracker.log("test_event")
        tracker.log("test_event_2")

        assert len(flushed) == 2
        assert flushed[0] == ("CAMP-006", 1)
        assert flushed[1] == ("CAMP-006", 2)

    def test_flush_callback_failure_does_not_crash(self) -> None:
        tracker = ProgressTracker("CAMP-007")
        tracker.set_flush_callback(lambda cid, events: (_ for _ in ()).throw(RuntimeError("boom")))
        # Should not raise
        tracker.log("test_event")
        assert tracker.count == 1

    def test_count(self) -> None:
        tracker = ProgressTracker("CAMP-008")
        assert tracker.count == 0
        tracker.log("a")
        tracker.log("b")
        assert tracker.count == 2
