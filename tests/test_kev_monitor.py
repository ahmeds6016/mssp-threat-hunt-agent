"""Tests for the CISA KEV monitor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.intel.kev_monitor import (
    _MAX_SEEN_IDS,
    KEVAlert,
    KEVMonitor,
    _alert_from_dict,
    _make_alert_id,
)


# ── Sample CISA KEV catalog (real shape, fake CVEs) ───────────────────

SAMPLE_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.04.10",
    "dateReleased": "2026-04-10T00:00:00.0000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "WebPortal",
            "vulnerabilityName": "Acme WebPortal RCE",
            "dateAdded": "2026-04-10",
            "dueDate": "2026-04-30",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "Acme WebPortal contains an authentication bypass leading to RCE.",
        },
        {
            "cveID": "CVE-2026-0002",
            "vendorProject": "Microsoft",
            "product": "Exchange Server",
            "vulnerabilityName": "Microsoft Exchange Server Privilege Escalation",
            "dateAdded": "2026-04-09",
            "dueDate": "2026-04-29",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "Privilege escalation in Exchange Server via crafted request.",
        },
        {
            "cveID": "CVE-2026-0003",
            "vendorProject": "Cisco",
            "product": "ASA",
            "vulnerabilityName": "Cisco ASA Memory Disclosure",
            "dateAdded": "2026-04-08",
            "dueDate": "2026-04-28",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "Memory disclosure flaw in Cisco ASA SSL VPN.",
        },
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────


def _mock_blob_store(initial_seen: list[str] | None = None) -> MagicMock:
    """Build a fake blob store that round-trips JSON in memory."""
    state: dict[str, dict] = {}
    if initial_seen:
        state["kev-feeds/seen_ids.json"] = {"ids": list(initial_seen), "count": len(initial_seen)}

    blob = MagicMock()
    blob._download_json.side_effect = lambda key: state.get(key)
    blob._upload_json.side_effect = lambda key, data: state.update({key: data})
    blob._state = state  # expose for inspection
    return blob


def _mock_http_with_catalog(catalog: dict | None = SAMPLE_CATALOG, status_code: int = 200) -> MagicMock:
    """Build a fake httpx.Client whose .get returns the given catalog."""
    client = MagicMock()
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = catalog or {}
    client.get.return_value = response
    return client


# ── _make_alert_id ────────────────────────────────────────────────────


class TestMakeAlertId:
    def test_deterministic(self):
        assert _make_alert_id("CVE-2026-0001") == _make_alert_id("CVE-2026-0001")

    def test_case_insensitive(self):
        assert _make_alert_id("cve-2026-0001") == _make_alert_id("CVE-2026-0001")

    def test_strip_whitespace(self):
        assert _make_alert_id(" CVE-2026-0001 ") == _make_alert_id("CVE-2026-0001")

    def test_unique_per_cve(self):
        assert _make_alert_id("CVE-2026-0001") != _make_alert_id("CVE-2026-0002")

    def test_length(self):
        assert len(_make_alert_id("CVE-2026-0001")) == 16


# ── KEVAlert ──────────────────────────────────────────────────────────


class TestKEVAlert:
    def test_to_dict_round_trip(self):
        alert = KEVAlert(
            alert_id="abc",
            cve_id="CVE-2026-0001",
            vendor="Acme",
            product="WebPortal",
            vulnerability_name="RCE",
            short_description="bad",
            date_added="2026-04-10",
            due_date="2026-04-30",
            known_ransomware_use="Known",
        )
        d = alert.to_dict()
        assert d["cve_id"] == "CVE-2026-0001"
        assert d["vendor"] == "Acme"
        assert d["known_ransomware_use"] == "Known"
        # Round-trip via _alert_from_dict
        rebuilt = _alert_from_dict(d)
        assert rebuilt.cve_id == alert.cve_id
        assert rebuilt.product == alert.product

    def test_from_kev_entry_populates_detection_sources(self):
        from mssp_hunt_agent.intel.landscape_models import KEVEntry

        entry = KEVEntry(
            cve_id="CVE-2026-0002",
            vendor="Microsoft",
            product="Exchange Server",
            vulnerability_name="Test",
            date_added="2026-04-09",
            due_date="2026-04-29",
            known_ransomware_use="Unknown",
        )
        alert = KEVAlert.from_kev_entry(entry)
        assert alert.cve_id == "CVE-2026-0002"
        # infer_detection_sources should produce SecurityEvent + OfficeActivity for Exchange
        assert "SecurityEvent" in alert.inferred_detection_sources
        assert "OfficeActivity" in alert.inferred_detection_sources
        # alert_id is derived from cve_id
        assert alert.alert_id == _make_alert_id("CVE-2026-0002")


# ── KEVMonitor.check_catalog ──────────────────────────────────────────


class TestKEVMonitorCheckCatalog:
    def test_returns_all_entries_on_first_run(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        alerts = monitor.check_catalog()

        assert len(alerts) == 3
        cves = {a.cve_id for a in alerts}
        assert cves == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}

    def test_returns_empty_on_second_run_with_no_changes(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        first = monitor.check_catalog()
        assert len(first) == 3

        # Second call against the same catalog should return zero new alerts
        # (state is persisted to blob, but the existing monitor still has it
        # in memory so we don't even need to reload)
        second = monitor.check_catalog()
        assert second == []

    def test_returns_only_new_entries_when_catalog_grows(self):
        blob = _mock_blob_store()
        # First run with 2 entries
        http = _mock_http_with_catalog(catalog={
            "vulnerabilities": SAMPLE_CATALOG["vulnerabilities"][:2],
        })
        monitor = KEVMonitor(blob_store=blob, http_client=http)
        first = monitor.check_catalog()
        assert len(first) == 2

        # Second run with 3 entries — only the new one comes back
        http2 = _mock_http_with_catalog(catalog=SAMPLE_CATALOG)
        monitor2 = KEVMonitor(blob_store=blob, http_client=http2)
        second = monitor2.check_catalog()
        assert len(second) == 1
        assert second[0].cve_id == "CVE-2026-0003"

    def test_loads_seen_ids_from_blob(self):
        # Pre-populate the blob with the alert_id for CVE-2026-0001
        seen_id = _make_alert_id("CVE-2026-0001")
        blob = _mock_blob_store(initial_seen=[seen_id])
        http = _mock_http_with_catalog()

        monitor = KEVMonitor(blob_store=blob, http_client=http)
        alerts = monitor.check_catalog()

        assert len(alerts) == 2
        cves = {a.cve_id for a in alerts}
        assert "CVE-2026-0001" not in cves

    def test_skips_entries_with_blank_cve_id(self):
        catalog = {
            "vulnerabilities": [
                {**SAMPLE_CATALOG["vulnerabilities"][0]},
                {**SAMPLE_CATALOG["vulnerabilities"][1], "cveID": ""},
            ],
        }
        blob = _mock_blob_store()
        http = _mock_http_with_catalog(catalog=catalog)
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        alerts = monitor.check_catalog()
        assert len(alerts) == 1

    def test_returns_empty_on_http_error(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog(status_code=503)
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        assert monitor.check_catalog() == []

    def test_returns_empty_on_fetch_exception(self):
        blob = _mock_blob_store()
        http = MagicMock()
        http.get.side_effect = RuntimeError("network down")
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        assert monitor.check_catalog() == []

    def test_sorts_by_date_added_desc(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        alerts = monitor.check_catalog()
        dates = [a.date_added for a in alerts]
        assert dates == sorted(dates, reverse=True)

    def test_persists_new_alerts_batch_to_blob(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)
        monitor.check_catalog()

        # Find the batch entry — key starts with kev-feeds/batches/
        batch_keys = [k for k in blob._state if k.startswith("kev-feeds/batches/")]
        assert len(batch_keys) == 1
        batch = blob._state[batch_keys[0]]
        assert batch["count"] == 3
        assert len(batch["alerts"]) == 3

    def test_persists_seen_ids_to_blob(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)
        monitor.check_catalog()

        seen = blob._state["kev-feeds/seen_ids.json"]
        assert seen["count"] == 3
        assert len(seen["ids"]) == 3

    def test_handles_catalog_without_vulnerabilities_field(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog(catalog={"title": "empty"})
        monitor = KEVMonitor(blob_store=blob, http_client=http)
        assert monitor.check_catalog() == []

    def test_works_without_blob_store(self):
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=None, http_client=http)
        alerts = monitor.check_catalog()
        assert len(alerts) == 3
        # Second call still returns 0 — dedup works in-memory
        assert monitor.check_catalog() == []


# ── KEVMonitor.reset_dedup_state ──────────────────────────────────────


class TestKEVMonitorResetDedup:
    def test_resets_in_memory_state(self):
        blob = _mock_blob_store()
        http = _mock_http_with_catalog()
        monitor = KEVMonitor(blob_store=blob, http_client=http)

        monitor.check_catalog()
        assert monitor.check_catalog() == []  # already seen

        monitor.reset_dedup_state()
        # After reset, a fresh check returns everything again. Need a new
        # client because the existing mock returns the same response object.
        monitor._http = _mock_http_with_catalog()
        alerts = monitor.check_catalog()
        assert len(alerts) == 3


# ── KEVMonitor.get_recent_alerts ──────────────────────────────────────


class TestKEVMonitorRecent:
    def test_returns_empty_without_blob(self):
        monitor = KEVMonitor(blob_store=None)
        assert monitor.get_recent_alerts(days=7) == []

    def test_replays_persisted_batches(self):
        from datetime import datetime, timezone

        blob = _mock_blob_store()
        # Seed today's batch
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        blob._state[f"kev-feeds/batches/{today}.json"] = {
            "date": today,
            "count": 1,
            "alerts": [
                KEVAlert(
                    alert_id="aid1",
                    cve_id="CVE-2026-9999",
                    vendor="Test",
                    product="App",
                    vulnerability_name="Test",
                    short_description="",
                    date_added="2026-04-10",
                    due_date="2026-04-30",
                    known_ransomware_use="Unknown",
                ).to_dict(),
            ],
        }

        monitor = KEVMonitor(blob_store=blob)
        alerts = monitor.get_recent_alerts(days=7)
        assert len(alerts) == 1
        assert alerts[0].cve_id == "CVE-2026-9999"
