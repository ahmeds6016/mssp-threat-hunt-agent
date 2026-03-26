"""Tests for V4.4 Continuous Threat Landscape Correlation."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.intel.landscape_models import KEVEntry, ThreatCorrelation, LandscapeAlert
from mssp_hunt_agent.intel.cisa_kev import parse_kev_catalog, infer_detection_sources
from mssp_hunt_agent.intel.correlation import (
    correlate_threats_to_clients,
    generate_alerts,
    build_landscape_report,
)
from mssp_hunt_agent.intel.landscape import ThreatLandscapeEngine


def _make_kev(cve_id="CVE-2024-0001", vendor="Microsoft", product="Windows") -> KEVEntry:
    return KEVEntry(
        cve_id=cve_id,
        vendor=vendor,
        product=product,
        vulnerability_name=f"Test vuln in {product}",
        date_added="2024-01-15",
        due_date="2024-02-05",
    )


_SAMPLE_KEV_JSON = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1234",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "RCE in Windows SMB",
            "dateAdded": "2024-03-01",
            "dueDate": "2024-03-22",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "Remote code execution in SMB",
        },
        {
            "cveID": "CVE-2024-5678",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Path traversal",
            "dateAdded": "2024-03-05",
            "dueDate": "2024-03-26",
        },
    ]
}


class TestKEVParsing:
    def test_parse_catalog(self):
        entries = parse_kev_catalog(_SAMPLE_KEV_JSON)
        assert len(entries) == 2
        assert entries[0].cve_id == "CVE-2024-1234"
        assert entries[0].vendor == "Microsoft"

    def test_parse_empty(self):
        entries = parse_kev_catalog({"vulnerabilities": []})
        assert len(entries) == 0

    def test_infer_windows_sources(self):
        entry = _make_kev(vendor="Microsoft", product="Windows")
        sources = infer_detection_sources(entry)
        assert "SecurityEvent" in sources or "DeviceProcessEvents" in sources

    def test_infer_apache_sources(self):
        entry = _make_kev(vendor="Apache", product="HTTP Server")
        sources = infer_detection_sources(entry)
        assert "CommonSecurityLog" in sources

    def test_infer_unknown_product_fallback(self):
        entry = _make_kev(vendor="UnknownVendor", product="UnknownProduct")
        sources = infer_detection_sources(entry)
        assert len(sources) > 0


class TestCorrelation:
    def test_correlate_detectable_threat(self):
        threats = [_make_kev(vendor="Microsoft", product="Windows")]
        clients = {"Contoso": ["SecurityEvent", "DeviceProcessEvents"]}
        corrs = correlate_threats_to_clients(threats, clients)
        assert len(corrs) == 1
        assert corrs[0].can_detect is True
        assert corrs[0].coverage_score > 0

    def test_correlate_undetectable_threat(self):
        threats = [_make_kev(vendor="Microsoft", product="Windows")]
        clients = {"Fabrikam": ["DnsEvents"]}
        corrs = correlate_threats_to_clients(threats, clients)
        assert corrs[0].can_detect is False
        assert len(corrs[0].missing_sources) > 0

    def test_correlate_multiple_clients(self):
        threats = [_make_kev()]
        clients = {"A": ["SecurityEvent"], "B": ["DnsEvents"], "C": ["DeviceProcessEvents"]}
        corrs = correlate_threats_to_clients(threats, clients)
        assert len(corrs) == 3

    def test_generate_alerts_only_for_blind(self):
        threats = [_make_kev()]
        clients = {"Good": ["SecurityEvent", "DeviceProcessEvents"], "Bad": ["DnsEvents"]}
        corrs = correlate_threats_to_clients(threats, clients)
        alerts = generate_alerts(corrs)
        alert_clients = [a.client_name for a in alerts]
        assert "Bad" in alert_clients
        # "Good" should not be in alerts (it can detect)

    def test_alerts_have_recommendations(self):
        threats = [_make_kev()]
        clients = {"Blind": []}
        corrs = correlate_threats_to_clients(threats, clients)
        alerts = generate_alerts(corrs)
        assert len(alerts) > 0
        assert len(alerts[0].recommended_actions) > 0


class TestLandscapeEngine:
    def test_ingest_and_correlate(self):
        engine = ThreatLandscapeEngine()
        entries = engine.ingest_kev(_SAMPLE_KEV_JSON)
        assert len(entries) == 2

        clients = {"Contoso": ["SecurityEvent", "DeviceProcessEvents", "CommonSecurityLog"]}
        report = engine.correlate(clients)
        assert report.total_threats_analyzed == 2
        assert report.total_correlations == 2

    def test_empty_correlate(self):
        engine = ThreatLandscapeEngine()
        report = engine.correlate({"Contoso": ["SecurityEvent"]})
        assert report.total_threats_analyzed == 0

    def test_build_full_report(self):
        threats = parse_kev_catalog(_SAMPLE_KEV_JSON)
        clients = {"A": ["SecurityEvent"], "B": []}
        report = build_landscape_report(threats, clients)
        assert report.total_threats_analyzed == 2
        assert len(report.clients_at_risk) > 0
