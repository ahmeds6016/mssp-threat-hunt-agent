"""Tests for the AbuseIPDB threat-intel adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.adapters.intel.abuseipdb import AbuseIPDBAdapter, _verdict_from_score


class TestVerdictFromScore:
    def test_high_score_malicious(self) -> None:
        verdict, conf, labels = _verdict_from_score(95)
        assert verdict == "malicious"
        assert "high-abuse-score" in labels

    def test_moderate_score_suspicious(self) -> None:
        verdict, conf, labels = _verdict_from_score(55)
        assert verdict == "suspicious"
        assert "moderate-abuse-score" in labels

    def test_low_score_suspicious(self) -> None:
        verdict, conf, labels = _verdict_from_score(10)
        assert verdict == "suspicious"
        assert "low-abuse-score" in labels

    def test_zero_score_benign(self) -> None:
        verdict, conf, labels = _verdict_from_score(0)
        assert verdict == "benign"
        assert "clean" in labels


class TestAbuseIPDBAdapter:
    def _make_adapter(self) -> AbuseIPDBAdapter:
        return AbuseIPDBAdapter(api_key="test-key")

    @patch("mssp_hunt_agent.adapters.intel.abuseipdb.AbuseIPDBAdapter._request")
    def test_enrich_ip_malicious(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {
            "data": {
                "ipAddress": "203.0.113.77",
                "abuseConfidenceScore": 90,
                "countryCode": "RU",
                "isp": "Shady ISP",
                "totalReports": 150,
            }
        }

        adapter = self._make_adapter()
        result = adapter.enrich_ip("203.0.113.77")

        assert result.verdict == "malicious"
        assert result.entity_type == "ip"
        assert result.source == "AbuseIPDB"
        assert "RU" in result.context
        assert "150" in result.context

    @patch("mssp_hunt_agent.adapters.intel.abuseipdb.AbuseIPDBAdapter._request")
    def test_enrich_ip_clean(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "totalReports": 0,
            }
        }

        adapter = self._make_adapter()
        result = adapter.enrich_ip("8.8.8.8")

        assert result.verdict == "benign"

    @patch("mssp_hunt_agent.adapters.intel.abuseipdb.AbuseIPDBAdapter._request")
    def test_error_returns_unknown(self, mock_req: MagicMock) -> None:
        from mssp_hunt_agent.adapters.intel.abuseipdb import AbuseIPDBError
        mock_req.side_effect = AbuseIPDBError("403 forbidden")

        adapter = self._make_adapter()
        result = adapter.enrich_ip("1.2.3.4")

        assert result.verdict == "unknown"

    def test_domain_not_supported(self) -> None:
        adapter = self._make_adapter()
        result = adapter.enrich_domain("example.com")
        assert result.verdict == "unknown"
        assert "only supports IP" in result.context

    def test_hash_not_supported(self) -> None:
        adapter = self._make_adapter()
        result = adapter.enrich_hash("abc123")
        assert result.verdict == "unknown"

    def test_user_agent_not_supported(self) -> None:
        adapter = self._make_adapter()
        result = adapter.enrich_user_agent("curl/7.88")
        assert result.verdict == "unknown"

    def test_provider_name(self) -> None:
        assert self._make_adapter().get_provider_name() == "AbuseIPDB"
