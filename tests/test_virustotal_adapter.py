"""Tests for the VirusTotal v3 threat-intel adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from mssp_hunt_agent.adapters.intel.virustotal import VirusTotalAdapter, _verdict_from_stats


class TestVerdictFromStats:
    def test_high_malicious_ratio(self) -> None:
        verdict, conf, labels = _verdict_from_stats(
            {"malicious": 40, "suspicious": 5, "harmless": 20, "undetected": 35}
        )
        assert verdict == "malicious"
        assert "malicious-detections" in labels

    def test_moderate_ratio(self) -> None:
        verdict, conf, labels = _verdict_from_stats(
            {"malicious": 8, "suspicious": 5, "harmless": 50, "undetected": 37}
        )
        assert verdict == "suspicious"

    def test_clean_file(self) -> None:
        verdict, conf, labels = _verdict_from_stats(
            {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10}
        )
        assert verdict == "benign"
        assert "clean" in labels

    def test_empty_stats(self) -> None:
        verdict, conf, labels = _verdict_from_stats({})
        assert verdict == "unknown"


class TestVirusTotalAdapter:
    def _make_adapter(self) -> VirusTotalAdapter:
        return VirusTotalAdapter(api_key="test-key")

    @patch("mssp_hunt_agent.adapters.intel.virustotal.VirusTotalAdapter._request")
    def test_enrich_ip_malicious(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40, "suspicious": 5, "harmless": 15, "undetected": 40,
                    }
                }
            }
        }

        adapter = self._make_adapter()
        result = adapter.enrich_ip("203.0.113.77")

        assert result.verdict == "malicious"
        assert result.entity_type == "ip"
        assert result.source == "VirusTotal"

    @patch("mssp_hunt_agent.adapters.intel.virustotal.VirusTotalAdapter._request")
    def test_enrich_domain_benign(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5,
                    }
                }
            }
        }

        adapter = self._make_adapter()
        result = adapter.enrich_domain("example.com")

        assert result.verdict == "benign"
        assert result.entity_type == "domain"

    @patch("mssp_hunt_agent.adapters.intel.virustotal.VirusTotalAdapter._request")
    def test_enrich_hash(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15, "suspicious": 10, "harmless": 40, "undetected": 35,
                    }
                }
            }
        }

        adapter = self._make_adapter()
        result = adapter.enrich_hash("e99a18c428cb38d5f260853678922e03")

        assert result.verdict in ("malicious", "suspicious")

    @patch("mssp_hunt_agent.adapters.intel.virustotal.VirusTotalAdapter._request")
    def test_not_found_returns_unknown(self, mock_req: MagicMock) -> None:
        mock_req.return_value = {}

        adapter = self._make_adapter()
        result = adapter.enrich_ip("192.168.1.1")

        assert result.verdict == "unknown"

    @patch("mssp_hunt_agent.adapters.intel.virustotal.VirusTotalAdapter._request")
    def test_error_returns_unknown(self, mock_req: MagicMock) -> None:
        from mssp_hunt_agent.adapters.intel.virustotal import VirusTotalError
        mock_req.side_effect = VirusTotalError("VT error 403: forbidden")

        adapter = self._make_adapter()
        result = adapter.enrich_ip("1.2.3.4")

        assert result.verdict == "unknown"
        assert "error" in result.context.lower()

    def test_user_agent_not_supported(self) -> None:
        adapter = self._make_adapter()
        result = adapter.enrich_user_agent("curl/7.88.1")

        assert result.verdict == "unknown"
        assert "not support" in result.context.lower()

    def test_provider_name(self) -> None:
        assert self._make_adapter().get_provider_name() == "VirusTotal"
