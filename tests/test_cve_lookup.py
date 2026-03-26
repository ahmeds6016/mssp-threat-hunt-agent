"""Tests for the CVE lookup client (cvelistV5 + fallback)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.intel.cve_lookup import CVEDetail, CVELookup, _build_cve_url


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "cve_cache"


@pytest.fixture
def mock_lookup(cache_dir: Path) -> CVELookup:
    return CVELookup(use_mock=True, cache_dir=cache_dir)


# ── CVEDetail model ─────────────────────────────────────────────────


class TestCVEDetailModel:
    def test_create_detail(self) -> None:
        d = CVEDetail(
            cve_id="CVE-2024-3400",
            description="PAN-OS GlobalProtect RCE",
            cvss_score=10.0,
            severity="CRITICAL",
            affected_products=["PAN-OS"],
        )
        assert d.cve_id == "CVE-2024-3400"
        assert d.cvss_score == 10.0

    def test_detail_defaults(self) -> None:
        d = CVEDetail(cve_id="CVE-2024-0001")
        assert d.severity == "unknown"
        assert d.cvss_score == 0.0
        assert d.affected_products == []


# ── Mock mode ───────────────────────────────────────────────────────


class TestCVELookupMock:
    def test_mock_returns_detail(self, mock_lookup: CVELookup) -> None:
        detail = mock_lookup.fetch("CVE-2024-3400")
        assert isinstance(detail, CVEDetail)
        assert detail.cve_id == "CVE-2024-3400"

    def test_mock_unknown_cve(self, mock_lookup: CVELookup) -> None:
        detail = mock_lookup.fetch("CVE-9999-0001")
        assert isinstance(detail, CVEDetail)
        assert detail.cve_id == "CVE-9999-0001"


# ── URL construction ────────────────────────────────────────────────


class TestURLConstruction:
    def test_url_for_cve_2024_3400(self) -> None:
        url = _build_cve_url("CVE-2024-3400")
        assert "2024" in url
        assert "3xxx" in url
        assert "CVE-2024-3400" in url

    def test_url_for_cve_2023_44487(self) -> None:
        url = _build_cve_url("CVE-2023-44487")
        assert "2023" in url
        assert "44xxx" in url

    def test_url_for_short_id(self) -> None:
        url = _build_cve_url("CVE-2024-100")
        assert "2024" in url
        assert "0xxx" in url


# ── Caching ─────────────────────────────────────────────────────────


class TestCVECaching:
    def test_cached_result_returned(self, cache_dir: Path) -> None:
        lookup = CVELookup(use_mock=True, cache_dir=cache_dir)
        # First fetch
        detail1 = lookup.fetch("CVE-2024-3400")
        # Second fetch should hit cache
        detail2 = lookup.fetch("CVE-2024-3400")
        assert detail1.cve_id == detail2.cve_id
