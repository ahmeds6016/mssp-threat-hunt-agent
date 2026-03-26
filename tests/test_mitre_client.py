"""Tests for the MITRE ATT&CK STIX client."""

import json
import tempfile
from pathlib import Path

import pytest

from mssp_hunt_agent.intel.mitre_client import MITREClient, MITRETechnique


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "mitre_cache"


@pytest.fixture
def client(cache_dir: Path) -> MITREClient:
    """Client that will use fallback data (no real download)."""
    return MITREClient(cache_dir=cache_dir)


# ── MITRETechnique model ────────────────────────────────────────────


class TestMITRETechniqueModel:
    def test_create_technique(self) -> None:
        t = MITRETechnique(
            technique_id="T1059.001",
            name="PowerShell",
            description="Adversaries may abuse PowerShell...",
            tactics=["execution"],
            platforms=["Windows"],
            data_sources=["Process: Process Creation"],
            is_subtechnique=True,
            parent_id="T1059",
        )
        assert t.technique_id == "T1059.001"
        assert t.is_subtechnique
        assert t.parent_id == "T1059"

    def test_technique_url(self) -> None:
        t = MITRETechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            url="https://attack.mitre.org/techniques/T1059/",
        )
        assert "T1059" in t.url


# ── Client with pre-cached data ─────────────────────────────────────


class TestMITREClientCached:
    def _write_cache(self, cache_dir: Path) -> None:
        """Write a minimal cache file for testing."""
        techniques = [
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters.",
                "tactics": ["execution"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process: Process Creation", "Command: Command Execution"],
                "is_subtechnique": False,
                "parent_id": "",
                "url": "https://attack.mitre.org/techniques/T1059/",
                "detection": "",
            },
            {
                "technique_id": "T1059.001",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell commands.",
                "tactics": ["execution"],
                "platforms": ["Windows"],
                "data_sources": ["Process: Process Creation"],
                "is_subtechnique": True,
                "parent_id": "T1059",
                "url": "https://attack.mitre.org/techniques/T1059/001/",
                "detection": "",
            },
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                "platforms": ["Windows", "Azure AD", "Linux"],
                "data_sources": ["Logon Session: Logon Session Creation"],
                "is_subtechnique": False,
                "parent_id": "",
                "url": "https://attack.mitre.org/techniques/T1078/",
                "detection": "",
            },
        ]
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "techniques.json").write_text(json.dumps(techniques))

    def test_get_technique_by_id(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        t = client.get_technique("T1059")
        assert t is not None
        assert t.name == "Command and Scripting Interpreter"

    def test_get_technique_not_found(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        t = client.get_technique("T9999")
        assert t is None

    def test_search_techniques(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        results = client.search_techniques("PowerShell")
        assert len(results) >= 1
        assert any(t.technique_id == "T1059.001" for t in results)

    def test_search_techniques_by_tactic(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        results = client.get_techniques_for_tactic("execution")
        assert len(results) >= 1

    def test_get_subtechniques(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        subs = client.get_subtechniques("T1059")
        assert len(subs) >= 1
        assert subs[0].technique_id == "T1059.001"

    def test_technique_count(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        assert client.technique_count() == 3

    def test_get_all_technique_ids(self, cache_dir: Path) -> None:
        self._write_cache(cache_dir)
        client = MITREClient(cache_dir=cache_dir)
        ids = client.get_all_technique_ids()
        assert "T1059" in ids
        assert "T1078" in ids


# ── Client fallback ─────────────────────────────────────────────────


class TestMITREClientFallback:
    def test_fallback_techniques_loaded(self, client: MITREClient) -> None:
        """Without cache or network, should use fallback techniques."""
        # The client should either have downloaded or used fallback
        count = client.technique_count()
        assert count > 0
