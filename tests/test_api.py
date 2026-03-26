"""Tests for the FastAPI REST API."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

# FastAPI is an optional dep — skip entire module if not installed
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from mssp_hunt_agent.api.app import app
from mssp_hunt_agent.api import background as bg
from mssp_hunt_agent.api.dependencies import get_config


@pytest.fixture(autouse=True)
def _clear_run_store():
    """Reset the in-memory run store between tests."""
    bg._run_store.clear()
    yield
    bg._run_store.clear()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


# ── Health ───────────────────────────────────────────────────────────


class TestHealth:
    def test_health_ok(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.4.0"

    def test_health_shows_config(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        data = resp.json()
        assert "adapter_mode" in data
        assert "persist_enabled" in data


# ── Hypothesis Hunt ──────────────────────────────────────────────────


class TestHuntEndpoint:
    def _hunt_payload(self) -> dict:
        return {
            "client_name": "Acme Corp",
            "hunt_objective": "Detect credential abuse",
            "hunt_hypothesis": "Compromised VPN creds from Eastern Europe",
            "time_range": "2024-01-01 to 2024-01-31",
            "available_data_sources": ["Azure AD sign-in logs", "VPN logs"],
        }

    def test_start_hunt_returns_202(self, client: TestClient) -> None:
        resp = client.post("/api/v1/hunts", json=self._hunt_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("queued", "running", "completed")
        assert data["hunt_type"] == "hypothesis"
        assert data["client_name"] == "Acme Corp"
        assert data["run_id"].startswith("RUN-")

    def test_start_hunt_validation_error(self, client: TestClient) -> None:
        resp = client.post("/api/v1/hunts", json={"client_name": ""})
        assert resp.status_code == 422

    def test_poll_after_hunt(self, client: TestClient) -> None:
        resp = client.post("/api/v1/hunts", json=self._hunt_payload())
        run_id = resp.json()["run_id"]

        # Wait for background thread to finish (mock pipeline is fast)
        for _ in range(50):
            status = client.get(f"/api/v1/hunts/{run_id}")
            if status.json()["status"] in ("completed", "stopped", "failed"):
                break
            time.sleep(0.1)

        data = status.json()
        assert data["status"] in ("completed", "stopped")
        assert data["run_id"] == run_id

    def test_hunt_plan_only(self, client: TestClient) -> None:
        payload = self._hunt_payload()
        payload["plan_only"] = True
        resp = client.post("/api/v1/hunts", json=payload)
        run_id = resp.json()["run_id"]

        for _ in range(50):
            status = client.get(f"/api/v1/hunts/{run_id}")
            if status.json()["status"] in ("completed", "stopped", "failed"):
                break
            time.sleep(0.1)

        data = status.json()
        assert data["status"] in ("completed", "stopped")


# ── IOC Sweep ────────────────────────────────────────────────────────


class TestIOCSweepEndpoint:
    def _ioc_payload(self) -> dict:
        return {
            "client_name": "Acme Corp",
            "iocs": [
                {"value": "203.0.113.77", "ioc_type": "ip"},
                {"value": "evil.example.com", "ioc_type": "domain"},
            ],
            "time_range": "2024-01-01 to 2024-01-31",
            "available_data_sources": ["Firewall logs", "DNS logs"],
        }

    def test_start_sweep_returns_202(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ioc-sweeps", json=self._ioc_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["hunt_type"] == "ioc_sweep"
        assert data["run_id"].startswith("RUN-IOC-")

    def test_sweep_completes(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ioc-sweeps", json=self._ioc_payload())
        run_id = resp.json()["run_id"]

        for _ in range(50):
            status = client.get(f"/api/v1/hunts/{run_id}")
            if status.json()["status"] in ("completed", "stopped", "failed"):
                break
            time.sleep(0.1)

        assert status.json()["status"] in ("completed", "stopped")

    def test_sweep_validation_error(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ioc-sweeps", json={"client_name": "X"})
        assert resp.status_code == 422


# ── Profile ──────────────────────────────────────────────────────────


class TestProfileEndpoint:
    def _profile_payload(self) -> dict:
        return {
            "client_name": "Acme Corp",
            "time_range": "2024-11-01 to 2024-11-30",
        }

    def test_start_profile_returns_202(self, client: TestClient) -> None:
        resp = client.post("/api/v1/profiles", json=self._profile_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["hunt_type"] == "profile"
        assert data["run_id"].startswith("RUN-PROF-")

    def test_profile_completes(self, client: TestClient) -> None:
        resp = client.post("/api/v1/profiles", json=self._profile_payload())
        run_id = resp.json()["run_id"]

        for _ in range(50):
            status = client.get(f"/api/v1/hunts/{run_id}")
            if status.json()["status"] in ("completed", "stopped", "failed"):
                break
            time.sleep(0.1)

        assert status.json()["status"] in ("completed", "stopped")


# ── Status / 404 ─────────────────────────────────────────────────────


class TestStatusEndpoint:
    def test_unknown_run_id_404(self, client: TestClient) -> None:
        resp = client.get("/api/v1/hunts/NOPE-12345")
        assert resp.status_code == 404

    def test_status_returns_run(self, client: TestClient) -> None:
        # Create a run first
        payload = {
            "client_name": "X",
            "hunt_objective": "test",
            "hunt_hypothesis": "test hyp",
            "time_range": "2024-01-01 to 2024-01-31",
            "available_data_sources": ["logs"],
        }
        resp = client.post("/api/v1/hunts", json=payload)
        run_id = resp.json()["run_id"]

        # Immediate poll should find it
        status = client.get(f"/api/v1/hunts/{run_id}")
        assert status.status_code == 200
        assert status.json()["run_id"] == run_id


# ── Client / Run listing ─────────────────────────────────────────────


class TestListEndpoints:
    def test_list_clients_empty(self, client: TestClient) -> None:
        resp = client.get("/api/v1/clients")
        assert resp.status_code == 200
        assert resp.json()["clients"] == [] or isinstance(resp.json()["clients"], list)

    def test_list_runs_empty(self, client: TestClient) -> None:
        resp = client.get("/api/v1/runs")
        assert resp.status_code == 200
        assert isinstance(resp.json()["runs"], list)

    def test_list_runs_with_filters(self, client: TestClient) -> None:
        resp = client.get("/api/v1/runs?client=Acme&hunt_type=hypothesis&limit=5")
        assert resp.status_code == 200
