"""Tests for BlobStateStore — memory-only mode and blob-backed mode."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.persistence.blob_store import BlobStateStore


class TestMemoryOnlyMode:
    """BlobStateStore with no connection string — pure in-memory."""

    def test_init_memory_only(self) -> None:
        store = BlobStateStore()
        assert not store.blob_enabled

    def test_save_and_get_request(self) -> None:
        store = BlobStateStore()
        store.save_request("REQ-001", {"status": "processing"})
        result = store.get_request("REQ-001")
        assert result == {"status": "processing"}

    def test_get_missing_request(self) -> None:
        store = BlobStateStore()
        assert store.get_request("REQ-999") is None

    def test_save_and_get_campaign_dict(self) -> None:
        store = BlobStateStore()
        data = {"campaign_id": "CAMP-001", "status": "starting"}
        store.save_campaign("CAMP-001", data)
        result = store.get_campaign("CAMP-001")
        assert result == data

    def test_get_missing_campaign(self) -> None:
        store = BlobStateStore()
        assert store.get_campaign("CAMP-999") is None

    def test_save_and_get_campaign_state_object(self) -> None:
        from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState

        store = BlobStateStore()
        state = CampaignState(
            campaign_id="CAMP-002",
            config=CampaignConfig(client_name="TestCo"),
            status="completed",
            total_kql_queries=10,
        )
        store.save_campaign("CAMP-002", state)
        result = store.get_campaign("CAMP-002")
        assert result is state  # same object in cache

    def test_list_campaigns(self) -> None:
        store = BlobStateStore()
        store.save_campaign("CAMP-A", {"campaign_id": "CAMP-A", "status": "starting"})
        store.save_campaign("CAMP-B", {"campaign_id": "CAMP-B", "status": "failed"})
        result = store.list_campaigns()
        assert len(result) == 2
        assert "CAMP-A" in result
        assert "CAMP-B" in result

    def test_overwrite_request(self) -> None:
        store = BlobStateStore()
        store.save_request("REQ-001", {"status": "processing"})
        store.save_request("REQ-001", {"status": "completed", "response": "done"})
        result = store.get_request("REQ-001")
        assert result["status"] == "completed"

    def test_overwrite_campaign(self) -> None:
        store = BlobStateStore()
        store.save_campaign("CAMP-001", {"status": "starting"})
        store.save_campaign("CAMP-001", {"status": "completed", "findings": 5})
        result = store.get_campaign("CAMP-001")
        assert result["status"] == "completed"


class TestBlobBackedMode:
    """BlobStateStore with mocked Azure Blob client."""

    def test_init_with_connection_string(self) -> None:
        """When azure-storage-blob is available and connection works, blob_enabled is True."""
        mock_service = MagicMock()
        mock_container = MagicMock()
        mock_container.exists.return_value = True
        mock_service.get_container_client.return_value = mock_container

        with patch.dict("sys.modules", {"azure.storage.blob": MagicMock()}):
            with patch(
                "mssp_hunt_agent.persistence.blob_store.BlobStateStore._ensure_container"
            ):
                store = BlobStateStore()
                store._client = mock_service
                assert store.blob_enabled

    def test_init_with_bad_connection_string_falls_back(self) -> None:
        """Bad connection string should fall back to memory-only."""
        store = BlobStateStore(connection_string="garbage")
        assert not store.blob_enabled

    def test_save_request_calls_upload(self) -> None:
        store = BlobStateStore()
        store._client = MagicMock()  # Fake blob enabled
        store.save_request("REQ-X", {"status": "done"})
        # Should be in cache
        assert store.get_request("REQ-X") == {"status": "done"}
        # Should have attempted upload
        store._client.get_container_client.assert_called()

    def test_save_campaign_state_serializes(self) -> None:
        from mssp_hunt_agent.hunter.models.campaign import CampaignConfig, CampaignState

        store = BlobStateStore()
        store._client = MagicMock()
        state = CampaignState(
            campaign_id="CAMP-X",
            config=CampaignConfig(client_name="TestCo"),
            status="completed",
        )
        store.save_campaign("CAMP-X", state)
        assert store.get_campaign("CAMP-X") is state
        store._client.get_container_client.assert_called()

    def test_upload_failure_does_not_crash(self) -> None:
        """Blob upload failure should log warning, not raise."""
        store = BlobStateStore()
        store._client = MagicMock()
        store._client.get_container_client.side_effect = Exception("network error")
        # Should not raise
        store.save_request("REQ-ERR", {"status": "test"})
        # Data should still be in cache
        assert store.get_request("REQ-ERR") == {"status": "test"}
