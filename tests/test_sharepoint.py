"""Tests for the SharePoint Graph API uploader."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.persistence.sharepoint import SharePointError, SharePointUploader


def _make_uploader() -> SharePointUploader:
    return SharePointUploader(
        tenant_id="test-tenant",
        client_id="test-client-id",
        client_secret="test-secret",
        site_id="contoso.sharepoint.com,abc,def",
    )


class TestSharePointAuth:
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_token_acquired(self, mock_post: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok-123"}),
        )
        up = _make_uploader()
        up._ensure_token()
        assert up._token == "tok-123"
        mock_post.assert_called_once()

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_token_cached(self, mock_post: MagicMock) -> None:
        up = _make_uploader()
        up._token = "already-have"
        up._ensure_token()
        mock_post.assert_not_called()

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_token_failure(self, mock_post: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=401,
            text="bad credentials",
        )
        up = _make_uploader()
        with pytest.raises(SharePointError, match="Token request failed"):
            up._ensure_token()


class TestUploadArtifact:
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.put")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_upload_success(self, mock_post: MagicMock, mock_put: MagicMock) -> None:
        # Token call
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        # Upload call
        mock_put.return_value = MagicMock(
            status_code=201,
            json=MagicMock(return_value={
                "id": "file-123",
                "webUrl": "https://contoso.sharepoint.com/sites/hunts/report.md",
            }),
        )

        up = _make_uploader()
        result = up.upload_artifact("ClientA/2024-01", "report.md", "# Report\n...")

        assert result["id"] == "file-123"
        mock_put.assert_called_once()
        call_url = mock_put.call_args[0][0]
        assert "ClientA/2024-01/report.md" in call_url

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.put")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_upload_bytes(self, mock_post: MagicMock, mock_put: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_put.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"id": "f1"}),
        )

        up = _make_uploader()
        result = up.upload_artifact("folder", "data.bin", b"\x00\x01\x02")
        assert result["id"] == "f1"

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.put")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_upload_failure(self, mock_post: MagicMock, mock_put: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_put.return_value = MagicMock(
            status_code=403,
            text="Access denied",
        )

        up = _make_uploader()
        with pytest.raises(SharePointError, match="Upload failed"):
            up.upload_artifact("folder", "file.md", "content")


class TestEnsureFolder:
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_create_folder(self, mock_post: MagicMock) -> None:
        # First call = token, second call = folder creation
        token_resp = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        folder_resp = MagicMock(
            status_code=201,
            json=MagicMock(return_value={"id": "folder-1", "name": "ClientA"}),
        )
        mock_post.side_effect = [token_resp, folder_resp]

        up = _make_uploader()
        result = up.ensure_folder("ClientA")
        assert result["id"] == "folder-1"

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_create_nested_folder(self, mock_post: MagicMock) -> None:
        token_resp = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        folder_resp_1 = MagicMock(
            status_code=201,
            json=MagicMock(return_value={"id": "f1", "name": "ClientA"}),
        )
        folder_resp_2 = MagicMock(
            status_code=201,
            json=MagicMock(return_value={"id": "f2", "name": "2024-01"}),
        )
        mock_post.side_effect = [token_resp, folder_resp_1, folder_resp_2]

        up = _make_uploader()
        result = up.ensure_folder("ClientA/2024-01")
        assert result["id"] == "f2"

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_folder_already_exists(self, mock_post: MagicMock) -> None:
        token_resp = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        conflict_resp = MagicMock(status_code=409)
        mock_post.side_effect = [token_resp, conflict_resp]

        up = _make_uploader()
        result = up.ensure_folder("Existing")
        assert result["status"] == "already_exists"

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_folder_creation_error(self, mock_post: MagicMock) -> None:
        token_resp = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        error_resp = MagicMock(status_code=500, text="Server error")
        mock_post.side_effect = [token_resp, error_resp]

        up = _make_uploader()
        with pytest.raises(SharePointError, match="Folder creation failed"):
            up.ensure_folder("BadFolder")


class TestListArtifacts:
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.get")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_list_success(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "value": [
                    {"name": "report.md", "id": "f1"},
                    {"name": "audit.json", "id": "f2"},
                ]
            }),
        )

        up = _make_uploader()
        items = up.list_artifacts("ClientA/2024-01")
        assert len(items) == 2
        assert items[0]["name"] == "report.md"

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.get")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_list_not_found(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_get.return_value = MagicMock(status_code=404)

        up = _make_uploader()
        items = up.list_artifacts("Nonexistent")
        assert items == []

    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.get")
    @patch("mssp_hunt_agent.persistence.sharepoint.httpx.post")
    def test_list_error(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_get.return_value = MagicMock(status_code=500, text="Server error")

        up = _make_uploader()
        with pytest.raises(SharePointError, match="List failed"):
            up.list_artifacts("ClientA")


class TestDrivePath:
    def test_with_site_id(self) -> None:
        up = _make_uploader()
        assert up._drive_path() == "/sites/contoso.sharepoint.com,abc,def/drive"

    def test_with_drive_id(self) -> None:
        up = SharePointUploader(
            tenant_id="t", client_id="c", client_secret="s",
            site_id="site", drive_id="drv-123",
        )
        assert up._drive_path() == "/drives/drv-123"
