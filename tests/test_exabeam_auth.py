"""Tests for Sentinel Azure AD service-principal authentication.

This file was previously test_exabeam_auth.py — migrated to Sentinel auth.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.adapters.sentinel.auth import SentinelAuth, SentinelAuthError


class TestSentinelAuth:
    def _make_auth(self, **kwargs) -> SentinelAuth:
        return SentinelAuth(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            **kwargs,
        )

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_get_token_fetches_on_first_call(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"access_token": "tok123", "expires_in": 3600}
        mock_post.return_value = mock_resp

        auth = self._make_auth()
        token = auth.get_token()

        assert token == "tok123"
        mock_post.assert_called_once()

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_token_cached_on_second_call(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"access_token": "tok123", "expires_in": 3600}
        mock_post.return_value = mock_resp

        auth = self._make_auth()
        auth.get_token()
        auth.get_token()

        assert mock_post.call_count == 1

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_refresh_on_expiry(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"access_token": "tok123", "expires_in": 3600}
        mock_post.return_value = mock_resp

        auth = self._make_auth()
        auth.get_token()
        auth._expires_at = time.time() - 10

        mock_resp.json.return_value = {"access_token": "tok456", "expires_in": 3600}
        token = auth.get_token()

        assert token == "tok456"
        assert mock_post.call_count == 2

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_invalidate_forces_refresh(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"access_token": "tok1", "expires_in": 3600}
        mock_post.return_value = mock_resp

        auth = self._make_auth()
        auth.get_token()
        auth.invalidate()

        mock_resp.json.return_value = {"access_token": "tok2", "expires_in": 3600}
        token = auth.get_token()

        assert token == "tok2"
        assert mock_post.call_count == 2

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_http_error_raises_auth_error(self, mock_post: MagicMock) -> None:
        import httpx
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_resp,
        )
        mock_post.return_value = mock_resp

        auth = self._make_auth()
        with pytest.raises(SentinelAuthError, match="401"):
            auth.get_token()

    @patch("mssp_hunt_agent.adapters.sentinel.auth.httpx.post")
    def test_connection_error_raises_auth_error(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        auth = self._make_auth()
        with pytest.raises(SentinelAuthError, match="connection"):
            auth.get_token()

    def test_is_expired_initially(self) -> None:
        auth = self._make_auth()
        assert auth.is_expired is True

    def test_token_url_uses_tenant(self) -> None:
        auth = self._make_auth()
        assert "test-tenant" in auth._token_url
        assert "oauth2/v2.0/token" in auth._token_url
