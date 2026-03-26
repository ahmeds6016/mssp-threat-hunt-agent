"""Azure AD service-principal authentication for the Sentinel / Log Analytics API."""

from __future__ import annotations

import time
import logging

import httpx

logger = logging.getLogger(__name__)

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_EXPIRY_BUFFER_SECONDS = 60  # refresh token this many seconds before it expires


class SentinelAuthError(Exception):
    """Raised when Azure AD token acquisition fails."""


class SentinelAuth:
    """Client-credentials token provider for the Log Analytics Query API.

    Parameters
    ----------
    tenant_id:
        Azure AD tenant ID (GUID).
    client_id:
        Service-principal / app-registration client ID.
    client_secret:
        Service-principal client secret value.
    scope:
        OAuth2 scope to request (default: Log Analytics API).
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str = _LOG_ANALYTICS_SCOPE,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._token_url = _TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id)

    # ── public API ────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        return time.time() >= self._expires_at - _EXPIRY_BUFFER_SECONDS

    def get_token(self) -> str:
        """Return a valid bearer token, refreshing if necessary."""
        if self._token is None or self.is_expired:
            self._refresh()
        assert self._token is not None
        return self._token

    def invalidate(self) -> None:
        """Force next call to get_token() to fetch a fresh token."""
        self._token = None
        self._expires_at = 0.0

    # ── internals ─────────────────────────────────────────────────────

    def _refresh(self) -> None:
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": self._scope,
        }
        try:
            resp = httpx.post(self._token_url, data=payload, timeout=10)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise SentinelAuthError(
                f"Azure AD token request failed: {exc.response.status_code} "
                f"{exc.response.text}"
            ) from exc
        except httpx.TransportError as exc:
            raise SentinelAuthError(
                f"Azure AD token request connection error: {exc}"
            ) from exc

        data = resp.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + int(data.get("expires_in", 3600))
        logger.debug("Refreshed Azure AD token; expires in %ss", data.get("expires_in"))
