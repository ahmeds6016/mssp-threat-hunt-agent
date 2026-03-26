"""OAuth2 client-credentials authentication for Exabeam New-Scale."""

from __future__ import annotations

import time
import logging

import httpx

logger = logging.getLogger(__name__)

# Buffer (in seconds) before real expiry to trigger a proactive refresh
_EXPIRY_BUFFER = 60


class ExabeamAuthError(Exception):
    """Raised when token acquisition fails."""


class ExabeamAuth:
    """Manages OAuth2 client-credentials tokens for the Exabeam API.

    Usage::

        auth = ExabeamAuth(client_id, client_secret, token_url)
        token = auth.get_token()   # cached until near expiry
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str = "https://auth.exabeam.cloud/auth/v1/token",
        *,
        timeout: float = 15.0,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._timeout = timeout
        self._access_token: str | None = None
        self._expires_at: float = 0.0

    @property
    def is_expired(self) -> bool:
        """True when the cached token is absent or about to expire."""
        return self._access_token is None or time.time() >= (self._expires_at - _EXPIRY_BUFFER)

    def get_token(self) -> str:
        """Return a valid Bearer token, refreshing if necessary."""
        if not self.is_expired:
            return self._access_token  # type: ignore[return-value]
        self._refresh()
        return self._access_token  # type: ignore[return-value]

    def _refresh(self) -> None:
        """Request a new token from the OAuth2 endpoint."""
        logger.debug("Refreshing Exabeam OAuth2 token from %s", self._token_url)
        try:
            resp = httpx.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ExabeamAuthError(
                f"Token request failed ({exc.response.status_code}): {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ExabeamAuthError(f"Token request error: {exc}") from exc

        body = resp.json()
        self._access_token = body["access_token"]
        expires_in = int(body.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in
        logger.debug("Token acquired, expires in %ds", expires_in)

    def invalidate(self) -> None:
        """Force the next call to ``get_token`` to refresh."""
        self._access_token = None
        self._expires_at = 0.0
