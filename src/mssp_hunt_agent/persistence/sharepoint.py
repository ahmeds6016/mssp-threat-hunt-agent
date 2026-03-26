"""SharePoint uploader via Microsoft Graph API.

Uploads hunt artefacts (reports, profiles) to a SharePoint document library
so client-facing deliverables are accessible from Teams/SharePoint.

Requires the ``azure`` optional dependency group::

    pip install mssp-hunt-agent[azure]
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SharePointError(Exception):
    """Raised on Graph API failures."""


class SharePointUploader:
    """Upload artefacts to a SharePoint Online document library.

    Parameters
    ----------
    tenant_id:
        Azure AD tenant ID.
    client_id:
        App registration client ID with *Sites.ReadWrite.All* or
        *Files.ReadWrite.All* (application permission).
    client_secret:
        App registration client secret.
    site_id:
        SharePoint site ID (``{hostname},{site-collection-id},{web-id}``).
    drive_id:
        Optional drive ID. If omitted the site's default document library is
        used.
    """

    TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        site_id: str,
        drive_id: str = "",
        timeout: int = 30,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._site_id = site_id
        self._drive_id = drive_id
        self._timeout = timeout
        self._token: str = ""

    # ── public API ────────────────────────────────────────────────────

    def upload_artifact(
        self, folder: str, filename: str, content: str | bytes
    ) -> dict[str, Any]:
        """Upload a single file to ``<drive>/<folder>/<filename>``.

        Returns the Graph API response dict (contains ``id``, ``webUrl``, …).
        """
        self._ensure_token()
        drive_path = self._drive_path()
        url = (
            f"{self.GRAPH_BASE}{drive_path}"
            f"/root:/{folder}/{filename}:/content"
        )
        body = content.encode("utf-8") if isinstance(content, str) else content
        headers = self._auth_headers()
        headers["Content-Type"] = "application/octet-stream"

        resp = httpx.put(url, content=body, headers=headers, timeout=self._timeout)
        if resp.status_code not in (200, 201):
            raise SharePointError(
                f"Upload failed ({resp.status_code}): {resp.text[:300]}"
            )
        data: dict[str, Any] = resp.json()
        logger.info("Uploaded %s/%s → %s", folder, filename, data.get("webUrl", ""))
        return data

    def ensure_folder(self, path: str) -> dict[str, Any]:
        """Create a folder (and parents) under the drive root. Idempotent.

        Returns the Graph API folder item dict.
        """
        self._ensure_token()
        drive_path = self._drive_path()
        url = (
            f"{self.GRAPH_BASE}{drive_path}"
            f"/root:/{ path}:/children"
        )
        # Graph trick: create a folder by uploading a folder-typed item via
        # /root:/{path} — but simpler: use /items endpoint.
        # Instead, create via the children endpoint on the parent.
        # For nested paths we just create the full path at once using
        # PUT to /root:/{full_path}  which auto-creates parents.
        # Actually, the easiest way is to upload a placeholder then delete.
        # Simplest: use PATCH to create folder item.

        # Graph API: POST /drive/root/children with folder facet
        parts = [p for p in path.strip("/").split("/") if p]
        current_path = ""
        result: dict[str, Any] = {}
        for part in parts:
            parent_url = (
                f"{self.GRAPH_BASE}{drive_path}/root"
                if not current_path
                else f"{self.GRAPH_BASE}{drive_path}/root:/{current_path}:"
            )
            create_url = f"{parent_url}/children"
            body = {
                "name": part,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "replace",
            }
            resp = httpx.post(
                create_url,
                json=body,
                headers=self._auth_headers(),
                timeout=self._timeout,
            )
            if resp.status_code in (200, 201):
                result = resp.json()
            elif resp.status_code == 409:
                # Folder already exists — that's fine
                result = {"name": part, "status": "already_exists"}
            else:
                raise SharePointError(
                    f"Folder creation failed for '{part}' ({resp.status_code}): "
                    f"{resp.text[:300]}"
                )
            current_path = f"{current_path}/{part}" if current_path else part

        return result

    def list_artifacts(self, folder: str) -> list[dict[str, Any]]:
        """List items in a folder."""
        self._ensure_token()
        drive_path = self._drive_path()
        url = (
            f"{self.GRAPH_BASE}{drive_path}"
            f"/root:/{folder}:/children"
        )
        resp = httpx.get(url, headers=self._auth_headers(), timeout=self._timeout)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise SharePointError(
                f"List failed ({resp.status_code}): {resp.text[:300]}"
            )
        items: list[dict[str, Any]] = resp.json().get("value", [])
        return items

    # ── auth helpers ──────────────────────────────────────────────────

    def _ensure_token(self) -> None:
        """Acquire an OAuth2 client-credentials token for MS Graph."""
        if self._token:
            return
        url = self.TOKEN_URL.format(tenant=self._tenant_id)
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        resp = httpx.post(url, data=data, timeout=self._timeout)
        if resp.status_code != 200:
            raise SharePointError(
                f"Token request failed ({resp.status_code}): {resp.text[:300]}"
            )
        self._token = resp.json()["access_token"]

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _drive_path(self) -> str:
        """Build the Graph API path segment for the target drive."""
        if self._drive_id:
            return f"/drives/{self._drive_id}"
        return f"/sites/{self._site_id}/drive"
