"""Azure Blob Storage state store — durable persistence for requests and campaigns.

Stores request state and campaign state as JSON blobs. Survives deploys,
restarts, and scale-out. Falls back to in-memory-only when no connection
string is configured.

Container layout:
    agent-state/
        requests/{request_id}.json
        campaigns/{campaign_id}.json
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class BlobStateStore:
    """Durable state store backed by Azure Blob Storage.

    When ``connection_string`` is empty, operates in memory-only mode
    (same behavior as before, but with a consistent interface).
    """

    def __init__(self, connection_string: str = "", container_name: str = "agent-state") -> None:
        self._conn_str = connection_string
        self._container_name = container_name
        self._client: Any | None = None  # BlobServiceClient

        # In-memory cache for fast polling (always populated)
        self._requests: dict[str, dict] = {}
        self._campaigns: dict[str, Any] = {}

        if connection_string:
            try:
                from azure.storage.blob import BlobServiceClient
                self._client = BlobServiceClient.from_connection_string(connection_string)
                self._ensure_container()
                logger.info("BlobStateStore initialized — container=%s", container_name)
            except Exception as exc:
                logger.warning("Blob storage init failed, running memory-only: %s", exc)
                self._client = None

    @property
    def blob_enabled(self) -> bool:
        return self._client is not None

    def _ensure_container(self) -> None:
        """Create the container if it doesn't exist."""
        try:
            container = self._client.get_container_client(self._container_name)
            if not container.exists():
                self._client.create_container(self._container_name)
                logger.info("Created blob container: %s", self._container_name)
        except Exception as exc:
            logger.warning("Container check/create failed: %s", exc)

    # ── Request State ────────────────────────────────────────────────

    def save_request(self, request_id: str, data: dict) -> None:
        """Save request state to blob + cache."""
        self._requests[request_id] = data
        self._upload_json(f"requests/{request_id}.json", data)

    def get_request(self, request_id: str) -> dict | None:
        """Get request state. Cache-first, blob fallback."""
        cached = self._requests.get(request_id)
        if cached is not None:
            return cached

        if not self._client:
            return None

        blob_data = self._download_json(f"requests/{request_id}.json")
        if blob_data:
            self._requests[request_id] = blob_data
        return blob_data

    # ── Campaign State ───────────────────────────────────────────────

    def save_campaign(self, campaign_id: str, state: Any) -> None:
        """Save campaign state to blob + cache.

        Accepts either a dict (starting/failed) or a CampaignState object.
        """
        self._campaigns[campaign_id] = state

        if isinstance(state, dict):
            data = state
        elif hasattr(state, "model_dump"):
            data = state.model_dump(mode="json")
            data["_type"] = "CampaignState"
        else:
            data = {"raw": str(state)}

        self._upload_json(f"campaigns/{campaign_id}.json", data)

    def get_campaign(self, campaign_id: str) -> Any | None:
        """Get campaign state. Cache-first, blob fallback with deserialization."""
        cached = self._campaigns.get(campaign_id)
        if cached is not None:
            return cached

        if not self._client:
            return None

        blob_data = self._download_json(f"campaigns/{campaign_id}.json")
        if blob_data is None:
            return None

        # Deserialize CampaignState if it was stored as one
        if blob_data.get("_type") == "CampaignState":
            try:
                from mssp_hunt_agent.hunter.models.campaign import CampaignState
                blob_data.pop("_type", None)
                state = CampaignState.model_validate(blob_data)
                self._campaigns[campaign_id] = state
                return state
            except Exception as exc:
                logger.warning("Failed to deserialize CampaignState %s: %s", campaign_id, exc)

        self._campaigns[campaign_id] = blob_data
        return blob_data

    def list_campaigns(self) -> dict[str, Any]:
        """Return all known campaigns (cache + blob)."""
        if self._client:
            self._reload_campaigns_from_blob()
        return dict(self._campaigns)

    def _reload_campaigns_from_blob(self) -> None:
        """Load campaign IDs from blob that aren't in cache."""
        try:
            container = self._client.get_container_client(self._container_name)
            blobs = container.list_blobs(name_starts_with="campaigns/")
            for blob in blobs:
                cid = blob.name.replace("campaigns/", "").replace(".json", "")
                if cid not in self._campaigns:
                    state = self.get_campaign(cid)
                    if state:
                        self._campaigns[cid] = state
        except Exception as exc:
            logger.warning("Failed to list campaigns from blob: %s", exc)

    # ── Blob I/O ─────────────────────────────────────────────────────

    def _upload_json(self, blob_name: str, data: dict) -> None:
        """Upload a JSON blob (fire-and-forget on failure)."""
        if not self._client:
            return
        try:
            container = self._client.get_container_client(self._container_name)
            blob = container.get_blob_client(blob_name)
            blob.upload_blob(
                json.dumps(data, default=str),
                overwrite=True,
                content_settings=_json_content_settings(),
            )
        except Exception as exc:
            logger.warning("Blob upload failed for %s: %s", blob_name, exc)

    def _download_json(self, blob_name: str) -> dict | None:
        """Download and parse a JSON blob. Returns None if not found."""
        if not self._client:
            return None
        try:
            container = self._client.get_container_client(self._container_name)
            blob = container.get_blob_client(blob_name)
            raw = blob.download_blob().readall()
            return json.loads(raw)
        except Exception:
            return None


def _json_content_settings():
    """Build ContentSettings for JSON blobs."""
    from azure.storage.blob import ContentSettings
    return ContentSettings(content_type="application/json")
