"""Index storage — persist and load EnvironmentIndex to JSON + SQLite."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mssp_hunt_agent.hunter.models.environment import EnvironmentIndex

logger = logging.getLogger(__name__)


class IndexStore:
    """Persist EnvironmentIndex to disk as JSON.

    On Azure Functions, use /tmp/ as the base directory.
    Locally, use .cache/index/ or a configurable path.
    """

    def __init__(self, base_dir: str = "/tmp/hunt_index") -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    def _index_path(self, client_id: str) -> Path:
        return self._base / f"{client_id}.json"

    def save(self, index: EnvironmentIndex) -> str:
        """Save index to JSON file. Returns the file path."""
        path = self._index_path(index.metadata.client_id)
        data = index.model_dump(mode="json")
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Index saved: %s (%d bytes)", path, path.stat().st_size)
        return str(path)

    def load(self, client_id: str) -> Optional[EnvironmentIndex]:
        """Load index from JSON file. Returns None if not found."""
        path = self._index_path(client_id)
        if not path.exists():
            logger.info("No index found for client %s", client_id)
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            index = EnvironmentIndex.model_validate(data)
            logger.info("Index loaded for client %s (v%d)", client_id, index.metadata.index_version)
            return index
        except Exception as exc:
            logger.error("Failed to load index for %s: %s", client_id, exc)
            return None

    def exists(self, client_id: str) -> bool:
        return self._index_path(client_id).exists()

    def delete(self, client_id: str) -> bool:
        path = self._index_path(client_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def needs_refresh(self, client_id: str, layer: str, max_age_hours: float) -> bool:
        """Check if a layer needs refreshing based on age.

        Parameters
        ----------
        layer: "static" | "semi_static" | "dynamic"
        max_age_hours: Maximum acceptable age in hours.
        """
        index = self.load(client_id)
        if not index:
            return True

        field_map = {
            "static": index.metadata.static_refreshed_at,
            "semi_static": index.metadata.semi_static_refreshed_at,
            "dynamic": index.metadata.dynamic_refreshed_at,
        }
        refreshed_at = field_map.get(layer, "")
        if not refreshed_at:
            return True

        try:
            last = datetime.fromisoformat(refreshed_at)
            age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
            return age_hours > max_age_hours
        except (ValueError, TypeError):
            return True

    def list_clients(self) -> list[str]:
        """List all client IDs that have stored indexes."""
        return [p.stem for p in self._base.glob("*.json")]
