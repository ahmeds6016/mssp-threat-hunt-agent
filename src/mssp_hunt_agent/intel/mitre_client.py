"""MITRE ATT&CK client — fetch and parse enterprise techniques from STIX data."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


class MITRETechnique(BaseModel):
    """Parsed ATT&CK technique."""

    technique_id: str
    name: str
    description: str = ""
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: str = ""
    url: str = ""
    detection: str = ""


def _parse_stix_bundle(bundle: dict) -> list[MITRETechnique]:
    """Parse STIX 2.1 bundle into MITRETechnique list."""
    objects = bundle.get("objects", [])

    # Build relationship map: subtechnique → parent
    subtechnique_parents: dict[str, str] = {}
    technique_ids_by_stix_id: dict[str, str] = {}

    # First pass: collect technique STIX IDs
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_ids_by_stix_id[obj["id"]] = ref["external_id"]
                    break

    # Second pass: collect subtechnique relationships
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "subtechnique-of"
        ):
            child_id = technique_ids_by_stix_id.get(obj.get("source_ref", ""), "")
            parent_id = technique_ids_by_stix_id.get(obj.get("target_ref", ""), "")
            if child_id and parent_id:
                subtechnique_parents[child_id] = parent_id

    # Third pass: parse techniques
    techniques: list[MITRETechnique] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # Tactics from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        # Data sources
        data_sources = obj.get("x_mitre_data_sources", [])

        # Detection guidance
        detection = obj.get("x_mitre_detection", "")

        is_sub = obj.get("x_mitre_is_subtechnique", False)

        techniques.append(MITRETechnique(
            technique_id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", "")[:500],  # Truncate long descriptions
            tactics=tactics,
            platforms=obj.get("x_mitre_platforms", []),
            data_sources=data_sources,
            is_subtechnique=is_sub,
            parent_id=subtechnique_parents.get(technique_id, ""),
            url=url,
            detection=detection[:300] if detection else "",
        ))

    return techniques


class MITREClient:
    """Fetch and query MITRE ATT&CK enterprise techniques."""

    def __init__(self, cache_dir: str | Path = ".cache/mitre", cache_ttl_days: int = 7) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_ttl_seconds = cache_ttl_days * 86400
        self._techniques: list[MITRETechnique] = []
        self._index: dict[str, MITRETechnique] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Load technique data from cache or GitHub."""
        if self._loaded:
            return

        # Try cache
        cached = self._read_cache()
        if cached:
            self._techniques = cached
            self._build_index()
            self._loaded = True
            return

        # Fetch from GitHub
        try:
            self._fetch_and_parse()
        except Exception as exc:
            logger.warning("MITRE ATT&CK fetch failed: %s — using bundled fallback", exc)
            self._load_fallback()

        self._loaded = True

    def _fetch_and_parse(self) -> None:
        """Download and parse the STIX bundle."""
        import httpx

        logger.info("Fetching MITRE ATT&CK data from GitHub...")
        resp = httpx.get(_STIX_URL, timeout=60, follow_redirects=True)
        resp.raise_for_status()

        bundle = resp.json()
        self._techniques = _parse_stix_bundle(bundle)
        self._build_index()
        self._write_cache()
        logger.info("Loaded %d ATT&CK techniques", len(self._techniques))

    def _build_index(self) -> None:
        """Build lookup index by technique ID."""
        self._index = {t.technique_id: t for t in self._techniques}

    def get_technique(self, technique_id: str) -> MITRETechnique | None:
        """Get a technique by ID (e.g., T1059.001)."""
        self._ensure_loaded()
        return self._index.get(technique_id.upper())

    def search_techniques(self, keyword: str, max_results: int = 20) -> list[MITRETechnique]:
        """Search techniques by keyword in name, description, or tactics."""
        self._ensure_loaded()
        keyword_lower = keyword.lower()
        results = []
        for t in self._techniques:
            if (
                keyword_lower in t.name.lower()
                or keyword_lower in t.description.lower()
                or keyword_lower in t.technique_id.lower()
                or any(keyword_lower in tac for tac in t.tactics)
            ):
                results.append(t)
                if len(results) >= max_results:
                    break
        return results

    def get_techniques_for_tactic(self, tactic: str) -> list[MITRETechnique]:
        """Get all techniques for a tactic (e.g., 'persistence')."""
        self._ensure_loaded()
        tactic_lower = tactic.lower().replace(" ", "-")
        return [t for t in self._techniques if tactic_lower in t.tactics]

    def get_subtechniques(self, parent_id: str) -> list[MITRETechnique]:
        """Get subtechniques of a parent technique."""
        self._ensure_loaded()
        parent_upper = parent_id.upper()
        return [t for t in self._techniques if t.parent_id == parent_upper]

    def get_all_technique_ids(self) -> list[str]:
        """Return all technique IDs."""
        self._ensure_loaded()
        return [t.technique_id for t in self._techniques]

    def technique_count(self) -> int:
        """Return total number of techniques."""
        self._ensure_loaded()
        return len(self._techniques)

    # ── Caching ──────────────────────────────────────────────────

    def _read_cache(self) -> list[MITRETechnique] | None:
        """Read cached techniques if fresh enough."""
        cache_file = self._cache_dir / "techniques.json"
        if not cache_file.exists():
            return None

        age = time.time() - cache_file.stat().st_mtime
        if age > self._cache_ttl_seconds:
            logger.info("MITRE cache expired (%.0f days old)", age / 86400)
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return [MITRETechnique(**t) for t in data]
        except Exception as exc:
            logger.debug("Cache read failed: %s", exc)
            return None

    def _write_cache(self) -> None:
        """Write techniques to cache."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = self._cache_dir / "techniques.json"
            cache_file.write_text(
                json.dumps([t.model_dump() for t in self._techniques]),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("Cache write failed: %s", exc)

    def _load_fallback(self) -> None:
        """Load minimal bundled technique data when GitHub is unreachable."""
        # Use the 42 techniques from the existing detection templates as fallback
        from mssp_hunt_agent.detection.generator import list_available_techniques

        fallback_ids = list_available_techniques()
        self._techniques = [
            MITRETechnique(
                technique_id=tid,
                name=f"Technique {tid}",
                description="Fallback — full details unavailable (GitHub unreachable)",
                tactics=[],
                platforms=["Windows"],
            )
            for tid in fallback_ids
        ]
        self._build_index()
        logger.info("Loaded %d fallback techniques", len(self._techniques))
