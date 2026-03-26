"""Azure Sentinel community rules client — fetch detection rules from GitHub."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# GitHub API to search for YAML detection rules by technique ID
_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_GITHUB_RAW_BASE = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/"


class SentinelRule(BaseModel):
    """Parsed Azure Sentinel community detection rule."""

    name: str = ""
    description: str = ""
    severity: str = ""
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    kql_query: str = ""
    data_connectors: list[str] = Field(default_factory=list)
    query_frequency: str = ""
    query_period: str = ""
    source_url: str = ""


def _parse_yaml_rule(content: str, source_url: str = "") -> SentinelRule | None:
    """Parse a Sentinel YAML detection rule. Uses simple parsing to avoid PyYAML dependency."""
    lines = content.split("\n")
    fields: dict[str, Any] = {}
    current_key = ""
    current_list: list[str] = []
    in_query = False
    query_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Handle multi-line query block
        if in_query:
            if line and not line[0].isspace() and ":" in line and not line.startswith(" "):
                in_query = False
                fields["query"] = "\n".join(query_lines).strip()
            else:
                query_lines.append(line.lstrip())
                continue

        # Key: value pairs
        if ":" in stripped and not stripped.startswith("-"):
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip("'\"")

            if key == "query":
                in_query = True
                query_lines = []
                if value:
                    query_lines.append(value)
                continue

            if key in ("tactics", "relevantTechniques", "requiredDataConnectors"):
                current_key = key
                current_list = []
                fields[key] = current_list
                if value and value.startswith("["):
                    # Inline list
                    items = value.strip("[]").split(",")
                    fields[key] = [i.strip().strip("'\"") for i in items if i.strip()]
                    current_key = ""
                continue

            fields[key] = value
            current_key = ""

        elif stripped.startswith("- ") and current_key:
            item = stripped[2:].strip().strip("'\"")
            current_list.append(item)

    # Finalize query if still in progress
    if in_query and query_lines:
        fields["query"] = "\n".join(query_lines).strip()

    name = fields.get("name", "")
    kql = fields.get("query", "")
    if not name and not kql:
        return None

    return SentinelRule(
        name=name,
        description=fields.get("description", "")[:500],
        severity=fields.get("severity", "").lower(),
        tactics=fields.get("tactics", []),
        techniques=fields.get("relevantTechniques", []),
        kql_query=kql,
        data_connectors=[str(d) for d in fields.get("requiredDataConnectors", [])],
        query_frequency=fields.get("queryFrequency", ""),
        query_period=fields.get("queryPeriod", ""),
        source_url=source_url,
    )


class SentinelRulesClient:
    """Fetch community detection rules from Azure-Sentinel GitHub."""

    def __init__(self, cache_dir: str | Path = ".cache/sentinel_rules") -> None:
        self._cache_dir = Path(cache_dir)
        self._index: dict[str, list[str]] | None = None  # technique_id → [yaml_urls]

    def get_rules_for_technique(
        self, technique_id: str, max_rules: int = 3
    ) -> list[SentinelRule]:
        """Fetch community detection rules for a MITRE technique."""
        technique_id = technique_id.upper()
        rules: list[SentinelRule] = []

        # Try cache first
        cached = self._read_cached_rules(technique_id)
        if cached:
            return cached[:max_rules]

        # Search GitHub for rules mentioning this technique
        try:
            urls = self._search_github(technique_id)
            for url in urls[:max_rules]:
                rule = self._fetch_and_parse_rule(url)
                if rule:
                    rules.append(rule)
        except Exception as exc:
            logger.warning("Sentinel rules fetch failed for %s: %s", technique_id, exc)

        # Cache results
        if rules:
            self._cache_rules(technique_id, rules)

        return rules

    def search_rules(self, keyword: str, max_rules: int = 5) -> list[SentinelRule]:
        """Search community rules by keyword."""
        try:
            urls = self._search_github(keyword)
            rules = []
            for url in urls[:max_rules]:
                rule = self._fetch_and_parse_rule(url)
                if rule:
                    rules.append(rule)
            return rules
        except Exception as exc:
            logger.warning("Sentinel rules search failed for '%s': %s", keyword, exc)
            return []

    def _search_github(self, query: str) -> list[str]:
        """Search Azure-Sentinel GitHub for YAML files matching query."""
        import httpx

        # Search in the Solutions directory for analytic rules
        params = {
            "q": f"{query} repo:Azure/Azure-Sentinel path:Analytic extension:yaml",
            "per_page": 10,
        }

        resp = httpx.get(
            _GITHUB_SEARCH_URL,
            params=params,
            timeout=15,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        resp.raise_for_status()

        data = resp.json()
        urls = []
        for item in data.get("items", []):
            path = item.get("path", "")
            if path.endswith(".yaml") and "Analytic" in path:
                raw_url = f"{_GITHUB_RAW_BASE}{path}"
                urls.append(raw_url)

        return urls

    def _fetch_and_parse_rule(self, url: str) -> SentinelRule | None:
        """Fetch a YAML rule file and parse it."""
        # Check file cache
        cache_key = url.replace("/", "_").replace(":", "")[-100:]
        cache_file = self._cache_dir / "rules" / f"{cache_key}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                return SentinelRule(**data)
            except Exception:
                pass

        # Fetch from GitHub
        try:
            import httpx
            resp = httpx.get(url, timeout=10, follow_redirects=True)
            resp.raise_for_status()
            rule = _parse_yaml_rule(resp.text, source_url=url)

            # Cache
            if rule:
                try:
                    cache_file.parent.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(
                        json.dumps(rule.model_dump()),
                        encoding="utf-8",
                    )
                except Exception:
                    pass

            return rule
        except Exception as exc:
            logger.debug("Failed to fetch rule from %s: %s", url, exc)
            return None

    def _read_cached_rules(self, technique_id: str) -> list[SentinelRule] | None:
        """Read cached rules for a technique."""
        cache_file = self._cache_dir / "by_technique" / f"{technique_id}.json"
        if not cache_file.exists():
            return None

        # Check freshness (24 hours)
        age = time.time() - cache_file.stat().st_mtime
        if age > 86400:
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return [SentinelRule(**r) for r in data]
        except Exception:
            return None

    def _cache_rules(self, technique_id: str, rules: list[SentinelRule]) -> None:
        """Cache rules for a technique."""
        try:
            cache_dir = self._cache_dir / "by_technique"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / f"{technique_id}.json"
            cache_file.write_text(
                json.dumps([r.model_dump() for r in rules]),
                encoding="utf-8",
            )
        except Exception:
            pass
