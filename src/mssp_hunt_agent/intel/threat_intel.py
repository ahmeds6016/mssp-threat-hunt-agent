"""Threat intelligence enrichment — aggregates open-source feeds for IOC/IP/CVE enrichment.

Sources (all free, no API keys):
- FIRST EPSS: Exploit probability scoring for CVEs
- Abuse.ch ThreatFox: IOC-to-malware-family mapping
- Abuse.ch Feodo Tracker: Known botnet C2 IPs
- Firehol/IPsum: Aggregated IP reputation from 100+ blocklists
- Shodan InternetDB: Passive IP enrichment (ports, vulns, hostnames)
- TOR exit nodes: Known TOR exit node IPs
- LOLBAS: Living-off-the-land binaries and scripts
- LOLDrivers: Known vulnerable/malicious drivers
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Cache TTL in seconds (refresh every 24 hours)
_CACHE_TTL = 86400
_cache: dict[str, tuple[float, Any]] = {}


def _cached_fetch(key: str, url: str, parse_fn, ttl: int = _CACHE_TTL) -> Any:
    """Fetch and cache a remote resource."""
    now = time.time()
    if key in _cache:
        ts, data = _cache[key]
        if now - ts < ttl:
            return data

    try:
        import httpx
        resp = httpx.get(url, timeout=15, follow_redirects=True)
        resp.raise_for_status()
        data = parse_fn(resp)
        _cache[key] = (now, data)
        return data
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", key, exc)
        # Return stale cache if available
        if key in _cache:
            return _cache[key][1]
        return None


# ── FIRST EPSS — Exploit Prediction Scoring ─────────────────────────

class EPSSScore(BaseModel):
    """EPSS score for a CVE."""
    cve_id: str
    epss: float = 0.0  # Probability of exploitation (0-1)
    percentile: float = 0.0  # How this CVE ranks (0-1)


def get_epss_score(cve_id: str) -> EPSSScore | None:
    """Get EPSS exploit probability score for a CVE.

    Source: https://api.first.org/data/v1/epss
    No API key required.
    """
    try:
        import httpx
        resp = httpx.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        entries = data.get("data", [])
        if entries:
            e = entries[0]
            return EPSSScore(
                cve_id=e.get("cve", cve_id),
                epss=float(e.get("epss", 0)),
                percentile=float(e.get("percentile", 0)),
            )
    except Exception as exc:
        logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)
    return None


# ── Abuse.ch ThreatFox — IOC Database ───────────────────────────────

class ThreatFoxIOC(BaseModel):
    """IOC from ThreatFox database."""
    ioc_type: str = ""  # ip:port, domain, url, md5, sha256
    ioc_value: str = ""
    malware: str = ""  # Malware family name
    confidence: int = 0
    tags: list[str] = Field(default_factory=list)
    first_seen: str = ""
    reference: str = ""


def lookup_ioc_threatfox(ioc_value: str, ioc_type: str = "") -> list[ThreatFoxIOC]:
    """Query ThreatFox API for an IOC (IP, domain, hash, URL).

    Source: https://threatfox-api.abuse.ch/api/v1/
    No API key required. Rate limited.
    """
    try:
        import httpx

        # Determine search type
        if not ioc_type:
            if "." in ioc_value and ":" in ioc_value:
                ioc_type = "ip:port"
            elif len(ioc_value) == 64:
                ioc_type = "hash"
            elif len(ioc_value) == 32:
                ioc_type = "hash"
            elif "://" in ioc_value:
                ioc_type = "url"
            else:
                ioc_type = "host"

        payload = {"query": "search_ioc", "search_term": ioc_value}
        resp = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        results = []
        for entry in (data.get("data") or [])[:10]:
            results.append(ThreatFoxIOC(
                ioc_type=entry.get("ioc_type", ""),
                ioc_value=entry.get("ioc", ""),
                malware=entry.get("malware_printable", ""),
                confidence=entry.get("confidence_level", 0),
                tags=entry.get("tags", []) or [],
                first_seen=entry.get("first_seen", ""),
                reference=entry.get("reference", ""),
            ))
        return results
    except Exception as exc:
        logger.debug("ThreatFox lookup failed for %s: %s", ioc_value, exc)
        return []


# ── Abuse.ch Feodo Tracker — Botnet C2 IPs ─────────────────────────

def get_feodo_c2_ips() -> set[str]:
    """Get known botnet C2 IP addresses from Feodo Tracker.

    Source: https://feodotracker.abuse.ch/downloads/ipblocklist.json
    No API key required.
    """
    def parse(resp):
        data = resp.json()
        return {entry["ip_address"] for entry in data if entry.get("ip_address")}

    result = _cached_fetch("feodo_c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", parse)
    return result or set()


def check_ip_feodo(ip: str) -> dict[str, Any] | None:
    """Check if an IP is a known botnet C2 server."""
    c2_ips = get_feodo_c2_ips()
    if ip in c2_ips:
        return {"ip": ip, "is_c2": True, "source": "feodo_tracker", "malware_families": ["Dridex", "Emotet", "TrickBot", "QakBot"]}
    return None


# ── TOR Exit Nodes ──────────────────────────────────────────────────

def get_tor_exit_nodes() -> set[str]:
    """Get current TOR exit node IPs.

    Source: https://check.torproject.org/torbulkexitlist
    No API key required.
    """
    def parse(resp):
        return {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}

    result = _cached_fetch("tor_exits", "https://check.torproject.org/torbulkexitlist", parse)
    return result or set()


def check_ip_tor(ip: str) -> bool:
    """Check if an IP is a known TOR exit node."""
    return ip in get_tor_exit_nodes()


# ── IPsum — Aggregated IP Reputation ────────────────────────────────

def get_ipsum_blacklist(min_score: int = 3) -> dict[str, int]:
    """Get aggregated IP reputation scores from IPsum.

    Source: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
    Score = number of blocklists an IP appears on (higher = worse).
    No API key required.
    """
    def parse(resp):
        result = {}
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) == 2:
                ip, score = parts[0], int(parts[1])
                if score >= min_score:
                    result[ip] = score
        return result

    result = _cached_fetch("ipsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", parse)
    return result or {}


def check_ip_reputation(ip: str) -> dict[str, Any]:
    """Check an IP against multiple reputation sources.

    Returns aggregated reputation from: IPsum, TOR, Feodo, Shodan.
    """
    result: dict[str, Any] = {
        "ip": ip,
        "is_tor": False,
        "is_c2": False,
        "ipsum_score": 0,
        "ipsum_lists": 0,
        "threat_level": "unknown",
        "sources_flagged": [],
        "shodan": None,
    }

    # TOR check
    if check_ip_tor(ip):
        result["is_tor"] = True
        result["sources_flagged"].append("tor_exit_node")

    # Feodo C2 check
    feodo = check_ip_feodo(ip)
    if feodo:
        result["is_c2"] = True
        result["sources_flagged"].append("feodo_c2")

    # IPsum reputation
    ipsum = get_ipsum_blacklist()
    if ip in ipsum:
        result["ipsum_score"] = ipsum[ip]
        result["ipsum_lists"] = ipsum[ip]
        result["sources_flagged"].append(f"ipsum_score_{ipsum[ip]}")

    # Shodan InternetDB
    shodan = lookup_shodan_internetdb(ip)
    if shodan:
        result["shodan"] = shodan

    # Derive threat level
    flags = len(result["sources_flagged"])
    if result["is_c2"]:
        result["threat_level"] = "critical"
    elif result["is_tor"] or result["ipsum_score"] >= 5:
        result["threat_level"] = "high"
    elif result["ipsum_score"] >= 3 or flags >= 2:
        result["threat_level"] = "medium"
    elif flags >= 1:
        result["threat_level"] = "low"
    else:
        result["threat_level"] = "clean"

    return result


# ── Shodan InternetDB — Passive IP Enrichment ───────────────────────

def lookup_shodan_internetdb(ip: str) -> dict[str, Any] | None:
    """Passive IP enrichment from Shodan InternetDB.

    Source: https://internetdb.shodan.io/{ip}
    No API key required. Returns open ports, vulns, hostnames.
    """
    try:
        import httpx
        resp = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if resp.status_code == 404:
            return None  # IP not in Shodan database
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": data.get("ip", ip),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "tags": data.get("tags", []),
        }
    except Exception as exc:
        logger.debug("Shodan InternetDB lookup failed for %s: %s", ip, exc)
        return None


# ── LOLBAS — Living Off The Land Binaries ───────────────────────────

def get_lolbas_binaries() -> list[dict[str, Any]]:
    """Get LOLBAS (Living Off The Land Binaries) database.

    Source: https://lolbas-project.github.io/api/lolbas.json
    No API key required.
    """
    def parse(resp):
        data = resp.json()
        return [{
            "name": entry.get("Name", ""),
            "description": entry.get("Description", ""),
            "commands": [c.get("Command", "") for c in entry.get("Commands", [])[:3]],
            "mitre": list({c.get("MitreID", "") for c in entry.get("Commands", []) if c.get("MitreID")}),
            "paths": entry.get("Full_Path", [])[:3] if isinstance(entry.get("Full_Path"), list) else [],
            "type": entry.get("Type", ""),
        } for entry in data]

    result = _cached_fetch("lolbas", "https://lolbas-project.github.io/api/lolbas.json", parse)
    return result or []


def check_lolbas(binary_name: str) -> dict[str, Any] | None:
    """Check if a binary is a known LOLBAS entry."""
    binaries = get_lolbas_binaries()
    name_lower = binary_name.lower().replace(".exe", "")
    for b in binaries:
        if b["name"].lower().replace(".exe", "") == name_lower:
            return b
    return None


# ── LOLDrivers — Vulnerable/Malicious Drivers ──────────────────────

def get_loldrivers() -> list[dict[str, Any]]:
    """Get LOLDrivers database.

    Source: https://www.loldrivers.io/api/drivers.json
    No API key required.
    """
    def parse(resp):
        data = resp.json()
        result = []
        for entry in data:
            hashes = []
            for sample in entry.get("KnownVulnerableSamples", [])[:3]:
                if sample.get("SHA256"):
                    hashes.append(sample["SHA256"])
            result.append({
                "name": entry.get("Tags", [""])[0] if entry.get("Tags") else "",
                "category": entry.get("Category", ""),
                "commands": [c.get("Command", "") for c in entry.get("Commands", [])[:2]],
                "hashes": hashes,
                "description": entry.get("Commands", [{}])[0].get("Description", "") if entry.get("Commands") else "",
            })
        return result

    result = _cached_fetch("loldrivers", "https://www.loldrivers.io/api/drivers.json", parse)
    return result or []


# ── Unified Enrichment Functions ────────────────────────────────────

def enrich_cve(cve_id: str) -> dict[str, Any]:
    """Enrich a CVE with EPSS score and exploit availability.

    Returns dict with epss_score, epss_percentile, exploit_probability.
    """
    result: dict[str, Any] = {
        "cve_id": cve_id,
        "epss_score": None,
        "epss_percentile": None,
        "exploit_probability": "unknown",
    }

    epss = get_epss_score(cve_id)
    if epss:
        result["epss_score"] = epss.epss
        result["epss_percentile"] = epss.percentile
        if epss.epss >= 0.5:
            result["exploit_probability"] = "very_high"
        elif epss.epss >= 0.1:
            result["exploit_probability"] = "high"
        elif epss.epss >= 0.01:
            result["exploit_probability"] = "medium"
        else:
            result["exploit_probability"] = "low"

    return result


def enrich_ip(ip: str) -> dict[str, Any]:
    """Full IP enrichment from all sources."""
    return check_ip_reputation(ip)


def enrich_hash(file_hash: str) -> list[ThreatFoxIOC]:
    """Check a file hash against ThreatFox."""
    return lookup_ioc_threatfox(file_hash, "hash")


def enrich_domain(domain: str) -> list[ThreatFoxIOC]:
    """Check a domain against ThreatFox."""
    return lookup_ioc_threatfox(domain, "host")


def get_lolbas_for_technique(technique_id: str) -> list[dict[str, Any]]:
    """Get LOLBAS binaries associated with a MITRE technique."""
    binaries = get_lolbas_binaries()
    return [b for b in binaries if technique_id in b.get("mitre", [])]


# ── Summary for Agent Context ───────────────────────────────────────

def get_available_sources() -> dict[str, str]:
    """Return a summary of available threat intel sources for agent context."""
    return {
        "FIRST EPSS": "Exploit probability scoring (0-1) for any CVE",
        "ThreatFox (Abuse.ch)": "IOC lookup (IP, domain, hash, URL) → malware family attribution",
        "Feodo Tracker (Abuse.ch)": "Known botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot)",
        "IPsum": "Aggregated IP reputation from 100+ blocklists with confidence scoring",
        "TOR Exit Nodes": "Current TOR exit node IPs for anomalous auth detection",
        "Shodan InternetDB": "Passive IP enrichment — open ports, vulns, hostnames (no auth)",
        "LOLBAS": "Living-off-the-land binaries with ATT&CK mapping",
        "LOLDrivers": "Known vulnerable/malicious Windows drivers with hashes",
    }
