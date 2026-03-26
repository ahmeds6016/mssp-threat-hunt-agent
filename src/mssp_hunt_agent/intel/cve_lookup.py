"""CVE lookup — fetch from cvelistV5 GitHub + CISA KEV cross-reference."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CVEDetail(BaseModel):
    """Parsed CVE information."""

    cve_id: str
    description: str = ""
    severity: str = "unknown"  # low | medium | high | critical
    cvss_score: float = 0.0
    attack_vector: str = ""
    techniques: list[str] = Field(default_factory=list)  # ATT&CK technique IDs
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    actively_exploited: bool = False
    cwe_ids: list[str] = Field(default_factory=list)
    source: str = "mock"  # "github" | "mock" | "cache"


# CWE → ATT&CK technique mapping (common mappings)
_CWE_TO_ATTACK: dict[str, list[str]] = {
    "CWE-77": ["T1059"],      # Command Injection
    "CWE-78": ["T1059"],      # OS Command Injection
    "CWE-79": ["T1059.007"],  # XSS → JavaScript
    "CWE-89": ["T1190"],      # SQL Injection
    "CWE-94": ["T1059"],      # Code Injection
    "CWE-119": ["T1203"],     # Buffer Overflow
    "CWE-120": ["T1203"],     # Buffer Overflow (classic)
    "CWE-125": ["T1203"],     # Out-of-bounds Read
    "CWE-190": ["T1203"],     # Integer Overflow
    "CWE-20": ["T1190"],      # Improper Input Validation
    "CWE-200": ["T1005"],     # Information Exposure
    "CWE-22": ["T1083"],      # Path Traversal
    "CWE-250": ["T1068"],     # Unnecessary Privileges
    "CWE-269": ["T1068"],     # Improper Privilege Management
    "CWE-276": ["T1068"],     # Incorrect Default Permissions
    "CWE-287": ["T1078"],     # Improper Authentication
    "CWE-306": ["T1078"],     # Missing Authentication
    "CWE-352": ["T1190"],     # CSRF
    "CWE-416": ["T1203"],     # Use After Free
    "CWE-434": ["T1190"],     # Unrestricted Upload
    "CWE-502": ["T1068"],     # Deserialization
    "CWE-611": ["T1190"],     # XXE
    "CWE-787": ["T1203"],     # Out-of-bounds Write
    "CWE-798": ["T1078.001"], # Hard-coded Credentials
    "CWE-862": ["T1068"],     # Missing Authorization
    "CWE-918": ["T1190"],     # SSRF
}


# Mock CVE database — fallback when GitHub fetch fails
_MOCK_CVE_DB: dict[str, dict[str, Any]] = {
    "CVE-2025-55182": {
        "description": "Remote code execution vulnerability in web application framework allowing unauthenticated attackers to execute arbitrary commands via crafted HTTP requests.",
        "severity": "critical",
        "cvss_score": 9.8,
        "attack_vector": "Network",
        "techniques": ["T1190", "T1059.001"],
        "affected_products": ["WebFramework 4.x", "WebFramework 5.0-5.2"],
        "actively_exploited": True,
    },
    "CVE-2024-21887": {
        "description": "Command injection vulnerability in Ivanti Connect Secure VPN appliance.",
        "severity": "critical",
        "cvss_score": 9.1,
        "attack_vector": "Network",
        "techniques": ["T1190", "T1059.004", "T1078"],
        "affected_products": ["Ivanti Connect Secure", "Ivanti Policy Secure"],
        "actively_exploited": True,
    },
    "CVE-2023-44228": {
        "description": "Privilege escalation via insecure deserialization in enterprise management suite.",
        "severity": "high",
        "cvss_score": 8.1,
        "attack_vector": "Network",
        "techniques": ["T1068", "T1055"],
        "affected_products": ["Enterprise Manager Pro 6.x"],
        "actively_exploited": False,
    },
    "CVE-2024-3400": {
        "description": "OS command injection in Palo Alto Networks PAN-OS GlobalProtect.",
        "severity": "critical",
        "cvss_score": 10.0,
        "attack_vector": "Network",
        "techniques": ["T1190", "T1059.004", "T1105"],
        "affected_products": ["PAN-OS 10.2", "PAN-OS 11.0", "PAN-OS 11.1"],
        "actively_exploited": True,
    },
    "CVE-2025-21298": {
        "description": "Remote code execution in Windows OLE (Object Linking and Embedding).",
        "severity": "critical",
        "cvss_score": 9.8,
        "attack_vector": "Network",
        "techniques": ["T1566.001", "T1203", "T1059.005"],
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2019/2022"],
        "actively_exploited": False,
    },
}


def _build_cve_url(cve_id: str) -> str:
    """Build raw GitHub URL for a CVE from cvelistV5 repo.

    Path format: cves/{year}/{id_prefix}xxx/CVE-{year}-{id}.json
    Example: CVE-2024-3400 → cves/2024/3xxx/CVE-2024-3400.json
    """
    parts = cve_id.split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    year = parts[1]
    num = parts[2]
    # ID prefix: strip last 3 digits, pad with xxx
    prefix = num[:-3] if len(num) > 3 else "0"
    return (
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
        f"cves/{year}/{prefix}xxx/{cve_id}.json"
    )


def _parse_cve_json(cve_id: str, data: dict) -> CVEDetail:
    """Parse CVE JSON v5 format from cvelistV5 repo."""
    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Description
    descriptions = cna.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang", "en") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS score and severity
    cvss_score = 0.0
    severity = "unknown"
    attack_vector = ""
    metrics = cna.get("metrics", [])
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                cvss_data = m[key]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown").lower()
                attack_vector = cvss_data.get("attackVector", "")
                break
        if cvss_score > 0:
            break

    # Affected products
    affected_products = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor", "")
        product = aff.get("product", "")
        if vendor and product:
            affected_products.append(f"{vendor} {product}")
        elif product:
            affected_products.append(product)

    # CWE IDs
    cwe_ids = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_val = desc.get("cweId", "") or desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                cwe_ids.append(cwe_val)

    # Map CWE → ATT&CK techniques
    techniques = []
    for cwe in cwe_ids:
        techniques.extend(_CWE_TO_ATTACK.get(cwe, []))
    techniques = list(dict.fromkeys(techniques))  # dedupe

    # References
    references = []
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append(url)

    return CVEDetail(
        cve_id=cve_id,
        description=description,
        severity=severity if severity != "unknown" else _severity_from_score(cvss_score),
        cvss_score=cvss_score,
        attack_vector=attack_vector,
        techniques=techniques,
        affected_products=affected_products[:10],
        references=references[:10],
        cwe_ids=cwe_ids,
        source="github",
    )


def _severity_from_score(score: float) -> str:
    """Derive severity from CVSS score if not explicitly provided."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


class CVELookup:
    """Look up CVE details from cvelistV5 GitHub repo."""

    def __init__(
        self,
        *,
        use_mock: bool = False,
        cache_dir: str | Path = ".cache/cve",
    ) -> None:
        self._use_mock = use_mock
        self._cache_dir = Path(cache_dir)

    def fetch(self, cve_id: str) -> CVEDetail:
        """Fetch CVE details. Tries: cache → GitHub → mock fallback."""
        cve_id = cve_id.upper().strip()

        if self._use_mock:
            return self._mock_fetch(cve_id)

        # Try cache first
        cached = self._read_cache(cve_id)
        if cached:
            return cached

        # Fetch from GitHub
        try:
            return self._fetch_from_github(cve_id)
        except Exception as exc:
            logger.warning("GitHub CVE fetch failed for %s: %s — using mock", cve_id, exc)
            return self._mock_fetch(cve_id)

    def _fetch_from_github(self, cve_id: str) -> CVEDetail:
        """Fetch CVE JSON from cvelistV5 GitHub repo."""
        import httpx

        url = _build_cve_url(cve_id)
        logger.info("Fetching CVE from %s", url)

        resp = httpx.get(url, timeout=15, follow_redirects=True)
        resp.raise_for_status()

        data = resp.json()
        detail = _parse_cve_json(cve_id, data)

        # Cross-reference with CISA KEV
        detail.actively_exploited = self._check_cisa_kev(cve_id)

        # Cache the result
        self._write_cache(cve_id, data, detail)

        return detail

    def _check_cisa_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog."""
        try:
            from mssp_hunt_agent.intel.cisa_kev import parse_kev_catalog

            import httpx
            resp = httpx.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=10,
            )
            if resp.status_code == 200:
                entries = parse_kev_catalog(resp.json())
                return any(e.cve_id.upper() == cve_id.upper() for e in entries)
        except Exception as exc:
            logger.debug("CISA KEV check failed: %s", exc)
        return False

    def _read_cache(self, cve_id: str) -> CVEDetail | None:
        """Read cached CVE detail."""
        cache_file = self._cache_dir / f"{cve_id}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                return CVEDetail(**data["detail"])
            except Exception:
                pass
        return None

    def _write_cache(self, cve_id: str, raw: dict, detail: CVEDetail) -> None:
        """Cache CVE data."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = self._cache_dir / f"{cve_id}.json"
            cache_file.write_text(
                json.dumps({"raw": raw, "detail": detail.model_dump()}, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("Cache write failed: %s", exc)

    def _mock_fetch(self, cve_id: str) -> CVEDetail:
        """Return mock CVE data."""
        data = _MOCK_CVE_DB.get(cve_id)
        if data:
            return CVEDetail(cve_id=cve_id, source="mock", **data)

        return CVEDetail(
            cve_id=cve_id,
            description=f"Vulnerability {cve_id} — details not available in mock database.",
            severity="medium",
            cvss_score=6.5,
            attack_vector="Network",
            techniques=["T1190"],
            actively_exploited=False,
            source="mock",
        )
