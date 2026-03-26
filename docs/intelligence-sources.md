# Intelligence Sources

All sources are free and require no API keys unless noted.

## CVE and Vulnerability

| Source | Data | Integration |
|--------|------|-------------|
| **cvelistV5** (GitHub) | CVE details, CVSS, affected products, CWE | Direct HTTP fetch per CVE ID |
| **CISA KEV** | Actively exploited CVEs with remediation deadlines | JSON catalog download, cross-referenced on every CVE lookup |
| **FIRST EPSS** | Exploit probability score (0-1) for every CVE | REST API, enriches `lookup_cve` results automatically |

## Threat Actor and Technique Intelligence

| Source | Data | Integration |
|--------|------|-------------|
| **MITRE ATT&CK STIX** | 770+ techniques, tactics, groups, software | Local STIX JSON, searched via `search_mitre` tool |
| **Azure-Sentinel GitHub** | Community KQL detection rules | Fetched per technique via `get_sentinel_rule_examples` |

## IOC Reputation

| Source | Data | Integration |
|--------|------|-------------|
| **Abuse.ch ThreatFox** | IOC-to-malware-family mapping (IPs, domains, hashes, URLs) | POST API, queried via `enrich_ioc` tool |
| **Abuse.ch Feodo Tracker** | Known botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot) | JSON blocklist, cached 24h |
| **IPsum** | Aggregated IP reputation from 100+ blocklists with confidence scoring | Text file, cached 24h |
| **TOR Exit Nodes** | Current TOR exit node IP addresses | Text file from torproject.org, cached 24h |
| **Shodan InternetDB** | Passive IP enrichment — open ports, vulns, hostnames | REST API per IP, no auth required |

## Binary and Driver Intelligence

| Source | Data | Integration |
|--------|------|-------------|
| **LOLBAS Project** | 150+ living-off-the-land binaries with ATT&CK mapping and abuse commands | JSON API, queried via `check_lolbas` tool |
| **LOLDrivers** | 400+ known vulnerable/malicious Windows drivers with hashes | JSON API, queried via `check_lolbas` tool |

## How Enrichment Works

When the agent encounters a suspicious indicator in query results:

- **IP address**: `enrich_ioc` checks TOR → Feodo C2 → IPsum → Shodan. Returns aggregated threat level (critical/high/medium/low/clean).
- **Domain or hash**: `enrich_ioc` checks ThreatFox for malware family attribution.
- **CVE ID**: `lookup_cve` fetches from cvelistV5, cross-references CISA KEV, and adds EPSS exploit probability.
- **Binary name**: `check_lolbas` checks LOLBAS database and LOLDrivers for known abuse techniques.

All enrichment is automatic — the system prompt instructs the agent to call these tools whenever it encounters suspicious indicators.
