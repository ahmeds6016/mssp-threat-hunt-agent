# Architecture

## System Overview

```
Analyst (Teams/Copilot Studio)
    |
    v
Power Automate Flow ("Ask Threat Hunt Agent")
    |
    v
POST /api/v1/ask  ──────────────>  202 Accepted + request_id
    |                                       |
    |                              Background thread:
    |                              1. GPT-5.3 classifier (chat vs campaign)
    |                              2. Chat: AgentLoop (1-12 iterations, 12 tools)
    |                                 Campaign: 5-phase orchestrator
    |                              3. Store result in memory
    v
GET /api/v1/ask/{request_id}  ──>  processing | completed | error
    |
    v
Flow returns response to Copilot Studio
```

## Why Async

Copilot Studio's generative orchestrator has a ~40 second timeout for tool calls. Complex queries (CVE lookup + 3 KQL queries + MITRE search) take 30-60 seconds. The async pattern eliminates timeouts entirely:

1. `/ask` returns 202 in under 1 second
2. Background thread does all the work
3. Flow polls every 10 seconds until complete
4. Copilot Studio sees one action call that returns the final result

## Complexity Classification

GPT-5.3 classifies every message before routing:

- **Chat**: single-topic queries, CVE lookups, detection rules, specific hunts, telemetry checks
- **Campaign**: multi-vector investigations, comprehensive assessments, posture reviews

The classifier prompt explicitly defines what goes where. Single-tactic hunts ("hunt for defense evasion") stay in chat. Multi-tactic requests ("credential theft AND lateral movement AND persistence") go to campaign.

## Agent Loop (Chat Path)

The AgentLoop runs GPT-5.3 with tool-calling capability:

1. System prompt loaded with Sentinel table schemas, tool descriptions, behavioral rules
2. User message sent to GPT-5.3
3. GPT-5.3 returns a tool call (e.g., `run_kql_query`)
4. Tool Executor runs the function, returns result
5. GPT-5.3 reasons over result, decides: more tools or final answer
6. Repeat up to 12 iterations

Tools available: `run_kql_query`, `validate_kql`, `lookup_cve`, `search_mitre`, `get_sentinel_rule_examples`, `check_telemetry`, `run_hunt`, `assess_risk`, `check_landscape`, `identify_attack_paths`, `enrich_ioc`, `check_lolbas`

## Campaign Pipeline

See [Campaign Lifecycle](campaign-lifecycle.md) for the full 5-phase breakdown.

## Persistence

SQLite (WAL mode, schema V3) stores:
- Campaign records (ID, status, findings count, timing)
- Findings (classification, severity, MITRE technique, entities, evidence)
- Hypotheses (priority, tables, outcome)
- Lessons (type, description, times_confirmed)

Database location: `/tmp/mssp_hunt_agent.db` on Azure (ephemeral — survives days on B1 with Always On, lost on deploy/restart).

## Data Flow

```
Sentinel workspace
    ├── SecurityEvent, SigninLogs, AuditLogs, DeviceProcessEvents, Syslog, ...
    ├── AttackSimulation_CL (287K Mordor/OTRF events)
    └── (queried via Log Analytics REST API through Service Principal)

External intelligence (all free, no API keys)
    ├── cvelistV5 → CVE details
    ├── CISA KEV → actively exploited CVEs
    ├── FIRST EPSS → exploit probability
    ├── MITRE ATT&CK STIX → techniques/tactics
    ├── Azure-Sentinel GitHub → community KQL rules
    ├── Abuse.ch ThreatFox → malware family IOCs
    ├── Abuse.ch Feodo Tracker → botnet C2 IPs
    ├── IPsum → aggregated IP reputation
    ├── TOR exit nodes → anonymization detection
    ├── Shodan InternetDB → passive IP enrichment
    ├── LOLBAS → living-off-the-land binaries
    └── LOLDrivers → vulnerable/malicious drivers
```

## Fallback

When Azure OpenAI is unavailable, the Agent Controller falls back to a rule-based ReasoningChain. It produces simpler results but keeps the system operational.
