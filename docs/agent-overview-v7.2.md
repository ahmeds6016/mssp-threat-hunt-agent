# MSSP Threat Hunt Agent — V7.2 Overview

**Built by**: Ahmed Shiekhaden, Global Technology
**Platform**: Microsoft Sentinel + Azure OpenAI (GPT-5.3) + Copilot Studio
**Status**: Live — deployed to Azure Function App, integrated with Copilot Studio

---

## What It Does

An autonomous threat hunting agent that connects directly to a client's Microsoft Sentinel workspace. Analysts ask questions in natural language — the agent queries real data, analyzes results, and delivers grounded, evidence-backed answers.

**Two modes, one entry point:**

| Mode | Response Time | What It Does |
|------|--------------|--------------|
| **Chat** | 15-60 seconds | CVE lookups, sign-in analysis, detection rule generation, MITRE mapping, risk assessments, IOC sweeps |
| **Campaign** | 5-15 minutes | Full autonomous threat hunts — generates hypotheses, runs 50-200 KQL queries, classifies findings, delivers a report |

The analyst doesn't choose the mode. GPT-5.3 classifies complexity automatically and routes internally.

---

## Architecture

```
Analyst → Copilot Studio → Power Automate Flow → Azure Function App
                                                      ↓
                                              GPT-5.3 Classifier
                                              ↙            ↘
                                          Chat              Campaign
                                     (Agent Loop)      (5-Phase Orchestrator)
                                      1-5 tool calls    50-200 KQL queries
                                      15-60 seconds     5-15 minutes
                                          ↓                   ↓
                                     Direct answer      Full hunt report
```

**Key components:**
- **Azure Function App** (`mssphuntagent-fn.azurewebsites.net`) — async API, returns results via polling
- **GPT-5.3-chat** (Azure OpenAI, eastus2) — reasoning engine, tool selection, analysis synthesis
- **10 agent tools** — KQL execution, CVE lookup, MITRE ATT&CK, detection rules, risk assessment, telemetry checks
- **Copilot Studio** — conversational interface with generative orchestration
- **Power Automate Flow** — handles async submit + poll pattern (eliminates timeout issues)

---

## What It Can Answer (Tested Examples)

| Question | What the Agent Does |
|----------|-------------------|
| "Are we vulnerable to CVE-2026-21262?" | Looks up CVE details, queries Sentinel for affected technology (SQL Server processes), gives verdict with evidence |
| "List all users who signed in the past 24 hours" | Runs KQL against SigninLogs, returns users with counts and timestamps |
| "Review sign-in patterns for ahmed for the past month" | Analyzes 30 days of sign-ins, identifies anomalies (failure spikes, volume spikes), assesses risk |
| "What MITRE techniques cover lateral movement?" | Returns full technique list with sub-techniques from ATT&CK STIX data |
| "Write a KQL detection rule for impossible travel" | Generates production-ready KQL with MITRE mapping, severity, schedule, and tuning tips |
| "Stryker suffered a mass wipe attack — what detection rules do we have for destructive operations?" | Queries AuditLogs for deletion activity, identifies 5 detection gaps, generates 5 KQL rules to deploy |
| "Run a full threat hunt focused on ransomware" | Launches autonomous campaign — indexes environment, generates hypotheses, executes queries, classifies findings, delivers report |

---

## Intelligence Features

- **Environment-aware**: Profiles the client's Sentinel workspace — tables, columns, row counts, admin users, risky users, critical assets, MITRE coverage gaps
- **Evidence-grounded**: Every finding backed by specific KQL queries, event counts, timestamps, and affected entities
- **Learning engine**: Extracts lessons from campaign outcomes (true positives, false positive patterns, effective queries) and feeds them into future hunts
- **Real data sources**: CVE data from cvelistV5 GitHub, MITRE ATT&CK from STIX, detection rules from Azure-Sentinel community — no paid API keys required

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Python 3.11, Azure Functions v4 |
| LLM | Azure OpenAI GPT-5.3-chat |
| SIEM | Microsoft Sentinel (Log Analytics API) |
| Frontend | Microsoft Copilot Studio |
| Orchestration | Power Automate (async polling Flow) |
| Persistence | SQLite (WAL mode, schema V3) |
| Models | Pydantic v2 |
| Tests | 873 passing (pytest) |
| Deployment | Kudu zipdeploy |

---

## Deployment Status

- **Azure Function App**: Live at `mssphuntagent-fn.azurewebsites.net`
- **Copilot Studio Agent**: Live with generative orchestration
- **Custom Connector**: Swagger 2.0, 5 operations
- **Power Automate Flow**: "Ask Threat Hunt Agent" — submit + poll loop

---

## Open Items

1. **Test log ingestion** — Need sample logs in Sentinel (Purple Stratus sandbox) for diverse threat scenarios. Estimated cost: $3-14 for 1-5 GB. Needs approval.
2. **Report export** — PDF/DOC automated export via Power Automate (not yet started)
3. **Broader team testing** — Process for other analysts to test the agent
4. **Agent marketplace publishing** — Microsoft Partner Center submission (future)

---

## Codebase

- **130+ Python files, 15k+ LOC**
- **873 tests** — all passing, zero real API calls in tests
- **6 YAML playbooks** — identity, endpoint, network, cloud, ransomware, BEC
- **8 Jinja2 report templates**
- Source: `mssp-hunt-agent/src/mssp_hunt_agent/`
