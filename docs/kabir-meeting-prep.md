# Kabir Meeting Prep — Agent Development Practice

## Current Status: MSSP Threat Hunt Agent V7.2

### What's Live
- **100/100 live evaluation** — 98% correct routing, ~85% evidence-grounded, ~97% actionable
- **Copilot Studio** — fully integrated, analysts ask questions in natural language
- **10 autonomous tools** — KQL execution, CVE lookup, MITRE search, risk assessment, attack path analysis, detection rule generation
- **Campaign pipeline** — 5-phase autonomous threat hunts: 10 hypotheses, 30-60 KQL queries, 5-10 findings per campaign
- **Recursive learning** — campaigns learn from prior campaigns (verified)
- **287K attack simulation events** — Mordor/OTRF data in Sentinel for testing
- **892 unit tests passing**, deployed on Azure Function App (B1, Always On)

### Architecture (One Slide)
```
Analyst (Teams) → Copilot Studio → Power Automate Flow → Azure Function /api/v1/ask
                                                              ↓
                                                    GPT-5.3 Classifier
                                                    (chat vs campaign)
                                                              ↓
                                              ┌───────────────┴────────────────┐
                                         Chat (15-45s)                  Campaign (5-15min)
                                         1-3 tool calls                 5 phases, 30-60 queries
                                              ↓                              ↓
                                         Immediate answer              CAMP-ID → poll → report
```

---

## Agenda Item 1: Tools Required to Build Agents

### Development Tools
| Tool | Purpose | Cost |
|------|---------|------|
| **Claude Code** (Anthropic) | Autonomous coding agent — architecture, refactoring, deployment, testing | Anthropic subscription |
| **GitHub Copilot** | Inline IDE autocomplete — faster code writing | GitHub subscription |
| **VS Code** | Primary IDE | Free |
| **Python 3.11** | Backend language | Free |
| **pytest** | Testing framework (892 tests) | Free |
| **Git/GitHub** | Version control | Free tier or GT org |

### Azure Services (already provisioned)
| Service | Purpose | SKU/Cost |
|---------|---------|----------|
| **Azure Function App** | Hosts the agent API | B1 (~$13/mo) |
| **Azure OpenAI** | GPT-5.3-chat (the agent's brain) | S0, pay-per-token |
| **Microsoft Sentinel** | SIEM — all client security telemetry | Pay-per-GB ingested |
| **Log Analytics Workspace** | Stores Sentinel data + custom tables | Included with Sentinel |

### Microsoft Platform (no additional cost)
| Tool | Purpose |
|------|---------|
| **Copilot Studio** | Agent frontend — natural language chat for analysts |
| **Power Automate** | Flow for async polling pattern |
| **Custom Connector** | Bridges Copilot Studio to Azure Function API |
| **Teams** | Delivery channel (where analysts work) |

### Data Sources (free, no API keys)
| Source | What it provides |
|--------|-----------------|
| **cvelistV5** (NVD GitHub) | CVE database — CVSS scores, affected products |
| **MITRE ATT&CK STIX** | Tactics, techniques, threat actor profiles |
| **Azure-Sentinel GitHub** | Community KQL detection rules |
| **Mordor/OTRF** | Attack simulation datasets for testing |

---

## Agenda Item 2: Team Collaboration

### Recommended Setup
1. **GitHub Repository** — Central codebase, branch-per-feature, PR reviews
2. **`.github/copilot-instructions.md`** — Already created. Any developer opening the repo in VS Code + Copilot Chat gets full project context automatically
3. **Shared Azure Subscription** — Trevor, Herb, Deely need at minimum Reader on the resource group, Contributor for active development
4. **Working Session** — Kabir requested recording of custom table ingestion setup. Guide ready: `docs/custom-table-ingestion-guide.md`

### Team Roles
| Person | Role | Access Needed |
|--------|------|---------------|
| **Ahmed** | Lead developer, architecture, deployment | Current access (Contributor + Kudu) |
| **Trevor** | Sentinel engineering, KQL, detection rules | Contributor on RG, Sentinel Contributor |
| **Herb** | Sentinel engineering, data connectors | Same as Trevor |
| **Deely** | Optional — review, testing | Reader on RG minimum |
| **Kabir** | Oversight, approvals, strategic direction | Owner (current) |

### Knowledge Transfer Assets
- `docs/agent-overview-v7.2.md` — Architecture and capability overview
- `docs/custom-table-ingestion-guide.md` — Step-by-step for custom table setup
- `docs/how-it-works-v7.2.md` — Detailed step-by-step flow explainer
- `docs/system-breakdown-v7.2.md` — Full technical breakdown
- `.github/copilot-instructions.md` — Auto-loaded context for GitHub Copilot Chat

---

## Agenda Item 3: Weekly Recurring Meetings

### Suggested Format (30 min)
1. **Status update** (5 min) — what shipped since last meeting
2. **Demo** (10 min) — live Copilot Studio walkthrough of new capabilities
3. **Blockers** (5 min) — what's stuck, who can unblock
4. **Next sprint** (10 min) — priorities for the coming week

### Current Blockers
| Blocker | Owner | Impact |
|---------|-------|--------|
| **Monitoring Metrics Publisher role** | Kabir | Blocks DCR-based ingestion (legacy API workaround in place) |
| **Teams channel deployment** | Ahmed | Copilot Studio works in test pane, Teams deployment pending |

### Next Priorities
1. **Teams channel deployment** — put the agent where analysts actually work
2. **Permanent persistence** — swap SQLite `/tmp/` for Azure Blob or CosmosDB
3. **Multi-tenant support** — serve multiple MSSP clients from one agent
4. **Microsoft marketplace publication** — agent-as-a-service for other MSSPs
5. **Working session recording** — custom table ingestion for Trevor, Herb, Deely
