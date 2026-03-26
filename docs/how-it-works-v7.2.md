# How It Works — Step by Step Explainer (V7.2)

## The Core Pattern

Every analyst message follows one path. The agent decides internally whether it's a quick query or a deep investigation. The analyst never chooses — they just ask.

```
Analyst asks a question
    → Copilot Studio calls Power Automate Flow
        → Flow POST /api/v1/ask (returns 202 in <1 second)
            → Background thread: GPT-5.3 classifies complexity
                → Chat path (15-45 seconds) OR Campaign path (5-15 minutes)
        → Flow polls GET /api/v1/ask/{request_id} every 10 seconds
        → Flow returns final response to Copilot Studio
    → Analyst sees the answer
```

---

## Flow 1: Quick Query (Chat Path)

**Examples**: "Are we vulnerable to CVE-2024-3400?", "List users who signed in today", "Write a detection rule for brute force"

### Step 1 — Analyst types a message in Teams / Copilot Studio

The analyst opens the agent in Teams or Copilot Studio and types a plain-English question. No KQL, no MITRE technique IDs, no Sentinel table names required. Just ask like you'd ask a colleague.

### Step 2 — Copilot Studio calls the Power Automate Flow

Copilot Studio's generative orchestrator reads the analyst's message and decides which action to call. For all security questions, it calls the **"Ask Threat Hunt Agent"** Flow — a single action that handles everything.

**Why a Flow instead of calling the API directly?** Copilot Studio has a ~40-second timeout on connector calls. Complex queries take 30-60 seconds. The Flow handles the async submit-and-poll pattern so Copilot Studio never times out.

### Step 3 — Flow submits the question to the Azure Function

The Flow makes a `POST /api/v1/ask` call with `{"message": "..."}`. The Azure Function returns **immediately** (< 1 second) with a `202 Accepted` and a `request_id`:

```json
{"request_id": "REQ-d3380419", "status": "processing"}
```

A background thread starts processing the request.

### Step 4 — GPT-5.3 classifies complexity

The first thing the background thread does is call GPT-5.3 with a classification prompt. In ~2-3 seconds, it decides:

- **"chat"** — single-topic query, 1-3 tool calls needed, respond in seconds
- **"campaign"** — multi-vector investigation, 30-60 queries needed, run the 5-phase pipeline

For this flow, it returns "chat". The agent loop begins.

**Why GPT-5.3 instead of keyword matching?** GPT-5.3 understands nuance. "Check for brute force" is chat. "Hunt for credential theft, lateral movement, and persistence across all data sources" is campaign. A keyword matcher can't reliably distinguish these.

### Step 5 — Agent Controller initializes the Agent Loop

The Agent Controller sets up the loop with:
- The analyst's message
- The **system prompt** (contains all Sentinel table schemas, AttackSimulation_CL column names, tool descriptions, and behavioral rules)
- The **10 available tools** the agent can call
- Conversation history (if any)

Everything is sent to GPT-5.3-chat via Azure OpenAI.

### Step 6 — GPT-5.3 picks a tool and calls it

GPT-5.3 doesn't just respond with text. It has **tool-calling capability** — it looks at the question and decides which tool to run:

```
call: lookup_cve
arguments: {"cve_id": "CVE-2024-3400"}
```

The Tool Executor runs the actual function and sends the result back to GPT-5.3.

**This is what makes it an agent, not a chatbot.** It actively runs queries, looks up data, and reasons over real results.

### Step 7 — Iterative reasoning loop

GPT-5.3 reviews the tool result and decides: do I have enough information to answer, or do I need more?

**Example for "Are we vulnerable to CVE-2024-3400?":**

| Iteration | What GPT-5.3 does | Tool called | Result |
|-----------|-------------------|-------------|--------|
| 1 | Look up the CVE details | `lookup_cve("CVE-2024-3400")` | Critical RCE in Palo Alto PAN-OS, CVSS 10.0 |
| 2 | Check if we have Palo Alto telemetry | `run_kql_query("Syslog \| where SyslogMessage has 'PAN-OS'")` | 0 events |
| 3 | Double-check with firewall logs | `run_kql_query("CommonSecurityLog \| where DeviceVendor has 'Palo'")` | 0 events |
| 4 | Now I have enough — write the response | (no tool call) | Final answer |

The loop runs up to 12 iterations maximum. Most queries complete in 2-4.

### Step 8 — Tool calls hit real data sources

Each tool connects to a real data source:

| Tool | Data Source | What comes back |
|------|-----------|-----------------|
| `run_kql_query` | Microsoft Sentinel (Log Analytics REST API) | Actual query results from client telemetry |
| `validate_kql` | KQL syntax parser | Syntax validation before running |
| `lookup_cve` | cvelistV5 on GitHub (official NVD) | CVE details, CVSS score, affected products |
| `search_mitre` | MITRE ATT&CK STIX data (local) | Techniques, tactics, sub-techniques |
| `check_telemetry` | Sentinel | What log tables exist, row counts, health |
| `get_sentinel_rule_examples` | Azure-Sentinel GitHub | Community KQL detection rules |
| `assess_risk` | Internal risk engine | Attack path coverage, risk scores |
| `identify_attack_paths` | Internal analysis | Likely attack chains based on environment |
| `check_landscape` | Threat intelligence | Current threat landscape for industry |
| `run_hunt` | Sentinel (multi-query) | Full single-topic hunt results |

**New in V7.2**: The agent also queries **`AttackSimulation_CL`** — a custom table containing 287,513 curated attack simulation events (Mordor/OTRF datasets) mapped to MITRE ATT&CK. When hunting for threats, the agent checks both real telemetry AND simulation data.

### Step 9 — GPT-5.3 writes the final response

Once GPT-5.3 has all the data, it synthesizes the answer:
- Correlates multiple data points
- Identifies patterns and anomalies
- Assesses severity and risk
- Maps to MITRE ATT&CK techniques
- Writes specific, actionable recommendations
- Formats in professional security analyst language

The analyst gets a synthesized, reasoned answer — not raw query results they have to interpret.

### Step 10 — Flow polls and returns the response

While all this was happening, the Flow has been polling `GET /api/v1/ask/{request_id}` every 10 seconds. When the status changes from "processing" to "completed", the Flow returns the response to Copilot Studio, which displays it to the analyst.

**Total round trip: 15-45 seconds** depending on query complexity.

---

## Flow 2: Campaign (Autonomous Deep Hunt)

**Examples**: "Run a comprehensive threat hunt across credential theft and lateral movement", "Do a full security posture review", "What threats are we missing?"

### Step 1 — Same entry point

The analyst types a message. Copilot Studio calls the same Flow. The Flow calls the same `/api/v1/ask` endpoint. **The analyst doesn't know or care whether it'll be a chat or campaign.**

### Step 2 — GPT-5.3 classifies as "campaign"

The classifier sees multi-vector scope ("credential theft AND lateral movement"), broad language ("comprehensive", "full", "all threats"), or multiple ATT&CK tactics — and returns `route: "campaign"`.

### Step 3 — Campaign starts, analyst gets immediate acknowledgment

The `/ask` endpoint spins up a campaign thread and immediately stores a result with:
- `route: "campaign"`
- `campaign_id: "CAMP-e807eadb"`
- A message explaining what's happening and how to check status

The Flow picks this up and Copilot Studio shows the analyst the campaign ID within seconds.

### Step 4 — Phase 1: INDEX_REFRESH

Before hunting, the agent needs to understand the environment. It runs ~40-60 KQL queries to discover:

| What it discovers | Example |
|-------------------|---------|
| Active tables | SecurityEvent (14K events/7d), SigninLogs (178 events/7d), AttackSimulation_CL (287K events/30d) |
| All users | 135 users, 15 admins, MFA at 1.5% |
| All assets | 3 monitored devices, OS breakdown, EDR status |
| Network context | Known IPs, geographic locations (US, India) |
| Security posture | 2,321 open incidents, threat intelligence indicators |
| MITRE coverage gaps | Techniques with no detection coverage |

This becomes the **environment index** — the "map" that guides all subsequent phases.

**New in V7.2**: The index uses `rich_summary()` — a detailed JSON representation with specific admin UPNs, risky users, critical assets, MITRE gap technique IDs, and sample values per table. This gives GPT-5.3 concrete data to reference in hypotheses.

**Caching**: If a campaign ran recently, the index is cached and reused. Campaign 2 loaded the cached index from Campaign 1 in our testing.

### Step 5 — Phase 2: HYPOTHESIZE

GPT-5.3 generates **10 prioritized threat hunt hypotheses**, each grounded in the actual environment:

```
HYPOTHESIS 1 — Compromised Azure AD Admin Using Valid Cloud Credentials
Focus: Credential Theft / Privilege Escalation
Description: Attackers may have obtained credentials for admin accounts without MFA
  (Trevor.Cutshall, josue.berra, Felipe.Vilalta, Hannah.VanTran) and are using them
  to authenticate to Azure services.
Required Tables: SigninLogs, AuditLogs, MicrosoftGraphActivityLogs
MITRE: T1078.004 — Valid Accounts: Cloud Accounts
Priority Score: 9.2 (likelihood × feasibility × impact)
```

Every hypothesis references **specific table names, specific user accounts, specific MITRE technique IDs** from the environment index. Not generic templates.

**New in V7.2 — Recursive Learning**: If prior campaigns exist, the learning engine injects context:
- "Previous campaign CAMP-f4d3e5e7 found 7 findings including legacy auth bypass via svc-mailrelay"
- "Known false positive: CA bypass alerts are ResultType 53003 enforcement, not real bypasses"
- "Effective query pattern: SigninLogs | where MFARequirement == 'Not required' for admin hunting"

Campaign 2 uses Campaign 1's lessons to generate smarter hypotheses and avoid repeating false positives.

### Step 6 — Phase 3: EXECUTE

For each hypothesis, GPT-5.3 runs a **tool-calling loop** — the same mechanism as chat, but with stricter rules:

**Mandatory rules enforced by the execute prompt:**
- Minimum 3 KQL queries per hypothesis before concluding
- Entity extraction after EVERY query (IPs, users, devices, timestamps)
- Mandatory pivot on ANY suspicious result with EXACT entity values
- Drill-down pattern: summarize → raw events → time-zoom
- Must try 2+ tables and 1 alternative explanation before concluding

**Available tools in execute phase** (6 tools):
`run_kql_query`, `validate_kql`, `search_mitre`, `lookup_cve`, `assess_risk`, `identify_attack_paths`

**Typical execution**: 10 hypotheses × 3-6 queries each = **30-60 KQL queries total**.

Each finding is documented with evidence, affected entities, MITRE technique, and severity.

### Step 7 — Phase 4: CONCLUDE

GPT-5.3 reviews all findings and classifies each one:

| Classification | Meaning |
|---------------|---------|
| **True Positive** | Real evidence of threat activity — needs attention |
| **False Positive** | Explainable, benign — not a threat |
| **Inconclusive** | Anomalous but needs further investigation |

For each TP, it documents:
- Evidence chain (specific queries, results, entity values)
- MITRE technique mapping
- Severity rating (Critical / High / Medium / Low)
- Recommended response actions

### Step 8 — Phase 5: DELIVER

The agent writes a complete professional report:

1. **Executive Summary** — business-readable, non-technical overview
2. **Environment Overview** — tenant details, user/asset counts, MFA coverage
3. **Findings by Severity** — each finding with evidence, MITRE mapping, recommendations
4. **Detection Engineering** — KQL rules to deploy based on findings
5. **MITRE ATT&CK Coverage** — heatmap of what's covered vs gaps
6. **Prioritized Action Plan** — immediate (0-7 days), short-term (30-60 days), future

### Step 9 — Persistence and Learning

**New in V7.2**: After the campaign completes, the **CampaignLearningEngine** runs:

1. Saves the campaign record to SQLite (campaign ID, findings count, hypotheses, timing)
2. Saves each finding (classification, severity, MITRE technique, entities, evidence)
3. Extracts **lessons** from the outcomes:
   - `productive_hypothesis` — hypothesis that led to a true positive
   - `false_positive_pattern` — pattern confirmed as benign (skip faster next time)
   - `effective_query` — KQL pattern that produced results
   - `technique_relevance` — which MITRE techniques are relevant to this environment

These lessons are injected into the next campaign's hypothesize and execute prompts, making each successive hunt smarter.

### Step 10 — Analyst retrieves the report

The analyst asks: "What's the status of CAMP-e807eadb?" → gets progress summary.
Then: "Show me the report for CAMP-e807eadb" → gets the full executive report.

**Total campaign time: 5-15 minutes** for 10 hypotheses, 30-60 KQL queries, and a full deliverable report.

---

## Flow 3: Direct Actions (No Flow Needed)

Some actions bypass the Flow and use direct connector calls:

| Action | Trigger | Connector Operation |
|--------|---------|-------------------|
| Campaign status | "What's the status of CAMP-xxx?" | `getCampaign` |
| Campaign report | "Show me the report for CAMP-xxx" | `getCampaignReport` |
| Health check | "Are you connected?" / "Health check" | `healthCheck` |

These are synchronous and fast (< 2 seconds).

---

## Summary — The Three Modes

| | Quick Query | Campaign | Direct Action |
|---|---|---|---|
| **Trigger** | Any security question | Multi-vector / "comprehensive" / "full hunt" | Status / report / health |
| **Routing** | GPT-5.3 classifier → "chat" | GPT-5.3 classifier → "campaign" | Copilot Studio → connector |
| **Returns** | Immediate answer (via Flow polling) | CAMP-ID immediately, report in 5-15 min | Immediate response |
| **Time** | 15-45 seconds | 5-15 minutes | < 2 seconds |
| **KQL queries** | 1-5 | 30-60 | 0 |
| **Output** | Chat message with evidence | Professional executive report | Status / health JSON |
| **Best for** | Ad-hoc investigation, CVE checks, detection rules | Client deliverables, periodic hunts, deep dives | Checking on running campaigns |

---

## What Makes V7.2 Different from V7.0

| Feature | V7.0 | V7.2 |
|---------|------|------|
| Entry point | Separate `/chat` and `/campaigns` endpoints | Single `/ask` — GPT-5.3 routes automatically |
| Timeout handling | Direct connector calls → 40s timeout | Async Flow with 4-minute polling window |
| Copilot Studio complexity | Multiple actions, manual routing in Topics | One Flow action, generative orchestration |
| Environment context | Basic `summary()` — table names and counts | `rich_summary()` — specific users, admin UPNs, MFA status, MITRE gaps |
| Execute phase intelligence | Generic prompts, no minimum query enforcement | Mandatory 3+ queries, entity extraction, pivot rules |
| Learning | None — every campaign starts from scratch | Recursive learning — campaigns build on prior findings |
| Persistence | In-memory only — lost on restart | SQLite with campaign records, findings, hypotheses, lessons |
| Attack simulation data | None | 287K Mordor/OTRF events in `AttackSimulation_CL` |
| Campaign report | Broken — conclude/deliver phases didn't complete | Fixed — unlimited token budget for conclude/deliver |
| Evaluation | Manual testing only | 100/100 automated evaluation with 3 custom classifications |
