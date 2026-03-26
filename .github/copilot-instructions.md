# MSSP Threat Hunt Agent — Copilot Context

## What This Project Is
An autonomous MSSP (Managed Security Service Provider) threat hunting agent that connects to Microsoft Sentinel via GPT-5.3-chat. It runs as an Azure Function App, exposed to analysts through Microsoft Copilot Studio. Version 7.2.

## Architecture Overview

```
Analyst → Copilot Studio → Power Automate Flow → Azure Function /api/v1/ask (202 async)
                                                    ↓
                                              GPT-5.3 Classifier (chat vs campaign)
                                                    ↓
                                    ┌───────────────┴───────────────┐
                                    Chat Path                    Campaign Path
                              (AgentLoop, 1-3 tools)      (5-phase orchestrator)
                                    ↓                            ↓
                              Immediate response          CAMP-ID → poll → report
```

## Directory Structure
```
mssp-hunt-agent/
├── src/mssp_hunt_agent/           # Main package
│   ├── agent/                     # Agent loop, controller, system prompt, complexity classifier
│   │   ├── controller.py          # Routes to AgentLoop (LLM) or ReasoningChain (rules)
│   │   ├── agent_loop.py          # GPT-5.3 tool-calling loop (max 12 iterations)
│   │   ├── system_prompt.py       # System prompt with table schemas, AttackSimulation_CL
│   │   ├── complexity_classifier.py # GPT-5.3 chat vs campaign routing
│   │   └── response_formatter.py  # Formats responses for Copilot Studio
│   ├── hunter/                    # Campaign orchestrator + phases
│   │   ├── campaign.py            # CampaignOrchestrator — 5-phase pipeline
│   │   ├── learning.py            # CampaignLearningEngine — recursive learning
│   │   ├── models/
│   │   │   ├── campaign.py        # CampaignState, CampaignConfig, Hypothesis, Finding
│   │   │   └── environment.py     # EnvironmentIndex with rich_summary()
│   │   ├── phases/
│   │   │   ├── hypothesize.py     # Generate 10 hypotheses from environment index
│   │   │   ├── execute.py         # Execute hypotheses with tool-calling loop
│   │   │   ├── conclude.py        # Classify findings (TP/FP/inconclusive)
│   │   │   └── deliver.py         # Generate executive report
│   │   └── prompts/
│   │       └── phase_prompts.py   # LLM prompts for each campaign phase
│   ├── adapters/
│   │   ├── llm/
│   │   │   ├── base.py            # LLMAdapter ABC
│   │   │   ├── azure_openai.py    # Real GPT-5.3 adapter
│   │   │   └── mock.py            # MockLLMAdapter for tests (prompt-aware)
│   │   └── sentinel/
│   │       ├── base.py            # SentinelAdapter ABC
│   │       ├── real.py            # Real Sentinel adapter (azure-identity + azure-monitor-query)
│   │       └── mock.py            # MockSentinelAdapter for tests
│   ├── persistence/
│   │   ├── database.py            # SQLite DB — schema V3, campaigns/findings/hypotheses/lessons
│   │   └── models.py              # CampaignRecord, FindingRecord, LessonRecord
│   ├── tools/                     # 10 agent tools
│   │   ├── kql_query.py           # run_kql_query — execute KQL against Sentinel
│   │   ├── kql_validator.py       # validate_kql — syntax check
│   │   ├── cve_lookup.py          # lookup_cve — cvelistV5 GitHub
│   │   ├── mitre_search.py        # search_mitre — MITRE ATT&CK STIX
│   │   ├── sentinel_rules.py      # get_sentinel_rule_examples — community rules
│   │   ├── telemetry_check.py     # check_telemetry — table discovery
│   │   ├── hunt_runner.py         # run_hunt — single-shot hunt
│   │   ├── risk_assessment.py     # assess_risk — what-if risk scenarios
│   │   ├── threat_landscape.py    # check_landscape — industry threats
│   │   └── attack_paths.py        # identify_attack_paths — attack chain mapping
│   └── config.py                  # HuntAgentConfig.from_env()
├── azure_function/
│   ├── function_app.py            # Azure Function entry point — /ask, /campaigns, /health
│   ├── host.json                  # Function host config
│   ├── requirements.txt           # Azure Function dependencies
│   ├── openapi.json               # OpenAPI 3.0 spec
│   └── copilot-connector-swagger.json  # Swagger 2.0 for Copilot Studio connector
├── infra/
│   ├── ingest_test_data.py        # Attack simulation data ingestion (legacy Data Collector API)
│   ├── build_zip.py               # Zip builder for Azure deployment (no Windows backslash paths)
│   └── deploy.sh                  # Deployment script
├── tests/                         # 892 tests
│   ├── test_agent_loop.py
│   ├── test_campaign_learning.py
│   ├── test_complexity_classifier.py
│   ├── test_hunter_phases.py
│   ├── copilot_evaluation.csv     # 100 test cases for Copilot Studio evaluation
│   └── ...
└── docs/
    ├── agent-overview-v7.2.md
    ├── custom-table-ingestion-guide.md
    └── test-log-ingestion-plan.md
```

## Key Technical Details

### Azure Environment
- **Subscription**: Advisory-01 (`bb4b211f-c55c-4fae-b154-10ab473609c1`)
- **Tenant**: Purple Stratus (`fed72de5-3efd-4c47-95e9-61d0d1e6f86e`)
- **Resource Group**: `adv01-eastus-vnet-1-rg`
- **Function App**: `mssphuntagent-fn` (Linux, Python 3.11, B1 App Service, Always On)
- **Function Key**: `qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ==`
- **Log Analytics Workspace**: `adv01-eastus-logspace-1` (workspace ID: `69e807f3-872b-4348-926f-16df15c02f9b`)
- **Azure OpenAI**: `Ahmed-mmfbvpyc-eastus2` → deployment `gpt-5.3-chat` (model 2026-03-03)

### API Endpoints
- `POST /api/v1/ask` — Unified entry point (returns 202 + request_id)
- `GET /api/v1/ask/{request_id}` — Poll for result
- `GET /api/v1/campaigns/{campaign_id}` — Campaign status
- `GET /api/v1/campaigns/{campaign_id}/report` — Campaign report
- `GET /api/v1/health` — Health check
- All endpoints require `?code=<function_key>` query parameter

### Async Pattern
1. POST `/ask` with `{"message": "..."}` → returns 202 with `request_id`
2. Background thread: GPT-5.3 classifier decides chat vs campaign
3. Chat: agent loop runs, stores result in memory
4. Campaign: 5-phase orchestrator runs (index → hypothesize → execute → conclude → deliver)
5. Poll `GET /ask/{request_id}` → `processing` or `completed` with full response

### GPT-5.3 Specifics
- Does NOT support custom `temperature` — only default (1). Use `_supports_temperature` flag.
- Requires `"type": "function"` in tool_calls messages sent back to the API
- API version: `2024-12-01-preview`
- Max 12 iterations in agent loop, unlimited budget for conclude/deliver phases

### Campaign Pipeline (5 Phases)
1. **INDEX_REFRESH**: Discover all Sentinel tables, users, assets, incidents (33 tables, ~40-60 KQL queries)
2. **HYPOTHESIZE**: Generate 10 prioritized threat hunt hypotheses grounded in environment data
3. **EXECUTE**: Run each hypothesis with tool-calling loop (30-60 KQL queries total)
4. **CONCLUDE**: Classify findings as true_positive/false_positive/inconclusive
5. **DELIVER**: Generate executive report with findings, recommendations, MITRE mapping

### Recursive Learning
- `CampaignLearningEngine` persists campaign outcomes to SQLite
- Lesson types: productive_hypothesis, false_positive_pattern, effective_query, technique_relevance
- Next campaign loads learning context from prior campaigns (verified working)
- SQLite at `/tmp/mssp_hunt_agent.db` (ephemeral — survives days on B1, lost on deploy)

### Custom Attack Simulation Data
- Table: `AttackSimulation_CL` (287K events, 6 MITRE tactics, 15 techniques)
- Source: Mordor/OTRF datasets ingested via legacy Data Collector API
- **Column naming uses `_s`/`_d` suffixes**: `MitreTechnique_s`, `EventID_d`, `AttackScenario_s`, etc.
- System prompt hardcodes this table with exact column names
- Ingestion script: `infra/ingest_test_data.py --ingest`
- ~6-7 hour lag between ingestion and queryability

### Copilot Studio Integration
- Custom connector with Swagger 2.0 spec (5 operations)
- Power Automate Flow "Ask Threat Hunt Agent" handles submit + poll loop
- Flow: Do Until loop, 24 polls × 10s = 4 min timeout
- Flow fixes: `pollStatus` variable, `string(body('PollResult'))`, `body('ParseFinal')?['response']`
- Generative orchestration — no Topics, AI routes to correct action

### Deployment
```bash
# Build and deploy (from mssp-hunt-agent/ directory)
STAGING=$(mktemp -d)
cp azure_function/function_app.py "$STAGING/"
cp azure_function/host.json "$STAGING/"
cp azure_function/requirements.txt "$STAGING/"
cp -r src/mssp_hunt_agent "$STAGING/mssp_hunt_agent"
pip install -r azure_function/requirements.txt \
  --target "$STAGING/.python_packages/lib/site-packages" \
  --platform manylinux2014_x86_64 --python-version 3.11 --only-binary=:all:
py infra/build_zip.py "$STAGING" "$STAGING/deploy.zip"
TOKEN=$(az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv)
curl -X POST "https://mssphuntagent-fn.scm.azurewebsites.net/api/zipdeploy" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @"$STAGING/deploy.zip"
# Force restart by touching host.json
HOSTJSON=$(curl -s "https://mssphuntagent-fn.scm.azurewebsites.net/api/vfs/site/wwwroot/host.json" -H "Authorization: Bearer $TOKEN")
curl -X PUT "https://mssphuntagent-fn.scm.azurewebsites.net/api/vfs/site/wwwroot/host.json" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "If-Match: *" -d "$HOSTJSON"
```

### Testing
```bash
# Run all tests (892 passing)
py -m pytest tests/ -x -q --tb=short

# Test specific module
py -m pytest tests/test_complexity_classifier.py -v

# Live endpoint test
curl -X POST "https://mssphuntagent-fn.azurewebsites.net/api/v1/ask?code=<key>" \
  -H "Content-Type: application/json" -d '{"message": "Health check"}'
```

## Code Patterns
- **Pydantic models** for all data structures
- **`HuntAgentConfig.from_env()`** for config loading
- **Mock adapters** (`MockSentinelAdapter`, `MockLLMAdapter`) — no real API calls in tests
- **Agent controller** routes to `AgentLoop` (LLM) or `ReasoningChain` (rules fallback)
- **SQLite** with WAL mode, schema V3
- **`MSYS_NO_PATHCONV=1`** needed for Azure CLI on Git Bash
- **Never use `Compress-Archive`** — use `infra/build_zip.py` (Python zipfile)

## Critical Gotchas
- Copilot Studio GO has ~40s tool call timeout — async Flow is the only fix
- `RequestTimeoutInMilliseconds` does NOT reliably override connector timeouts
- Updating connector spec doesn't update connection references — must delete and recreate
- Legacy Data Collector API returns 200 even when silently dropping data (use batch_size=200 + 1s delay)
- Legacy API adds `_s`/`_d` suffixes to column names — KQL queries MUST use suffixed names
- AttackSimulation_CL is a Classic table — cannot be deleted via DCR-based API
- Azure Functions Python worker doesn't add wwwroot to sys.path — function_app.py inserts manually
- Deploy via Kudu bearer token — RBAC blocks `az functionapp deployment`

## Current State (2026-03-26)
- **892 tests passing**, 1 skipped
- **100/100 live evaluation**: 98% correct routing, ~85% evidence-grounded, ~97% actionable
- **287K attack simulation events** live in Sentinel
- **Recursive learning verified** across campaigns
- **Campaign report endpoint fixed** — conclude/deliver phases complete
- **Deployed and live** at `https://mssphuntagent-fn.azurewebsites.net`

## What's Next / Known Issues
- Monitoring Metrics Publisher role still needed for DCR-based ingestion (legacy API works as workaround)
- SQLite on `/tmp/` is ephemeral — swap to Azure Blob or CosmosDB for permanent persistence
- Analytics/KPI, Policy/Autonomy, SharePoint Delivery, MCP Server — built but not wired to production
- Working session recording for Trevor, Herb, Deely on custom table ingestion
- Microsoft marketplace publication strategy in progress
