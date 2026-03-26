# CLAUDE.md — MSSP Threat Hunt Agent

## What This Project Is

An autonomous MSSP threat hunting platform that connects Microsoft Sentinel to GPT-5.3-chat via Azure Functions. Analysts interact through Copilot Studio (Teams) — every message goes through a unified async endpoint (`/api/v1/ask`). GPT-5.3 classifies complexity server-side and routes simple queries to a real-time agent loop or complex investigations to an async campaign pipeline. All intelligence is grounded in real Sentinel data, MITRE ATT&CK, and CVE databases.

## Architecture

```
Analyst (Teams) → Copilot Studio → Power Automate Flow → Azure Function /api/v1/ask
    → GPT-5.3 classifier → chat (agent loop) or campaign (5-phase orchestrator)
    → Flow polls /api/v1/ask/{request_id} every 10s → returns result to Copilot Studio
```

Unified async pattern (V7.2):
1. **Submit**: `POST /api/v1/ask` — accepts any message, returns `request_id` instantly (202)
2. **Classify**: GPT-5.3 complexity classifier routes to chat or campaign
3. **Execute**: Chat path runs agent loop in background thread; Campaign path runs 5-phase orchestrator
4. **Poll**: `GET /api/v1/ask/{request_id}` — returns `processing`, `completed`, or `error`
5. **Fallback** — Rule-based reasoning chain when LLM is unavailable

Power Automate Flow ("Ask Threat Hunt Agent") handles the submit + poll loop internally.
Copilot Studio makes one call to the Flow, gets the final result back. No timeout issues.

## Project Layout

```
src/mssp_hunt_agent/
├── agent/          # V6 agentic loop + V7.2 complexity classifier
│   ├── agent_loop.py          # GPT-5.3 tool-calling loop
│   ├── complexity_classifier.py # GPT-5.3 chat vs campaign routing
│   ├── controller.py          # Routes to AgentLoop or ReasoningChain
│   ├── tool_defs.py           # 10 agent tools + ToolExecutor
│   └── system_prompt.py       # Dynamic system prompt builder
├── hunter/         # V7 campaign orchestrator
│   ├── campaign.py            # 5-phase orchestrator
│   ├── learning.py            # Recursive learning engine
│   ├── phases/                # hypothesize, execute, conclude, deliver
│   ├── models/                # CampaignState, CampaignConfig, EnvironmentIndex
│   └── prompts/               # Phase-specific LLM prompts
├── pipeline/       # V5 rule-based pipeline (orchestrator.py, planner.py, executor.py)
├── adapters/       # Sentinel, LLM, Intel, Exabeam integrations
├── intel/          # MITRE, CVE, Sentinel rules, landscape analysis
├── models/         # Pydantic schemas (input, hunt, result, report, IOC, profile)
├── persistence/    # SQLite (WAL mode, schema V3), SharePoint delivery
├── detection/      # KQL rule generation and validation
├── policy/         # Autonomy levels and compliance
├── risk/           # Risk simulation and portfolio scoring
├── threat_model/   # Attack paths and breach simulation
├── analytics/      # KPI engine and rollup reports
├── templates/      # Jinja2 report templates
├── data/           # YAML playbooks (ransomware, BEC, credential theft)
├── prompts/        # LLM prompt templates
├── mcp/            # Claude MCP server (experimental)
├── api/            # FastAPI app (deprecated — use azure_function/ instead)
azure_function/     # Deployed entry point
├── function_app.py            # All HTTP endpoints
├── openapi.json               # OpenAPI 3.0 spec
└── copilot-connector-swagger.json  # Swagger 2.0 for Copilot Studio connector
infra/              # Bicep IaC, deploy scripts, zip builder
tests/              # 873 passing
```

## Key Entry Points

- **Azure Function**: `azure_function/function_app.py` — all HTTP endpoints
- **Unified endpoint**: `POST /api/v1/ask` + `GET /api/v1/ask/{request_id}` — async submit + poll
- **Complexity classifier**: `src/mssp_hunt_agent/agent/complexity_classifier.py` — GPT-5.3 routing
- **Agent loop**: `src/mssp_hunt_agent/agent/agent_loop.py` — GPT-5.3 tool-calling
- **Campaign**: `src/mssp_hunt_agent/hunter/campaign.py` — 5-phase orchestrator
- **Learning engine**: `src/mssp_hunt_agent/hunter/learning.py` — recursive learning from past campaigns
- **Config**: `src/mssp_hunt_agent/config.py` — `HuntAgentConfig.from_env()`
- **Tools**: `src/mssp_hunt_agent/agent/tool_defs.py` — 10 agent tools
- **System prompt**: `src/mssp_hunt_agent/agent/system_prompt.py`
- **Copilot connector spec**: `azure_function/copilot-connector-swagger.json` — Swagger 2.0

## Development Rules

### Code Conventions
- **Pydantic models** for all data structures. No raw dicts crossing module boundaries.
- **`HuntAgentConfig.from_env()`** for all configuration. Never read env vars directly in business logic.
- **Mock adapters for all tests.** `MockSentinelAdapter`, `MockLLMAdapter` — no real API calls in tests.
- **Type hints** on all function signatures. Use `from __future__ import annotations`.
- **Logging** via `logging.getLogger(__name__)`. No print statements.

### Testing
- Run: `pytest` from project root
- All tests use mock adapters — safe to run anywhere, no credentials needed
- 873 tests passing — do not reduce this number
- New features require tests. New tools require tests in `test_tool_defs.py`.
- Campaign phases tested in `test_hunter_phases.py`
- Complexity classifier tested in `test_complexity_classifier.py`
- Campaign learning tested in `test_campaign_learning.py`

### Deployment
- **Build**: `python infra/build_zip.py` (NOT PowerShell Compress-Archive — Windows backslash paths break Linux)
- **Deploy**: `./infra/deploy_zip.sh` or Kudu zipdeploy with bearer token
- **Linux deps**: `pip install --platform manylinux2014_x86_64 --python-version 3.11 --only-binary=:all:`
- **After deploy**: touch host.json via Kudu VFS to force restart (WEBSITE_RUN_FROM_PACKAGE=1 doesn't auto-restart)
- **Staging**: `rm -rf build_staging && rebuild` when source structure changes

### Azure Function Specifics
- Direct `func.FunctionApp` routing — no ASGI middleware (unreliable)
- `function_app.py` must insert wwwroot into sys.path manually
- Two functions on same route with different methods → 404. Merge into one with method dispatch.
- Writable paths must use `/tmp/` (read-only filesystem)
- Campaign state and async request results are in-memory (thread-safe dicts) — restarting the function app loses running state

### LLM Integration
- GPT-5.x does NOT support custom temperature — only default (1). Check `_supports_temperature` flag.
- GPT-5.x requires `"type": "function"` in tool_calls messages sent back to the API.
- `_build_llm_adapter()` must check Azure OpenAI credentials BEFORE falling back to MockLLMAdapter.
- `adapter_mode=mock` is for Sentinel, not LLM — these are independent settings.

### Copilot Studio Integration
- **V7.2 pattern**: All requests go through Power Automate Flow → `/api/v1/ask` (async submit + poll)
- Flow "Ask Threat Hunt Agent" handles submit → poll loop → returns final result to Copilot Studio
- Connector uses Swagger 2.0 spec (`azure_function/copilot-connector-swagger.json`)
- Connector actions: `askAgent`, `getAskResult`, `getCampaign`, `getCampaignReport`, `healthCheck`
- Generative orchestration — no Topics. AI routes to correct action based on descriptions.
- **CRITICAL: Copilot Studio's Generative Orchestrator has a ~40s timeout for tool calls. Use the async Flow pattern to avoid this.**
- **CRITICAL: `RequestTimeoutInMilliseconds` and `x-ms-api-timeout` do NOT reliably override the GO timeout.**
- Updating a connector spec doesn't update existing connection references — must delete tools, delete connections, re-add from scratch.
- Having both a Flow and a Connector action for the same endpoint causes the Flow to intercept everything.

### Intelligence Features (V7.1+)
- `rich_summary()` on EnvironmentIndex — detailed env context for LLM (table profiles, admin users, MITRE gaps)
- Phase prompts enforce minimum 3 queries, mandatory entity extraction, mandatory pivot on suspicious findings
- `auto_pivot` and `max_pivot_depth` wired from CampaignConfig into execute phase
- Recursive learning engine extracts lessons from campaigns and injects into future prompts
- SQLite schema V3 with 4 new tables: campaigns, campaign_findings, campaign_hypotheses, hunt_lessons

## Do NOT

- Do not use `Compress-Archive` for deployment zips (Windows backslash paths)
- Do not use ASGI middleware in Azure Functions
- Do not add `temperature` parameter for GPT-5.x models
- Do not reference `report.gaps` — use `report.correlations` on LandscapeReport
- Do not reference `total_events` on QueryResult — use `result_count`
- Do not create new API endpoints in `src/mssp_hunt_agent/api/` — it's deprecated, use `azure_function/function_app.py`
- Do not run real API calls in tests — always use mock adapters
- Do not store secrets in code — all credentials come from env vars via `HuntAgentConfig`
- Do not use `git add -A` — stage specific files to avoid committing .env or credentials
- Do not make `/api/v1/ask` synchronous — Copilot Studio's GO will timeout. Always use async pattern.

## Environment

- **Function App**: `https://mssphuntagent-fn.azurewebsites.net`
- **Azure OpenAI**: `https://ahmed-mmfbvpyc-eastus2.cognitiveservices.azure.com/`
- **Deployment**: `gpt-5.3-chat` (model version 2026-03-03)
- **Tenant**: Purple Stratus (`fed72de5-3efd-4c47-95e9-61d0d1e6f86e`)
- **Azure OpenAI RG**: `adv01-eastus-vnet-1-rg` (not mssp-hunt-agent-rg)
- **Python**: 3.11 (Azure Functions), 3.10+ (local dev)

## Version History

| Version | What |
|---------|------|
| V1-V4 | Rule-based pipeline (intake → plan → execute → enrich → reason → report) |
| V5 | IOC sweeps, telemetry profiling, LLM reasoning, policy engine |
| V6 | Agentic tool-calling loop with GPT-5.3-chat, 10 tools, real data sources |
| V7.0 | Campaign pipeline, Copilot Studio integration, complexity-based routing |
| V7.1 | Rich environment summaries, mandatory drill-down/pivot, recursive learning engine, SQLite schema V3 |
| V7.2 | Unified async `/api/v1/ask` endpoint, GPT-5.3 complexity classifier, Power Automate Flow polling, 873 tests |
