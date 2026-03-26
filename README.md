# MSSP Threat Hunt Agent

An autonomous threat hunting platform for Managed Security Service Providers. Connects Microsoft Sentinel to GPT-5.3-chat via Azure Functions. Analysts interact through Microsoft Copilot Studio — every message is classified by GPT-5.3 and routed to either a real-time agent loop or an autonomous multi-phase campaign pipeline. All intelligence is grounded in real Sentinel data, MITRE ATT&CK, CVE databases, and 8+ open-source threat intelligence feeds.

## Architecture

```
Analyst (Teams/Copilot Studio)
    → Power Automate Flow ("Ask Threat Hunt Agent")
        → POST /api/v1/ask (returns 202 immediately)
            → GPT-5.3 complexity classifier
                ├── Chat path (15-45s): AgentLoop with 12 tools
                └── Campaign path (5-15min): 5-phase orchestrator
        → Flow polls GET /api/v1/ask/{request_id} every 10s
    → Final response returned to analyst
```

### Key Design Decisions

- **Async pattern**: Every request returns 202 immediately. A background thread processes the request. The Power Automate Flow handles polling. This eliminates Copilot Studio's ~40s timeout limitation.
- **GPT-5.3 classifier**: The analyst never decides whether to run a quick query or a campaign. GPT-5.3 classifies complexity server-side and routes internally.
- **Grounded intelligence**: Every response is backed by real Sentinel queries. The agent runs KQL, checks results, reasons over evidence, and cites specific event counts, user accounts, and timestamps.
- **Recursive learning**: Each campaign persists findings to SQLite. The next campaign loads prior context — known false positives, confirmed threats, effective query patterns — and generates smarter hypotheses.

## Campaign Lifecycle

```
Phase 1: INDEX_REFRESH
    → 40-60 KQL queries across 3 refresh layers
    → Discovers all tables, users, assets, incidents, MITRE gaps
    → Cached per-client, refreshed based on layer age

Phase 2: HYPOTHESIZE
    → GPT-5.3 generates 10 prioritized threat hunt hypotheses
    → Each references specific tables, users, MITRE techniques
    → Injects learning context from prior campaigns

Phase 3: EXECUTE
    → Tool-calling loop per hypothesis (3-6 queries each)
    → Mandatory: minimum 3 queries, entity extraction, pivot on suspicious findings
    → 6 tools: run_kql_query, validate_kql, search_mitre, lookup_cve, assess_risk, identify_attack_paths
    → Total: 30-60 KQL queries per campaign

Phase 4: CONCLUDE
    → Classifies each finding: true_positive, false_positive, inconclusive
    → Documents evidence chain, MITRE technique, severity, affected entities

Phase 5: DELIVER
    → Executive summary, findings by severity, recommendations, MITRE mapping
    → Detection rules generated for identified gaps
```

## Agent Tools (12)

| Tool | Source | Description |
|------|--------|-------------|
| `run_kql_query` | Microsoft Sentinel | Execute KQL against live workspace |
| `validate_kql` | KQL parser | Syntax check before execution |
| `lookup_cve` | cvelistV5 + CISA KEV + FIRST EPSS | CVE details with exploit probability scoring |
| `search_mitre` | MITRE ATT&CK STIX | Technique/tactic search across 770+ techniques |
| `get_sentinel_rule_examples` | Azure-Sentinel GitHub | Community KQL detection rules |
| `check_telemetry` | Sentinel | Table discovery, custom _CL tables, coverage mapping |
| `run_hunt` | Sentinel (multi-query) | Full single-topic hunt pipeline |
| `assess_risk` | Internal engine | What-if risk simulation |
| `check_landscape` | CISA KEV | Threat landscape correlation |
| `identify_attack_paths` | Internal analysis | Attack chain mapping |
| `enrich_ioc` | TOR + Feodo + IPsum + Shodan + ThreatFox | Multi-source IP/domain/hash enrichment |
| `check_lolbas` | LOLBAS + LOLDrivers | Living-off-the-land binary and driver detection |

## Threat Intelligence Sources

All free, no API keys required:

| Source | What it provides |
|--------|-----------------|
| cvelistV5 (GitHub) | CVE details, CVSS scores, affected products |
| CISA KEV | Actively exploited vulnerabilities catalog |
| FIRST EPSS | Exploit probability scoring (0-1) for every CVE |
| MITRE ATT&CK STIX | 770+ techniques, tactics, threat actor profiles |
| Azure-Sentinel GitHub | Community KQL detection rules |
| Abuse.ch ThreatFox | IOC-to-malware-family mapping (IPs, domains, hashes) |
| Abuse.ch Feodo Tracker | Known botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot) |
| IPsum | Aggregated IP reputation from 100+ blocklists |
| Shodan InternetDB | Passive IP enrichment (open ports, vulns, hostnames) |
| TOR Exit Nodes | Current TOR exit node IP list |
| LOLBAS Project | 150+ living-off-the-land binaries with ATT&CK mapping |
| LOLDrivers | 400+ known vulnerable/malicious Windows drivers |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ask` | Submit any question (returns 202 + request_id) |
| GET | `/api/v1/ask/{request_id}` | Poll for result (processing/completed/error) |
| GET | `/api/v1/campaigns/{campaign_id}` | Campaign status and progress |
| GET | `/api/v1/campaigns/{campaign_id}/report` | Full campaign report |
| GET | `/api/v1/health` | Health check and connectivity status |

All endpoints require `?code=<function_key>` query parameter.

### Example: Ask a question

```bash
# Submit
curl -X POST "https://<function-app>.azurewebsites.net/api/v1/ask?code=<key>" \
  -H "Content-Type: application/json" \
  -d '{"message": "Are we vulnerable to CVE-2024-3400?"}'

# Response (202)
{"request_id": "REQ-d3380419", "status": "processing"}

# Poll
curl "https://<function-app>.azurewebsites.net/api/v1/ask/REQ-d3380419?code=<key>"

# Response (200)
{
  "status": "completed",
  "route": "chat",
  "response": "CVE-2024-3400 is a critical PAN-OS vulnerability (CVSS 10.0, EPSS 0.94)..."
}
```

## Project Structure

```
mssp-hunt-agent/
├── src/mssp_hunt_agent/           # Main package
│   ├── agent/                     # Agent loop, controller, classifier, tools
│   ├── hunter/                    # Campaign orchestrator, phases, learning engine
│   ├── adapters/                  # Sentinel + LLM adapters (real + mock)
│   ├── intel/                     # CVE, MITRE, threat intel, LOLBAS, Sentinel rules
│   ├── persistence/               # SQLite database, campaign/finding/lesson storage
│   ├── models/                    # Pydantic data models
│   ├── detection/                 # KQL rule generation and validation
│   ├── risk/                      # Risk simulation and scoring
│   ├── threat_model/              # Attack paths and breach simulation
│   └── config.py                  # HuntAgentConfig.from_env()
├── azure_function/                # Deployed entry point
│   ├── function_app.py            # All HTTP endpoints
│   ├── host.json                  # Function host config
│   ├── requirements.txt           # Azure Function dependencies
│   ├── openapi.json               # OpenAPI 3.0 spec
│   └── copilot-connector-swagger.json  # Swagger 2.0 for Copilot Studio
├── infra/                         # Infrastructure and deployment
│   ├── build_zip.py               # Zip builder (avoids Windows path issues)
│   ├── ingest_test_data.py        # Attack simulation data ingestion
│   └── deploy.sh                  # Deployment script
├── tests/                         # 892 tests + evaluation scripts
├── docs/                          # Documentation
├── .github/copilot-instructions.md  # Auto-loaded GitHub Copilot Chat context
└── local.settings.json.template   # Environment variable template
```

## Deployment

### Prerequisites

- Python 3.11+
- Azure subscription with:
  - Azure Function App (Linux, Python 3.11, B1+ App Service plan)
  - Azure OpenAI resource with GPT-5.3-chat deployment
  - Microsoft Sentinel workspace with active data connectors
- Azure CLI authenticated

### Deploy to Azure

```bash
STAGING=$(mktemp -d)
cp azure_function/function_app.py "$STAGING/"
cp azure_function/host.json "$STAGING/"
cp azure_function/requirements.txt "$STAGING/"
cp -r src/mssp_hunt_agent "$STAGING/mssp_hunt_agent"

pip install -r azure_function/requirements.txt \
  --target "$STAGING/.python_packages/lib/site-packages" \
  --platform manylinux2014_x86_64 --python-version 3.11 --only-binary=:all:

python infra/build_zip.py "$STAGING" "$STAGING/deploy.zip"

TOKEN=$(az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv)
curl -X POST "https://<function-app>.scm.azurewebsites.net/api/zipdeploy" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @"$STAGING/deploy.zip"
```

### Run Locally

```bash
git clone https://github.com/ahmeds6016/mssp-threat-hunt-agent.git
cd mssp-threat-hunt-agent
pip install -e ".[dev]"
cp local.settings.json.template local.settings.json
# Edit local.settings.json with your credentials
pytest tests/ -x -q
```

### Connect to Sentinel

1. Create a Service Principal with `Microsoft Sentinel Reader` role
2. Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `SENTINEL_WORKSPACE_ID`
3. Set `ADAPTER_MODE=real`

### Connect to Copilot Studio

1. Import `copilot-connector-swagger.json` as a Custom Connector in Power Automate
2. Create a Flow: POST `/ask` → Do Until loop polling `/ask/{request_id}` → return response
3. Add the Flow as an action in Copilot Studio with generative orchestration

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Yes | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Yes | Service principal secret |
| `SENTINEL_WORKSPACE_ID` | Yes | Log Analytics workspace ID |
| `AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_API_KEY` | Yes | Azure OpenAI API key |
| `AZURE_OPENAI_DEPLOYMENT` | No | Model deployment name (default: `gpt-5.3-chat`) |
| `DEFAULT_CLIENT_NAME` | No | Client name (default: `Default`) |
| `ADAPTER_MODE` | No | `real` or `mock` for Sentinel adapter |
| `AGENT_ENABLED` | No | Enable LLM agent loop (default: `true`) |

## Testing

```bash
# Full test suite (892 tests, all mock adapters)
pytest tests/ -x -q

# Live endpoint evaluation
python tests/run_live_eval.py

# Intelligence enrichment audit
python tests/run_intel_eval.py
```

### Evaluation Results (V7.2)

| Metric | Score |
|--------|-------|
| Completion Rate | 110/110 (100%) |
| Correct Routing | 109/110 (99%) |
| Evidence-Grounded | 87/90 (97%) |
| Actionable Response | 97/110 (88%) |
| Intelligence Enrichment | 47/50 (94%) |

## Version History

| Version | Changes |
|---------|---------|
| V1-V4 | Rule-based pipeline |
| V5 | IOC sweeps, telemetry profiling, LLM reasoning |
| V6 | Agentic tool-calling loop with GPT-5.3-chat, 10 tools |
| V7.0 | Campaign pipeline, Copilot Studio integration |
| V7.1 | Rich environment summaries, drill-down rules, recursive learning |
| V7.2 | Unified async /ask, GPT-5.3 classifier, 287K attack sim events, 12 tools, 8 intel sources, 892 tests |

## Architecture

```
Intake → Planner → Query Safety → Approval → Executor → Enrichment → Reasoning → Reporting → Audit
```

| Module | Responsibility |
|--------|---------------|
| **Intake** | Validate inputs, classify telemetry readiness (Green/Yellow/Red) |
| **Planner** | Generate hypotheses, ATT&CK mapping, Exabeam query candidates from playbooks |
| **Query Safety** | Flag risky queries (no time range, broad wildcards, free-text only, no limit) |
| **Approval** | Human-in-the-loop gate — analyst reviews plan before execution |
| **Executor** | Run approved queries through Exabeam adapter (mock or real) |
| **Enrichment** | Extract entities (IP/domain/hash/UA), enrich via threat-intel adapter |
| **Reasoning** | Analyse evidence, derive findings, assess confidence |
| **Reporting** | Render executive summary + analyst report via Jinja2 templates |
| **Audit** | Save all artefacts to timestamped run folder |

## Quick Start

```bash
cd mssp-hunt-agent

# Create virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

# Install
pip install -e ".[dev]"

# Run from JSON input (non-interactive, mock mode)
python -m mssp_hunt_agent.cli --input examples/client_inputs/identity_foreign_auth.json --no-approve

# Run in plan-only mode (no execution)
python -m mssp_hunt_agent.cli --input examples/client_inputs/endpoint_lolbin_hunt.json --plan-only

# Run interactively
python -m mssp_hunt_agent.cli

# Run tests
pytest -v
```

## Modes

### Interactive Mode

Run without `--input` to get a guided Q&A intake that walks through all required and optional fields:

```
python -m mssp_hunt_agent.cli
```

### File-Based Mode

Supply a JSON file matching the `HuntInput` schema:

```
python -m mssp_hunt_agent.cli --input examples/client_inputs/identity_foreign_auth.json
```

### Plan-Only Mode

Generate the hunt plan and reports without executing any queries:

```
python -m mssp_hunt_agent.cli --input examples/client_inputs/identity_foreign_auth.json --plan-only
```

### Approval Workflow

By default, the pipeline pauses after planning to show the query plan and safety flags, then asks for analyst approval before executing. Use `--no-approve` to skip this gate.

## Output Artefacts

Each run creates a timestamped folder under `output/`:

```
output/20241201T120000Z_contoso_financial/
├── executive_summary.md     # Client-facing summary
├── analyst_report.md        # Full technical report
├── evidence_table.md        # Evidence appendix
├── run_trace.json           # Complete audit trail
├── input_payload.json       # Original inputs
└── hunt_plan.json           # Generated plan
```

## Mock vs Real Integration

**v1 ships with mock adapters only.** This lets you validate the pipeline flow, question sequence, and report quality without needing real Exabeam or threat-intel API access.

| Component | Mock | Real (future) |
|-----------|------|----------------|
| Exabeam Search | `MockExabeamAdapter` — synthetic events | `RealExabeamAdapter` — stub in `adapters/exabeam/real_stub.py` |
| Threat Intel | `MockThreatIntelAdapter` — deterministic verdicts | Wire up VirusTotal, AbuseIPDB, Shodan via `.env` |
| Enrichment Cache | File-based `CachedIntelAdapter` | Same cache wraps any provider |

## Hunt Playbooks

YAML playbooks in `src/mssp_hunt_agent/data/hunt_playbooks/` define query templates, triage checklists, and escalation criteria per hunt type:

- `identity.yaml` — credential abuse, MFA bypass, impossible travel
- `endpoint.yaml` — LOLBins, encoded PowerShell, persistence
- `network.yaml` — C2 traffic, DNS tunneling, exfiltration
- `cloud.yaml` — IAM abuse, resource hijacking, storage exposure

## CLI Options

```
python -m mssp_hunt_agent.cli [OPTIONS]

Options:
  -i, --input PATH     JSON input file (non-interactive mode)
  -p, --plan-only      Generate plan only, skip execution
  --no-approve         Auto-approve safe queries (skip interactive approval)
  -o, --output PATH    Output directory (default: output/)
  -v, --verbose        Enable debug logging
```

## Configuration

Environment variables (or `.env` file for future use):

| Variable | Default | Description |
|----------|---------|-------------|
| `HUNT_MOCK_MODE` | `true` | Use mock adapters |
| `HUNT_APPROVAL_REQUIRED` | `true` | Require human approval before execution |
| `HUNT_OUTPUT_DIR` | `output` | Artefact output directory |
| `HUNT_CACHE_DIR` | `.cache/enrichment` | Enrichment cache directory |
| `EXABEAM_BASE_URL` | — | Real Exabeam API URL (future) |
| `EXABEAM_API_KEY` | — | Real Exabeam API key (future) |

## Design Limitations (v1)

- **Mock integrations only** — no real Exabeam or TI API calls
- **Rule-based reasoning** — findings derived from pattern matching, not LLM analysis
- **No persistent state** — each run is independent; no cross-run correlation
- **Single-provider enrichment** — one TI adapter at a time (but interface supports multiple)
- **No RBAC or multi-tenancy** — designed for single-analyst local use

## Roadmap

1. **Real Exabeam adapter** — implement `RealExabeamAdapter` with httpx + tenacity
2. **Multi-provider enrichment** — fan out to VT, AbuseIPDB, Shodan in parallel
3. **LLM-powered reasoning** — pass structured evidence to Claude for deeper analysis (prompts ready in `prompts/`)
4. **Copilot Studio integration** — wrap CLI as a Power Platform connector for Teams-based workflows
5. **SharePoint output** — auto-publish reports to client SharePoint sites
6. **Cross-run correlation** — SQLite or similar for historical hunt tracking
7. **Detection-as-code export** — generate Sigma/KQL rules from hunt findings

## Testing

```bash
pytest -v                    # All tests
pytest tests/test_models.py  # Model validation only
pytest -k "e2e"              # End-to-end only
```

## Project Structure

```
mssp-hunt-agent/
├── pyproject.toml
├── .env.example
├── README.md
├── src/mssp_hunt_agent/
│   ├── cli.py                    # Typer CLI entry point
│   ├── config.py                 # Runtime configuration
│   ├── models/                   # Pydantic schemas
│   │   ├── input_models.py       #   Analyst intake
│   │   ├── hunt_models.py        #   Plan, queries, telemetry
│   │   ├── result_models.py      #   Query results, enrichment
│   │   └── report_models.py      #   Findings, reports, audit
│   ├── pipeline/                 # Core pipeline stages
│   │   ├── orchestrator.py       #   End-to-end coordination
│   │   ├── intake.py             #   Input validation + telemetry classification
│   │   ├── planner.py            #   Hypothesis + query generation
│   │   ├── query_safety.py       #   Guardrail checks
│   │   ├── executor.py           #   Query execution via adapter
│   │   ├── enrichment.py         #   Entity extraction + TI enrichment
│   │   ├── reasoning.py          #   Evidence analysis + findings
│   │   ├── reporting.py          #   Jinja2 rendering
│   │   └── audit.py              #   Artefact persistence
│   ├── adapters/
│   │   ├── exabeam/
│   │   │   ├── base.py           #   ABC
│   │   │   ├── mock.py           #   Synthetic results
│   │   │   └── real_stub.py      #   TODO: real API integration
│   │   └── intel/
│   │       ├── base.py           #   ABC
│   │       ├── mock.py           #   Deterministic fake enrichment
│   │       └── cache.py          #   File-backed cache wrapper
│   ├── templates/                # Jinja2 report templates
│   ├── prompts/                  # Future LLM prompts
│   └── data/hunt_playbooks/      # YAML playbooks per hunt type
├── examples/
│   ├── client_inputs/            # Sample JSON inputs
│   └── mock_results/             # Sample Exabeam result payloads
├── tests/                        # pytest suite
└── output/                       # Generated artefacts (gitignored)
```
