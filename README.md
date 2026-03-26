# MSSP Threat Hunt Agent

Autonomous threat hunting for Managed Security Service Providers. Analysts ask questions in plain English through Microsoft Teams — the agent runs KQL queries against Sentinel, correlates with threat intelligence, and returns grounded, evidence-backed analysis. Complex investigations launch multi-phase campaigns that generate hypotheses, execute dozens of queries, classify findings, and produce executive reports.

Built on GPT-5.3-chat, Microsoft Sentinel, and 8+ open-source intelligence sources. No vendor lock-in on data — all threat intel comes from free public sources.

## Why This Exists

MSSPs run the same threat hunts across dozens of client environments. Each hunt requires a senior analyst to write KQL, cross-reference MITRE ATT&CK, check CVE databases, and produce a report. This agent automates that workflow end-to-end while keeping the analyst in control.

## What It Does

- **Ask anything** — CVE exposure checks, sign-in analysis, detection rule generation, MITRE lookups, risk assessments
- **Autonomous campaigns** — 5-phase deep investigations: environment indexing, hypothesis generation, KQL execution (30-60 queries), finding classification, report delivery
- **Threat intelligence enrichment** — IP reputation (TOR, botnets, 100+ blocklists), malware family attribution, exploit probability scoring (EPSS), LOLBin detection
- **Recursive learning** — each campaign builds on prior findings, avoids known false positives, reuses effective query patterns
- **Grounded in real data** — every claim backed by specific Sentinel query results, event counts, and entity names

## Architecture

```
Analyst → Copilot Studio → Power Automate Flow → POST /api/v1/ask
                                                      |
                                              GPT-5.3 classifier
                                                      |
                                         chat (15-45s) | campaign (5-15min)
                                                      |
                                              12 tools, 8 intel sources
                                              Microsoft Sentinel KQL
```

## Quick Start

```bash
# Clone
git clone https://github.com/ahmeds6016/mssp-threat-hunt-agent.git
cd mssp-threat-hunt-agent

# Install
pip install -e ".[dev]"

# Run tests (no credentials needed — mock adapters)
pytest tests/ -x -q
# 892 passed

# Deploy to Azure (see docs/deployment.md for full guide)
cp local.settings.json.template local.settings.json
# Fill in Azure credentials, then:
python infra/build_zip.py ...
```

## Repository Structure

```
src/mssp_hunt_agent/
├── agent/          # Agent loop, GPT-5.3 classifier, 12 tools, system prompt
├── hunter/         # Campaign orchestrator, 5 phases, learning engine
├── adapters/       # Sentinel + LLM adapters (real + mock)
├── intel/          # CVE, MITRE, threat intel, LOLBAS, Sentinel rules
├── persistence/    # SQLite — campaigns, findings, lessons
├── detection/      # KQL rule generation and validation
├── risk/           # Risk simulation and attack path analysis
└── config.py       # Environment-based configuration

azure_function/     # Azure Function entry point + API specs
infra/              # Deployment scripts + data ingestion
tests/              # 892 tests + live evaluation runners
docs/               # Architecture, deployment, API, integrations
```

## Documentation

| Document | What it covers |
|----------|---------------|
| [Architecture](docs/architecture.md) | System design, async pattern, data flow |
| [How It Works](docs/how-it-works-v7.2.md) | Step-by-step request lifecycle |
| [API Reference](docs/api.md) | Endpoints, request/response examples |
| [Deployment Guide](docs/deployment.md) | Azure Function setup, Sentinel connection, Copilot Studio |
| [Intelligence Sources](docs/intelligence-sources.md) | All 12 data sources with integration details |
| [Campaign Lifecycle](docs/campaign-lifecycle.md) | 5-phase pipeline deep dive |
| [Evaluation Results](docs/evaluation.md) | 110-prompt live eval, intelligence audit scores |
| [Custom Table Ingestion](docs/custom-table-ingestion-guide.md) | Importing attack simulation data into Sentinel |

## Current Status

| Metric | Value |
|--------|-------|
| Tests | 892 passing |
| Live evaluation | 110/110 completed, 99% correct routing |
| Intelligence audit | 47/50 (94%) |
| Tools | 12 |
| Threat intel sources | 8 (all free, no API keys) |
| Attack simulation data | 287K events across 6 MITRE tactics |
| Deployment | Azure Function App (B1) + Copilot Studio |

## Contributing

This project is under active development. See the [roadmap](docs/roadmap.md) for planned features.

## License

Proprietary. All rights reserved.
