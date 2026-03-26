# Copilot Studio — Campaign Integration Guide

## Overview

This guide adds **autonomous threat hunt campaign** capabilities to your existing Copilot Studio bot. Analysts can:

1. **Start a hunt** — "Run a threat hunt for Acme Corp focusing on ransomware"
2. **Check status** — "What's the status of campaign CAMP-96ede78f?"
3. **Get the report** — "Show me the report for CAMP-96ede78f"
4. **List campaigns** — "Show all campaigns"

No Topics needed — generative orchestration handles routing automatically.

## Prerequisites

- Copilot Studio bot with **generative orchestration** enabled
- Function App URL: `https://mssphuntagent-fn.azurewebsites.net`
- Function Key: configured in the custom connector

---

## Step 1: Update the Custom Connector

### Option A: Re-import OpenAPI spec (recommended)

1. Go to **Power Platform** > **Custom connectors**
2. Find your existing `MSSP Threat Hunt Agent` connector
3. Click **Edit** > **Swagger Editor** (toggle on)
4. Replace the entire spec with the Swagger 2.0 YAML (see below or `azure_function/openapi.json`)
5. Click **Update connector**

The updated spec adds these new operations:
| Operation | Method | Path | Description |
|-----------|--------|------|-------------|
| `startCampaign` | POST | `/api/v1/campaigns` | Start a hunt campaign |
| `listCampaigns` | GET | `/api/v1/campaigns` | List all campaigns |
| `getCampaign` | GET | `/api/v1/campaigns/{campaign_id}` | Poll campaign status |
| `getCampaignReport` | GET | `/api/v1/campaigns/{campaign_id}/report` | Get the final report |

### Option B: Add operations manually

If you prefer not to re-import, add each operation manually:

**startCampaign (POST /api/v1/campaigns)**
- Request body: `client_name` (string), `time_range` (string), `focus_areas` (array of string)
- Response: `campaign_id`, `status`, `client_name`, `message`

**getCampaign (GET /api/v1/campaigns/{campaign_id})**
- Path parameter: `campaign_id` (string)
- Response: `campaign_id`, `status`, `current_phase`, `hypotheses_count`, `findings_count`, `total_kql_queries`, `errors`, `phase_results`

**getCampaignReport (GET /api/v1/campaigns/{campaign_id}/report?format=markdown)**
- Path parameter: `campaign_id` (string)
- Query parameter: `format` = `markdown`
- Response: raw markdown text

**listCampaigns (GET /api/v1/campaigns)**
- Response: `campaigns` array with `campaign_id`, `status`, `client_name`, `findings_count`

### Test the connector

After updating, click **Test** on each operation:
- `healthCheck` — should return `{"status": "ok"}`
- `startCampaign` — should return 202 with a `campaign_id`
- `getCampaign` — use the campaign_id from above
- `listCampaigns` — should show the campaign you just started

---

## Step 2: Add Actions (Generative Orchestration)

With generative orchestration enabled, you don't need Topics. The bot uses the OpenAPI descriptions to automatically decide which action to call.

1. In Copilot Studio, go to your bot
2. Navigate to **Actions** > **Add an action**
3. Select your **MSSP Threat Hunt Agent** connector
4. Enable all operations:
   - `startCampaign`
   - `getCampaign`
   - `getCampaignReport`
   - `listCampaigns`
   - `chatWithAgent`
   - `healthCheck`
5. Save and publish

That's it. The orchestrator reads the operation descriptions and parameter schemas from the OpenAPI spec and automatically:
- Routes "Start a hunt for Acme Corp focusing on ransomware" → `startCampaign`
- Routes "What's the status of CAMP-96ede78f?" → `getCampaign`
- Routes "Show me the report" → `getCampaignReport`
- Routes "List all campaigns" → `listCampaigns`
- Routes everything else (CVE lookups, KQL questions, etc.) → `chatWithAgent`

The detailed `description` fields in the OpenAPI spec are what guide the orchestrator — that's why they're verbose.

---

## Step 3: Campaigns Are Long-Running

Campaigns take 5-15 minutes. The bot handles this naturally:

1. Analyst: "Start a threat hunt for Purple Stratus"
2. Bot calls `startCampaign` → returns campaign_id immediately
3. Bot tells analyst the campaign_id and suggests checking back
4. Analyst (5 min later): "What's the status of CAMP-96ede78f?"
5. Bot calls `getCampaign` → shows progress
6. Analyst (when complete): "Show me the report for CAMP-96ede78f"
7. Bot calls `getCampaignReport` → displays findings

No polling loops needed — analysts check when they're ready.

---

## Step 4: Test End-to-End

1. Open your Copilot Studio bot in the test pane
2. Say: **"Start a threat hunt for Purple Stratus"**
   - Bot should call `startCampaign` and return a campaign_id
3. Wait 5-10 minutes
4. Say: **"Check status of CAMP-xxxxxxxx"**
   - Bot should call `getCampaign` and show running/completed status
5. Once completed, say: **"Show me the report for CAMP-xxxxxxxx"**
   - Bot should call `getCampaignReport` and display the findings

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Connector test returns 401 | Check function key in connector security settings |
| startCampaign returns 500 | Check Function App logs — LLM or Sentinel may be misconfigured |
| Report not available | Campaign must reach DELIVER phase — check status first |
| Campaign stuck in "starting" | The background thread may have crashed — check `errors` field |
| Bot doesn't call the right action | Check that the action is enabled in Copilot Studio and generative orchestration is on |
| Bot calls chatWithAgent instead of campaign action | The OpenAPI descriptions guide routing — make sure the connector has the latest spec |
