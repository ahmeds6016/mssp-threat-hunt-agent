# API Reference

All endpoints require `?code=<function_key>` query parameter.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ask` | Submit any question (returns 202 + request_id) |
| GET | `/api/v1/ask/{request_id}` | Poll for result (processing/completed/error) |
| GET | `/api/v1/campaigns/{campaign_id}` | Campaign status and progress |
| GET | `/api/v1/campaigns/{campaign_id}/report` | Full campaign report |
| GET | `/api/v1/health` | Health check |

## POST /api/v1/ask

Submit a question. Returns immediately with a request_id.

**Request:**
```json
{"message": "Are we vulnerable to CVE-2024-3400?"}
```

**Response (202):**
```json
{"request_id": "REQ-d3380419", "status": "processing"}
```

## GET /api/v1/ask/{request_id}

Poll for result. Returns `processing` until the agent finishes.

**Response (completed — chat):**
```json
{
  "status": "completed",
  "route": "chat",
  "response": "CVE-2024-3400 is a critical PAN-OS vulnerability...",
  "intent": "cve_lookup",
  "confidence": 0.99,
  "thinking_trace": ["Called lookup_cve(CVE-2024-3400)", "Called run_kql_query(...)"]
}
```

**Response (completed — campaign):**
```json
{
  "status": "completed",
  "route": "campaign",
  "campaign_id": "CAMP-e807eadb",
  "response": "Deep investigation started. Campaign CAMP-e807eadb is running."
}
```

## GET /api/v1/campaigns/{campaign_id}

**Response:**
```json
{
  "campaign_id": "CAMP-e807eadb",
  "status": "completed",
  "client_name": "PurpleStratus",
  "hypotheses_count": 10,
  "findings_count": 7,
  "total_kql_queries": 46,
  "started_at": "2026-03-23T19:01:06Z",
  "completed_at": "2026-03-23T19:09:41Z"
}
```

## GET /api/v1/campaigns/{campaign_id}/report

Returns the full executive report with findings, recommendations, and MITRE mapping.

## GET /api/v1/health

```json
{
  "status": "ok",
  "llm_adapter": "AzureOpenAI(gpt-5.3-chat)",
  "sentinel_adapter": "real",
  "agent_enabled": true,
  "version": "0.7.2"
}
```
