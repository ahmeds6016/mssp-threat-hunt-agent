# Deployment Guide

## Prerequisites

- Python 3.11+
- Azure CLI authenticated
- Azure subscription with:
  - Azure Function App (Linux, Python 3.11, B1+ App Service plan with Always On)
  - Azure OpenAI resource with a GPT model deployment
  - Microsoft Sentinel workspace with active data connectors
  - Service Principal with Microsoft Sentinel Reader role

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

## Deploy to Azure

```bash
# Build deployment package
STAGING=$(mktemp -d)
cp azure_function/function_app.py "$STAGING/"
cp azure_function/host.json "$STAGING/"
cp azure_function/requirements.txt "$STAGING/"
cp -r src/mssp_hunt_agent "$STAGING/mssp_hunt_agent"

# Install Linux-compatible dependencies
pip install -r azure_function/requirements.txt \
  --target "$STAGING/.python_packages/lib/site-packages" \
  --platform manylinux2014_x86_64 --python-version 3.11 --only-binary=:all:

# Build zip (do NOT use PowerShell Compress-Archive — creates broken paths on Linux)
python infra/build_zip.py "$STAGING" "$STAGING/deploy.zip"

# Deploy via Kudu
TOKEN=$(az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv)
curl -X POST "https://<function-app>.scm.azurewebsites.net/api/zipdeploy" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @"$STAGING/deploy.zip"

# Force restart (required with WEBSITE_RUN_FROM_PACKAGE=1)
HOSTJSON=$(curl -s "https://<function-app>.scm.azurewebsites.net/api/vfs/site/wwwroot/host.json" \
  -H "Authorization: Bearer $TOKEN")
curl -X PUT "https://<function-app>.scm.azurewebsites.net/api/vfs/site/wwwroot/host.json" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "If-Match: *" -d "$HOSTJSON"
```

## Connect to Sentinel

1. Create a Service Principal in Azure AD
2. Assign `Microsoft Sentinel Reader` role on the Log Analytics workspace
3. Set the environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `SENTINEL_WORKSPACE_ID`
4. Set `ADAPTER_MODE=real`

## Connect to Copilot Studio

1. In Power Automate, create a Custom Connector using `azure_function/copilot-connector-swagger.json`
2. Security: API Key auth, parameter name `code`, location Query
3. Create a Power Automate Flow "Ask Threat Hunt Agent":
   - Trigger: Run a flow from Copilot (input: `message` text)
   - HTTP POST to `/api/v1/ask` with `{"message": message}`
   - Parse JSON response for `request_id`
   - Do Until loop: poll `/api/v1/ask/{request_id}` every 10s (24 max, PT4M timeout)
   - Return `response` field to Copilot Studio
4. In Copilot Studio, add the Flow as an action
5. Enable generative orchestration — no Topics needed

## Run Locally

```bash
pip install -e ".[dev]"
cp local.settings.json.template local.settings.json
# Fill in credentials
pytest tests/ -x -q  # 892 tests, all use mock adapters
```

## Known Deployment Issues

- PowerShell `Compress-Archive` creates Windows backslash paths — Linux can't read them. Use `infra/build_zip.py`.
- Azure Functions Python worker doesn't add wwwroot to sys.path with `WEBSITE_RUN_FROM_PACKAGE=1` — `function_app.py` handles this.
- Kudu zipdeploy doesn't restart the instance — touch `host.json` via VFS after deploy.
- Two functions on the same route with different methods causes 404 — merge into one function with method dispatch.
