#!/usr/bin/env bash
set -euo pipefail

# ── MSSP Hunt Agent — Azure Deployment Script ────────────────────────
# Usage:
#   ./infra/deploy.sh \
#     --resource-group myRG \
#     --sentinel-workspace-id "xxxxxxxx-xxxx-..." \
#     --tenant-id "xxxxxxxx-xxxx-..." \
#     --client-id "xxxxxxxx-xxxx-..." \
#     --client-secret "your-secret"

RESOURCE_GROUP=""
SENTINEL_WS=""
TENANT_ID=""
CLIENT_ID=""
CLIENT_SECRET=""
LOCATION="eastus"
BASE_NAME="mssphuntagent"

while [[ $# -gt 0 ]]; do
  case $1 in
    --resource-group) RESOURCE_GROUP="$2"; shift 2;;
    --sentinel-workspace-id) SENTINEL_WS="$2"; shift 2;;
    --tenant-id) TENANT_ID="$2"; shift 2;;
    --client-id) CLIENT_ID="$2"; shift 2;;
    --client-secret) CLIENT_SECRET="$2"; shift 2;;
    --location) LOCATION="$2"; shift 2;;
    --base-name) BASE_NAME="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$SENTINEL_WS" || -z "$TENANT_ID" || -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  echo "ERROR: Missing required arguments."
  echo "Usage: ./infra/deploy.sh --resource-group RG --sentinel-workspace-id WS --tenant-id T --client-id C --client-secret S"
  exit 1
fi

echo "=== MSSP Hunt Agent Deployment ==="
echo "Resource Group : $RESOURCE_GROUP"
echo "Location       : $LOCATION"
echo "Base Name      : $BASE_NAME"
echo ""

# 1. Ensure logged in
echo "[1/4] Checking Azure CLI login..."
az account show > /dev/null 2>&1 || { echo "Run 'az login' first."; exit 1; }

# 2. Create resource group if needed
echo "[2/4] Ensuring resource group exists..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none 2>/dev/null || true

# 3. Deploy Bicep template
echo "[3/4] Deploying infrastructure (Bicep)..."
RESULT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file infra/main.bicep \
  --parameters \
    baseName="$BASE_NAME" \
    sentinelWorkspaceId="$SENTINEL_WS" \
    tenantId="$TENANT_ID" \
    clientId="$CLIENT_ID" \
    clientSecret="$CLIENT_SECRET" \
  --query "properties.outputs" \
  --output json)

FUNC_NAME=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['functionAppName']['value'])" 2>/dev/null || echo "${BASE_NAME}-fn")
FUNC_URL=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['functionAppUrl']['value'])" 2>/dev/null || echo "unknown")

echo "  Function App: $FUNC_NAME"
echo "  URL: $FUNC_URL"

# 4. Deploy function code (zip deploy with package at root)
echo "[4/4] Building and deploying function code..."
STAGING=$(mktemp -d)

# Copy Azure Function entry point
cp azure_function/function_app.py "$STAGING/"
cp azure_function/host.json "$STAGING/"
cp azure_function/requirements.txt "$STAGING/"

# Copy mssp_hunt_agent package flat at root (NOT inside src/)
cp -r src/mssp_hunt_agent "$STAGING/mssp_hunt_agent"

# Clean bytecode
find "$STAGING" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$STAGING" -name "*.pyc" -delete 2>/dev/null || true

# Create zip (use PowerShell on Windows since zip may not be available)
STAGING_WIN=$(cygpath -w "$STAGING" 2>/dev/null || echo "$STAGING")
ZIP_WIN=$(cygpath -w "$STAGING/deploy.zip" 2>/dev/null || echo "$STAGING/deploy.zip")
powershell.exe -NoProfile -Command "Compress-Archive -Path '$STAGING_WIN\\*' -DestinationPath '$ZIP_WIN' -Force"

az functionapp deployment source config-zip \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FUNC_NAME" \
  --src "$STAGING/deploy.zip" \
  --output none

rm -rf "$STAGING"

echo ""
echo "=== Deployment Complete ==="
echo "Function URL: $FUNC_URL"
echo ""
echo "Test: curl $FUNC_URL/api/health"
echo ""
echo "Update Power Automate flows with this URL."
