#!/usr/bin/env bash
set -euo pipefail

# MSSP Hunt Agent — Zip Deploy to Azure Functions
# Builds a deployment zip with mssp_hunt_agent/ + Linux deps, deploys via az CLI.
#
# Usage:
#   ./infra/deploy_zip.sh --resource-group myRG --function-app mssphuntagent-fn

RESOURCE_GROUP=""
FUNCTION_APP=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --resource-group) RESOURCE_GROUP="$2"; shift 2;;
    --function-app)   FUNCTION_APP="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$FUNCTION_APP" ]]; then
  echo "Usage: ./infra/deploy_zip.sh --resource-group RG --function-app APP_NAME"
  exit 1
fi

echo "=== MSSP Hunt Agent — Zip Deploy ==="
echo "Resource Group : $RESOURCE_GROUP"
echo "Function App   : $FUNCTION_APP"

echo "[1/5] Checking Azure CLI login..."
az account show > /dev/null 2>&1 || { echo "Run 'az login' first."; exit 1; }

STAGING=$(mktemp -d)
echo "[2/5] Staging in $STAGING ..."
cp azure_function/function_app.py "$STAGING/"
cp azure_function/host.json "$STAGING/"
cp azure_function/requirements.txt "$STAGING/"
cp -r src/mssp_hunt_agent "$STAGING/mssp_hunt_agent"

echo "[3/5] Installing Linux-targeted dependencies..."
pip install -r azure_function/requirements.txt \
  --target "$STAGING/.python_packages/lib/site-packages" \
  --upgrade --quiet \
  --platform manylinux2014_x86_64 --python-version 3.11 --only-binary=:all: 2>&1

find "$STAGING" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$STAGING" -name "*.pyc" -delete 2>/dev/null || true

ZIP_PATH="$STAGING/deploy.zip"
echo "[4/5] Building zip (Unix paths)..."
py infra/build_zip.py "$STAGING" "$ZIP_PATH"

echo "[5/5] Deploying..."
az functionapp deployment source config-zip \
  --resource-group "$RESOURCE_GROUP" --name "$FUNCTION_APP" \
  --src "$ZIP_PATH" --output none

rm -rf "$STAGING"
echo ""
echo "=== Deployed to https://${FUNCTION_APP}.azurewebsites.net ==="
