#!/usr/bin/env bash
# Deploy RSS-triggered threat intel Logic Apps.
#
# Usage:
#   ./infra/deploy_intel_feeds.sh [poll_interval_minutes]
#
# Requires FUNCTION_KEY env var or prompts for it.

set -euo pipefail

RG="${RG:-adv01-eastus-vnet-1-rg}"
BICEP="$(dirname "$0")/intel_feed_logic_apps.bicep"
POLL_INTERVAL="${1:-15}"

if [[ -z "${FUNCTION_KEY:-}" ]]; then
  read -rsp "Function key for mssphuntagent-fn: " FUNCTION_KEY
  echo
fi

if [[ -z "${FUNCTION_KEY}" ]]; then
  echo "ERROR: FUNCTION_KEY is required" >&2
  exit 1
fi

echo "Deploying intel feed Logic Apps to ${RG}..."
echo "  Poll interval: ${POLL_INTERVAL} minutes"

MSYS_NO_PATHCONV=1 az deployment group create \
  --resource-group "${RG}" \
  --template-file "${BICEP}" \
  --parameters \
      functionKey="${FUNCTION_KEY}" \
      pollIntervalMinutes="${POLL_INTERVAL}" \
  --query "properties.outputs.logicAppNames.value" \
  -o json

echo
echo "Deployment complete. Verify Logic Apps in the portal:"
echo "  https://portal.azure.com/#@/resource/subscriptions/bb4b211f-c55c-4fae-b154-10ab473609c1/resourceGroups/${RG}/providers/Microsoft.Logic/workflows"
