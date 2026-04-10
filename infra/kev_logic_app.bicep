// Logic App that triggers a CISA KEV scan twice daily.
//
// CISA typically updates the KEV catalog once per business day. Polling
// twice daily (00:00 and 12:00 UTC) gives us ~12-hour worst-case detection
// latency without spamming the function. Dedup happens server-side in
// KEVMonitor — repeat invocations on an unchanged catalog cost zero KQL.
//
// Usage:
//   az deployment group create \
//     -g adv01-eastus-vnet-1-rg \
//     -f infra/kev_logic_app.bicep \
//     -p functionKey='<key>' \
//     -p recipients='ahmed.shiekhaden@purplestratus.onmicrosoft.com'

@description('Function key for mssphuntagent-fn')
@secure()
param functionKey string

@description('Comma-separated list of email recipients for exposure alerts')
param recipients string = ''

@description('Maximum KEV alerts to process per scan run')
param maxAlertsPerScan int = 25

@description('Function app base URL')
param functionAppUrl string = 'https://mssphuntagent-fn.azurewebsites.net'

@description('Location for the Logic App')
param location string = resourceGroup().location

var recipientArray = empty(recipients) ? [] : split(recipients, ',')

resource kevScanWorkflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'cisa-kev-scan-daily'
  location: location
  tags: {
    purpose: 'cisa-kev-monitor'
    cadence: 'twice-daily'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        // Twice daily — 00:00 and 12:00 UTC
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 12
            startTime: '2026-04-11T00:00:00Z'
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Trigger_KEV_Scan: {
          type: 'Http'
          runAfter: {}
          inputs: {
            method: 'POST'
            uri: '${functionAppUrl}/api/v1/kev-scan'
            headers: {
              'Content-Type': 'application/json'
              'x-functions-key': functionKey
            }
            body: {
              recipients: recipientArray
              max_alerts: maxAlertsPerScan
              dry_run: false
            }
            // The endpoint returns 202 immediately and runs the scan in the
            // background. Don't follow the Location header — we don't need
            // the result, just the kick-off.
            retryPolicy: {
              type: 'fixed'
              count: 2
              interval: 'PT30S'
            }
          }
        }
      }
    }
  }
}

output workflowName string = kevScanWorkflow.name
output workflowId string = kevScanWorkflow.id
