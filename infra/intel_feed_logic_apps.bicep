// Logic Apps that watch threat intel RSS feeds and trigger /api/v1/intel-hunt
// when new articles are published. One Logic App per feed.
//
// Deploys:
//   - 1 RSS API connection (shared by all workflows)
//   - N Logic Apps, each watching a single feed
//
// Usage:
//   az deployment group create \
//     -g adv01-eastus-vnet-1-rg \
//     -f infra/intel_feed_logic_apps.bicep \
//     -p functionKey='<key>' \
//     -p pollIntervalMinutes=15

@description('Function key for mssphuntagent-fn')
@secure()
param functionKey string

@description('Poll interval in minutes for RSS feeds')
param pollIntervalMinutes int = 15

@description('Location for Logic Apps (defaults to resource group location)')
param location string = resourceGroup().location

@description('Function app base URL')
param functionAppUrl string = 'https://mssphuntagent-fn.azurewebsites.net'

// ── Shared RSS API connection ─────────────────────────────────────────
resource rssConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'rss-intel-feeds'
  location: location
  properties: {
    displayName: 'RSS Intel Feeds'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'rss')
    }
  }
}

// ── Feed definitions ──────────────────────────────────────────────────
var feeds = [
  {
    name: 'google-tag'
    displayName: 'Google Threat Analysis Group'
    feedUrl: 'https://blog.google/threat-analysis-group/rss/'
  }
  {
    name: 'microsoft-security'
    displayName: 'Microsoft Security Blog'
    feedUrl: 'https://www.microsoft.com/en-us/security/blog/feed/'
  }
  {
    name: 'unit42'
    displayName: 'Palo Alto Unit 42'
    feedUrl: 'https://unit42.paloaltonetworks.com/feed/'
  }
  {
    name: 'sentinelone-labs'
    displayName: 'SentinelOne Labs'
    feedUrl: 'https://www.sentinelone.com/labs/feed/'
  }
  {
    name: 'dfir-report'
    displayName: 'The DFIR Report'
    feedUrl: 'https://thedfirreport.com/feed/'
  }
  {
    name: 'crowdstrike'
    displayName: 'CrowdStrike Blog'
    feedUrl: 'https://www.crowdstrike.com/blog/feed/'
  }
]

// ── One Logic App per feed ────────────────────────────────────────────
resource feedWorkflows 'Microsoft.Logic/workflows@2019-05-01' = [for feed in feeds: {
  name: 'intel-feed-${feed.name}'
  location: location
  tags: {
    purpose: 'threat-intel-feed-trigger'
    feed: feed.displayName
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        When_a_feed_item_is_published: {
          recurrence: {
            frequency: 'Minute'
            interval: pollIntervalMinutes
          }
          splitOn: '@triggerBody()?[\'value\']'
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'rss\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/OnNewFeed'
            queries: {
              feedUrl: feed.feedUrl
            }
          }
        }
      }
      actions: {
        Launch_Intel_Hunt: {
          type: 'Http'
          runAfter: {}
          inputs: {
            method: 'POST'
            uri: '${functionAppUrl}/api/v1/intel-hunt'
            headers: {
              'Content-Type': 'application/json'
              'x-functions-key': functionKey
            }
            body: {
              url: '@triggerBody()?[\'primaryLink\']'
              title: '@triggerBody()?[\'title\']'
            }
          }
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          rss: {
            connectionId: rssConnection.id
            connectionName: 'rss-intel-feeds'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'rss')
          }
        }
      }
    }
  }
}]

output logicAppNames array = [for (feed, i) in feeds: feedWorkflows[i].name]
output rssConnectionId string = rssConnection.id
