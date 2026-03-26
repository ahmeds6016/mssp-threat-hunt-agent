@description('Base name for all resources')
param baseName string = 'mssphuntagent'

@description('Azure region')
param location string = resourceGroup().location

@description('Sentinel workspace ID (GUID)')
param sentinelWorkspaceId string

@description('Azure AD tenant ID')
param tenantId string

@description('Service principal client ID (leave empty to use Managed Identity)')
param clientId string = ''

@description('Service principal client secret (leave empty to use Managed Identity)')
@secure()
param clientSecret string = ''

@description('Autonomy level (level_0, level_1, level_2, level_3)')
param autonomyLevel string = 'level_2'

@description('Azure OpenAI endpoint (leave empty to disable agentic loop)')
param azureOpenAIEndpoint string = ''

@description('Azure OpenAI API key')
@secure()
param azureOpenAIKey string = ''

@description('Azure OpenAI deployment name')
param azureOpenAIDeployment string = 'gpt-4o'

var useLLM = !empty(azureOpenAIEndpoint) && !empty(azureOpenAIKey)

var functionAppName = '${baseName}-fn'
var storageName = replace('${baseName}st', '-', '')
var appInsightsName = '${baseName}-ai'
var hostingPlanName = '${baseName}-plan'

// Determine auth mode: service principal or managed identity
var useServicePrincipal = !empty(clientId) && !empty(clientSecret)
var adapterMode = 'real'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web' }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: hostingPlanName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  kind: ''
  properties: { reserved: false }
}

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    siteConfig: {
      appSettings: concat([
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=core.windows.net;AccountKey=${storageAccount.listKeys().keys[0].value}' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'APPINSIGHTS_INSTRUMENTATIONKEY', value: appInsights.properties.InstrumentationKey }
        { name: 'HUNT_ADAPTER_MODE', value: adapterMode }
        { name: 'SENTINEL_WORKSPACE_ID', value: sentinelWorkspaceId }
        { name: 'AZURE_TENANT_ID', value: tenantId }
        { name: 'HUNT_PERSIST', value: 'true' }
        { name: 'HUNT_MAX_RESULTS', value: '1000' }
        { name: 'HUNT_AUTONOMY_LEVEL', value: autonomyLevel }
        { name: 'HUNT_POLICY_ENABLED', value: 'true' }
        { name: 'HUNT_APPROVAL_REQUIRED', value: 'false' }
        { name: 'HUNT_API_ENABLED', value: 'true' }
        { name: 'HUNT_MOCK_MODE', value: 'true' }
        { name: 'HUNT_AGENT_ENABLED', value: 'true' }
        { name: 'HUNT_AGENT_THINKING_VISIBLE', value: 'true' }
        { name: 'HUNT_DB_PATH', value: '/tmp/.hunt_agent.db' }
        { name: 'HUNT_OUTPUT_DIR', value: '/tmp/output' }
        { name: 'HUNT_CACHE_DIR', value: '/tmp/.cache/enrichment' }
        { name: 'HUNT_CVE_CACHE_DIR', value: '/tmp/.cache/cve' }
        { name: 'HUNT_MITRE_CACHE_DIR', value: '/tmp/.cache/mitre' }
        { name: 'HUNT_SENTINEL_RULES_CACHE_DIR', value: '/tmp/.cache/sentinel_rules' }
      ], useServicePrincipal ? [
        { name: 'AZURE_CLIENT_ID', value: clientId }
        { name: 'AZURE_CLIENT_SECRET', value: clientSecret }
      ] : [], useLLM ? [
        { name: 'HUNT_LLM_ENABLED', value: 'true' }
        { name: 'AZURE_OPENAI_ENDPOINT', value: azureOpenAIEndpoint }
        { name: 'AZURE_OPENAI_KEY', value: azureOpenAIKey }
        { name: 'AZURE_OPENAI_DEPLOYMENT', value: azureOpenAIDeployment }
      ] : [])
    }
  }
}

output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output functionAppName string = functionApp.name
output managedIdentityPrincipalId string = functionApp.identity.principalId
