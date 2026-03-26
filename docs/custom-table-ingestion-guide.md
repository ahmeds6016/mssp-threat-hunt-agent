# Custom Table Log Ingestion Guide — Microsoft Sentinel

How to create custom tables in Sentinel and ingest data via the DCR Log Ingestion API. This is the modern approach Microsoft recommends for bringing external or simulated data into Log Analytics.

## Architecture

```
Data Source (GitHub repos, APIs, scripts)
    → Python script (download + transform)
    → DCR Log Ingestion API
    → Data Collection Endpoint (DCE)
    → Data Collection Rule (DCR) — schema + destination mapping
    → Log Analytics Custom Table (e.g., AttackSimulation_CL)
    → Queryable in Sentinel via KQL
```

### Components

| Component | What it does |
|-----------|-------------|
| **Data Collection Endpoint (DCE)** | HTTPS endpoint that accepts log data. Think of it as the "front door" for ingestion. |
| **Data Collection Rule (DCR)** | Defines the schema (what columns the data has), the destination (which workspace/table), and optional KQL transformations. |
| **Custom Table** | The table in Log Analytics where data lands. Always ends in `_CL`. |
| **Monitoring Metrics Publisher** | RBAC role required on the DCR for the identity pushing data. Contributor alone isn't enough. |

## Prerequisites

Before starting, make sure you have the following:

- **Azure CLI** installed and logged in (`az login`)
- **Python 3.10+** with packages: `azure-identity`, `azure-monitor-ingestion`, `requests`
- **Contributor** role on the target resource group (for creating DCE, table, DCR)
- **Monitoring Metrics Publisher** role on the DCR (for actually pushing data)

> **Important**: Contributor alone is NOT enough to ingest data. You need **Monitoring Metrics Publisher** specifically scoped to the Data Collection Rule. This is a data plane permission that must be granted by an **Owner** or **User Access Administrator** on the resource group.
>
> If you don't have Owner access, request it from your admin:
> 1. Go to **Azure Portal** → **Data collection rules** → select your DCR
> 2. **Access control (IAM)** → **+ Add** → **Add role assignment**
> 3. Role: **Monitoring Metrics Publisher** → Next
> 4. **+ Select members** → search for the user or service principal → Select → Review + assign
>
> Role assignments can take 5-10 minutes to propagate. If you get 403 errors after assignment, wait and retry.

## Step-by-Step Setup

### 1. Create a Data Collection Endpoint (DCE)

The DCE is the HTTPS ingestion endpoint that your script sends data to.

#### Portal

1. Go to **Azure Portal** → search **"Data collection endpoints"** → **Create**
2. Fill in:
   - **Name**: `mssp-hunt-agent-dce`
   - **Subscription**: Advisory-01
   - **Resource group**: `adv01-eastus-vnet-1-rg`
   - **Region**: East US (must match workspace region)
3. **Review + Create** → **Create**
4. Once created, open the DCE → **Overview** → note the **Logs Ingestion URI** (you'll need this later):
   `https://mssp-hunt-agent-dce-xxxx.eastus-1.ingest.monitor.azure.com`

#### CLI

```bash
az monitor data-collection endpoint create \
  --name mssp-hunt-agent-dce \
  --resource-group adv01-eastus-vnet-1-rg \
  --location eastus \
  --public-network-access Enabled
```

### 2. Create a Custom Table + DCR (Portal — Recommended)

The portal wizard creates the table and DCR together in one flow.

**Navigate to**: Azure Portal → **Log Analytics workspaces** → `adv01-eastus-logspace-1` → **Tables** → **Create** → **New custom log (DCR-based)**

#### Step 1: Basics

| Field | Value |
|-------|-------|
| **Table name** | `AttackSimulation` (portal auto-appends `_CL`) |
| **Description** | "Curated attack simulation data from Mordor/OTRF for threat hunt testing" |
| **Table plan** | **Analytics** (supports full KQL — choose this for Sentinel hunting) |
| **Data collection rule** | Click **Create a new data collection rule** |
| **DCR name** | `mssp-hunt-agent-attack-sim` |
| **DCR subscription** | Advisory-01 |
| **DCR resource group** | `adv01-eastus-vnet-1-rg` |
| **Data collection endpoint** | Select the DCE created in Step 1 (`mssp-hunt-agent-dce`) |

Click **Next**.

#### Step 2: Schema and transformation

The portal asks you to upload a **sample file** so it can auto-detect the schema. Upload a sample JSON file with one event:

```json
[
  {
    "TimeGenerated": "2026-03-18T12:00:00Z",
    "SourceSystem": "Mordor - DCSync",
    "Computer": "YOURPC.contoso.local",
    "EventID": 4662,
    "Channel": "Security",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "EventData": "{}",
    "MitreTactic": "Credential Access",
    "MitreTechnique": "T1003.006",
    "AttackScenario": "DCSync via DRS",
    "Severity": "Medium",
    "ProcessName": "lsass.exe",
    "ProcessId": 1234,
    "ParentProcessName": "services.exe",
    "CommandLine": "",
    "User": "contoso\\admin",
    "SourceIP": "10.0.0.5",
    "DestinationIP": "10.0.0.1",
    "DestinationPort": 445,
    "LogonType": 3,
    "RawEvent": "{}"
  }
]
```

After uploading:
1. The portal auto-detects columns from the JSON
2. **Review each column** — verify types are correct:
   - `TimeGenerated` → **datetime**
   - `EventID`, `ProcessId`, `DestinationPort`, `LogonType` → **int**
   - Everything else → **string**
3. **Transformation editor** shows a KQL box. Leave it as `source` (passthrough, no transformation needed)
4. Click **Next**

#### Step 3: Review + Create

Review the summary:
- Table: `AttackSimulation_CL`
- Plan: Analytics
- DCR: `mssp-hunt-agent-attack-sim`
- DCE: `mssp-hunt-agent-dce`
- Columns: all listed

Click **Create**. Wait 1-2 minutes for provisioning.

#### Table plan options explained

| Plan | Use case | KQL support | Cost |
|------|----------|-------------|------|
| **Analytics** | Active hunting, alerting, Sentinel rules | Full KQL | $5.20/GB |
| **Basic** | Compliance/archive, occasional search | Limited (no joins, no alerts) | $1.04/GB |
| **Auxiliary/Lake** | Long-term storage, rare access | Search only | $0.13/GB |

For threat hunting, always use **Analytics**.

### 2b. Create via CLI (Alternative)

If you prefer CLI or need to script it:

```bash
# Create table
az monitor log-analytics workspace table create \
  --workspace-name adv01-eastus-logspace-1 \
  --resource-group adv01-eastus-vnet-1-rg \
  --name AttackSimulation_CL \
  --retention-time 90 \
  --total-retention-time 90 \
  --columns TimeGenerated=datetime SourceSystem=string Computer=string \
            EventID=int Channel=string Provider=string EventData=string \
            MitreTactic=string MitreTechnique=string AttackScenario=string \
            Severity=string ProcessName=string ProcessId=int \
            ParentProcessName=string CommandLine=string User=string \
            SourceIP=string DestinationIP=string DestinationPort=int \
            LogonType=int RawEvent=string

# Create DCR via REST API (CLI doesn't support custom stream declarations)
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{dcr-name}?api-version=2022-06-01" \
  --body @dcr_body.json \
  --headers "Content-Type=application/json"
```

### Key rules

- Table name **must** end in `_CL` (portal auto-appends it)
- `TimeGenerated` column is **required** (datetime) — Sentinel uses this for all time filtering
- Retention defaults to 90 days, adjustable up to 730 days
- Column types: `string`, `int`, `long`, `real`, `bool`, `datetime`, `guid`, `dynamic`
- **Stream name** in the DCR must be `Custom-{TableName}` (e.g., `Custom-AttackSimulation_CL`)
- **Stream columns** in the DCR must exactly match the table columns (names and types)
- **transformKql**: Use `"source"` for passthrough. You can add KQL here to filter, rename, or enrich data during ingestion.

### 3. Ingest Data via Python

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

credential = DefaultAzureCredential()
client = LogsIngestionClient(
    endpoint="https://mssp-hunt-agent-dce-xxxx.eastus-1.ingest.monitor.azure.com",
    credential=credential,
)

# Events must match the stream schema
events = [
    {
        "TimeGenerated": "2026-03-18T15:30:00.000Z",
        "SourceSystem": "AttackSimulation",
        "Computer": "WORKSTATION-01",
        "EventID": 4688,
        "MitreTactic": "Execution",
        "MitreTechnique": "T1059.001",
        "CommandLine": "powershell.exe -enc SQBFAFgA...",
        "User": "contoso\\admin",
        "RawEvent": "{...full event json...}",
    }
]

# Upload in batches (API limit ~1MB per request, ~500 events per batch)
client.upload(
    rule_id="dcr-xxxxxxxxxxxxx",    # DCR immutable ID
    stream_name="Custom-AttackSimulation_CL",
    logs=events,
)
```

Required packages:
```bash
pip install azure-identity azure-monitor-ingestion
```

Authentication: `DefaultAzureCredential` tries (in order):
1. Environment variables (service principal)
2. Managed Identity (if running in Azure)
3. Azure CLI (`az login`)
4. Visual Studio / VS Code credentials

### 4. Verify in Sentinel

Data takes **5-10 minutes** to appear after ingestion. Query:

```kql
AttackSimulation_CL
| summarize Count=count() by MitreTactic
| order by Count desc
```

## How Our Ingestion Script Works

The script at `infra/ingest_test_data.py` automates all of this:

```bash
# First time — creates DCE, table, DCR
python infra/ingest_test_data.py --setup

# Download attack datasets, shift timestamps, ingest
python infra/ingest_test_data.py --ingest

# Verify data landed
python infra/ingest_test_data.py --verify

# Or do everything at once
python infra/ingest_test_data.py --all
```

### What it does

1. **Downloads** curated attack datasets from the OTRF/Security-Datasets GitHub repo (Mordor project) — real Windows security events from simulated attacks
2. **Spreads timestamps** across the last 30 days so `ago(7d)`, `ago(14d)`, and `ago(30d)` KQL queries all find data
3. **Normalizes** events into a consistent schema (EventID, Computer, User, CommandLine, MITRE mapping)
4. **Ingests** via DCR API in batches of 500

### Datasets included

| Dataset | Tactic | Technique | What it simulates |
|---------|--------|-----------|-------------------|
| DCSync via DRS | Credential Access | T1003.006 | Domain replication to steal password hashes |
| Mimikatz LogonPasswords | Credential Access | T1003.001 | LSASS memory credential dumping |
| Mimikatz SAM Access | Credential Access | T1003.002 | SAM database credential extraction |
| WMI Event Subscription | Lateral Movement | T1047 | Remote code exec via WMI subscriptions |
| PSRemoting Grunt | Lateral Movement | T1021.006 | PowerShell remoting for C2 |
| WMIC Backdoor User | Lateral Movement | T1047 | WMIC adding backdoor accounts |
| VBS Launcher | Execution | T1059.005 | VBScript-based payload execution |
| PowerShell HTTP Listener | Execution | T1059.001 | PowerShell reverse shell / C2 |
| Scheduled Task | Persistence | T1053.005 | schtasks-based persistence |
| UAC Bypass FodHelper | Privilege Escalation | T1548.002 | UAC bypass via fodhelper.exe |
| Service Modification | Privilege Escalation | T1543.003 | Service binary path manipulation |
| InstallUtil | Defense Evasion | T1218.004 | LOLBin .NET InstallUtil bypass |
| Disable Event Log | Defense Evasion | T1562.002 | Disabling Windows event logging |
| LOLBin wuauclt | Defense Evasion | T1218 | Living-off-the-land binary abuse |

### Timestamp spreading

Original datasets have timestamps from 2019-2020. The script maps them proportionally onto the last 30 days:

```
Original:  [2020-01-01 ............... 2020-01-03]
Mapped to: [2026-02-16 ............... 2026-03-18]
```

Events that were close together stay close together. Events that were far apart stay proportionally far apart. This preserves the attack sequence timing while making the data fresh for Sentinel queries.

### Re-ingestion

Data has 90-day retention. Re-run `--ingest` monthly to keep fresh data in the query window. The script re-downloads and re-shifts timestamps each time.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `403 - does not have access to ingest` | Need Monitoring Metrics Publisher role on the DCR |
| `404 - table not found` | Wait 2-3 min after table creation, or check table name ends in `_CL` |
| `400 - schema mismatch` | Stream columns in DCR must exactly match table columns (names and types) |
| Data not appearing after ingest | Wait 5-10 min. Check DCR dataFlows outputStream matches table name |
| `ContentLengthExceeded` | Reduce batch size (default 500, try 100) |

## Cost

- **Pay-as-you-go**: $5.20/GB ingested
- Our datasets: ~200-500 MB per ingestion run → **$1-3 per run**
- Retention: 90 days (included in workspace plan)
- Monthly re-ingestion: **$1-3/month**

## References

- [Logs Ingestion API overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [Tutorial: Send data via Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)
- [Data Collection Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview)
- [OTRF Security Datasets (Mordor)](https://github.com/OTRF/Security-Datasets)
