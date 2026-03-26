# Test Log Ingestion Plan — Purple Stratus Sentinel Sandbox

**Purpose**: Ingest realistic attack scenario logs into our Sentinel workspace so the threat hunt agent can be tested against diverse threat scenarios (ransomware, lateral movement, credential theft, etc.) beyond what organic telemetry provides.

**Approach**: One-time ingestion of all 5 datasets with timestamps shifted to the current week so `ago(7d)` / `ago(30d)` queries return results.

---

## Cost Estimate

| Pricing Tier | Rate | 1 GB | 5 GB | 10 GB |
|-------------|------|------|------|-------|
| **Pay-As-You-Go** | $5.20/GB | $5.20 | $26.00 | $52.00 |
| **Free trial** (first 31 days, new workspace) | $0/GB up to 10 GB/day | $0 | $0 | $0 |
| **Existing workspace (our case)** | $5.20/GB | $5.20 | $26.00 | $52.00 |

**All 5 datasets combined**: ~1.5-3 GB after conversion and dedup

**Estimated cost**: **$8-16 one-time**

**Cost control**: Ingest once with timestamps spread across the last 30 days. Default 90-day retention means the data stays queryable for 3 months. Re-run the ingestion script to refresh timestamps when they age out.

---

## Datasets (All 5)

### 1. Azure-Sentinel Sample Data (Microsoft Official)
- **Source**: [github.com/Azure/Azure-Sentinel/Sample Data](https://github.com/Azure/Azure-Sentinel/blob/master/Sample%20Data/README.md)
- **Format**: CSV/JSON, ready for Log Analytics ingestion
- **Coverage**: SecurityEvent, SigninLogs, AuditLogs, Syslog, OfficeActivity, DNS, firewall logs
- **Size**: ~500 MB
- **Why**: Maps directly to our existing Sentinel tables. Minimal transformation needed.

### 2. Mordor / Security Datasets (OTRF)
- **Source**: [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
- **Format**: JSON (pre-recorded Windows events mapped to MITRE ATT&CK)
- **Coverage**: Credential dumping, lateral movement, privilege escalation, persistence, defense evasion
- **Size**: ~200 MB (small datasets)
- **Why**: Real attack simulation data organized by ATT&CK tactic. Perfect for testing hypothesis-driven hunts.

### 3. EVTX-ATTACK-SAMPLES
- **Source**: [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- **Format**: EVTX (Windows Event Log), needs conversion to JSON
- **Coverage**: 200+ samples covering all ATT&CK tactics — credential access, lateral movement, execution, persistence, defense evasion, exfiltration
- **Size**: ~300 MB (converted JSON)
- **Why**: Most comprehensive single-source attack event collection. Ideal for detection rule testing.

### 4. EVTX-to-MITRE-Attack
- **Source**: [github.com/mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
- **Format**: EVTX mapped to MITRE, 270+ samples
- **Coverage**: Broader ATT&CK mapping including less common techniques
- **Size**: ~150 MB

### 5. SecRepo
- **Source**: [secrepo.com](https://www.secrepo.com/)
- **Format**: Various (PCAP, logs, malware samples)
- **Coverage**: Network traffic, malware, web logs
- **Size**: Variable (~200 MB curated selection)

---

## Ingestion Method

### DCR-based Log Ingestion API + Timestamp Shifting

**How it works:**
1. Python script downloads datasets from GitHub repos
2. Parses each event (JSON/CSV/EVTX)
3. Shifts all timestamps so events are spread across the last 30 days (relative to today)
4. Ingests via `azure-monitor-ingestion` SDK into custom tables in Sentinel

**Timestamp shifting logic:**
- Find the min/max timestamp in the original dataset
- Map the original time range onto `[now - 30d, now]`
- Each event gets a proportionally shifted `TimeGenerated`
- Result: `ago(7d)` returns the most recent ~25% of events, `ago(30d)` returns everything

**Custom tables created:**
| Custom Table | Source Dataset | Maps To |
|-------------|---------------|---------|
| `AttackSecurityEvent_CL` | Sentinel samples, EVTX-ATTACK, EVTX-MITRE | SecurityEvent |
| `AttackSigninLogs_CL` | Sentinel samples | SigninLogs |
| `AttackAuditLogs_CL` | Sentinel samples | AuditLogs |
| `AttackSyslog_CL` | Sentinel samples, Mordor | Syslog |
| `AttackNetworkLogs_CL` | SecRepo, Mordor | CommonSecurityLog / network |
| `MordorATTACK_CL` | Mordor datasets | Mixed (indexed by MITRE technique) |

**Why custom tables (not standard tables):**
- Avoids contaminating real production data
- Agent queries both `SecurityEvent` (real) and `AttackSecurityEvent_CL` (test) — can be toggled
- Easy cleanup: drop the custom tables when done

---

## Prerequisites (Azure Setup)

Before running the ingestion script:

### 1. Create a Data Collection Endpoint (DCE)
```bash
az monitor data-collection endpoint create \
  --name "mssp-test-data-dce" \
  --resource-group "mssp-hunt-agent-rg" \
  --location "eastus2" \
  --public-network-access "Enabled"
```

### 2. Create Custom Tables in Log Analytics
Done automatically by the ingestion script on first run (via DCR API).

### 3. Create Data Collection Rules (DCR)
One DCR per custom table, mapping source schema → table columns. The ingestion script creates these.

### 4. Grant Permissions
The Service Principal or Managed Identity needs:
- `Monitoring Metrics Publisher` role on the DCE
- `Log Analytics Contributor` on the workspace

---

## Ingestion Script

Location: `infra/ingest_test_data.py`

```
Usage:
  python infra/ingest_test_data.py --workspace-id <id> --dce-endpoint <url> --dcr-id <id>

Options:
  --datasets all|sentinel|mordor|evtx-attack|evtx-mitre|secrepo
  --days 30          # Spread timestamps across this many days
  --dry-run          # Download and transform only, don't ingest
```

---

## What This Enables for Agent Testing

| Threat Scenario | Dataset | Query Target |
|----------------|---------|-------------|
| Credential theft / Pass-the-Hash | Mordor, EVTX-ATTACK | `AttackSecurityEvent_CL` (4624, 4625, 4648, 4672) |
| Lateral movement (RDP, SMB, WinRM) | Mordor, EVTX-ATTACK | `AttackSecurityEvent_CL` (4624 type 3/10) |
| Ransomware precursors | EVTX-ATTACK, Sentinel samples | `AttackSecurityEvent_CL`, `AttackSyslog_CL` |
| Privilege escalation | Mordor | `AttackSecurityEvent_CL` (4672, 4728), `AttackAuditLogs_CL` |
| Persistence (scheduled tasks, services) | EVTX-ATTACK | `AttackSecurityEvent_CL` (4698, 7045) |
| Defense evasion (log clearing) | EVTX-ATTACK | `AttackSecurityEvent_CL` (1102) |
| Phishing / BEC indicators | Sentinel samples | `AttackSigninLogs_CL`, `AttackAuditLogs_CL` |
| C2 beaconing / network anomalies | SecRepo, Mordor | `AttackNetworkLogs_CL` |
| Broad MITRE coverage (270+ techniques) | EVTX-MITRE | `AttackSecurityEvent_CL` |

---

## Execution Plan

### Step 1: Get Kabir's Approval
- **Ask**: $8-16 one-time for 1.5-3 GB of test data
- **What we get**: Realistic attack data across all MITRE ATT&CK tactics
- **Retention**: 90 days, re-run script to refresh timestamps
- **Cleanup**: Drop custom tables when no longer needed

### Step 2: Azure Setup (~30 min)
- Create DCE, grant permissions
- Run `infra/ingest_test_data.py --dry-run` to validate

### Step 3: Ingest (~1-2 hours)
- Run `infra/ingest_test_data.py --datasets all --days 30`
- Verify in Sentinel: `AttackSecurityEvent_CL | count`

### Step 4: Update Agent Queries
- Add custom table awareness to the agent's system prompt
- Agent queries both real tables and `Attack*_CL` tables
- Or: use KQL `union` to combine real + test data

### Step 5: Test
- Run all 10 test prompts against the enriched data
- Run a full campaign — should now find actual attack patterns
- Validate learning engine captures findings from test data

---

## Refreshing the Data

When timestamps age out (after 90 days, or when `ago(30d)` stops returning results):

```bash
python infra/ingest_test_data.py --datasets all --days 30
```

This re-downloads, re-shifts timestamps to today, and re-ingests. Same cost applies (~$8-16).
