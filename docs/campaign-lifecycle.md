# Campaign Lifecycle

Campaigns are autonomous multi-phase threat investigations. They run in the background and produce executive-grade reports.

## When Campaigns Trigger

The GPT-5.3 complexity classifier routes to a campaign when:
- The request spans multiple ATT&CK tactics ("credential theft AND lateral movement")
- The request asks for comprehensive/full assessment
- The request uses words like "comprehensive", "full hunt", "posture review"

Single-topic requests ("check for brute force") stay in the chat path.

## Five Phases

### Phase 1: INDEX_REFRESH

Profiles the environment before hunting. Runs 40-60 KQL queries across 3 refresh layers:

- **Static (monthly)**: table discovery, column schemas, domain extraction
- **Semi-static (weekly)**: all users (UPN, roles, MFA, risk), all assets (hostname, OS, EDR), ingestion baselines, network context, security posture, connector health
- **Dynamic (per-hunt)**: 24h/7d/30d row counts, active incidents, recent changes

Output: `EnvironmentIndex` with `rich_summary()` — detailed JSON passed to all subsequent phases.

Index is cached per-client and reused across campaigns when fresh enough.

### Phase 2: HYPOTHESIZE

GPT-5.3 generates 10 prioritized threat hunt hypotheses. Each hypothesis:
- References specific Sentinel tables and columns from the index
- Names specific user accounts, assets, or MITRE techniques
- Includes a KQL approach outline
- Has a priority score (likelihood x feasibility x impact)

If prior campaigns exist, the learning engine injects context:
- Past confirmed threats (investigate more aggressively)
- Known false positive patterns (skip or deprioritize)
- Effective query patterns (reuse what worked)

### Phase 3: EXECUTE

For each hypothesis, runs a tool-calling loop with mandatory rules:
- Minimum 3 KQL queries before concluding
- Entity extraction after every query (IPs, users, devices, timestamps)
- Mandatory pivot on suspicious results using exact entity values
- Must try 2+ tables and 1 alternative explanation

Available tools: `run_kql_query`, `validate_kql`, `search_mitre`, `lookup_cve`, `assess_risk`, `identify_attack_paths`

Typical output: 30-60 KQL queries total, 5-10 findings across all hypotheses.

### Phase 4: CONCLUDE

Classifies each finding:
- **True Positive**: real evidence of threat activity
- **False Positive**: explainable, benign
- **Inconclusive**: anomalous but needs further investigation

Documents evidence chain, MITRE technique, severity, and affected entities for each.

### Phase 5: DELIVER

Generates the executive report:
1. Executive summary (business-readable)
2. Environment overview
3. Findings by severity with evidence and MITRE mapping
4. Detection rules to deploy
5. MITRE ATT&CK coverage assessment
6. Prioritized action plan (immediate, short-term, future)

## Recursive Learning

After completion, `CampaignLearningEngine` extracts lessons:
- `productive_hypothesis` — led to a true positive
- `false_positive_pattern` — confirmed benign, skip next time
- `effective_query` — KQL that produced results
- `technique_relevance` — which techniques matter for this environment

Lessons persist in SQLite. The next campaign loads them during the hypothesize and execute phases.

## Typical Campaign Stats

| Metric | Range |
|--------|-------|
| Duration | 5-15 minutes |
| Hypotheses | 10 |
| KQL queries | 26-61 |
| Findings | 5-10 |
| Report length | 3,000-8,000 characters |
