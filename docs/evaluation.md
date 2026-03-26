# Evaluation Results

## Live Evaluation (V7.2 — 2026-03-26)

110 prompts submitted to the live Azure Function endpoint. No mock adapters — real GPT-5.3, real Sentinel data, real threat intelligence feeds.

### Overall Scores

| Metric | Score |
|--------|-------|
| Completion | 110/110 (100%) |
| Correct Routing | 109/110 (99%) |
| Evidence-Grounded | 87/90 gradable (97%) |
| Actionable Response | 97/110 (88%) |

### By Category

| Category | Prompts | Pass Rate |
|----------|---------|-----------|
| CVE lookups | 5 | 100% |
| Sign-in queries | 10 | 100% |
| Identity/MFA | 5 | 100% |
| MITRE knowledge | 7 | 86% (knowledge-only queries scored lower on grounding) |
| Detection rules | 11 | 100% |
| Active hunts | 10 | 100% |
| AttackSimulation_CL | 10 | 100% |
| Telemetry/operational | 6 | 100% |
| Risk assessment | 7 | 100% |
| Real-world scenarios | 8 | 88% |
| Campaigns | 20 | 100% routing accuracy |

### Intelligence Enrichment Audit (50 prompts)

| Source | Score |
|--------|-------|
| EPSS / CVE enrichment | 10/10 (100%) |
| IP/domain/hash reputation | 15/15 (100%) |
| LOLBAS / LOLDrivers | 10/10 (100%) |
| Combined multi-source | 12/15 (80%) |
| Overall | 47/50 (94%) |

The 3 combined failures were iteration limit issues on complex multi-tool chains, not intelligence gaps.

### Intelligence Quality Audit (15 prompts)

| Dimension | Score |
|-----------|-------|
| KQL Quality | 9/10 — production-grade queries with proper filtering, joins, aggregation |
| Reasoning Depth | 8/10 — senior analyst-level investigation workflows |
| Assessment Accuracy | 9.5/10 — correct MITRE mappings, correct attack chain analysis |
| Knowledge Breadth | 9/10 (up from 7/10 after Tier 1 intel sources) |

### Routing Misroutes

| Prompt | Expected | Actual |
|--------|----------|--------|
| "Hunt for defense evasion techniques" | Chat | Campaign |
| "Identify attack paths from a compromised user account" | Chat | Campaign |

Both are borderline cases where single-topic requests used broad language.

## Test Methods

Evaluations used 7 classification dimensions:

1. **Correct Routing** — chat vs campaign classification accuracy
2. **Evidence-Grounded** — references specific Sentinel tables, event counts, entities
3. **Actionable Response** — ends with 2+ concrete next steps
4. **AttackSimulation Awareness** — queries AttackSimulation_CL when relevant
5. **MITRE Accuracy** — correct technique IDs and tactic mapping
6. **KQL Quality** — syntactically correct, operationally useful queries
7. **Completeness** — answers the full question without missing parts
