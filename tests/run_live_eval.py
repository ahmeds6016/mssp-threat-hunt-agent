"""Live evaluation runner — submits prompts to the live endpoint and grades responses."""

import json
import time

import requests

BASE = "https://mssphuntagent-fn.azurewebsites.net/api/v1"
KEY = "qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ=="

CHAT_PROMPTS = [
    # CVE lookups (5)
    "Are we vulnerable to CVE-2024-3400",
    "Are we vulnerable to CVE-2026-21262",
    "Look up CVE-2024-21887 and check if we are exposed",
    "Are we exposed to Log4Shell CVE-2021-44228",
    "What is the latest CVE affecting Microsoft Exchange",
    # Sign-in queries (10)
    "List all users who signed in the past 24 hours",
    "Any failed sign-ins in the last 24 hours",
    "Show me sign-in activity for ahmed.shiekhaden today",
    "Who has the most sign-ins in the last 7 days",
    "Any sign-ins from outside the US or India",
    "Any risky sign-ins flagged by Azure AD",
    "Show me all failed sign-ins with ResultType 50126",
    "Review sign-in patterns for ahmed.shiekhaden for the past month",
    "Any impossible travel detected in sign-in logs",
    "Which users are signing in from the most unique IP addresses",
    # Identity / MFA (5)
    "Is MFA enabled for all admin accounts",
    "Which admin accounts signed in without MFA this week",
    "How many users have Global Admin role",
    "Any new user accounts created in the last 7 days",
    "Any role assignments changed this week",
    # MITRE knowledge + coverage (7)
    "What MITRE techniques cover lateral movement",
    "What MITRE techniques cover credential access",
    "Explain T1003 OS Credential Dumping and our detection coverage",
    "What is T1059 and do we have detection for it",
    "Map T1078 Valid Accounts to our telemetry",
    "What techniques does APT29 use and are we covered",
    "What MITRE techniques cover initial access",
    # Detection rules (11)
    "Write a KQL detection rule for brute force attacks",
    "Create a detection rule for DCSync attacks",
    "Write a detection rule for password spraying",
    "Create a rule to detect suspicious PowerShell execution",
    "Write a KQL rule for detecting scheduled task persistence",
    "Build a detection for lateral movement via SMB",
    "Create a KQL rule for detecting new service installation",
    "Write a KQL detection rule for impossible travel",
    "Build a Sentinel KQL detection rule for LSASS credential dumping T1003",
    "Create a KQL rule to detect Kerberoasting activity",
    "Write a detection rule for Azure AD conditional access policy changes",
    # Active hunts (10)
    "Check for brute force attempts in the last 7 days",
    "Hunt for lateral movement in the last 7 days",
    "Check for privilege escalation attempts",
    "Any suspicious PowerShell activity",
    "Hunt for persistence mechanisms in the last 7 days",
    "Any indicators of ransomware activity",
    "Hunt for defense evasion techniques",
    "Check for Kerberoasting activity",
    "Search for DCSync activity in all data sources",
    "Check for data exfiltration indicators",
    # AttackSimulation_CL (10)
    "Hunt for UAC bypass or privilege escalation in our attack simulation data",
    "What attack scenarios exist in our AttackSimulation_CL table",
    "Search AttackSimulation_CL for T1003 credential dumping events",
    "How many attack simulation events do we have by MITRE tactic",
    "What lateral movement techniques are in our simulation data",
    "Show me all persistence techniques in AttackSimulation_CL",
    "What defense evasion scenarios do we have in simulation data",
    "Compare credential dumping activity in simulation data against real telemetry",
    "Are there any signs of credential dumping tools like mimikatz in our environment",
    "Hunt for all T1003 variants across both real and simulation data",
    # Telemetry / operational (6)
    "What log sources are we ingesting into Sentinel",
    "What data sources do we have for detecting credential theft",
    "How many events are we ingesting per day",
    "What tables have data in the last 7 days",
    "Is our Syslog connector healthy",
    "What devices are reporting to Defender for Endpoint",
    # Risk assessment (7)
    "How exposed are we to pass-the-hash attacks",
    "What if we lose our EDR coverage",
    "What is our risk if an admin account is compromised",
    "Assess our ransomware readiness",
    "Identify attack paths from a compromised user account",
    "What attack paths exist if our domain controller is compromised",
    "How would an attacker move laterally in our environment",
    # Real-world scenarios (8)
    "Stryker suffered a cyberattack where 200k devices were wiped. Do we have detection rules for mass deletion",
    "We just received a phishing report from an employee. What do I check",
    "An alert fired on DESKTOP-ABC123 for suspicious PowerShell. What do I do",
    "Our CEO account may be compromised. Walk me through the investigation",
    "A zero-day RCE in our VPN was just announced with no patch. What should we do",
    "We detected a potential C2 beacon. How do we investigate",
    "What is the current threat landscape for healthcare",
    "What are the top threats facing financial services",
    # Operational queries (9)
    "Any Azure resource changes in the last 24 hours",
    "Check for any conditional access policy changes",
    "Check for any suspicious app registrations in Azure AD",
    "Any Linux servers showing suspicious activity",
    "What Office 365 activity looks suspicious",
    "How many incidents do we have open in Sentinel",
    "What are the top 5 most common alert types this week",
    "Check for DNS tunneling indicators",
    "Give me a ransomware response playbook",
    # Health / meta (2)
    "Health check",
    "Are you connected to Sentinel",
]

CAMPAIGN_PROMPTS = [
    "Run a comprehensive threat hunt across credential theft lateral movement persistence and privilege escalation",
    "Do a comprehensive security posture review of our environment",
    "What threats are we missing in our environment",
    "Hunt for signs of business email compromise data exfiltration and insider threats across all data sources",
    "Do a deep dive into ransomware readiness defense evasion and command and control beaconing",
    "Run a full threat hunt across all attack vectors in our environment",
    "Comprehensive investigation into credential abuse privilege escalation and persistence mechanisms",
    "Hunt for advanced persistent threat activity across identity endpoint and network telemetry",
    "Assess our full MITRE ATT&CK coverage gaps and hunt for threats in uncovered areas",
    "Run a full security audit covering authentication anomalies lateral movement data exfiltration and insider threats",
    "Run a comprehensive threat hunt using both real telemetry and AttackSimulation_CL data to validate detection coverage",
    "Do a full assessment of ransomware kill chain coverage using our attack simulation baselines",
    "Comprehensive hunt for persistence and defense evasion across production logs and Mordor simulation data",
    "Run a full gap analysis comparing our Sentinel detections against the attack scenarios in AttackSimulation_CL",
    "Hunt for APT29 TTPs across all data sources including credential access lateral movement and data staging",
    "We suspect a breach occurred 2 weeks ago. Run a comprehensive investigation across all attack stages",
    "Run a comprehensive insider threat investigation across data exfiltration unusual access patterns and privilege abuse",
    "Full investigation into potential cloud compromise. Check Azure AD sign-ins conditional access bypasses and resource modifications",
    "Run a full threat hunt and produce an executive summary suitable for presenting to our CISO",
    "Hunt for all known attack techniques across every data source we have with maximum coverage",
]


def submit(prompt):
    try:
        r = requests.post(f"{BASE}/ask?code={KEY}", json={"message": prompt}, timeout=15)
        return r.json().get("request_id", "FAIL")
    except Exception as e:
        return f"FAIL:{e}"


def poll(req_id):
    try:
        r = requests.get(f"{BASE}/ask/{req_id}?code={KEY}", timeout=15)
        return r.json()
    except Exception:
        return {"status": "error"}


def grade(d, expected_route):
    resp = d.get("response", "") or ""
    route = d.get("route", "?")
    status = d.get("status", "?")
    camp = d.get("campaign_id", "")

    # Routing
    route_pass = route == expected_route

    # Evidence grounded
    tables = any(t in resp for t in [
        "SecurityEvent", "SigninLogs", "DeviceProcessEvents", "AttackSimulation",
        "AuditLogs", "Syslog", "CommonSecurityLog", "OfficeActivity", "AzureActivity",
    ])
    evidence = any(e in resp for e in [
        "0 events", "event", "count", "sign-in", "query", "queried",
        "checked", "Result", "found", "detected", "returned",
    ])
    if tables and evidence:
        grounding = "grounded"
    elif evidence:
        grounding = "partial"
    else:
        grounding = "ungrounded"

    # Campaign launches are exempt from grounding
    if expected_route == "campaign" and route == "campaign":
        grounding = "exempt"

    # Actionable
    actionable = any(a in resp for a in [
        "recommend", "next step", "deploy", "create", "enable",
        "investigate", "should", "rule", "detection", "action",
        "remediat", "mitigat", "CAMP-", "campaign",
    ])

    # AttackSimulation awareness
    sim_aware = "AttackSimulation" in resp or "simulation" in resp.lower() or "Mordor" in resp

    # KQL quality
    has_kql = "where" in resp and (
        "EventID" in resp or "TimeGenerated" in resp or
        "summarize" in resp or "SigninLogs" in resp
    )

    # MITRE accuracy (check for valid technique IDs)
    import re
    mitre_ids = re.findall(r"T\d{4}(?:\.\d{3})?", resp)
    has_mitre = len(mitre_ids) > 0

    # Completeness (response length as proxy — short responses may be incomplete)
    complete = len(resp) > 200 or (expected_route == "campaign" and camp)

    return {
        "status": status,
        "route": route,
        "route_pass": route_pass,
        "grounding": grounding,
        "actionable": actionable,
        "sim_aware": sim_aware,
        "has_kql": has_kql,
        "has_mitre": has_mitre,
        "complete": complete,
        "resp_len": len(resp),
        "campaign_id": camp,
    }


def run_eval(prompts, expected_route, label):
    print(f"\n{'='*60}")
    print(f"  EVAL {label}: {len(prompts)} prompts (expected: {expected_route})")
    print(f"{'='*60}")

    # Submit all
    req_ids = []
    for i, p in enumerate(prompts):
        rid = submit(p)
        req_ids.append(rid)
        if (i + 1) % 10 == 0:
            print(f"  Submitted {i+1}/{len(prompts)}...")

    # Wait
    wait = 120 if expected_route == "chat" else 30
    print(f"  Waiting {wait}s for responses...")
    time.sleep(wait)

    # Poll
    results = []
    for i, rid in enumerate(req_ids):
        d = poll(rid)
        if d.get("status") == "processing":
            time.sleep(30)
            d = poll(rid)
        if d.get("status") == "processing":
            time.sleep(30)
            d = poll(rid)
        g = grade(d, expected_route)
        g["i"] = i + 1
        g["prompt"] = prompts[i][:70]
        results.append(g)

    # Score
    total = len(results)
    completed = sum(1 for r in results if r["status"] == "completed")
    errors = total - completed
    route_pass = sum(1 for r in results if r["route_pass"])
    grounded = sum(1 for r in results if r["grounding"] == "grounded")
    partial = sum(1 for r in results if r["grounding"] == "partial")
    ungrounded = sum(1 for r in results if r["grounding"] == "ungrounded")
    exempt = sum(1 for r in results if r["grounding"] == "exempt")
    actionable = sum(1 for r in results if r["actionable"])
    sim_aware = sum(1 for r in results if r["sim_aware"])
    has_kql = sum(1 for r in results if r["has_kql"])
    has_mitre = sum(1 for r in results if r["has_mitre"])
    complete = sum(1 for r in results if r["complete"])

    gradable = total - exempt
    grounded_pct = ((grounded + partial) / gradable * 100) if gradable > 0 else 0

    print(f"\n{'='*60}")
    print(f"  SCORECARD: {label}")
    print(f"{'='*60}")
    print(f"  Completed:          {completed}/{total}")
    print(f"  Errors:             {errors}/{total}")
    print(f"  ---")
    print(f"  CORRECT ROUTING:    {route_pass}/{total} ({route_pass/total*100:.0f}%)")
    print(f"  EVIDENCE-GROUNDED:  {grounded} grounded + {partial} partial + {ungrounded} ungrounded + {exempt} exempt = {grounded_pct:.0f}% of gradable")
    print(f"  ACTIONABLE:         {actionable}/{total} ({actionable/total*100:.0f}%)")
    print(f"  SIM DATA AWARE:     {sim_aware}/{total}")
    print(f"  KQL IN RESPONSE:    {has_kql}/{total}")
    print(f"  MITRE REFERENCED:   {has_mitre}/{total}")
    print(f"  COMPLETE RESPONSE:  {complete}/{total}")

    # Show failures
    failures = [r for r in results if not r["route_pass"] or not r["actionable"] or r["grounding"] == "ungrounded" or r["status"] != "completed"]
    if failures:
        print(f"\n  --- ISSUES ({len(failures)}) ---")
        for r in failures:
            issues = []
            if not r["route_pass"]:
                issues.append(f"MISROUTE({r['route']})")
            if r["grounding"] == "ungrounded":
                issues.append("UNGROUNDED")
            if not r["actionable"]:
                issues.append("VAGUE")
            if r["status"] != "completed":
                issues.append(f"ERROR({r['status']})")
            if issues:
                print(f"  #{r['i']:3d} [{', '.join(issues)}] {r['prompt']}")

    return results


if __name__ == "__main__":
    print("MSSP Threat Hunt Agent — Live Evaluation")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Endpoint: {BASE}")
    print(f"Chat prompts: {len(CHAT_PROMPTS)}")
    print(f"Campaign prompts: {len(CAMPAIGN_PROMPTS)}")

    # Run chat eval
    chat_results = run_eval(CHAT_PROMPTS, "chat", "A: CHAT")

    # Run campaign eval
    campaign_results = run_eval(CAMPAIGN_PROMPTS, "campaign", "B: CAMPAIGNS")

    # Combined scorecard
    all_results = chat_results + campaign_results
    total = len(all_results)
    completed = sum(1 for r in all_results if r["status"] == "completed")
    route_pass = sum(1 for r in all_results if r["route_pass"])
    actionable = sum(1 for r in all_results if r["actionable"])

    print(f"\n{'='*60}")
    print(f"  COMBINED SCORECARD ({total} prompts)")
    print(f"{'='*60}")
    print(f"  Completed:       {completed}/{total} ({completed/total*100:.0f}%)")
    print(f"  Correct Routing: {route_pass}/{total} ({route_pass/total*100:.0f}%)")
    print(f"  Actionable:      {actionable}/{total} ({actionable/total*100:.0f}%)")
    print(f"  Zero Errors:     {'YES' if completed == total else 'NO'}")
