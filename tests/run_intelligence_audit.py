"""Intelligence quality audit — tests KQL sophistication, reasoning depth, and assessment accuracy."""

import json
import os
import time

import requests

os.environ["PYTHONIOENCODING"] = "utf-8"

BASE = "https://mssphuntagent-fn.azurewebsites.net/api/v1"
KEY = "qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ=="

PROMPTS = [
    # === KQL SOPHISTICATION (5) ===
    "Write a KQL detection rule for Kerberoasting that filters out legitimate service ticket requests and reduces false positives",
    "Create an advanced KQL rule that detects DCSync by correlating EventID 4662 with replication GUIDs and excludes domain controllers",
    "Build a KQL query that detects impossible travel using geodistance calculations between consecutive sign-ins for the same user",
    "Write a KQL rule to detect golden ticket attacks using Kerberos TGT anomalies",
    "Create a KQL correlation rule that links a brute force attempt to a successful login within 30 minutes from the same source IP",
    # === REASONING DEPTH (5) ===
    "We found 3 failed logins from IP 185.220.101.42 followed by a successful login 10 minutes later. Assess the risk and tell me exactly what to investigate next",
    "An admin account signed in from both New York and Mumbai within 2 hours. The account has no MFA. Walk me through the full investigation",
    "We see a service account svc-backup authenticating via NTLM instead of Kerberos to 5 different servers in 10 minutes. Is this malicious",
    "SigninLogs show 50 failed logins across 20 different accounts from the same IP in 5 minutes. What attack is this and how do we respond",
    "A user ran powershell.exe -enc followed by a base64 string. The parent process was outlook.exe. What happened and what do I do",
    # === ASSESSMENT ACCURACY (5) ===
    "How would you determine if a Conditional Access bypass alert is a true positive versus a false positive",
    "What is the difference between a golden ticket attack and a silver ticket attack and how would you detect each in Sentinel",
    "Explain the full attack chain for ransomware from initial access to encryption and map each stage to MITRE techniques and Sentinel tables",
    "What are the indicators that distinguish credential stuffing from password spraying in sign-in logs",
    "How would you detect a compromised service principal in Azure AD. What specific logs and fields would you check",
]

CATEGORIES = [
    "KQL", "KQL", "KQL", "KQL", "KQL",
    "REASONING", "REASONING", "REASONING", "REASONING", "REASONING",
    "ASSESSMENT", "ASSESSMENT", "ASSESSMENT", "ASSESSMENT", "ASSESSMENT",
]


def main():
    print("=" * 70)
    print("  MSSP Threat Hunt Agent — Intelligence Quality Audit")
    print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Submit all
    print(f"\nSubmitting {len(PROMPTS)} audit prompts...")
    rids = []
    for i, p in enumerate(PROMPTS):
        try:
            r = requests.post(f"{BASE}/ask?code={KEY}", json={"message": p}, timeout=15)
            rid = r.json().get("request_id", "FAIL")
        except Exception as e:
            rid = f"FAIL:{e}"
        rids.append(rid)
        print(f"  {i+1}: {rid}")

    print("\nWaiting 180s for complex responses...")
    time.sleep(180)

    # Poll and dump
    results = []
    for i, rid in enumerate(rids):
        try:
            r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
            d = r.json()
        except Exception:
            d = {"status": "error"}

        if d.get("status") == "processing":
            print(f"  #{i+1} still processing, waiting 60s...")
            time.sleep(60)
            try:
                r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
                d = r.json()
            except Exception:
                d = {"status": "error"}

        resp = d.get("response", "") or ""
        status = d.get("status", "?")
        route = d.get("route", "?")

        results.append({
            "i": i + 1,
            "category": CATEGORIES[i],
            "prompt": PROMPTS[i],
            "status": status,
            "route": route,
            "response": resp,
            "len": len(resp),
        })

        print(f"\n{'=' * 70}")
        print(f"#{i+1} [{CATEGORIES[i]}] | {status} | len={len(resp)}")
        print(f"PROMPT: {PROMPTS[i][:80]}")
        print(f"RESPONSE (first 1200 chars):")
        safe = resp[:1200].encode("ascii", "replace").decode()
        print(safe)

    # Summary
    print(f"\n{'=' * 70}")
    print("  AUDIT SUMMARY")
    print(f"{'=' * 70}")

    completed = sum(1 for r in results if r["status"] == "completed")
    print(f"Completed: {completed}/{len(results)}")

    for cat in ["KQL", "REASONING", "ASSESSMENT"]:
        cat_results = [r for r in results if r["category"] == cat]
        cat_completed = sum(1 for r in cat_results if r["status"] == "completed")
        avg_len = sum(r["len"] for r in cat_results) // max(len(cat_results), 1)
        print(f"\n{cat} ({cat_completed}/{len(cat_results)} completed, avg {avg_len} chars):")
        for r in cat_results:
            resp = r["response"]
            has_kql = "where" in resp and ("EventID" in resp or "TimeGenerated" in resp or "summarize" in resp)
            has_mitre = "T1" in resp
            has_evidence = any(e in resp for e in ["query", "checked", "event", "Result", "found"])
            has_action = any(a in resp for a in ["recommend", "should", "deploy", "investigate", "action", "next step"])
            print(f"  #{r['i']:2d} len={r['len']:4d} kql={has_kql} mitre={has_mitre} evidence={has_evidence} actionable={has_action}")


if __name__ == "__main__":
    main()
