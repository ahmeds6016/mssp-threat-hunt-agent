"""Live evaluation runner - submits test prompts to deployed agent and grades responses.

Usage:
    python tests/run_live_eval.py
    python tests/run_live_eval.py --batch-size 5 --max-questions 10
    python tests/run_live_eval.py --csv tests/eval_quick_functional.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

BASE_URL = "https://mssphuntagent-fn.azurewebsites.net"
FK = "qvMa0mwbfz3itHZMO20kbkWfpAr-oY9_1WHmJpFeK2EmAzFuK-xiGQ=="
ASK_URL = f"{BASE_URL}/api/v1/ask?code={FK}"
POLL_TPL = BASE_URL + "/api/v1/ask/{rid}?code=" + FK
MAX_POLL = 180
POLL_INT = 10


@dataclass
class Grade:
    evidence_grounded: bool = False
    actionable: bool = False
    correct_routing: bool = False
    complete: bool = False
    professional: bool = False
    notes: list = field(default_factory=list)

    @property
    def score(self):
        return sum([
            self.evidence_grounded, self.actionable,
            self.correct_routing, self.complete, self.professional,
        ])


@dataclass
class EvalResult:
    question: str
    expected: str
    response: str = ""
    route: str = ""
    status: str = ""
    request_id: str = ""
    elapsed_s: float = 0.0
    error: str = ""
    grade: Grade = field(default_factory=Grade)


EV_KW = [
    "SecurityEvent", "SigninLogs", "DeviceProcessEvents", "Syslog",
    "AttackSimulation_CL", "EventID", "TimeGenerated", "KQL",
    "| where", "| summarize", "| take", "| count", "| project",
    "events", "results", "queries", "0 events", "T1003", "T1021",
    "T1053", "T1059", "T1110", "T1218", "T1547", "T1558", "CVE-",
    "ago(", "count()", "dcount(",
]
AC_KW = [
    "| where", "| summarize", "| take", "| project", "KQL",
    "detection rule", "analytic rule", "recommend", "next steps",
    "deploy", "enable", "configure", "investigate", "block",
    "monitor", "alert", "DeviceProcessEvents", "SecurityEvent", "SigninLogs",
]
FILLER = [
    "great question", "happy to help", "glad you asked",
    "sure thing", "no problem", "let me help you with that",
]
CAMP_Q = [
    "hunt for lateral movement and credential access",
    "run a comprehensive assessment across all mitre tactics",
    "trace complete attack chains",
    "hunt for credential theft to lateral movement",
    "conduct a full spectrum threat assessment",
    "hunt for defense evasion and privilege escalation techniques across",
    "hunt for all persistence techniques",
    "hunt for advanced persistent threat activity",
    "hunt for all credential access techniques",
    "hunt for the full kill chain",
    "hunt for supply chain attack indicators",
    "hunt for insider threat indicators",
]
GREET_Q = [
    "hi", "hello, what can you do?", "thanks for the help",
    "can you help me with something unrelated to security?",
    "what version are you running?",
]


def is_camp(q):
    return any(k in q.lower() for k in CAMP_Q)


def is_greet(q):
    return q.lower().strip() in GREET_Q


def grade_response(r):
    g = Grade()
    resp = r.response.lower()
    ev = sum(1 for k in EV_KW if k.lower() in resp)
    ac = sum(1 for k in AC_KW if k.lower() in resp)

    # Evidence-Grounded
    if is_greet(r.question):
        g.evidence_grounded = True
        g.actionable = True
        g.notes.append("Greeting")
    else:
        if ev >= 3:
            g.evidence_grounded = True
        else:
            g.notes.append(f"Low evidence ({ev})")
        if ac >= 2:
            g.actionable = True
        else:
            g.notes.append(f"Low actionability ({ac})")

    # Correct Routing
    if is_greet(r.question):
        g.correct_routing = True
    elif is_camp(r.question):
        if r.route == "campaign" or "camp-" in resp or "campaign" in resp:
            g.correct_routing = True
        else:
            g.notes.append(f"Expected campaign, got {r.route}")
    else:
        if r.route in ("chat", "") or r.status == "completed":
            g.correct_routing = True
        else:
            g.notes.append(f"Expected chat, got {r.route}")

    # Completeness
    if is_greet(r.question):
        g.complete = bool(r.response.strip())
    elif r.error:
        g.notes.append(f"Error: {r.error[:80]}")
    elif len(r.response) < 50:
        g.notes.append(f"Too short ({len(r.response)})")
    else:
        ew = [w.lower() for w in r.expected.split() if len(w) > 4]
        mp = sum(1 for w in ew if w in resp) / max(len(ew), 1)
        if mp >= 0.2 or len(r.response) > 200:
            g.complete = True
        else:
            g.notes.append(f"Low keyword match ({mp:.0%})")

    # Professional Tone
    fl = sum(1 for p in FILLER if p in resp)
    if fl == 0:
        g.professional = True
    else:
        g.notes.append(f"Filler ({fl})")

    return g


def submit(cl, q):
    r = cl.post(ASK_URL, json={"message": q}, timeout=30)
    return r.json().get("request_id", "")


def poll(cl, rid):
    url = POLL_TPL.format(rid=rid)
    t0 = time.time()
    while time.time() - t0 < MAX_POLL:
        time.sleep(POLL_INT)
        r = cl.get(url, timeout=30)
        d = r.json()
        if d.get("status") != "processing":
            return d
    return {"status": "timeout", "error": "Polling timed out"}


def run_one(cl, q, exp):
    r = EvalResult(question=q, expected=exp)
    t0 = time.time()
    try:
        rid = submit(cl, q)
        r.request_id = rid
        if not rid:
            r.error = "No request_id"
            r.elapsed_s = time.time() - t0
            return r
        d = poll(cl, rid)
        r.status = d.get("status", "")
        r.route = d.get("route", "")
        r.response = d.get("response", "")
        r.error = d.get("error", "")
        if r.route == "campaign":
            cid = d.get("campaign_id", "")
            if cid:
                r.response = f"Campaign {cid} launched. {r.response}"
    except Exception as e:
        r.error = str(e)
    r.elapsed_s = time.time() - t0
    return r


def load_csv(p):
    qs = []
    with open(p, "r", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 2 and row[0] != "question":
                qs.append((row[0].strip(), row[1].strip()))
    return qs


def run_eval(csv_path, batch_size=10, max_q=0, out_dir="tests/eval_results"):
    qs = load_csv(csv_path)
    if max_q > 0:
        qs = qs[:max_q]
    total = len(qs)
    sep = "=" * 70
    print(f"\n{sep}")
    print("MSSP Threat Hunt Agent - Live Evaluation")
    print(sep)
    print(f"Questions: {total} | Batch: {batch_size} | Endpoint: {BASE_URL}")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}\n")

    cl = httpx.Client()
    results = []

    for bs in range(0, total, batch_size):
        be = min(bs + batch_size, total)
        bn = bs // batch_size + 1
        tb = (total + batch_size - 1) // batch_size
        print(f"\n--- Batch {bn}/{tb} ({bs+1}-{be}) ---\n")
        for i, (q, exp) in enumerate(qs[bs:be]):
            idx = bs + i + 1
            sq = q[:60] + ("..." if len(q) > 60 else "")
            print(f"  [{idx:3d}/{total}] {sq}")
            r = run_one(cl, q, exp)
            r.grade = grade_response(r)
            ic = "PASS" if r.grade.score >= 4 else "WARN" if r.grade.score >= 3 else "FAIL"
            rl = len(r.response)
            print(f"           {ic} {r.grade.score}/5 | {r.elapsed_s:.1f}s | route={r.route or 'n/a'} | len={rl}")
            for n in r.grade.notes[:3]:
                print(f"           -> {n}")
            if r.error:
                print(f"           ERROR: {r.error[:100]}")
            results.append(r)
        if be < total:
            print("\n  Pausing 5s...")
            time.sleep(5)
    cl.close()

    tr = len(results)
    er = sum(1 for r in results if r.error)
    to = sum(1 for r in results if r.status == "timeout")
    ep = sum(1 for r in results if r.grade.evidence_grounded)
    ap = sum(1 for r in results if r.grade.actionable)
    rp = sum(1 for r in results if r.grade.correct_routing)
    cp = sum(1 for r in results if r.grade.complete)
    pp = sum(1 for r in results if r.grade.professional)
    av = sum(r.grade.score for r in results) / max(tr, 1)
    at = sum(r.elapsed_s for r in results) / max(tr, 1)

    print(f"\n{sep}")
    print("EVALUATION SUMMARY")
    print(f"{sep}\n")
    print(f"  Total: {tr} | Errors: {er} | Timeouts: {to} | Avg time: {at:.1f}s | Avg score: {av:.1f}/5 ({av/5*100:.0f}%)\n")
    for label, val in [
        ("Evidence-Grounded:", ep), ("Actionable Output:", ap),
        ("Correct Routing:", rp), ("Response Completeness:", cp),
        ("Professional Tone:", pp),
    ]:
        print(f"  {label:<25} {val}/{tr} ({val/max(tr,1)*100:.0f}%)")
    print()

    dist = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for r in results:
        dist[r.grade.score] = dist.get(r.grade.score, 0) + 1
    print("  SCORE DISTRIBUTION:")
    labels = {5: "PERFECT", 4: "GOOD", 3: "OK", 2: "POOR", 1: "BAD", 0: "BAD"}
    for s in sorted(dist.keys(), reverse=True):
        print(f"    {s}/5 ({labels[s]:>7}): {dist[s]:3d} {'#' * dist[s]}")

    worst = sorted(results, key=lambda r: r.grade.score)[:10]
    if worst and worst[0].grade.score < 4:
        print(f"\n  LOWEST SCORING:")
        for r in worst:
            if r.grade.score >= 4:
                break
            print(f"    [{r.grade.score}/5] {r.question[:70]}")
            for n in r.grade.notes[:2]:
                print(f"           -> {n}")

    # Save results
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    jp = os.path.join(out_dir, f"eval_{ts}.json")
    rpt = {
        "timestamp": ts, "total": tr, "errors": er, "timeouts": to,
        "avg_time": round(at, 1), "avg_score": round(av, 2),
        "criteria": {
            "evidence": {"pass": ep, "pct": round(ep / max(tr, 1) * 100)},
            "actionable": {"pass": ap, "pct": round(ap / max(tr, 1) * 100)},
            "routing": {"pass": rp, "pct": round(rp / max(tr, 1) * 100)},
            "completeness": {"pass": cp, "pct": round(cp / max(tr, 1) * 100)},
            "professional": {"pass": pp, "pct": round(pp / max(tr, 1) * 100)},
        },
        "distribution": dist,
        "results": [{
            "q": r.question, "exp": r.expected, "resp": r.response[:2000],
            "route": r.route, "status": r.status, "rid": r.request_id,
            "time": round(r.elapsed_s, 1), "err": r.error,
            "grade": {
                "score": r.grade.score, "ev": r.grade.evidence_grounded,
                "ac": r.grade.actionable, "rt": r.grade.correct_routing,
                "cp": r.grade.complete, "pr": r.grade.professional,
                "notes": r.grade.notes,
            },
        } for r in results],
    }
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(rpt, f, indent=2, default=str)

    cp2 = os.path.join(out_dir, f"eval_{ts}.csv")
    with open(cp2, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "Question", "Score", "Evidence", "Actionable", "Routing",
            "Complete", "Professional", "Route", "Time", "Status", "Error", "Notes",
        ])
        for r in results:
            w.writerow([
                r.question[:100], r.grade.score,
                "P" if r.grade.evidence_grounded else "F",
                "P" if r.grade.actionable else "F",
                "P" if r.grade.correct_routing else "F",
                "P" if r.grade.complete else "F",
                "P" if r.grade.professional else "F",
                r.route, round(r.elapsed_s, 1), r.status,
                r.error[:80], "; ".join(r.grade.notes[:3]),
            ])

    print(f"\n  JSON: {jp}")
    print(f"  CSV:  {cp2}")
    print(f"\n{sep}")
    print(f"OVERALL: {av:.1f}/5 ({av/5*100:.0f}%)")
    print(f"{sep}\n")


if __name__ == "__main__":
    pa = argparse.ArgumentParser()
    pa.add_argument("--csv", default="tests/eval_quick_functional.csv")
    pa.add_argument("--batch-size", type=int, default=10)
    pa.add_argument("--max-questions", type=int, default=0)
    pa.add_argument("--output-dir", default="tests/eval_results")
    a = pa.parse_args()
    run_eval(a.csv, a.batch_size, a.max_questions, a.output_dir)
