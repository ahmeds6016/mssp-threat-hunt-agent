"""Attack path analysis — maps ATT&CK technique chains to client capabilities."""

from __future__ import annotations

import uuid

from mssp_hunt_agent.threat_model.models import AttackPath


# Common attack path templates: (entry_point, technique_chain, required_data_sources)
_ATTACK_PATH_TEMPLATES: list[dict] = [
    {
        "entry": "Phishing email",
        "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1003", "T1021.001"],
        "required_sources": {
            "T1566.001": ["DeviceProcessEvents"],
            "T1204.002": ["DeviceProcessEvents"],
            "T1059.001": ["DeviceProcessEvents"],
            "T1003": ["DeviceProcessEvents"],
            "T1021.001": ["SecurityEvent"],
        },
        "targets": ["Domain Controller", "File Server"],
    },
    {
        "entry": "Exposed RDP",
        "techniques": ["T1110", "T1078", "T1021.001", "T1053.005", "T1003"],
        "required_sources": {
            "T1110": ["SecurityEvent"],
            "T1078": ["SecurityEvent", "SigninLogs"],
            "T1021.001": ["SecurityEvent"],
            "T1053.005": ["SecurityEvent"],
            "T1003": ["DeviceProcessEvents"],
        },
        "targets": ["Internal Servers", "Workstations"],
    },
    {
        "entry": "Compromised cloud credentials",
        "techniques": ["T1078.004", "T1098", "T1136.003", "T1530"],
        "required_sources": {
            "T1078.004": ["SigninLogs"],
            "T1098": ["AuditLogs"],
            "T1136.003": ["AuditLogs"],
            "T1530": ["AzureActivity", "OfficeActivity"],
        },
        "targets": ["Azure Resources", "SharePoint Data", "Email"],
    },
    {
        "entry": "Supply chain compromise",
        "techniques": ["T1195.002", "T1059.001", "T1071.001", "T1048"],
        "required_sources": {
            "T1195.002": ["DeviceProcessEvents", "DeviceFileEvents"],
            "T1059.001": ["DeviceProcessEvents"],
            "T1071.001": ["DeviceNetworkEvents", "CommonSecurityLog"],
            "T1048": ["DnsEvents", "DeviceNetworkEvents"],
        },
        "targets": ["All Endpoints", "Data Stores"],
    },
    {
        "entry": "Insider threat",
        "techniques": ["T1078", "T1083", "T1005", "T1567"],
        "required_sources": {
            "T1078": ["SecurityEvent", "SigninLogs"],
            "T1083": ["DeviceFileEvents"],
            "T1005": ["DeviceFileEvents", "OfficeActivity"],
            "T1567": ["DeviceNetworkEvents", "CommonSecurityLog"],
        },
        "targets": ["Sensitive Data", "IP Assets"],
    },
]


def identify_attack_paths(
    available_data_sources: list[str],
) -> list[AttackPath]:
    """Identify attack paths and compute detection coverage per path."""
    paths: list[AttackPath] = []
    sources_set = set(available_data_sources)

    for tmpl in _ATTACK_PATH_TEMPLATES:
        detectable = 0
        total = len(tmpl["techniques"])
        gaps: list[str] = []

        for technique in tmpl["techniques"]:
            required = tmpl["required_sources"].get(technique, [])
            if any(src in sources_set for src in required):
                detectable += 1
            else:
                gaps.append(f"{technique} (needs: {', '.join(required)})")

        coverage = detectable / total if total > 0 else 0.0

        if coverage >= 0.8:
            risk = "low"
        elif coverage >= 0.5:
            risk = "medium"
        else:
            risk = "high"

        paths.append(AttackPath(
            path_id=f"AP-{uuid.uuid4().hex[:6].upper()}",
            entry_point=tmpl["entry"],
            techniques=tmpl["techniques"],
            target_assets=tmpl["targets"],
            detection_coverage=round(coverage, 2),
            gaps=gaps,
            risk_level=risk,
        ))

    return paths
