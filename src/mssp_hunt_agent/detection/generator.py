"""Detection rule generator — creates KQL rules from hypotheses or ATT&CK techniques."""

from __future__ import annotations

import uuid
from typing import Optional

from mssp_hunt_agent.detection.models import DetectionRule, Severity


# ---------------------------------------------------------------------------
# ATT&CK Technique Templates — 42 techniques with behavioral KQL
# ---------------------------------------------------------------------------
_TECHNIQUE_TEMPLATES: dict[str, dict] = {
    # ── Initial Access ─────────────────────────────────────────────────
    "T1078": {
        "name": "Valid Accounts -- Anomalous Logon",
        "kql": (
            "SigninLogs\n"
            "| where ResultType == 0\n"
            "| where RiskLevelDuringSignIn in (\"high\", \"medium\")\n"
            "| summarize LogonCount=count(), DistinctIPs=dcount(IPAddress) "
            "by UserPrincipalName, bin(TimeGenerated, 1h)\n"
            "| where DistinctIPs > 3"
        ),
        "severity": "high",
        "data_sources": ["SigninLogs"],
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation"],
        "false_positive_guidance": (
            "Legitimate users traveling or using VPN may trigger geographic "
            "anomalies. Exclude service accounts with known multi-IP patterns. "
            "Validate against HR travel records or known VPN egress IPs."
        ),
    },
    "T1078.001": {
        "name": "Default Accounts -- Built-in Account Usage",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4624\n"
            "| where TargetUserName in~ (\"Administrator\", \"Guest\", "
            "\"DefaultAccount\", \"WDAGUtilityAccount\")\n"
            "| where LogonType in (2, 10)\n"
            "| project TimeGenerated, Computer, TargetUserName, IpAddress, "
            "LogonType"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Some legacy systems require built-in Administrator. Baseline "
            "expected usage and exclude known management workstations."
        ),
    },
    "T1078.002": {
        "name": "Domain Accounts -- Off-Hours Logon",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4624\n"
            "| where LogonType in (2, 3, 10)\n"
            "| extend HourOfDay = datetime_part(\"hour\", TimeGenerated)\n"
            "| where HourOfDay < 6 or HourOfDay > 22\n"
            "| summarize Count=count() by TargetUserName, Computer, "
            "bin(TimeGenerated, 1d)\n"
            "| where Count > 3"
        ),
        "severity": "medium",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Shift workers, IT on-call staff, and automated processes may "
            "log in outside business hours. Build a baseline of expected "
            "off-hours users."
        ),
    },
    "T1078.004": {
        "name": "Cloud Account Compromise",
        "kql": (
            "SigninLogs\n"
            "| where AppDisplayName != \"\"\n"
            "| where ResultType == 0\n"
            "| where RiskLevelDuringSignIn == \"high\"\n"
            "| project TimeGenerated, UserPrincipalName, IPAddress, "
            "Location, AppDisplayName, RiskDetail"
        ),
        "severity": "high",
        "data_sources": ["SigninLogs"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Azure AD Identity Protection may flag VPN or shared IP "
            "addresses. Review RiskDetail for context before escalating."
        ),
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "kql": (
            "CommonSecurityLog\n"
            "| where DeviceAction has_any (\"blocked\", \"denied\", \"dropped\")\n"
            "| summarize AttackAttempts=count() by SourceIP, DestinationIP, "
            "Activity, bin(TimeGenerated, 1h)\n"
            "| where AttackAttempts > 50"
        ),
        "severity": "high",
        "data_sources": ["CommonSecurityLog"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Vulnerability scanners and penetration testers may trigger "
            "high block counts. Exclude known scanner IPs from your "
            "authorized testing schedule."
        ),
    },
    "T1566.001": {
        "name": "Phishing -- Suspicious Email Attachment Execution",
        "kql": (
            "DeviceProcessEvents\n"
            "| where InitiatingProcessFileName in~ (\"outlook.exe\", "
            "\"winword.exe\", \"excel.exe\")\n"
            "| where FileName !in~ (\"outlook.exe\", \"winword.exe\", "
            "\"excel.exe\", \"msedge.exe\", \"chrome.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Legitimate macros and Office add-ins spawn child processes. "
            "Baseline known add-ins and exclude by publisher signature."
        ),
    },
    "T1566.002": {
        "name": "Spearphishing Link -- Suspicious URL Click",
        "kql": (
            "OfficeActivity\n"
            "| where Operation == \"ClickedUrl\" or Operation == \"SafeLinksUrlClicked\"\n"
            "| where UrlDomain !endswith \".microsoft.com\" and "
            "UrlDomain !endswith \".office.com\"\n"
            "| summarize ClickCount=count(), DistinctUsers=dcount(UserId) "
            "by UrlDomain, bin(TimeGenerated, 1h)\n"
            "| where DistinctUsers > 3"
        ),
        "severity": "high",
        "data_sources": ["OfficeActivity"],
        "tactics": ["Initial Access"],
        "false_positive_guidance": (
            "Legitimate external links (SaaS tools, partner portals) will "
            "trigger. Maintain an allowlist of approved external domains."
        ),
    },
    # ── Execution ──────────────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter -- Multi-Engine",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in~ (\"powershell.exe\", \"pwsh.exe\", "
            "\"cmd.exe\", \"wscript.exe\", \"cscript.exe\", \"mshta.exe\", "
            "\"bash.exe\")\n"
            "| where InitiatingProcessFileName !in~ (\"explorer.exe\", "
            "\"svchost.exe\", \"services.exe\")\n"
            "| where ProcessCommandLine has_any (\"encodedcommand\", "
            "\"-enc\", \"bypass\", \"hidden\", \"downloadstring\", "
            "\"invoke-expression\", \"certutil\", \"bitsadmin\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "Admin scripts and deployment tools (SCCM, Intune) regularly "
            "invoke scripting interpreters. Baseline known admin tools and "
            "exclude by InitiatingProcessFileName or signed publisher."
        ),
    },
    "T1059.001": {
        "name": "PowerShell Execution -- Suspicious Patterns",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ \"powershell.exe\" or FileName =~ \"pwsh.exe\"\n"
            "| where ProcessCommandLine has_any (\"encodedcommand\", "
            "\"-enc\", \"bypass\", \"hidden\", \"downloadstring\", \"iex\", "
            "\"invoke-expression\")\n"
            "| project TimeGenerated, DeviceName, AccountName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "Legitimate IT automation may use encoded commands. Verify "
            "the parent process and check if the script is signed."
        ),
    },
    "T1059.003": {
        "name": "Windows Command Shell -- Suspicious cmd.exe Usage",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ \"cmd.exe\"\n"
            "| where ProcessCommandLine has_any (\"whoami\", \"net user\", "
            "\"net group\", \"net localgroup\", \"systeminfo\", \"ipconfig\", "
            "\"tasklist\", \"wmic\", \"reg query\")\n"
            "| where InitiatingProcessFileName !in~ (\"explorer.exe\", "
            "\"svchost.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "medium",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "System administrators routinely use these commands. Correlate "
            "with user role and check if the parent process is expected."
        ),
    },
    "T1059.005": {
        "name": "Visual Basic Execution -- Suspicious VBScript/VBA",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in~ (\"wscript.exe\", \"cscript.exe\")\n"
            "| where ProcessCommandLine has_any (\".vbs\", \".vbe\", "
            "\".wsf\", \".wsh\")\n"
            "| where InitiatingProcessFileName !in~ (\"explorer.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "Legacy login scripts and enterprise apps may invoke VBScript. "
            "Validate against known script paths (e.g., NETLOGON share)."
        ),
    },
    "T1059.007": {
        "name": "JavaScript/JScript Execution -- Suspicious Activity",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in~ (\"wscript.exe\", \"cscript.exe\", "
            "\"node.exe\", \"mshta.exe\")\n"
            "| where ProcessCommandLine has_any (\".js\", \".jse\", "
            "\".hta\", \"javascript:\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "Web development tools and Node.js applications are expected. "
            "Focus on non-developer endpoints and unexpected parent processes."
        ),
    },
    "T1047": {
        "name": "WMI Execution -- Remote Process Creation",
        "kql": (
            "DeviceProcessEvents\n"
            "| where InitiatingProcessFileName =~ \"wmiprvse.exe\"\n"
            "| where FileName !in~ (\"wmiprvse.exe\", \"wmiapsrv.exe\", "
            "\"scrcons.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessCommandLine"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "SCCM, SCOM, and other management tools use WMI heavily. "
            "Exclude known management server source IPs."
        ),
    },
    "T1204.002": {
        "name": "Malicious File Execution -- User Triggered",
        "kql": (
            "DeviceProcessEvents\n"
            "| where InitiatingProcessFileName in~ (\"explorer.exe\", "
            "\"outlook.exe\", \"winword.exe\", \"excel.exe\", \"chrome.exe\", "
            "\"msedge.exe\")\n"
            "| where FileName has_any (\".exe\", \".scr\", \".bat\", "
            "\".cmd\", \".ps1\", \".vbs\", \".hta\")\n"
            "| where FolderPath has_any (\"Downloads\", \"Temp\", "
            "\"AppData\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "FolderPath, ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Execution"],
        "false_positive_guidance": (
            "Users may legitimately run installers from Downloads. Focus "
            "on unsigned executables and non-standard extensions."
        ),
    },
    # ── Persistence ────────────────────────────────────────────────────
    "T1053": {
        "name": "Scheduled Task/Job -- Creation or Modification",
        "kql": (
            "SecurityEvent\n"
            "| where EventID in (4698, 4702)\n"
            "| extend TaskName = extractjson(\"$.TaskName\", EventData)\n"
            "| extend TaskContent = extractjson(\"$.TaskContent\", EventData)\n"
            "| where TaskContent has_any (\"powershell\", \"cmd.exe\", "
            "\"wscript\", \"mshta\", \"http\", \"ftp\")\n"
            "| project TimeGenerated, Computer, SubjectUserName, TaskName, "
            "TaskContent"
        ),
        "severity": "medium",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Persistence", "Execution"],
        "false_positive_guidance": (
            "IT automation and patch management use scheduled tasks. "
            "Focus on tasks created by non-service accounts and those "
            "referencing suspicious executables or URLs."
        ),
    },
    "T1053.005": {
        "name": "Scheduled Task Creation",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4698\n"
            "| project TimeGenerated, Computer, SubjectUserName, "
            "TaskName=extractjson(\"$.TaskName\", EventData)"
        ),
        "severity": "medium",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Persistence", "Execution"],
        "false_positive_guidance": (
            "Windows Update and enterprise management tools create "
            "scheduled tasks routinely. Focus on tasks created by "
            "interactive user sessions."
        ),
    },
    "T1098": {
        "name": "Account Manipulation -- Role or Credential Changes",
        "kql": (
            "AuditLogs\n"
            "| where OperationName in (\"Add member to role\", "
            "\"Add owner to application\", "
            "\"Add delegated permission grant\", "
            "\"Update application - Certificates and secrets management\", "
            "\"Add app role assignment to service principal\", "
            "\"Add service principal credentials\")\n"
            "| where Result == \"success\"\n"
            "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n"
            "| extend Target = tostring(TargetResources[0].displayName)\n"
            "| project TimeGenerated, Actor, OperationName, Target, "
            "CorrelationId"
        ),
        "severity": "high",
        "data_sources": ["AuditLogs"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "IAM admins performing routine role assignments will trigger this. "
            "Exclude known IAM admin accounts. Focus on out-of-hours changes "
            "and assignments to high-privilege roles (Global Admin, "
            "Application Admin)."
        ),
    },
    "T1098.001": {
        "name": "Additional Cloud Credentials -- Secret or Certificate Added",
        "kql": (
            "AuditLogs\n"
            "| where OperationName in ("
            "\"Update application - Certificates and secrets management\", "
            "\"Add service principal credentials\")\n"
            "| where Result == \"success\"\n"
            "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n"
            "| extend AppName = tostring(TargetResources[0].displayName)\n"
            "| project TimeGenerated, Actor, OperationName, AppName, "
            "CorrelationId"
        ),
        "severity": "high",
        "data_sources": ["AuditLogs"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "Application developers rotate secrets as part of CI/CD. "
            "Correlate with change management tickets and focus on "
            "unscheduled credential additions."
        ),
    },
    "T1136": {
        "name": "Create Account -- New User or Service Principal",
        "kql": (
            "AuditLogs\n"
            "| where OperationName in (\"Add user\", "
            "\"Add service principal\")\n"
            "| where Result == \"success\"\n"
            "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n"
            "| extend NewAccount = tostring(TargetResources[0].displayName)\n"
            "| project TimeGenerated, Actor, OperationName, NewAccount"
        ),
        "severity": "medium",
        "data_sources": ["AuditLogs"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "HR onboarding and automated provisioning create accounts. "
            "Correlate with provisioning workflows and flag accounts "
            "created outside standard processes."
        ),
    },
    "T1136.003": {
        "name": "Cloud Account Creation",
        "kql": (
            "AuditLogs\n"
            "| where OperationName in (\"Add user\", "
            "\"Invite external user\")\n"
            "| where Result == \"success\"\n"
            "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n"
            "| extend NewUser = tostring(TargetResources[0].displayName)\n"
            "| extend NewUPN = tostring(TargetResources[0].userPrincipalName)\n"
            "| project TimeGenerated, Actor, OperationName, NewUser, NewUPN"
        ),
        "severity": "medium",
        "data_sources": ["AuditLogs"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "B2B collaboration invitations are normal. Focus on external "
            "invitations from non-HR accounts and accounts created with "
            "elevated roles."
        ),
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder Persistence",
        "kql": (
            "DeviceRegistryEvents\n"
            "| where RegistryKey has_any ("
            "\"CurrentVersion\\\\Run\", "
            "\"CurrentVersion\\\\RunOnce\", "
            "\"CurrentVersion\\\\Explorer\\\\Shell Folders\")\n"
            "| where ActionType in (\"RegistryValueSet\", \"RegistryKeyCreated\")\n"
            "| project TimeGenerated, DeviceName, "
            "InitiatingProcessAccountName, RegistryKey, RegistryValueName, "
            "RegistryValueData, InitiatingProcessFileName"
        ),
        "severity": "high",
        "data_sources": ["DeviceRegistryEvents"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "Software installers and updates modify Run keys. Filter by "
            "signed publishers and known installer processes."
        ),
    },
    "T1543.003": {
        "name": "Windows Service Creation -- New or Modified",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 7045 or EventID == 4697\n"
            "| extend ServiceName = extractjson(\"$.ServiceName\", EventData)\n"
            "| extend ImagePath = extractjson(\"$.ImagePath\", EventData)\n"
            "| where ImagePath has_any (\"cmd\", \"powershell\", \"temp\", "
            "\"appdata\", \"users\\\\public\")\n"
            "| project TimeGenerated, Computer, SubjectUserName, "
            "ServiceName, ImagePath"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Persistence"],
        "false_positive_guidance": (
            "Legitimate software installs create services. Focus on "
            "services with suspicious image paths (temp, user profile) "
            "and those created by non-admin accounts."
        ),
    },
    # ── Credential Access ──────────────────────────────────────────────
    "T1003": {
        "name": "Credential Dumping -- LSASS Access",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in~ (\"procdump.exe\", \"mimikatz.exe\", "
            "\"sekurlsa.exe\")\n"
            "   or ProcessCommandLine has \"lsass\"\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine"
        ),
        "severity": "critical",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "Legitimate crash dump collection may access LSASS. Verify "
            "the process is signed and from an authorized diagnostic tool."
        ),
    },
    "T1003.001": {
        "name": "LSASS Memory Dump -- Direct Access",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in~ (\"procdump.exe\", \"procdump64.exe\", "
            "\"sqldumper.exe\", \"createdump.exe\", \"comsvcs.exe\")\n"
            "| where ProcessCommandLine has_any (\"lsass\", \"-ma ls\", "
            "\"MiniDump\", \"#24\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "critical",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "Microsoft support diagnostics may dump LSASS. Verify with "
            "support ticket correlation. comsvcs.dll (#24) is almost "
            "always malicious."
        ),
    },
    "T1003.003": {
        "name": "NTDS.dit Access -- Active Directory Database",
        "kql": (
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine has_any (\"ntds.dit\", "
            "\"ntdsutil\", \"secretsdump\", \"vssadmin create shadow\", "
            "\"esentutl\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine"
        ),
        "severity": "critical",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "AD backup processes access ntds.dit. Verify the operation "
            "was scheduled and initiated from a known backup server."
        ),
    },
    "T1110": {
        "name": "Brute Force Detection",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4625\n"
            "| summarize FailedAttempts=count() by TargetUserName, "
            "IpAddress, bin(TimeGenerated, 5m)\n"
            "| where FailedAttempts > 10"
        ),
        "severity": "medium",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "Misconfigured service accounts and password managers may "
            "generate failed logons. Exclude known service account SPNs."
        ),
    },
    "T1110.003": {
        "name": "Password Spraying -- Low-and-Slow Authentication",
        "kql": (
            "SigninLogs\n"
            "| where ResultType == 50126\n"
            "| summarize FailedAttempts=count(), "
            "TargetAccounts=dcount(UserPrincipalName) "
            "by IPAddress, bin(TimeGenerated, 1h)\n"
            "| where TargetAccounts > 10 and FailedAttempts > 15"
        ),
        "severity": "high",
        "data_sources": ["SigninLogs"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "Shared NAT IPs (corporate egress) may show multiple users "
            "failing authentication. Check if the IP is a known corporate "
            "or VPN egress point."
        ),
    },
    "T1558.003": {
        "name": "Kerberoasting -- Service Ticket Request Anomaly",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4769\n"
            "| where TicketEncryptionType in (\"0x17\", \"0x18\")\n"
            "| where ServiceName !endswith \"$\"\n"
            "| summarize RequestCount=count(), "
            "DistinctServices=dcount(ServiceName) "
            "by TargetUserName, IpAddress, bin(TimeGenerated, 1h)\n"
            "| where DistinctServices > 5"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Credential Access"],
        "false_positive_guidance": (
            "Monitoring tools that enumerate SPNs may trigger. "
            "Focus on RC4 encryption (0x17) requests from non-service "
            "accounts targeting multiple unique services."
        ),
    },
    # ── Lateral Movement ───────────────────────────────────────────────
    "T1021": {
        "name": "Remote Services -- Anomalous Lateral Authentication",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4624\n"
            "| where LogonType in (3, 10)\n"
            "| summarize DistinctTargets=dcount(Computer), "
            "LogonCount=count() "
            "by TargetUserName, IpAddress, bin(TimeGenerated, 1h)\n"
            "| where DistinctTargets > 5"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Lateral Movement"],
        "false_positive_guidance": (
            "IT admins and vulnerability scanners access many hosts. "
            "Exclude known admin accounts and scanner service accounts."
        ),
    },
    "T1021.001": {
        "name": "RDP Lateral Movement -- Unusual Source",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 4624 and LogonType == 10\n"
            "| summarize RDPSessions=count(), "
            "DistinctTargets=dcount(Computer) "
            "by IpAddress, bin(TimeGenerated, 1h)\n"
            "| where DistinctTargets > 3"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Lateral Movement"],
        "false_positive_guidance": (
            "Jump servers and admin workstations legitimately RDP to "
            "multiple hosts. Exclude known bastion host IPs."
        ),
    },
    "T1021.002": {
        "name": "SMB/Admin Shares -- Lateral File Access",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 5140\n"
            "| where ShareName has_any (\"C$\", \"ADMIN$\", \"IPC$\")\n"
            "| summarize AccessCount=count(), "
            "DistinctShares=dcount(ShareName) "
            "by SubjectUserName, IpAddress, bin(TimeGenerated, 1h)\n"
            "| where AccessCount > 10"
        ),
        "severity": "high",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Lateral Movement"],
        "false_positive_guidance": (
            "SCCM, GPO updates, and backup software access admin shares. "
            "Exclude known management server IPs and service accounts."
        ),
    },
    "T1021.006": {
        "name": "Windows Remote Management (WinRM)",
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ \"wsmprovhost.exe\"\n"
            "| where InitiatingProcessFileName !in~ (\"svchost.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, "
            "ProcessCommandLine, InitiatingProcessFileName, "
            "InitiatingProcessCommandLine"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Lateral Movement"],
        "false_positive_guidance": (
            "PowerShell remoting and Ansible use WinRM. Exclude known "
            "automation servers and verify the initiating user context."
        ),
    },
    "T1570": {
        "name": "Lateral Tool Transfer -- Suspicious File Copy",
        "kql": (
            "DeviceFileEvents\n"
            "| where ActionType == \"FileCreated\"\n"
            "| where FolderPath has_any (\"\\\\ADMIN$\", \"\\\\C$\", "
            "\"\\\\IPC$\")\n"
            "| where FileName has_any (\".exe\", \".dll\", \".ps1\", "
            "\".bat\", \".vbs\")\n"
            "| project TimeGenerated, DeviceName, "
            "InitiatingProcessAccountName, FileName, FolderPath, SHA256"
        ),
        "severity": "high",
        "data_sources": ["DeviceFileEvents"],
        "tactics": ["Lateral Movement"],
        "false_positive_guidance": (
            "Software deployment and SCCM push installations copy files "
            "to admin shares. Verify against deployment schedules."
        ),
    },
    # ── Defense Evasion ────────────────────────────────────────────────
    "T1027": {
        "name": "Obfuscated Files or Information",
        "kql": (
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine has_any (\"-encodedcommand\", "
            "\"-enc \", \"frombase64string\", \"[convert]::\", "
            "\"char[]\", \"-join\", \"replace\", \"iex(\")\n"
            "| where FileName in~ (\"powershell.exe\", \"pwsh.exe\", "
            "\"cmd.exe\")\n"
            "| extend CmdLength = strlen(ProcessCommandLine)\n"
            "| where CmdLength > 500\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "CmdLength, ProcessCommandLine"
        ),
        "severity": "high",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Defense Evasion"],
        "false_positive_guidance": (
            "Encoded PowerShell is used by some management tools. Check "
            "command length and decode Base64 to inspect payload. Commands "
            "over 1000 chars from non-admin users are highly suspicious."
        ),
    },
    "T1562.001": {
        "name": "Disable or Modify Security Tools",
        "kql": (
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine has_any ("
            "\"Set-MpPreference -DisableRealtimeMonitoring\", "
            "\"sc stop WinDefend\", \"sc delete WinDefend\", "
            "\"net stop MsMpSvc\", \"Uninstall-WindowsFeature\", "
            "\"Remove-WindowsFeature\", "
            "\"Set-MpPreference -DisableBehaviorMonitoring\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        ),
        "severity": "critical",
        "data_sources": ["DeviceProcessEvents"],
        "tactics": ["Defense Evasion"],
        "false_positive_guidance": (
            "Some software installers temporarily disable AV. This should "
            "be rare and time-bounded. Investigate any occurrence not "
            "correlated with a known installation."
        ),
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "kql": (
            "SecurityEvent\n"
            "| where EventID == 1102\n"
            "| project TimeGenerated, Computer, "
            "SubjectUserName=extractjson(\"$.SubjectUserName\", EventData), "
            "SubjectDomainName=extractjson(\"$.SubjectDomainName\", EventData)"
        ),
        "severity": "critical",
        "data_sources": ["SecurityEvent"],
        "tactics": ["Defense Evasion"],
        "false_positive_guidance": (
            "Log rotation policies may clear logs. Event 1102 from "
            "non-SYSTEM accounts is almost always suspicious."
        ),
    },
    # ── Command and Control ────────────────────────────────────────────
    "T1071.001": {
        "name": "Web Protocols C2 -- Beaconing Detection",
        "kql": (
            "DeviceNetworkEvents\n"
            "| where RemotePort in (80, 443)\n"
            "| where RemoteUrl != \"\"\n"
            "| summarize BeaconCount=count(), "
            "AvgTimeDelta=avg(datetime_diff(\"second\", TimeGenerated, "
            "prev(TimeGenerated))) "
            "by DeviceName, RemoteUrl, bin(TimeGenerated, 1h)\n"
            "| where BeaconCount > 50"
        ),
        "severity": "high",
        "data_sources": ["DeviceNetworkEvents"],
        "tactics": ["Command and Control"],
        "false_positive_guidance": (
            "Health checks, telemetry, and update services beacon "
            "regularly. Focus on uncommon domains with consistent "
            "intervals and exclude CDN/cloud provider IPs."
        ),
    },
    "T1071.004": {
        "name": "DNS C2 -- Tunneling or Beaconing",
        "kql": (
            "DnsEvents\n"
            "| where QueryType in (\"TXT\", \"NULL\", \"CNAME\")\n"
            "| where Name !endswith \".microsoft.com\" and "
            "Name !endswith \".windows.net\" and "
            "Name !endswith \".azure.com\"\n"
            "| extend SubdomainLength = strlen(tostring(split(Name, \".\")[0]))\n"
            "| where SubdomainLength > 30\n"
            "| summarize QueryCount=count(), "
            "DistinctNames=dcount(Name) "
            "by ClientIP, bin(TimeGenerated, 1h)\n"
            "| where QueryCount > 50 or DistinctNames > 30"
        ),
        "severity": "high",
        "data_sources": ["DnsEvents"],
        "tactics": ["Command and Control"],
        "false_positive_guidance": (
            "DKIM, SPF, and email security use long TXT records. Filter "
            "by query type and focus on high-entropy subdomains "
            "exceeding 30 characters."
        ),
    },
    "T1105": {
        "name": "Ingress Tool Transfer -- Remote File Download",
        "kql": (
            "DeviceFileEvents\n"
            "| where InitiatingProcessFileName in~ (\"powershell.exe\", "
            "\"cmd.exe\", \"certutil.exe\", \"bitsadmin.exe\", "
            "\"curl.exe\", \"wget.exe\")\n"
            "| where ActionType == \"FileCreated\"\n"
            "| where FileName has_any (\".exe\", \".dll\", \".ps1\", "
            "\".bat\", \".vbs\", \".hta\")\n"
            "| project TimeGenerated, DeviceName, "
            "InitiatingProcessAccountName, FileName, FolderPath, "
            "SHA256, InitiatingProcessCommandLine"
        ),
        "severity": "high",
        "data_sources": ["DeviceFileEvents"],
        "tactics": ["Command and Control"],
        "false_positive_guidance": (
            "Developers and admins download tools via CLI. Focus on "
            "non-admin endpoints and files landing in temp/user folders."
        ),
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "kql": (
            "DnsEvents\n"
            "| where QueryType in (\"TXT\", \"NULL\")\n"
            "| where Name !endswith \".microsoft.com\" and "
            "Name !endswith \".windows.net\"\n"
            "| summarize QueryCount=count(), "
            "DistinctNames=dcount(Name) "
            "by ClientIP, bin(TimeGenerated, 1h)\n"
            "| where QueryCount > 100 or DistinctNames > 50"
        ),
        "severity": "high",
        "data_sources": ["DnsEvents"],
        "tactics": ["Exfiltration"],
        "false_positive_guidance": (
            "DNS analytics tools and monitoring may generate high query "
            "volumes. Validate against known DNS infrastructure."
        ),
    },
    # ── Impact ─────────────────────────────────────────────────────────
    "T1486": {
        "name": "Data Encrypted for Impact -- Ransomware Indicators",
        "kql": (
            "DeviceFileEvents\n"
            "| where ActionType == \"FileRenamed\"\n"
            "| where FileName has_any (\".encrypted\", \".locked\", "
            "\".crypt\", \".enc\", \".ransom\")\n"
            "| summarize RenamedFiles=count() "
            "by DeviceName, InitiatingProcessAccountName, "
            "InitiatingProcessFileName, bin(TimeGenerated, 5m)\n"
            "| where RenamedFiles > 20"
        ),
        "severity": "critical",
        "data_sources": ["DeviceFileEvents"],
        "tactics": ["Impact"],
        "false_positive_guidance": (
            "Encryption software (BitLocker, VeraCrypt) and backup tools "
            "may rename files in bulk. Verify the process is expected "
            "and check for ransom notes in the same directory."
        ),
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_detection_rule(
    technique_id: Optional[str] = None,
    description: Optional[str] = None,
    severity: Optional[str] = None,
) -> DetectionRule:
    """Generate a KQL detection rule from an ATT&CK technique ID or description.

    If technique_id is provided and has a template, uses the template.
    If only a description is provided, generates a generic rule.
    """
    rule_id = f"DET-{uuid.uuid4().hex[:8].upper()}"

    if technique_id and technique_id in _TECHNIQUE_TEMPLATES:
        tmpl = _TECHNIQUE_TEMPLATES[technique_id]
        return DetectionRule(
            rule_id=rule_id,
            name=tmpl["name"],
            description=description or f"Detection for {technique_id}: {tmpl['name']}",
            kql_query=tmpl["kql"],
            mitre_techniques=[technique_id],
            mitre_tactics=tmpl.get("tactics", []),
            severity=Severity(tmpl.get("severity", "medium")),
            data_sources=tmpl.get("data_sources", []),
            false_positive_guidance=tmpl.get("false_positive_guidance", ""),
            created_by="agent",
        )

    # Fallback: generate a rule from the description
    kql = _generate_from_description(description or "")
    sev = Severity(severity) if severity and severity in [s.value for s in Severity] else Severity.MEDIUM
    techniques = [technique_id] if technique_id else []

    return DetectionRule(
        rule_id=rule_id,
        name=description or "Custom Detection Rule",
        description=description or "Generated detection rule",
        kql_query=kql,
        mitre_techniques=techniques,
        severity=sev,
        data_sources=_infer_data_sources(kql),
        created_by="agent",
    )


def _generate_from_description(description: str) -> str:
    """Generate a KQL query from a natural language description."""
    desc_lower = description.lower()

    # -- Authentication / logon anomalies --
    if any(w in desc_lower for w in ["logon", "login", "sign-in", "authentication", "brute"]):
        return (
            "SecurityEvent\n"
            "| where EventID in (4624, 4625)\n"
            "| summarize Count=count() by TargetUserName, IpAddress, "
            "EventID, bin(TimeGenerated, 1h)\n"
            "| where Count > 5"
        )
    # -- Account manipulation --
    if any(w in desc_lower for w in ["account", "role", "permission", "credential add", "privilege"]):
        return (
            "AuditLogs\n"
            "| where OperationName has_any (\"Add member to role\", "
            "\"Add owner\", \"Add delegated permission\")\n"
            "| where Result == \"success\"\n"
            "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n"
            "| project TimeGenerated, Actor, OperationName, "
            "tostring(TargetResources[0].displayName)"
        )
    # -- PowerShell / scripting --
    if any(w in desc_lower for w in ["powershell", "script", "execution", "command"]):
        return (
            "DeviceProcessEvents\n"
            "| where FileName =~ \"powershell.exe\" or FileName =~ \"cmd.exe\"\n"
            "| where ProcessCommandLine has_any (\"encodedcommand\", "
            "\"-enc\", \"bypass\", \"hidden\", \"downloadstring\")\n"
            "| project TimeGenerated, DeviceName, AccountName, "
            "ProcessCommandLine"
        )
    # -- DNS / C2 --
    if any(w in desc_lower for w in ["dns", "domain", "tunnel", "c2", "beacon"]):
        return (
            "DnsEvents\n"
            "| summarize QueryCount=count() by ClientIP, Name, "
            "bin(TimeGenerated, 1h)\n"
            "| where QueryCount > 50"
        )
    # -- Lateral movement --
    if any(w in desc_lower for w in ["lateral", "rdp", "smb", "remote"]):
        return (
            "SecurityEvent\n"
            "| where EventID == 4624 and LogonType in (3, 10)\n"
            "| summarize Count=count() by IpAddress, Computer, "
            "bin(TimeGenerated, 1h)"
        )
    # -- Registry / persistence --
    if any(w in desc_lower for w in ["registry", "run key", "startup", "autorun"]):
        return (
            "DeviceRegistryEvents\n"
            "| where RegistryKey has_any (\"CurrentVersion\\\\Run\", "
            "\"CurrentVersion\\\\RunOnce\")\n"
            "| where ActionType == \"RegistryValueSet\"\n"
            "| project TimeGenerated, DeviceName, "
            "InitiatingProcessAccountName, RegistryKey, RegistryValueData"
        )
    # -- Service creation --
    if any(w in desc_lower for w in ["service", "install"]):
        return (
            "SecurityEvent\n"
            "| where EventID in (7045, 4697)\n"
            "| extend ServiceName = extractjson(\"$.ServiceName\", EventData)\n"
            "| project TimeGenerated, Computer, SubjectUserName, ServiceName"
        )
    # -- Kerberos attacks --
    if any(w in desc_lower for w in ["kerberos", "kerberoast", "ticket", "spn"]):
        return (
            "SecurityEvent\n"
            "| where EventID == 4769\n"
            "| where TicketEncryptionType in (\"0x17\", \"0x18\")\n"
            "| where ServiceName !endswith \"$\"\n"
            "| summarize RequestCount=count() by TargetUserName, "
            "ServiceName, bin(TimeGenerated, 1h)\n"
            "| where RequestCount > 5"
        )
    # -- Encryption / ransomware --
    if any(w in desc_lower for w in ["encrypt", "ransom", "impact"]):
        return (
            "DeviceFileEvents\n"
            "| where ActionType == \"FileRenamed\"\n"
            "| where FileName has_any (\".encrypted\", \".locked\", "
            "\".crypt\", \".ransom\")\n"
            "| summarize RenamedFiles=count() by DeviceName, "
            "InitiatingProcessFileName, bin(TimeGenerated, 5m)\n"
            "| where RenamedFiles > 20"
        )
    # -- Phishing / email --
    if any(w in desc_lower for w in ["phish", "email", "attachment", "mail"]):
        return (
            "DeviceProcessEvents\n"
            "| where InitiatingProcessFileName in~ (\"outlook.exe\", "
            "\"winword.exe\", \"excel.exe\")\n"
            "| where FileName !in~ (\"outlook.exe\", \"winword.exe\", "
            "\"excel.exe\", \"msedge.exe\", \"chrome.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, InitiatingProcessFileName"
        )
    # -- WMI --
    if any(w in desc_lower for w in ["wmi", "wmic", "wmiprvse"]):
        return (
            "DeviceProcessEvents\n"
            "| where InitiatingProcessFileName =~ \"wmiprvse.exe\"\n"
            "| where FileName !in~ (\"wmiprvse.exe\", \"wmiapsrv.exe\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, "
            "ProcessCommandLine"
        )
    # -- File / malware --
    if any(w in desc_lower for w in ["file", "hash", "malware", "download"]):
        return (
            "DeviceFileEvents\n"
            "| where ActionType == \"FileCreated\"\n"
            "| project TimeGenerated, DeviceName, FileName, FolderPath, "
            "SHA256, InitiatingProcessFileName"
        )

    # Very generic fallback
    return (
        "SecurityEvent\n"
        "| where TimeGenerated > ago(7d)\n"
        "| summarize Count=count() by EventID, Account, Computer, "
        "bin(TimeGenerated, 1h)\n"
        "| where Count > 10"
    )


def _infer_data_sources(kql: str) -> list[str]:
    """Extract table names referenced in the KQL query."""
    known_tables = [
        "SecurityEvent", "SigninLogs", "AuditLogs",
        "DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents",
        "DeviceLogonEvents", "DeviceRegistryEvents",
        "CommonSecurityLog", "DnsEvents",
        "OfficeActivity", "AzureActivity", "SecurityAlert",
    ]
    return [t for t in known_tables if t in kql]


def list_available_techniques() -> list[str]:
    """Return all technique IDs with built-in templates."""
    return sorted(_TECHNIQUE_TEMPLATES.keys())
