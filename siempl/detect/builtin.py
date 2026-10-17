"""Built-in detection rules: 22 hand-written KQL queries for common attack scenarios.

Each rule is self-contained KQL with its own `TimeGenerated > ago(Nm)` predicate.
"""
from ..db import Database
from .engine import RuleStore

BUILTIN_RULES: list[dict] = [
    # 1 ── SSH Brute Force: Repeated Failed Logins ──
    {"name": "SSH Brute Force — Repeated Failed Logins",
     "description": "Detects repeated SSH authentication failures from the same source IP targeting the same or different accounts. Attackers enumerate credentials by trying many password/username combinations. Key evidence: SrcIp, TargetUserName.",
     "triage_steps": "1. Identify SrcIp from evidence. Is it internal or external?\n2. Run query to check if any TargetUserName succeeded (EventResult='success') within the window.\n3. If external + no reason, escalate.\n4. If internal IP, verify whether misconfigured automation.\n5. Document verdict.",
     "severity": "high",
     "query": 'AuthEvents | where TimeGenerated > ago(10m) | where EventAction == "login" and EventResult == "failure" and AuthMethod == "ssh" | summarize fail_count=count() by SrcIp, TargetUserName | where fail_count >= 10',
     "tables": ["AuthEvents"], "frequency_minutes": 5, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["credential_access"], "mitre_techniques": ["T1110"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "TargetUserName"}], "origin": "builtin"},

    # 2 ── SSH Brute Force: Success After Failures ──
    {"name": "SSH Brute Force — Success After Failures",
     "description": "A source IP has both failed AND successful SSH logins within the window — the strongest signal of a successful brute-force attack. Key evidence: the successful TargetUserName is the compromised account.",
     "triage_steps": "1. Identify the TargetUserName that succeeded.\n2. Run: AuthEvents | where UserName == '<user>' | take 20.\n3. Look up entity for this user — check alert_count and reputation.\n4. Immediately rotate credentials for the compromised user.\n5. Check for lateral movement from SrcIp after the success time.\n6. Escalate and document.",
     "severity": "critical",
     "query": 'AuthEvents | where TimeGenerated > ago(10m) and AuthMethod == "ssh" and EventAction == "login" and EventResult in ("failure", "success") | summarize event_count=count(), result_types=dcount(EventResult), success_users=make_set(TargetUserName) by SrcIp | where event_count >= 6 and result_types > 1 | project SrcIp, TargetUserName=success_users',
     "tables": ["AuthEvents"], "frequency_minutes": 5, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["credential_access", "initial_access"], "mitre_techniques": ["T1110", "T1078"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "TargetUserName"}], "origin": "builtin"},

    # 3 ── Password Spray ──
    {"name": "Password Spray — Single Password, Many Accounts",
     "description": "Many accounts failing authentication from the same source IP. Unlike brute force (many attempts per account), password spray tries one common password across many accounts to avoid lockout. Key evidence: TargetUserName list, distinct accounts count.",
     "triage_steps": "1. List the TargetUserNames from evidence — how many distinct accounts?\n2. Verify whether any targeted accounts are high-value (admin, service).\n3. Check if any succeeded (join with successes).\n4. If >5 distinct accounts targeted, escalate immediately.\n5. Document accounts and time window.",
     "severity": "high",
     "query": 'AuthEvents | where TimeGenerated > ago(10m) | where EventResult == "failure" and isnotnull(TargetUserName) | summarize user_count=dcount(TargetUserName) by SrcIp | where user_count >= 10',
     "tables": ["AuthEvents"], "frequency_minutes": 10, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["credential_access"], "mitre_techniques": ["T1110.003"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "TargetUserName"}], "origin": "builtin"},

    # 4 ── Encoded PowerShell ──
    {"name": "Encoded PowerShell Execution",
     "description": "Detects PowerShell launched with -EncodedCommand or -e flag. Attackers use Base64-encoded commands to obfuscate malicious scripts. Key evidence: ProcessCmdLine, ParentCmdLine, UserName.",
     "triage_steps": "1. Extract ProcessCmdLine from evidence.\n2. The encoded string follows -e / -EncodedCommand. Decode it.\n3. Inspect decoded script for suspicious patterns (IEX, DownloadString, Invoke-Expression).\n4. Check ParentProcessName — what launched PowerShell?\n5. Look at UserName — legitimate admin or service account?\n6. If decoded content contains IEX/DownloadString, escalate.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(10m) | where ProcessName contains "powershell" and (ProcessCmdLine contains "EncodedCommand" or ProcessCmdLine contains "-Enc " or ProcessCmdLine contains "-e " or ProcessCmdLine contains "-ec ")',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["execution", "defense_evasion"], "mitre_techniques": ["T1059.001", "T1027"],
     "entity_mappings": [{"entity_type": "process", "column": "ProcessName"}, {"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}], "origin": "builtin"},

    # 5 ── Certutil Download ──
    {"name": "Certutil Used for File Download",
     "description": "certutil.exe is a legitimate Windows certificate tool that attackers abuse to download files from the internet (Living off the Land). Common flags: -urlcache -split -f. Key evidence: ProcessCmdLine shows the download URL and destination file.",
     "triage_steps": "1. Examine ProcessCmdLine for the URL and output file path.\n2. Look up the URL — known malware C2 or benign Microsoft CDN?\n3. Check the destination path — user-writable temp folder?\n4. Look for subsequent execution of the downloaded file.\n5. Verify whether certutil use is expected on this host.\n6. If URL is unknown and file path is suspicious, escalate.",
     "severity": "medium",
     "query": 'ProcessEvents | where TimeGenerated > ago(15m) | where ProcessName contains "certutil" and (ProcessCmdLine contains "urlcache" or ProcessCmdLine contains "split" or ProcessCmdLine contains "://")',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["command_and_control", "defense_evasion"], "mitre_techniques": ["T1105", "T1218"],
     "entity_mappings": [{"entity_type": "process", "column": "ProcessName"}, {"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 6 ── New Local Admin ──
    {"name": "New Local Administrator Account",
     "description": "A new local user is added to the Administrators group — a common persistence technique used after initial compromise. Key evidence: the newly added account name (in ProcessCmdLine).",
     "triage_steps": "1. Identify the account added from ProcessCmdLine.\n2. Check auth events for this new account — any logins yet?\n3. Check UserName — who created this account? Are they authorized?\n4. Look at ParentProcessName — what process initiated the account creation?\n5. Check if part of known provisioning workflow.\n6. If unauthorized, escalate and disable the account immediately.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(15m) | where (ProcessCmdLine contains "net localgroup administrators" and ProcessCmdLine contains "add") or ProcessCmdLine contains "Add-LocalGroupMember" or (ProcessCmdLine contains "net user" and ProcessCmdLine contains "add") or ProcessCmdLine contains "New-LocalUser"',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["persistence", "privilege_escalation"], "mitre_techniques": ["T1136", "T1098"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 7 ── Scheduled Task ──
    {"name": "Suspicious Scheduled Task Creation",
     "description": "A scheduled task is created via schtasks.exe or PowerShell. Attackers use scheduled tasks for persistence. Key evidence: ProcessCmdLine shows task name, trigger, and action.",
     "triage_steps": "1. Extract task name and executable path from ProcessCmdLine.\n2. Look for the scheduled task executable on disk — does it exist? Is it signed?\n3. Check UserName — who created the task?\n4. Is the task executable in a temp folder or user AppData?\n5. Look for other persistence mechanisms on same host.\n6. If suspicious, document the task for removal.",
     "severity": "medium",
     "query": 'ProcessEvents | where TimeGenerated > ago(30m) | where (ProcessCmdLine contains "schtasks" and ProcessCmdLine contains "create") or ProcessCmdLine contains "Register-ScheduledTask" or ProcessCmdLine contains "New-ScheduledTask"',
     "tables": ["ProcessEvents"], "frequency_minutes": 10, "lookback_minutes": 30, "threshold": 1,
     "mitre_tactics": ["persistence", "execution"], "mitre_techniques": ["T1053"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 8 ── Port Scan ──
    {"name": "Horizontal Port Scan",
     "description": "A single source IP connects to many distinct destination ports on a single host, or to the same port on many hosts — typical network reconnaissance. Key evidence: SrcIp, DstIp, DstPort distribution.",
     "triage_steps": "1. Check SrcIp — internal host doing recon or external scanner?\n2. Run: NetworkEvents | where SrcIp == '<ip>' | distinct DstPort, DstIp.\n3. If external + many ports: likely automated scanner.\n4. If internal: check whether vulnerability scanner running legitimately.\n5. Correlate with other alerts from same SrcIp.\n6. Escalate if unauthorized.",
     "severity": "medium",
     "query": 'NetworkEvents | where TimeGenerated > ago(15m) | where isnotnull(DstPort) | summarize ports_scanned=dcount(DstPort), hosts_scanned=dcount(DstIp) by SrcIp | where ports_scanned >= 50 or hosts_scanned >= 10',
     "tables": ["NetworkEvents"], "frequency_minutes": 10, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["discovery"], "mitre_techniques": ["T1046"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}], "origin": "builtin"},

    # 9 ── Web Scanner ──
    {"name": "Web Vulnerability Scanner — High Error Rate",
     "description": "A source IP generates a high rate of 4xx/5xx HTTP responses. Key evidence: SrcIp, UrlPath, StatusCode distribution.",
     "triage_steps": "1. Check SrcIp — known scanner IP? Internal or external?\n2. Review UrlPath list for scanner patterns.\n3. If high 404 rate from external IP, almost certainly a scanner.\n4. If server is internet-facing, may be routine background noise.\n5. If server is internal-only, escalate.\n6. Block IP at firewall if confirmed malicious.",
     "severity": "low",
     "query": 'WebAccess | where TimeGenerated > ago(10m) | summarize req_count=count(), error_count=countif(StatusCode >= 400) by SrcIp | where req_count >= 100 and error_count * 3 >= req_count',
     "tables": ["WebAccess"], "frequency_minutes": 10, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["reconnaissance"], "mitre_techniques": ["T1592"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}], "origin": "builtin"},

    # 10 ── DGA DNS ──
    {"name": "Suspicious DNS Queries — DGA-like Patterns",
     "description": "A host generates many distinct DNS queries in a short period — possible DGA (Domain Generation Algorithm) used by malware to locate C2 servers. Key evidence: HostName, DnsQuery list.",
     "triage_steps": "1. List DnsQuery values from evidence — do they look random?\n2. Run: NetworkEvents | where HostName == '<host>' | summarize count() by DnsQuery.\n3. Check if any resolved successfully — those may be C2 servers.\n4. Isolate host if confirmed DGA pattern.\n5. Document domain list for threat intel.",
     "severity": "high",
     "query": 'NetworkEvents | where TimeGenerated > ago(10m) | where isnotnull(DnsQuery) | summarize unique_domains=dcount(DnsQuery), total_queries=count() by HostName | where unique_domains >= 30',
     "tables": ["NetworkEvents"], "frequency_minutes": 5, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["command_and_control"], "mitre_techniques": ["T1568"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}], "origin": "builtin"},

    # 11 ── RDP Lateral Movement ──
    {"name": "RDP Lateral Movement — Multiple Destinations",
     "description": "A source IP initiates RDP (port 3389) or SMB (445) connections to multiple destination hosts — typical lateral movement. Key evidence: SrcIp, DstIp, DstPort.",
     "triage_steps": "1. List destination hosts (DstIp) targeted.\n2. Check whether source account has legitimate access.\n3. Look at AuthEvents for source user.\n4. Determine whether RDP/SMB is normal in this environment.\n5. If >2 destinations + unusual account, escalate.",
     "severity": "high",
     "query": 'NetworkEvents | where TimeGenerated > ago(15m) | where DstPort == 3389 or DstPort == 445 | summarize targets=dcount(DstIp) by SrcIp | where targets >= 3',
     "tables": ["NetworkEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["lateral_movement"], "mitre_techniques": ["T1021.001", "T1021.002"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}], "origin": "builtin"},

    # 12 ── SMB Admin Share ──
    {"name": "SMB Lateral Movement — Admin Share Access",
     "description": "SMB connections to ADMIN$ or C$ administrative shares on multiple hosts. Key evidence: SrcIp, DstIp, DstPort=445.",
     "triage_steps": "1. Identify destination hosts and source IP.\n2. Check whether source is management server or jump host.\n3. Look for subsequent ProcessEvents on destination hosts.\n4. Verify UserName against authorized admin accounts.\n5. If >4 hosts targeted by non-admin, escalate immediately.",
     "severity": "critical",
     "query": 'NetworkEvents | where TimeGenerated > ago(15m) | where DstPort == 445 and isnotnull(SrcIp) and isnotnull(DstIp) | summarize targets=dcount(DstIp) by SrcIp | where targets >= 4',
     "tables": ["NetworkEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["lateral_movement"], "mitre_techniques": ["T1021.002", "T1570"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "ip", "column": "DstIp"}], "origin": "builtin"},

    # 13 ── Office Spawning Shell ──
    {"name": "Microsoft Office Spawning Suspicious Child Process",
     "description": "A Microsoft Office application launches a suspicious child process — a primary vector for macro-based malware delivery. Key evidence: ParentProcessName, ProcessName, ProcessCmdLine.",
     "triage_steps": "1. Identify parent Office application and child process.\n2. Check ProcessCmdLine of child — what arguments?\n3. Look up document that was opened.\n4. Run: ProcessEvents | where HostName == '<host>' for process tree.\n5. Check if user has email with attachments.\n6. If spawned process is cmd/powershell/wscript, escalate.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(15m) | where (ParentProcessName contains "winword" or ParentProcessName contains "excel" or ParentProcessName contains "powerpnt" or ParentProcessName contains "outlook") and (ProcessName contains "cmd" or ProcessName contains "powershell" or ProcessName contains "wscript" or ProcessName contains "cscript" or ProcessName contains "mshta" or ProcessName contains "rundll32" or ProcessName contains "regsvr32" or ProcessName contains "certutil")',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["execution", "initial_access"], "mitre_techniques": ["T1204", "T1566"],
     "entity_mappings": [{"entity_type": "process", "column": "ProcessName"}, {"entity_type": "process", "column": "ParentProcessName"}, {"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 14 ── Large Outbound Transfer ──
    {"name": "Large Outbound Data Transfer — Potential Exfiltration",
     "description": "A host sends an unusually large volume of data to an external destination — possible data exfiltration. Key evidence: SrcIp, DstIp, BytesOut.",
     "triage_steps": "1. Identify SrcIp and DstIp. Is DstIp external?\n2. Check if destination is known cloud storage or file sharing service.\n3. Look at what process was active on source during transfer.\n4. Compare with normal baseline for this host.\n5. If >100MB to unknown external IP, escalate.",
     "severity": "high",
     "query": 'NetworkEvents | where TimeGenerated > ago(30m) | where isnotnull(BytesOut) and BytesOut > 0 and isnotnull(DstIp) | summarize total_bytes=sum(BytesOut), connection_count=count() by SrcIp, DstIp | where total_bytes >= 104857600',
     "tables": ["NetworkEvents"], "frequency_minutes": 10, "lookback_minutes": 30, "threshold": 1,
     "mitre_tactics": ["exfiltration"], "mitre_techniques": ["T1041"],
     "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "ip", "column": "DstIp"}], "origin": "builtin"},

    # 15 ── PowerShell Download Cradle ──
    {"name": "PowerShell Download Cradle",
     "description": "PowerShell invoked with a download pattern (IEX, Net.WebClient, Invoke-WebRequest). Key evidence: ProcessCmdLine (download URL), UserName.",
     "triage_steps": "1. Extract download URL from ProcessCmdLine.\n2. Is URL known malware C2 or legitimate?\n3. Check if URL is internal or external.\n4. Look at what parent process launched PowerShell.\n5. Look for subsequent process creation.\n6. Escalate if URL is external and unknown.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(10m) | where ProcessName contains "powershell" and (ProcessCmdLine contains "IEX" or ProcessCmdLine contains "Invoke-Expression" or ProcessCmdLine contains "WebClient" or ProcessCmdLine contains "Invoke-WebRequest" or ProcessCmdLine contains "DownloadString" or ProcessCmdLine contains "DownloadFile" or ProcessCmdLine contains "FromBase64String")',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 10, "threshold": 1,
     "mitre_tactics": ["execution", "command_and_control"], "mitre_techniques": ["T1059.001", "T1105"],
     "entity_mappings": [{"entity_type": "process", "column": "ProcessName"}, {"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}], "origin": "builtin"},

    # 16 ── Windows Service ──
    {"name": "New Windows Service Installed",
     "description": "A new Windows service is installed via sc.exe, New-Service, or registry modification. Attackers install malicious services for persistence. Key evidence: ProcessCmdLine.",
     "triage_steps": "1. Extract service name and binary path from ProcessCmdLine.\n2. Is binary path in user-writable directory?\n3. Check digital signature of service binary.\n4. Check if this is part of planned software deployment.\n5. Escalate if unauthorized and in suspicious path.",
     "severity": "medium",
     "query": 'ProcessEvents | where TimeGenerated > ago(30m) | where (ProcessCmdLine contains "sc" and ProcessCmdLine contains "create") or ProcessCmdLine contains "New-Service" or ProcessCmdLine contains "sc config"',
     "tables": ["ProcessEvents"], "frequency_minutes": 10, "lookback_minutes": 30, "threshold": 1,
     "mitre_tactics": ["persistence", "privilege_escalation"], "mitre_techniques": ["T1543"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 17 ── Registry Run Key ──
    {"name": "Registry Run Key Modification",
     "description": "A process modifies Run/RunOnce registry keys, a classic persistence technique. Key evidence: ProcessCmdLine shows registry path and value.",
     "triage_steps": "1. Extract registry key path and value from ProcessCmdLine.\n2. Identify executable being configured to auto-start.\n3. Check whether executable path exists and is signed.\n4. Look at UserName — legitimate software installation?\n5. Escalate if executable path is suspicious.",
     "severity": "medium",
     "query": 'ProcessEvents | where TimeGenerated > ago(30m) | where (ProcessCmdLine contains "reg" and ProcessCmdLine contains "add" and ProcessCmdLine contains "Run") or ProcessCmdLine contains "Set-ItemProperty" or ProcessCmdLine contains "New-ItemProperty"',
     "tables": ["ProcessEvents"], "frequency_minutes": 10, "lookback_minutes": 30, "threshold": 1,
     "mitre_tactics": ["persistence"], "mitre_techniques": ["T1547.001"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 18 ── WMI Persistence ──
    {"name": "WMI Event Subscription — Potential Persistence",
     "description": "A WMI event subscription is created that launches a process. Attackers use WMI for fileless persistence. Key evidence: ProcessCmdLine.",
     "triage_steps": "1. Examine ProcessCmdLine for WMI filter details and consumer command.\n2. The consumer's CommandLineTemplate is the actual payload.\n3. Check if payload process path is legitimate.\n4. This is rarely legitimate — escalate unless part of known monitoring.\n5. Document for removal procedure.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(30m) | where (ProcessName contains "wmic" and ProcessCmdLine contains "__EventFilter") or (ProcessName contains "powershell" and ProcessCmdLine contains "FilterToConsumerBinding") or ProcessCmdLine contains "ActiveScriptEventConsumer"',
     "tables": ["ProcessEvents"], "frequency_minutes": 10, "lookback_minutes": 30, "threshold": 1,
     "mitre_tactics": ["persistence"], "mitre_techniques": ["T1546.003"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 19 ── Process Injection ──
    {"name": "Suspicious Process Injection — Debug/Remote Thread",
     "description": "Detects tools commonly used for process injection: mavinject, rundll32 with reflective loading. Key evidence: ProcessCmdLine, target process.",
     "triage_steps": "1. Identify source and target processes from ProcessCmdLine.\n2. Check if target process is lsass.exe, svchost.exe, or browser.\n3. Look at UserName — developer debugging or attacker?\n4. Credential dumping often targets lsass.\n5. Escalate if targeting lsass or from unexpected user.",
     "severity": "high",
     "query": 'ProcessEvents | where TimeGenerated > ago(15m) | where ProcessName contains "mavinject" or (ProcessName contains "rundll32" and ProcessCmdLine contains "#1")',
     "tables": ["ProcessEvents"], "frequency_minutes": 5, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["defense_evasion", "credential_access"], "mitre_techniques": ["T1055", "T1003"],
     "entity_mappings": [{"entity_type": "process", "column": "ProcessName"}, {"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 20 ── DNS Tunneling ──
    {"name": "Potential DNS Tunneling — Long Queries",
     "description": "DNS queries with unusually long subdomains (>40 chars) — possible DNS tunneling for covert C2. Key evidence: DnsQuery length, HostName.",
     "triage_steps": "1. Examine full DnsQuery values — do they contain encoded data?\n2. High entropy in subdomain names suggests tunneling.\n3. Check if queries are to known DNS tunneling service.\n4. Look at BytesOut for host.\n5. Isolate host if confirmed tunneling pattern.",
     "severity": "medium",
     "query": 'NetworkEvents | where TimeGenerated > ago(15m) | where isnotnull(DnsQuery) and strlen(DnsQuery) > 40 | project HostName, DnsQuery, query_len=strlen(DnsQuery) | sort by query_len desc | take 100',
     "tables": ["NetworkEvents"], "frequency_minutes": 10, "lookback_minutes": 15, "threshold": 5,
     "mitre_tactics": ["command_and_control", "exfiltration"], "mitre_techniques": ["T1572", "T1048"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "domain", "column": "DnsQuery"}], "origin": "builtin"},

    # 21 ── Process Discovery ──
    {"name": "Process Discovery — Enumeration Commands",
     "description": "System discovery commands that enumerate processes (tasklist, ps, Get-Process) or system information (systeminfo, whoami). Common during post-exploitation reconnaissance. Key evidence: ProcessCmdLine, UserName.",
     "triage_steps": "1. Check UserName — administrator doing maintenance?\n2. Look at other commands ran before/after on same host.\n3. If paired with net user/group or whoami, this is recon.\n4. If from service account or compromised user, escalate.\n5. Document full chain of discovery commands.",
     "severity": "low",
     "query": 'ProcessEvents | where TimeGenerated > ago(15m) | where ProcessCmdLine contains "tasklist" or ProcessCmdLine contains "systeminfo" or ProcessCmdLine contains "whoami" or ProcessCmdLine contains "net user" or ProcessCmdLine contains "net group" or ProcessCmdLine contains "Get-Process" or (ProcessCmdLine contains "ipconfig" and ProcessCmdLine contains "all")',
     "tables": ["ProcessEvents"], "frequency_minutes": 10, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["discovery"], "mitre_techniques": ["T1057", "T1082", "T1033"],
     "entity_mappings": [{"entity_type": "host", "column": "HostName"}, {"entity_type": "user", "column": "UserName"}], "origin": "builtin"},

    # 22 ── Service Account Interactive Login ──
    {"name": "Service Account Interactive Login",
     "description": "A service account (SYSTEM, NETWORK SERVICE, or $ accounts) performs an interactive logon. Service accounts normally authenticate non-interactively. Key evidence: UserName, LogonType, HostName.",
     "triage_steps": "1. Verify UserName is indeed a service account.\n2. Check LogonType — 2=interactive, 10=remote interactive.\n3. Run: AuthEvents | where UserName == '<account>' for full login history.\n4. Look at ProcessEvents for this account.\n5. Check if scheduled task or service caused this legitimately.\n6. If unexpected interactive logon, escalate.",
     "severity": "high",
     "query": 'AuthEvents | where TimeGenerated > ago(15m) | where EventResult == "success" and LogonType in ("2", "10", "7") and (UserName endswith "$" or UserName contains "SYSTEM" or UserName contains "NETWORK SERVICE")',
     "tables": ["AuthEvents"], "frequency_minutes": 10, "lookback_minutes": 15, "threshold": 1,
     "mitre_tactics": ["privilege_escalation", "defense_evasion"], "mitre_techniques": ["T1134", "T1550"],
     "entity_mappings": [{"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}], "origin": "builtin"},
]


def install_builtin_rules(db: Database) -> int:
    store = RuleStore(db)
    installed = 0
    for rule in BUILTIN_RULES:
        existing = db.query_one("SELECT 1 FROM rules WHERE name=? AND origin='builtin'",
                                [rule["name"]])
        if existing:
            continue
        store.create(rule)
        installed += 1
    return installed
