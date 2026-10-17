"""Scenario 1: brute force from an external IP that ends in encoded PowerShell and a new local admin.

Not for: lateral movement or exfiltration (_scn_movement.py), noise or injection (_scn_noise.py,
_scn_injection.py). Each builder returns a scenario() spec; times are minutes before 'now'.
"""
from __future__ import annotations

import hashlib
from datetime import datetime

from ._scn_rows import alert, ev, rule, scenario, source

ATTACKER = "198.51.100.23"
TARGET = "srv-hrapp-01"
TARGET_IP = "10.42.3.14"
SRC_AUTH = "scn-brute-force-winsec"
SRC_SYS = "scn-brute-force-sysmon"
PS_PATH = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
ENC_CMD = ("powershell.exe -NoP -NonI -W Hidden -EncodedCommand "
           "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQ7")


def _sha(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def _failures(now: datetime) -> list[dict]:
    users = ["administrator", "svc-hrweb", "backup", "jdoe"]
    rows = []
    for i in range(60):
        rows.append(ev(SRC_AUTH, now, 180 - i * 2, EventCode="4625", EventAction="login",
                       EventResult="failure", HostName=TARGET, UserName=users[i % 4],
                       TargetUserName=users[i % 4], SrcIp=ATTACKER, DstIp=TARGET_IP,
                       SrcPort=49152 + i, DstPort=445, LogonType="3", AuthMethod="NTLM",
                       FailureReason="Unknown user name or bad password."))
    return rows


def _auth_success(now: datetime) -> dict:
    return ev(SRC_AUTH, now, 58, EventCode="4624", EventAction="login", EventResult="success",
              HostName=TARGET, UserName="svc-hrweb", TargetUserName="svc-hrweb", SrcIp=ATTACKER,
              DstIp=TARGET_IP, SrcPort=50311, DstPort=3389, LogonType="10", AuthMethod="NTLM")


def _process_chain(now: datetime) -> list[dict]:
    base = {"HostName": TARGET, "UserName": "svc-hrweb", "IntegrityLevel": "High", "EventAction": "process_start",
                "EventResult": "success", "EventCode": "1", "ProcessId": 4120, "ParentProcessId": 868}
    return [
        ev(SRC_SYS, now, 55, ProcessName="powershell.exe", ProcessPath=PS_PATH, ProcessCmdLine=ENC_CMD,
           ParentProcessName="wmiprvse.exe", ParentCmdLine="C:/Windows/system32/wbem/wmiprvse.exe -Embedding",
           FileHash=_sha("powershell.exe"), **base),
        ev(SRC_SYS, now, 50, ProcessName="net.exe", ProcessPath="C:/Windows/System32/net.exe",
           ProcessCmdLine="net user svc-helpdesk Ch4nge!2026 /add", ParentProcessName="powershell.exe",
           ParentCmdLine=ENC_CMD, FileHash=_sha("net.exe"), **{**base, "ProcessId": 4188}),
        ev(SRC_SYS, now, 49, ProcessName="net.exe", ProcessPath="C:/Windows/System32/net.exe",
           ProcessCmdLine="net localgroup administrators svc-helpdesk /add",
           ParentProcessName="powershell.exe", ParentCmdLine=ENC_CMD, FileHash=_sha("net.exe"),
           **{**base, "ProcessId": 4192}),
    ]


def _dropped_file(now: datetime) -> dict:
    return ev(SRC_SYS, now, 47, src_type="sysmon", FilePath="C:/Users/Public/upd.ps1", FileName="upd.ps1",
              Operation="create", HostName=TARGET, UserName="svc-hrweb", ProcessPath=PS_PATH,
              ProcessId=4120, FileHash=_sha("upd.ps1"), EventAction="file_create", EventResult="success")


def _rules_bf() -> list[dict]:
    user_map = [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "TargetUserName"}]
    return [
        rule("scn_bf_password_spray", "Password spray: failed logons from one source IP",
             "Many failed network logons from one source address against one host. Usually password spraying or brute force; the first step of a credential-access chain.",
             "1. Check if SrcIp is internal, a VPN, or external\n2. List targeted accounts\n3. Look for a later success from the same SrcIp",
             "high", 'AuthEvents | where EventResult == "failure" and LogonType == "3"', ["AuthEvents"],
             ["T1110.003"], user_map, threshold=20),
        rule("scn_bf_success_after_failures", "Successful RDP logon from an IP with recent failures",
             "Interactive RDP logon that succeeds from an address that just failed many times. Strong sign the password was guessed.",
             "1. Confirm the account owner\n2. Check the session's source IP history\n3. Check processes started in that session",
             "high", 'AuthEvents | where EventResult == "success" and LogonType == "10"', ["AuthEvents"],
             ["T1078"], user_map),
        rule("scn_bf_encoded_powershell", "Encoded PowerShell launched by WMI",
             "PowerShell started with -EncodedCommand, especially under wmiprvse.exe. Common post-exploitation loader.",
             "1. Decode the -EncodedCommand payload\n2. Check parent process tree\n3. Check network connections from the host",
             "critical", 'ProcessEvents | where ProcessName == "powershell.exe" and ProcessCmdLine contains "-EncodedCommand"',
             ["ProcessEvents"], ["T1059.001", "T1047"],
             [{"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}]),
        rule("scn_bf_new_local_admin", "New account added to local administrators",
             "net.exe adds an account to the administrators group. Privilege escalation for persistence.",
             "1. Check who created the account and when\n2. Check if the account is in the approved list\n3. Disable the account if unapproved",
             "critical", 'ProcessEvents | where ProcessName == "net.exe" and ProcessCmdLine contains "administrators"',
             ["ProcessEvents"], ["T1136.001", "T1098"],
             [{"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}]),
    ]


def brute_force_to_compromise(now: datetime) -> dict:
    """Spray from ATTACKER, a success via RDP, encoded PowerShell, then a new local admin."""
    fails = _failures(now)
    chain = _process_chain(now)
    success = _auth_success(now)
    ev_cols = ["SrcIp", "TargetUserName", "HostName", "LogonType", "FailureReason"]
    proc_cols = ["UserName", "HostName", "ProcessName", "ProcessCmdLine", "ParentProcessName"]
    events = [("AuthEvents", r) for r in fails + [success]]
    events += [("ProcessEvents", r) for r in chain] + [("FileEvents", _dropped_file(now))]
    alerts = [
        alert("scn_bf_password_spray", fails[:5], ev_cols, 60, 60),
        alert("scn_bf_success_after_failures", [success], ev_cols, 1, 58),
        alert("scn_bf_encoded_powershell", [chain[0]], proc_cols, 1, 55, status="active"),
        alert("scn_bf_new_local_admin", chain[1:], proc_cols, 2, 49),
    ]
    return scenario(
        "brute_force_to_compromise",
        [source(SRC_AUTH, "Windows Security (scenario)", "windows_json", "AuthEvents"),
         source(SRC_SYS, "Sysmon (scenario)", "sysmon", "ProcessEvents")],
        _rules_bf(), events, alerts)
