"""Scenarios 2 and 3: lateral movement from a workstation, and data exfiltration to a rare IP.

Not for: the brute-force chain (_scn_attack.py) or noise and injection scenarios (_scn_noise.py,
_scn_injection.py). Each builder returns a scenario() spec; times are minutes before 'now'.
"""
from __future__ import annotations

import hashlib
from datetime import datetime

from ._scn_rows import alert, ev, rule, scenario, source

# ---- scenario 2: lateral movement -------------------------------------------------------------
LAT_AUTH = "scn-lateral-winsec"
LAT_NET = "scn-lateral-netflow"
LAT_SYS = "scn-lateral-sysmon"
LAT_WS = "ws-hr-0231"
LAT_WS_IP = "10.42.8.31"
LAT_USER = "a.kowalski"
LAT_TARGETS = [("srv-file-01", "10.42.1.10"), ("srv-sql-02", "10.42.1.22"),
               ("dc-01", "10.42.0.5"), ("srv-app-03", "10.42.2.40")]


def _lat_auth(now: datetime) -> list[dict]:
    rows = []
    for t, (host, ip) in enumerate(LAT_TARGETS):
        for k in range(3):
            rows.append(ev(LAT_AUTH, now, 150 - t * 20 - k * 4, EventCode="4624", EventAction="login",
                           EventResult="success", HostName=host, UserName=LAT_USER,
                           TargetUserName=LAT_USER, SrcIp=LAT_WS_IP, DstIp=ip, SrcPort=50100 + k,
                           DstPort=445, LogonType="3", AuthMethod="NTLM"))
    return rows


def _lat_smb(now: datetime) -> list[dict]:
    rows = []
    for t, (host, ip) in enumerate(LAT_TARGETS):
        rows.append(ev(LAT_NET, now, 140 - t * 20, src_type="zeek", Protocol="SMB", DstPort=445,
                       Direction="internal", SrcIp=LAT_WS_IP, DstIp=ip, HostName=LAT_WS, UserName=LAT_USER,
                       ProcessPath="System", ProcessId=4, Url="smb://" + host + "/ADMIN$",
                       BytesOut=18432, BytesIn=6144))
    return rows


def _lat_rdp(now: datetime) -> list[dict]:
    rows = []
    for minutes, (host, ip) in ((70, LAT_TARGETS[3]), (45, LAT_TARGETS[1]), (30, LAT_TARGETS[3])):
        rows.append(ev(LAT_NET, now, minutes, src_type="zeek", Protocol="RDP", DstPort=3389,
                       Direction="internal", SrcIp=LAT_WS_IP, DstIp=ip, HostName=LAT_WS, UserName=LAT_USER,
                       ProcessPath="C:/Windows/System32/mstsc.exe", ProcessId=6120,
                       BytesOut=52000, BytesIn=910000))
    return rows


def _lat_psexec(now: datetime) -> dict:
    return ev(LAT_SYS, now, 139, src_type="sysmon", FilePath="C:/Windows/PSEXESVC.exe",
              FileName="PSEXESVC.exe", Operation="create", HostName="srv-file-01", UserName=LAT_USER,
              ProcessPath="C:/Windows/System32/services.exe", ProcessId=612,
              FileHash=hashlib.sha256(b"PSEXESVC").hexdigest(), EventAction="file_create",
              EventResult="success")


def _rules_lat() -> list[dict]:
    ip_user = [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "TargetUserName"}]
    return [
        rule("scn_lat_ntlm_fanout", "One account authenticating to several servers",
             "A single account and source host make NTLM network logons to three or more distinct servers in one hour. Typical of credential reuse during lateral movement.",
             "1. List the target servers and the account\n2. Ask the owner whether the workstation was used for admin work\n3. Check the workstation for tools that pivot over SMB",
             "high", 'AuthEvents | where AuthMethod == "NTLM" and LogonType == "3" and EventResult == "success"',
             ["AuthEvents"], ["T1021.002", "T1550.002"], ip_user, threshold=3),
        rule("scn_lat_smb_admin_share", "SMB access to ADMIN$ from a workstation",
             "SMB to a hidden admin share from a client workstation. Service-based remote execution (psexec-style) writes a service binary to ADMIN$.",
             "1. Check for PSEXESVC or similar service creation on the target\n2. Check the source host's processes\n3. Isolate the source if unexplained",
             "high", 'NetworkEvents | where DstPort == 445 and Url contains "ADMIN$"', ["NetworkEvents"], ["T1021.002"],
             [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "host", "column": "HostName"}]),
        rule("scn_lat_rdp_internal", "RDP session between internal hosts",
             "Internal RDP connections. Common for admins, also used for lateral movement; needs context.",
             "1. Confirm whether the source host belongs to an admin\n2. Check the logon events on the target\n3. Escalate if the account is not an admin",
             "medium", 'NetworkEvents | where DstPort == 3389 and Direction == "internal"', ["NetworkEvents"],
             ["T1021.001"], [{"entity_type": "ip", "column": "SrcIp"}, {"entity_type": "user", "column": "UserName"}]),
    ]


def lateral_movement(now: datetime) -> dict:
    """One workstation account fans out over NTLM and SMB to four servers, plus RDP and a psexec service."""
    auth, smb, rdp = _lat_auth(now), _lat_smb(now), _lat_rdp(now)
    psexec = _lat_psexec(now)
    auth_cols = ["SrcIp", "DstIp", "TargetUserName", "HostName", "LogonType", "AuthMethod"]
    net_cols = ["SrcIp", "DstIp", "HostName", "Url", "DstPort", "UserName"]
    rdp_cols = ["SrcIp", "DstIp", "DstPort", "ProcessPath", "UserName"]
    events = [("AuthEvents", r) for r in auth] + [("NetworkEvents", r) for r in smb + rdp]
    events.append(("FileEvents", psexec))
    alerts = [
        alert("scn_lat_ntlm_fanout", auth[:6], auth_cols, len(auth), 40, status="active"),
        alert("scn_lat_smb_admin_share", smb, net_cols, len(smb), 45),
        alert("scn_lat_rdp_internal", rdp, rdp_cols, len(rdp), 30),
    ]
    return scenario(
        "lateral_movement",
        [source(LAT_AUTH, "Windows Security (scenario)", "windows_json", "AuthEvents"),
         source(LAT_NET, "Zeek conn (scenario)", "zeek", "NetworkEvents"),
         source(LAT_SYS, "Sysmon (scenario)", "sysmon", "FileEvents")],
        _rules_lat(), events, alerts)


# ---- scenario 3: exfiltration --------------------------------------------------------------------
EXF_FLOW = "scn-exfil-netflow"
EXF_DNS = "scn-exfil-dns"
EXF_HOST = "fin-ws-0412"
EXF_IP = "10.42.5.12"
EXF_USER = "j.ortega"
EXF_DEST = "198.51.100.77"
EXF_ZONE = "t.telemetry-relay.example"
EXF_PROC = "C:/Users/j.ortega/AppData/Local/Temp/svchost32.exe"


def _exf_bulk(now: datetime) -> list[dict]:
    rows = []
    for i in range(12):
        rows.append(ev(EXF_FLOW, now, 120 - i * 7, src_type="zeek", Protocol="TLS", DstPort=443,
                       Direction="outbound", SrcIp=EXF_IP, DstIp=EXF_DEST, SrcPort=51000 + i,
                       HostName=EXF_HOST, UserName=EXF_USER, ProcessPath=EXF_PROC, ProcessId=7744,
                       BytesOut=150_000_000 + i * 1_000_000, BytesIn=52000, Domain="cdn-metrics.telemetry-relay.example"))
    return rows


def _exf_dns(now: datetime) -> list[dict]:
    rows = []
    for i in range(120):
        label = hashlib.sha1(str(i).encode()).hexdigest()[:24]
        rows.append(ev(EXF_DNS, now, 115 - i * 0.8, src_type="zeek", Protocol="DNS", DstPort=53,
                       Direction="outbound", SrcIp=EXF_IP, DstIp="10.42.0.53", HostName=EXF_HOST,
                       UserName=EXF_USER, ProcessPath=EXF_PROC, ProcessId=7744,
                       DnsQuery=label + "." + EXF_ZONE, Domain=EXF_ZONE, BytesOut=180, BytesIn=260))
    return rows


def _exf_rare(now: datetime) -> list[dict]:
    return [ev(EXF_FLOW, now, m, src_type="zeek", Protocol="TLS", DstPort=443, Direction="outbound",
               SrcIp=EXF_IP, DstIp="198.51.100.91", HostName=EXF_HOST, UserName=EXF_USER,
               ProcessPath="C:/Program Files/Microsoft OneDrive/OneDrive.exe", ProcessId=3320,
               BytesOut=8_000_000, BytesIn=400000, Domain="storage-sync.example") for m in (25, 20, 15)]


def _rules_exf() -> list[dict]:
    return [
        rule("scn_exfil_large_outbound", "Large outbound transfer to a rare destination",
             "Outbound sessions that send more than 100 MB from one host in a short window. Data theft or staging for exfiltration.",
             "1. Identify the process that sent the bytes\n2. Check whether the destination is a known business service\n3. Check the account's recent file access",
             "high", 'NetworkEvents | where Direction == "outbound" and BytesOut > 100000000', ["NetworkEvents"],
             ["T1041", "T1567"], [{"entity_type": "ip", "column": "DstIp"}, {"entity_type": "user", "column": "UserName"}]),
        rule("scn_exfil_dns_tunnel", "DNS query volume to a single zone",
             "Many DNS queries from one process to one parent zone, with random-looking labels. Pattern of DNS tunneling.",
             "1. Check the querying process and its hash\n2. Measure label entropy and length\n3. Block the zone at the resolver if confirmed",
             "high", 'NetworkEvents | where Protocol == "DNS" and DstPort == 53', ["NetworkEvents"],
             ["T1071.004", "T1048.003"], [{"entity_type": "domain", "column": "Domain"}, {"entity_type": "user", "column": "UserName"}],
             threshold=50),
        rule("scn_exfil_rare_destination", "First-seen outbound TLS destination",
             "Outbound TLS to an IP that has no prior history in the window. Needs a business owner to confirm the service.",
             "1. Look up the destination's owner and reputation\n2. Check which process opened the session\n3. Ask the user whether the service is approved",
             "medium", 'NetworkEvents | where Direction == "outbound" and DstPort == 443', ["NetworkEvents"],
             ["T1041"], [{"entity_type": "ip", "column": "DstIp"}, {"entity_type": "user", "column": "UserName"}]),
    ]


def data_exfil(now: datetime) -> dict:
    """Bulk TLS to a rare IP, a DNS tunnel-like flood from a masqueraded binary, and a benign sync client."""
    bulk, dns, rare = _exf_bulk(now), _exf_dns(now), _exf_rare(now)
    events = [("NetworkEvents", r) for r in bulk + dns + rare]
    bulk_cols = ["DstIp", "BytesOut", "UserName", "Domain", "ProcessPath"]
    dns_cols = ["Protocol", "DnsQuery", "Domain", "UserName", "ProcessPath"]
    alerts = [
        alert("scn_exfil_large_outbound", bulk[:5], bulk_cols, len(bulk), 30),
        alert("scn_exfil_dns_tunnel", dns[:5], dns_cols, len(dns), 22),
        alert("scn_exfil_rare_destination", rare, bulk_cols, len(rare), 15),
    ]
    return scenario(
        "data_exfil",
        [source(EXF_FLOW, "Zeek conn (scenario)", "zeek", "NetworkEvents"),
         source(EXF_DNS, "Zeek dns (scenario)", "zeek", "NetworkEvents")],
        _rules_exf(), events, alerts)
