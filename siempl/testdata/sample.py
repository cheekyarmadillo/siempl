"""Sample data generator for exercising siempl agents.

load_samples(db, seed=42) -> summary dict
  Idempotent: stable ids, INSERT OR IGNORE / check-before-insert.
  Running twice adds nothing.

clear_samples(db) -> summary dict
  Removes ONLY rows with id prefix 'sample_' or notes 'sample'.
  Audited as actor='system' action='samples.clear'.
"""
from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from typing import Any

from ..alerts_status import derived_verdict, normalize_legacy
from ..db import Database

try:
    from ..audit import record as audit_record
except Exception:
    def audit_record(db, actor, action, target_type=None, target_id=None, outcome="ok", details=None):
        pass  # best-effort


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ── stable IDs ─────────────────────────────────────────────────────────────────

def _stable(prefix: str, name: str) -> str:
    """Deterministic ID so load_samples is idempotent."""
    # Simple hash of name under prefix
    import hashlib
    h = hashlib.sha1(name.encode()).hexdigest()[:10]
    return f"{prefix}{h}"


# ── rules ──────────────────────────────────────────────────────────────────────

RULES: list[dict[str, Any]] = [
    {
        "rule_id": "sample_brute_force",
        "name": "Brute Force: Multiple Auth Failures",
        "description": "Detects 5+ failed authentication attempts for the same user within 5 minutes. May indicate password spraying or brute force.",
        "triage_steps": "1. Identify target account\n2. Check if SrcIp is known/trusted\n3. Verify if user is on vacation/locked out\n4. If external IP, consider blocking and alerting",
        "severity": "high",
        "query": "AuthEvents | where EventResult == 'failure' | summarize count() by bin(TimeGenerated, 5m), UserName | where count_ >= 5",
        "tables": ["AuthEvents"],
        "frequency_minutes": 5,
        "lookback_minutes": 5,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_powershell_encoded",
        "name": "Suspicious Process: Encoded PowerShell",
        "description": "Detects PowerShell executions with encoded commands. Common in malware and post-exploitation.",
        "triage_steps": "1. Check process tree and parent\n2. Review command line arguments\n3. Inspect host for other suspicious activity",
        "severity": "critical",
        "query": 'ProcessEvents | where ProcessName == "powershell.exe" and ProcessCmdLine contains "-EncodedCommand"',
        "tables": ["ProcessEvents"],
        "frequency_minutes": 5,
        "lookback_minutes": 5,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_outbound_high_bytes",
        "name": "Network: High-Volume Outbound Transfer",
        "description": "Detects hosts sending >1GB outbound in a 5-minute window. Possible data exfiltration.",
        "triage_steps": "1. Identify host and user\n2. Check if scheduled backup or legitimate transfer\n3. Review destination IPs and ports",
        "severity": "medium",
        "query": "NetworkEvents | where Direction == 'outbound' | summarize total_bytes=sum(BytesOut) by SrcIp | where total_bytes > 1000000000",
        "tables": ["NetworkEvents"],
        "frequency_minutes": 10,
        "lookback_minutes": 10,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_any_failed_login",
        "name": "NOISY: Any Failed Login",
        "description": "Fires on ANY single failed login. Intentionally noisy for tuning agent exercise.",
        "triage_steps": "1. Tuning agent should raise threshold or add exclusions\n2. High FP expected on this rule",
        "severity": "low",
        "query": "AuthEvents | where EventResult == 'failure'",
        "tables": ["AuthEvents"],
        "frequency_minutes": 1,
        "lookback_minutes": 1,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_dns_tunnel",
        "name": "NOISY: Long DNS Query",
        "description": "Detects DNS queries with length >50. Many CDNs and legitimate services trigger this. Tuning exercise.",
        "triage_steps": "1. Check domain reputation\n2. If internal domain, add exclusion\n3. Consider threshold tuning",
        "severity": "low",
        "query": "NetworkEvents | where DnsQuery != '' and len(DnsQuery) > 50",
        "tables": ["NetworkEvents"],
        "frequency_minutes": 5,
        "lookback_minutes": 5,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_no_data_table",
        "name": "Rule on Empty Table",
        "description": "References a table that has zero rows in the current DB. Used to test rule-runner error handling.",
        "triage_steps": "1. Verify table has data\n2. Check source configuration\n3. If expected empty, disable rule",
        "severity": "informational",
        "query": "FileEvents | where Operation == 'delete' and FilePath contains 'sensitive'",
        "tables": ["FileEvents"],
        "frequency_minutes": 60,
        "lookback_minutes": 60,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_never_queried",
        "name": "Rule on Rarely-Queried Table",
        "description": "References Syslog table which has data but no rule/human queries. Optimizer should flag this.",
        "triage_steps": "1. Confirm Syslog is still needed\n2. If not, disable or shorten retention",
        "severity": "low",
        "query": "Syslog | where SeverityLevel <= 3 and AppName == 'sshd'",
        "tables": ["Syslog"],
        "frequency_minutes": 60,
        "lookback_minutes": 60,
        "threshold": 1,
        "enabled": True,
        "origin": "manual",
    },
    {
        "rule_id": "sample_disabled_rule",
        "name": "Disabled: Old Test Rule",
        "description": "A disabled rule that should never fire. Used to verify disabled rules are skipped.",
        "triage_steps": "N/A — rule is disabled",
        "severity": "low",
        "query": "AuthEvents | where UserName == 'nonexistent_test_user_12345'",
        "tables": ["AuthEvents"],
        "frequency_minutes": 5,
        "lookback_minutes": 5,
        "threshold": 1,
        "enabled": False,
        "origin": "manual",
    },
    {
        "rule_id": "sample_temp_monitor",
        "name": "TEMP: Monitor Suspicious IP 203.0.113.77",
        "description": "Temporary monitoring rule for IP under investigation. Auto-expires in 7 days.",
        "triage_steps": "1. Check alert volume\n2. If benign, let rule expire\n3. If malicious, create permanent rule",
        "severity": "medium",
        "query": "NetworkEvents | where SrcIp == '203.0.113.77' or DstIp == '203.0.113.77'",
        "tables": ["AuthEvents", "NetworkEvents", "WebAccess"],
        "frequency_minutes": 5,
        "lookback_minutes": 5,
        "threshold": 1,
        "enabled": True,
        "origin": "ai_temporary",
        "expires_at": "",
    },
]


# ── entities ───────────────────────────────────────────────────────────────────

ENTITIES: list[tuple[str, str, float, int, int]] = [
    # type, value, reputation, alert_count, event_count
    ("ip", "203.0.113.42", 85.0, 5, 120),
    ("ip", "203.0.113.77", 75.0, 3, 80),
    ("ip", "198.51.100.5", 25.0, 1, 45),
    ("ip", "192.168.1.10", 15.0, 0, 200),
    ("ip", "192.168.1.100", 35.0, 2, 60),
    ("ip", "10.0.0.1", 10.0, 0, 500),
    ("user", "admin", 55.0, 4, 90),
    ("user", "svc_backup", 20.0, 0, 300),
    ("user", "jsmith", 30.0, 1, 40),
    ("user", "eve.malice", 90.0, 6, 50),
    ("host", "web-server-01", 45.0, 2, 150),
    ("host", "db-prod-01", 40.0, 1, 80),
    ("host", "backup-server-02", 15.0, 0, 220),
    ("host", "ws-192-168-1-50", 25.0, 1, 60),
    ("process", "powershell.exe", 50.0, 3, 70),
    ("process", "cmd.exe", 30.0, 1, 40),
    ("process", "mimikatz.exe", 95.0, 5, 10),
    ("domain", "evil.com", 80.0, 4, 30),
    ("domain", "cdn.example.com", 20.0, 0, 100),
    ("file_hash", "d41d8cd98f00b204e9800998ecf8427e", 50.0, 1, 5),
]


# ── alerts ─────────────────────────────────────────────────────────────────────

ALERT_SEED: list[dict[str, Any]] = [
    # rule_id, title, severity, status, verdict, entities, description extras
    {"rule": "sample_brute_force", "title": "Brute force on admin from 203.0.113.42", "sev": "high", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "203.0.113.42"}, {"type": "user", "value": "admin"}],
     "desc": "12 failed logins followed by 1 success. External IP."},
    {"rule": "sample_brute_force", "title": "Brute force on jsmith from 203.0.113.77", "sev": "high", "status": "triaging", "verdict": None,
     "ents": [{"type": "ip", "value": "203.0.113.77"}, {"type": "user", "value": "jsmith"}],
     "desc": "8 failed attempts in 3 minutes."},
    {"rule": "sample_brute_force", "title": "Brute force on svc_backup (FP?)", "sev": "medium", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.10"}, {"type": "user", "value": "svc_backup"}],
     "desc": "Automated backup script with retry logic."},
    {"rule": "sample_powershell_encoded", "title": "Encoded PowerShell on web-server-01", "sev": "critical", "status": "new", "verdict": None,
     "ents": [{"type": "host", "value": "web-server-01"}, {"type": "process", "value": "powershell.exe"}],
     "desc": "Base64 encoded command detected. Likely Cobalt Strike."},
    {"rule": "sample_powershell_encoded", "title": "Encoded PowerShell on db-prod-01 (benign)", "sev": "critical", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "host", "value": "db-prod-01"}, {"type": "process", "value": "powershell.exe"}],
     "desc": "DBA automation script using encoded parameters. Approved by IT."},
    {"rule": "sample_powershell_encoded", "title": "Encoded PowerShell on backup-server-02", "sev": "critical", "status": "closed", "verdict": "true_positive",
     "ents": [{"type": "host", "value": "backup-server-02"}, {"type": "process", "value": "powershell.exe"}],
     "desc": "Confirmed malicious: Empire PowerShell agent."},
    {"rule": "sample_outbound_high_bytes", "title": "1.2GB outbound from ws-192-168-1-50", "sev": "medium", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "192.168.1.50"}, {"type": "host", "value": "ws-192-168-1-50"}],
     "desc": "Large transfer to 198.51.100.5 during off-hours."},
    {"rule": "sample_outbound_high_bytes", "title": "2.5GB outbound from backup-server-02 (FP)", "sev": "medium", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.10"}, {"type": "host", "value": "backup-server-02"}],
     "desc": "Nightly offsite backup to S3. Expected behavior."},
    {"rule": "sample_any_failed_login", "title": "Failed login: admin from 10.0.0.1", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "10.0.0.1"}, {"type": "user", "value": "admin"}],
     "desc": "Typo by internal user."},
    {"rule": "sample_any_failed_login", "title": "Failed login: jsmith from 192.168.1.100", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.100"}, {"type": "user", "value": "jsmith"}],
     "desc": "Forgot password. Reset completed."},
    {"rule": "sample_any_failed_login", "title": "Failed login: svc_backup from 192.168.1.10", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.10"}, {"type": "user", "value": "svc_backup"}],
     "desc": "Service account key rotation."},
    {"rule": "sample_any_failed_login", "title": "Failed login: admin from 203.0.113.42", "sev": "low", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "203.0.113.42"}, {"type": "user", "value": "admin"}],
     "desc": "Part of brute force pattern."},
    {"rule": "sample_any_failed_login", "title": "Failed login: alice from 192.168.1.21", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.21"}, {"type": "user", "value": "alice"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: bob from 192.168.1.22", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.22"}, {"type": "user", "value": "bob"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: carol from 192.168.1.23", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.23"}, {"type": "user", "value": "carol"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: dave from 192.168.1.24", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.24"}, {"type": "user", "value": "dave"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: erin from 192.168.1.25", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.25"}, {"type": "user", "value": "erin"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: frank from 192.168.1.26", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.26"}, {"type": "user", "value": "frank"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: gina from 192.168.1.27", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.27"}, {"type": "user", "value": "gina"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_any_failed_login", "title": "Failed login: hank from 192.168.1.28", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "ip", "value": "192.168.1.28"}, {"type": "user", "value": "hank"}],
     "desc": "Single mistyped password by an internal user; succeeded on retry."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: img.cdn-example.net", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "domain", "value": "img.cdn-example.net"}],
     "desc": "Legitimate CDN/vendor hostname with long random token."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: static.assets-example.org", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "domain", "value": "static.assets-example.org"}],
     "desc": "Legitimate CDN/vendor hostname with long random token."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: update.vendor-example.com", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "domain", "value": "update.vendor-example.com"}],
     "desc": "Legitimate CDN/vendor hostname with long random token."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: cdn.example.com", "sev": "low", "status": "closed", "verdict": "false_positive",
     "ents": [{"type": "domain", "value": "cdn.example.com"}],
     "desc": "CDN subdomain with long token. Legitimate."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: suspicious.evil.com", "sev": "low", "status": "new", "verdict": None,
     "ents": [{"type": "domain", "value": "evil.com"}],
     "desc": "Possible DNS tunneling. High entropy subdomain."},
    {"rule": "sample_dns_tunnel", "title": "Long DNS query: data.exfil.evil.com", "sev": "low", "status": "triaging", "verdict": None,
     "ents": [{"type": "domain", "value": "evil.com"}],
     "desc": "Repeat offender domain. Needs investigation."},
    {"rule": "sample_brute_force", "title": "SSH success after brute force from 203.0.113.42", "sev": "high", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "203.0.113.42"}, {"type": "user", "value": "admin"}],
     "desc": "CLEARLY MALICIOUS: brute force succeeded. Immediate escalation required."},
    {"rule": "sample_any_failed_login", "title": "Vuln scanner hit from 198.51.100.5", "sev": "low", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "198.51.100.5"}],
     "desc": "CLEARLY BENIGN: scheduled vulnerability scanner from known internal range."},
    {"rule": "sample_any_failed_login", "title": "Ambiguous: failed login from guest wifi", "sev": "low", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "192.168.1.100"}],
     "desc": "AMBIGUOUS: guest wifi range, could be visitor or rogue device."},
    {"rule": "sample_powershell_encoded", "title": "Mimikatz execution on web-server-01", "sev": "critical", "status": "escalated", "verdict": "true_positive",
     "ents": [{"type": "host", "value": "web-server-01"}, {"type": "process", "value": "mimikatz.exe"}],
     "desc": "Credential dumping detected. SOC notified."},
    {"rule": "sample_brute_force", "title": "Admin account lockout — 203.0.113.77", "sev": "high", "status": "closed", "verdict": "true_positive",
     "ents": [{"type": "ip", "value": "203.0.113.77"}, {"type": "user", "value": "admin"}],
     "desc": "Confirmed brute force. IP blocked at firewall."},
    {"rule": "sample_outbound_high_bytes", "title": "Exfil to 203.0.113.77 from db-prod-01", "sev": "high", "status": "escalated", "verdict": "true_positive",
     "ents": [{"type": "ip", "value": "203.0.113.77"}, {"type": "host", "value": "db-prod-01"}],
     "desc": "Database dump outbound to known malicious IP."},
    {"rule": "sample_any_failed_login", "title": "Repeated failed login: eve.malice", "sev": "low", "status": "new", "verdict": None,
     "ents": [{"type": "user", "value": "eve.malice"}],
     "desc": "Test account used by red team. Monitoring."},
    {"rule": "sample_dns_tunnel", "title": "DNS tunneling indicator: evil.com", "sev": "medium", "status": "new", "verdict": None,
     "ents": [{"type": "domain", "value": "evil.com"}],
     "desc": "Aggregate: multiple long queries to evil.com."},
    {"rule": "sample_brute_force", "title": "Kill-chain: brute force -> success -> admin", "sev": "critical", "status": "new", "verdict": None,
     "ents": [{"type": "ip", "value": "203.0.113.42"}, {"type": "user", "value": "admin"}, {"type": "host", "value": "web-server-01"}],
     "desc": "Complete kill-chain: external IP brute forces admin, succeeds, creates local admin."},
]


# ── raw log lines (for onboarding agent) ───────────────────────────────────────

RAW_LOGS: list[tuple[str, str, str, str]] = [
    # source_id, parser, raw_line, target_table hint
    ("sample_acme_vpn", "auto",
     "timestamp=2026-10-01T12:34:56Z app=acme-vpn user=jsmith src=192.168.1.100 dst=10.0.0.1 action=connect status=success",
     "GenericEvents"),
    ("sample_acme_vpn", "auto",
     "timestamp=2026-10-01T12:35:10Z app=acme-vpn user=eve.malice src=203.0.113.42 dst=10.0.0.1 action=connect status=success",
     "GenericEvents"),
    ("sample_custom_app", "auto",
     json.dumps({"ts": "2026-10-01T13:00:00Z", "app": "custom-app", "level": "ERROR", "msg": "DB connection failed", "host": "db-prod-01"}),
     "GenericEvents"),
    ("sample_custom_app", "auto",
     json.dumps({"ts": "2026-10-01T13:01:00Z", "app": "custom-app", "level": "WARN", "msg": "Slow query detected", "host": "db-prod-01", "query_time_ms": 12000}),
     "GenericEvents"),
]


# ── table_usage skew (for optimizer) ───────────────────────────────────────────

TABLE_USAGE: list[tuple[str, int, int, int, int, int]] = [
    # table, rows, bytes, rule_queries, user_queries, alerts
    ("WebAccess", 500000, 25000000, 0, 2, 0),
    ("NetworkEvents", 450000, 22000000, 1, 5, 2),
    ("AuthEvents", 80000, 4000000, 3, 20, 8),
    ("ProcessEvents", 30000, 1500000, 2, 10, 3),
    ("Syslog", 200000, 10000000, 0, 0, 0),
    ("GenericEvents", 5000, 250000, 0, 1, 0),
]

QUERY_LOG: list[tuple[str, list[str], str]] = [
    ("user", ["AuthEvents"], "AuthEvents | where EventResult == 'failure' | summarize count() by UserName"),
    ("user", ["NetworkEvents"], "NetworkEvents | where Direction == 'outbound' | take 10"),
    ("rule", ["AuthEvents"], "AuthEvents | where EventResult == 'failure'"),
    ("rule", ["ProcessEvents"], 'ProcessEvents | where ProcessName == "powershell.exe"'),
    ("user", ["AuthEvents", "NetworkEvents"], "NetworkEvents | where SrcIp == '203.0.113.42'"),
]


# ── recommendations ────────────────────────────────────────────────────────────

RECOMMENDATIONS: list[dict[str, Any]] = [
    {
        "rec_id": "sample_rec_filter_webaccess",
        "agent": "optimizer",
        "kind": "ingest_filter",
        "target": "WebAccess",
        "title": "Filter WebAccess health-check noise",
        "rationale": "WebAccess has 500k rows/day, zero rule queries. Health checks account for ~40%.",
        "payload": {"filter": {"table": "WebAccess", "expression": 'UrlPath == "/health"'}},
        "est_savings": "~200k rows/day",
    },
    {
        "rec_id": "sample_rec_retention_syslog",
        "agent": "optimizer",
        "kind": "retention",
        "target": "Syslog",
        "title": "Shorten Syslog retention to 7 days",
        "rationale": "Syslog has 200k rows/day but no rule or human queries in 14 days.",
        "payload": {"table": "Syslog", "retention_days": 7},
        "est_savings": "~1.3M rows",
    },
    {
        "rec_id": "sample_rec_disable_noisy_dns",
        "agent": "tuning",
        "kind": "rule_disable",
        "target": "sample_dns_tunnel",
        "title": "Disable noisy DNS tunnel rule",
        "rationale": "70% FP rate on sample_dns_tunnel. Consider threshold or exclusion tuning first.",
        "payload": {"rule_id": "sample_dns_tunnel", "reason": "High FP rate"},
        "est_savings": "~15 alerts/day",
    },
]


# ── ingest filters ─────────────────────────────────────────────────────────────

INGEST_FILTERS: list[dict[str, Any]] = [
    {
        "filter_id": "sample_filter_healthcheck",
        "table_name": "WebAccess",
        "expression": 'UrlPath == "/health"',
        "description": "Drop health check requests (sample data)",
        "enabled": True,
        "origin": "manual",
    },
    {
        "filter_id": "sample_filter_debug",
        "table_name": "Syslog",
        "expression": 'SeverityLevel == 7',
        "description": "Drop debug-level syslog (sample data, disabled)",
        "enabled": False,
        "origin": "manual",
    },
]


# ── public API ─────────────────────────────────────────────────────────────────

def load_samples(db: Database, seed: int = 42) -> dict[str, Any]:
    """Idempotently load sample data. Returns summary dict."""
    random.seed(seed)
    now = _now()
    summary: dict[str, int] = {
        "rules_added": 0, "alerts_added": 0, "incidents_added": 0,
        "entities_added": 0, "events_added": 0, "table_usage_added": 0,
        "recommendations_added": 0, "sources_added": 0, "filters_added": 0,
    }

    # --- entities first (referenced by alerts) ---
    for etype, value, rep, ac, ec in ENTITIES:
        eid = f"{etype}:{value.lower()}"
        watch = (eid == "ip:203.0.113.42")  # watch-list one entity
        existing = db.query_one("SELECT entity_id FROM entities WHERE entity_id=?", [eid])
        if existing:
            continue
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen,watch,notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [eid, etype, value, rep, ac, ec, now, now, watch, "sample"])
        summary["entities_added"] += 1

    # --- rules ---
    for rule in RULES:
        rid = rule["rule_id"]
        existing = db.query_one("SELECT rule_id FROM rules WHERE rule_id=?", [rid])
        if existing:
            continue
        # Handle expires_at
        expires = rule.get("expires_at")
        if expires == "":
            expires = (now + timedelta(days=7)).isoformat()
        db.execute(
            """INSERT INTO rules(
                rule_id,name,description,triage_steps,severity,query,tables,
                frequency_minutes,lookback_minutes,threshold,enabled,origin,expires_at,
                version,tuning_history,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [rid, rule["name"], rule["description"], rule["triage_steps"],
             rule["severity"], rule["query"], json.dumps(rule.get("tables", [])),
             rule.get("frequency_minutes", 5), rule.get("lookback_minutes", 5),
             rule.get("threshold", 1), rule.get("enabled", True), rule.get("origin", "manual"),
             expires, 1, json.dumps([]), now, now])
        summary["rules_added"] += 1

    # --- alerts ---
    for i, a in enumerate(ALERT_SEED):
        aid = _stable("sample_alert_", f"{a['rule']}_{i}")
        existing = db.query_one("SELECT alert_id FROM alerts WHERE alert_id=?", [aid])
        if existing:
            continue
        ents = json.dumps(a["ents"])
        evidence = json.dumps([{"SrcIp": e["value"]} for e in a["ents"] if e["type"] == "ip"][:1])
        status = normalize_legacy(a["status"], a.get("verdict"))
        db.execute(
            """INSERT INTO alerts(
                alert_id,rule_id,title,severity,status,verdict,verdict_by,
                description,created_at,updated_at,window_start,window_end,
                row_count,evidence,entities,dedupe_key,alert_number,reputation_applied)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,nextval('alert_number_seq'),FALSE)""",
            [aid, a["rule"], a["title"], a["sev"], status, derived_verdict(status), None,
             a["desc"], now, now, now - timedelta(minutes=5), now,
             random.randint(1, 20), evidence, ents, aid])
        summary["alerts_added"] += 1

    # --- raw events (GenericEvents) for onboarding ---
    for src_id, parser, raw_line, target_table in RAW_LOGS:
        existing = db.query_one("SELECT source_id FROM sources WHERE source_id=?", [src_id])
        if not existing:
            db.execute(
                "INSERT INTO sources(source_id,name,kind,parser,target_table,status,events_total,notes) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [src_id, src_id, "file", parser, target_table, "pending", 0, "sample"])
            summary["sources_added"] += 1
        # Insert raw events
        existing_ev = db.query_one('SELECT 1 FROM "GenericEvents" WHERE SourceId=? AND RawEvent=?', [src_id, raw_line])
        if not existing_ev:
            db.execute(
                'INSERT INTO "GenericEvents"(TimeGenerated,IngestTime,SourceId,SourceType,Message,RawEvent,EventResult) '
                "VALUES (?,?,?,?,?,?,?)",
                [now, now, src_id, "unknown", raw_line[:200], raw_line, "unknown"])
            summary["events_added"] += 1

    # --- table_usage skew ---
    for table, rows, bytes_val, rq, uq, alerts in TABLE_USAGE:
        for days_ago in range(14):
            day = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            # Use a deterministic ID to avoid duplicates
            existing = db.query_one(
                "SELECT 1 FROM table_usage WHERE day=?::DATE AND table_name=?",
                [day, table])
            if not existing:
                db.execute(
                    """INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,rule_queries,user_queries,alerts_generated)
                    VALUES (?::DATE,?,?,?,?,?,?)""",
                    [day, table, rows, bytes_val, rq, uq, alerts])
                summary["table_usage_added"] += 1

    # --- query_log ---
    for origin, tables, kql in QUERY_LOG:
        qid = _stable("sample_ql_", kql[:60])
        existing = db.query_one("SELECT 1 FROM query_log WHERE ref=?", [qid])
        if not existing:
            db.execute(
                "INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms) "
                "VALUES (?,?,?,?,?,?,?)",
                [now, origin, qid, tables, kql, random.randint(1, 100), random.uniform(0.5, 5.0)])

    # --- recommendations ---
    for rec in RECOMMENDATIONS:
        existing = db.query_one("SELECT rec_id FROM recommendations WHERE rec_id=?", [rec["rec_id"]])
        if existing:
            continue
        db.execute(
            """INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,est_savings,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            [rec["rec_id"], rec["agent"], rec["kind"], rec["target"], rec["title"],
             rec["rationale"], json.dumps(rec["payload"]), rec["est_savings"], "open", now])
        summary["recommendations_added"] += 1

    # --- ingest_filters ---
    for filt in INGEST_FILTERS:
        existing = db.query_one("SELECT filter_id FROM ingest_filters WHERE filter_id=?", [filt["filter_id"]])
        if existing:
            continue
        db.execute(
            "INSERT INTO ingest_filters(filter_id,table_name,expression,description,enabled,origin,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            [filt["filter_id"], filt["table_name"], filt["expression"], filt["description"],
             filt["enabled"], filt["origin"], now])
        summary["filters_added"] += 1

    # --- table_retention ---
    db.execute(
        "INSERT INTO table_retention(table_name,retention_days) VALUES (?,?) ON CONFLICT DO NOTHING",
        ["Syslog", 30])

    # --- audit ---
    audit_record(db, "system", "samples.load", target_type="setting", target_id="samples",
                 outcome="ok", details=summary)
    return summary


def clear_samples(db: Database) -> dict[str, int]:
    """Remove ONLY sample-marked rows. Returns summary."""
    summary: dict[str, int] = {
        "rules_deleted": 0, "alerts_deleted": 0, "incidents_deleted": 0,
        "entities_deleted": 0, "events_deleted": 0, "sources_deleted": 0,
        "recommendations_deleted": 0, "filters_deleted": 0,
        "table_usage_deleted": 0,
    }

    # Alerts with sample_ prefix
    for row in db.query("SELECT alert_id FROM alerts WHERE alert_id LIKE 'sample_%'"):
        db.execute("DELETE FROM alerts WHERE alert_id=?", [row["alert_id"]])
        summary["alerts_deleted"] += 1

    # Incidents
    for row in db.query("SELECT incident_id FROM incidents WHERE incident_id LIKE 'sample_%'"):
        db.execute("DELETE FROM incidents WHERE incident_id=?", [row["incident_id"]])
        summary["incidents_deleted"] += 1

    # Rules
    for row in db.query("SELECT rule_id FROM rules WHERE rule_id LIKE 'sample_%'"):
        db.execute("DELETE FROM rules WHERE rule_id=?", [row["rule_id"]])
        summary["rules_deleted"] += 1

    # Entities with notes='sample'
    for row in db.query("SELECT entity_id FROM entities WHERE notes = 'sample'"):
        db.execute("DELETE FROM entities WHERE entity_id=?", [row["entity_id"]])
        summary["entities_deleted"] += 1

    # GenericEvents with sample source
    for row in db.query("SELECT rowid FROM GenericEvents WHERE SourceId LIKE 'sample_%'"):
        db.execute('DELETE FROM "GenericEvents" WHERE rowid=?', [row["rowid"]])
        summary["events_deleted"] += 1

    # Sources
    for row in db.query("SELECT source_id FROM sources WHERE source_id LIKE 'sample_%'"):
        db.execute("DELETE FROM sources WHERE source_id=?", [row["source_id"]])
        summary["sources_deleted"] += 1

    # Recommendations
    for row in db.query("SELECT rec_id FROM recommendations WHERE rec_id LIKE 'sample_%'"):
        db.execute("DELETE FROM recommendations WHERE rec_id=?", [row["rec_id"]])
        summary["recommendations_deleted"] += 1

    # Ingest filters
    for row in db.query("SELECT filter_id FROM ingest_filters WHERE filter_id LIKE 'sample_%'"):
        db.execute("DELETE FROM ingest_filters WHERE filter_id=?", [row["filter_id"]])
        summary["filters_deleted"] += 1

    # Table usage with sample prefix IDs (not stored there); use day pattern heuristic
    # Actually table_usage has no ID; delete rows for sample tables on recent days if no other data
    # Skip — too risky. We'll leave table_usage.

    # Comments linked to sample incidents (by alert_id pattern incident_id)
    for row in db.query("SELECT comment_id FROM alert_comments WHERE alert_id LIKE 'sample_%'"):
        db.execute("DELETE FROM alert_comments WHERE comment_id=?", [row["comment_id"]])

    # Entity edges for sample entities
    sample_entities = [r["entity_id"] for r in db.query("SELECT entity_id FROM entities WHERE notes = 'sample'")]
    if sample_entities:
        ph = ",".join("?" * len(sample_entities))
        db.execute(f"DELETE FROM entity_edges WHERE src_entity IN ({ph}) OR dst_entity IN ({ph})",
                     sample_entities + sample_entities)

    audit_record(db, "system", "samples.clear", target_type="setting", target_id="samples",
                 outcome="ok", details=summary)
    return summary
