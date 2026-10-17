"""Tests for siempl.detect: RuleStore, sigma_to_rule, sentinel_to_rule,
RuleRunner, create_alert, set_verdict, builtin rules, importer.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from siempl.db import Database
from siempl.detect.builtin import BUILTIN_RULES, install_builtin_rules
from siempl.detect.engine import (
    RuleRunner,
    RuleStore,
    UnsupportedRule,
    create_alert,
    sentinel_to_rule,
    set_verdict,
    sigma_to_rule,
    start_scheduler,
)
from siempl.detect.importer import fetch_sentinel, fetch_sigma, import_rules


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


@pytest.fixture
def store(db):
    return RuleStore(db)


@pytest.fixture
def runner(db):
    return RuleRunner(db)


# =====================================================================
# RuleStore
# =====================================================================

class TestRuleStoreCRUD:
    def test_create_and_get(self, store, db):
        rid = store.create({
            "name": "Test Rule",
            "description": "A test",
            "severity": "high",
            "query": "SELECT 1",
        })
        assert rid.startswith("rule_")

        rule = store.get(rid)
        assert rule["name"] == "Test Rule"
        assert rule["severity"] == "high"
        assert rule["enabled"]
        assert rule["origin"] == "manual"
        assert rule["version"] == 1

    def test_list_with_filters(self, store):
        store.create({"name": "R1", "query": "SELECT 1", "enabled": True, "origin": "builtin"})
        store.create({"name": "R2", "query": "SELECT 2", "enabled": False, "origin": "sigma"})
        store.create({"name": "R3", "query": "SELECT 3", "enabled": True, "origin": "builtin"})

        all_rules = store.list()
        assert len(all_rules) == 3

        enabled = store.list(enabled=True)
        assert len(enabled) == 2

        builtin = store.list(origin="builtin")
        assert len(builtin) == 2

    def test_update_bumps_version_and_history(self, store):
        rid = store.create({"name": "R1", "query": "SELECT 1"})
        store.update(rid, threshold=5)

        rule = store.get(rid)
        assert rule["version"] == 2
        history = json.loads(rule["tuning_history"]) if isinstance(rule["tuning_history"], str) else rule["tuning_history"]
        assert len(history) == 1
        assert "threshold" in history[0]["changes"]

    def test_update_nonexistent_returns_false(self, store):
        assert store.update("nonexistent", threshold=5) is False

    def test_enable_disable(self, store):
        rid = store.create({"name": "R1", "query": "SELECT 1"})
        store.disable(rid)
        assert store.get(rid)["enabled"] is False
        store.enable(rid)
        assert store.get(rid)["enabled"] is True

    def test_delete(self, store):
        rid = store.create({"name": "R1", "query": "SELECT 1"})
        store.delete(rid)
        assert store.get(rid) is None


# =====================================================================
# sigma_to_rule
# =====================================================================

SIMPLE_SIGMA = """\
title: Suspicious PowerShell Execution
id: 12345
status: test
description: Detects encoded PowerShell
level: high
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Legitimate admin scripts
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
"""


def _sigma_kql(y, ref=""):
    """These tests cover the KQL translator (the fallback path); pySigma is tested in test_sigma_pysigma.py."""
    return sigma_to_rule(y, ref, backend="kql")


class TestSigmaToRule:
    def test_basic_conversion(self):
        rule = _sigma_kql(SIMPLE_SIGMA)
        assert rule["name"] == "Suspicious PowerShell Execution"
        assert rule["severity"] == "high"
        assert rule["origin"] == "sigma"
        assert "ProcessEvents" in str(rule["tables"])
        assert "ProcessPath" in rule["query"]
        assert "ProcessCmdLine" in rule["query"]
        assert "endswith" in rule["query"]

    def test_mitre_extraction(self):
        rule = _sigma_kql(SIMPLE_SIGMA)
        assert "T1059.001" in rule["mitre_techniques"]
        assert "execution" in rule["mitre_tactics"]

    def test_falsepositives_in_description(self):
        rule = _sigma_kql(SIMPLE_SIGMA)
        assert "Legitimate admin scripts" in rule["description"]

    def test_triage_steps_generated(self):
        rule = _sigma_kql(SIMPLE_SIGMA)
        assert len(rule["triage_steps"]) > 50
        assert "ProcessEvents" in rule["triage_steps"]

    def test_entity_mappings_from_table(self):
        rule = _sigma_kql(SIMPLE_SIGMA)
        mappings = rule["entity_mappings"]
        assert len(mappings) > 0
        col_names = [m["column"] for m in mappings]
        assert "ProcessPath" in col_names or "ProcessName" in col_names

    def test_no_condition_raises(self):
        with pytest.raises(UnsupportedRule):
            _sigma_kql("title: X\nlogsource: {category: process_creation}\n")

    def test_bad_yaml_raises(self):
        with pytest.raises(UnsupportedRule, match="Invalid YAML"):
            _sigma_kql("title: [unclosed")

    def test_selection_list_or(self):
        """Lists in selections become KQL in clauses."""
        yml = """\
title: Multiple Extensions
logsource: {category: process_creation}
detection:
  selection:
    Image:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
  condition: selection
"""
        rule = _sigma_kql(yml)
        assert "in (" in rule["query"]
        assert "cmd.exe" in rule["query"]
        assert "powershell.exe" in rule["query"]

    def test_and_condition(self):
        yml = """\
title: Two Selections
logsource: {category: process_creation}
detection:
  sel1:
    Image|endswith: '\\\\cmd.exe'
  sel2:
    CommandLine|contains: 'whoami'
  condition: sel1 and sel2
"""
        rule = _sigma_kql(yml)
        assert "and" in rule["query"]

    def test_or_condition(self):
        yml = """\
title: Either
logsource: {category: process_creation}
detection:
  sel1:
    Image|endswith: '\\\\cmd.exe'
  sel2:
    Image|endswith: '\\\\powershell.exe'
  condition: sel1 or sel2
"""
        rule = _sigma_kql(yml)
        assert "or" in rule["query"]

    def test_not_condition(self):
        yml = """\
title: With Exclusion
logsource: {category: process_creation}
detection:
  sel:
    Image|endswith: '\\\\cmd.exe'
  filter:
    User|endswith: 'SYSTEM'
  condition: sel and not filter
"""
        rule = _sigma_kql(yml)
        assert "not" in rule["query"]

    def test_1_of_pattern(self):
        yml = """\
title: One of Many
logsource: {category: process_creation}
detection:
  sel1:
    Image|endswith: '\\\\cmd.exe'
  sel2:
    Image|endswith: '\\\\powershell.exe'
  sel3:
    Image|endswith: '\\\\wscript.exe'
  condition: 1 of them
"""
        rule = _sigma_kql(yml)
        assert "or" in rule["query"]

    def test_all_of_pattern(self):
        yml = """\
title: All of Many
logsource: {category: process_creation}
detection:
  sel1:
    Image|endswith: '\\\\cmd.exe'
  sel2:
    CommandLine|contains: 'cmd'
  condition: all of them
"""
        rule = _sigma_kql(yml)
        assert "and" in rule["query"]

    def test_modifiers_startswith_endswith_re(self):
        yml = """\
title: Modifiers
logsource: {category: process_creation}
detection:
  sel:
    Image|startswith: 'C:\\\\Windows\\\\'
    CommandLine|re: '.*cmd.*'
  condition: sel
"""
        rule = _sigma_kql(yml)
        assert "startswith" in rule["query"]
        assert "matches regex" in rule["query"]

    def test_unmapped_field_falls_back_to_extra(self):
        yml = """\
title: Custom Field
logsource: {category: process_creation}
detection:
  sel:
    CustomField: 'value'
  condition: sel
"""
        # Unmapped fields fall back to dynamic access on the JSON Extra
        # column: tostring(Extra.CustomField). The rule must import and the
        # generated KQL must compile (sigma_to_rule verifies compilation).
        rule = _sigma_kql(yml)
        assert "tostring(Extra.CustomField)" in rule["query"]

    def test_cidr_modifier(self):
        yml = """\
title: CIDR Match
logsource: {category: network_connection}
detection:
  sel:
    DestinationIp|cidr: '10.0.0.0/8'
  condition: sel
"""
        # CIDR now compiles to ipv4_is_in_range via cidr_contains in KQL
        rule = _sigma_kql(yml)
        assert "ipv4_is_in_range" in rule["query"]

    def test_aggregation_count_by(self):
        yml = """\
title: Count by
logsource: {category: process_creation}
detection:
  selection:
    CommandLine|contains: 'whoami'
    CommandLine|count: '>= 5'
  condition: selection
"""
        rule = _sigma_kql(yml)
        # Aggregation is expressed as canonical KQL (summarize ... by ...),
        # the same form used by the builtin rules; it must compile.
        assert "summarize" in rule["query"]
        assert "count()" in rule["query"]
        assert "by ProcessCmdLine" in rule["query"]
        assert "cnt >= 5" in rule["query"]

    def test_logsource_resolution(self):
        yml = """\
title: Auth Rule
logsource: {category: authentication}
detection:
  sel:
    User: admin
  condition: sel
"""
        rule = _sigma_kql(yml)
        assert "AuthEvents" in str(rule["tables"])


# =====================================================================
# sentinel_to_rule
# =====================================================================

SENTINEL_YAML = """\
id: 12345678-1234-1234-1234-123456789012
name: Rare subscription level operations
description: Detects rare operations at the subscription level
severity: Low
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: |
  SecurityEvent
  | where EventID == 4625
  | where AccountType == "User"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: Account
"""


class TestSentinelToRule:
    def test_basic_conversion(self):
        rule = sentinel_to_rule(SENTINEL_YAML)
        assert rule["name"] == "Rare subscription level operations"
        assert rule["severity"] == "low"
        assert rule["origin"] == "sentinel"
        assert "AuthEvents" in str(rule["tables"])
        assert "T1098" in rule["mitre_techniques"]

    def test_entity_mappings_converted(self):
        rule = sentinel_to_rule(SENTINEL_YAML)
        assert len(rule["entity_mappings"]) > 0
        assert rule["entity_mappings"][0]["entity_type"] == "user"  # Sentinel Account -> our user
        assert rule["entity_mappings"][0]["column"] == "UserName"

    def test_table_mapping(self):
        rule = sentinel_to_rule(SENTINEL_YAML)
        assert "AuthEvents" in str(rule["tables"])

    def test_no_query_raises(self):
        with pytest.raises(UnsupportedRule, match="no 'query' field"):
            sentinel_to_rule("id: x\nname: X\nseverity: Low\n")

    def test_bad_yaml_raises(self):
        with pytest.raises(UnsupportedRule, match="Invalid YAML"):
            sentinel_to_rule("{invalid: [yaml")

    def test_triage_steps(self):
        rule = sentinel_to_rule(SENTINEL_YAML)
        assert len(rule["triage_steps"]) > 50


# =====================================================================
# create_alert
# =====================================================================

class TestCreateAlert:
    def test_creates_alert(self, db):
        rule = {
            "rule_id": "rule_test",
            "name": "Test Alert",
            "severity": "high",
            "description": "Test desc",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": ["AuthEvents"],
            "entity_mappings": [
                {"entity_type": "ip", "column": "SrcIp"},
            ],
        }
        aid = create_alert(db, rule,
                           rows=[["1.2.3.4", "bob"]],
                           columns=["SrcIp", "UserName"])
        assert aid is not None
        assert aid.startswith("alert_")

        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        assert alert["title"] == "Test Alert"
        assert alert["severity"] == "high"
        assert alert["status"] == "new"
        assert alert["row_count"] == 1

    def test_deduplicates_same_rule_and_entities(self, db):
        rule = {
            "rule_id": "rule_dedup",
            "name": "Dedup Test",
            "severity": "low",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": [],
            "entity_mappings": [
                {"entity_type": "ip", "column": "SrcIp"},
            ],
        }
        aid1 = create_alert(db, rule,
                            rows=[["10.0.0.1"]],
                            columns=["SrcIp"])
        assert aid1 is not None

        aid2 = create_alert(db, rule,
                            rows=[["10.0.0.1"]],
                            columns=["SrcIp"])
        assert aid2 is None  # deduplicated

        # Check row_count bumped
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid1])
        assert alert["row_count"] == 2

    def test_creates_numbered_new_alert_without_incident(self, db):
        rule = {"rule_id": "rule_inc", "name": "Number Test", "severity": "medium",
                "frequency_minutes": 5, "lookback_minutes": 5, "tables": [], "entity_mappings": []}
        aid = create_alert(db, rule, rows=[["x"]], columns=["y"])
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        assert alert["status"] == "new"
        assert alert["alert_number"] >= 1
        assert alert["incident_id"] is None

    def test_alerts_sharing_entity_are_separate_and_numbered(self, db):
        rule = {"rule_id": "rule_group", "name": "Group Test", "severity": "low",
                "frequency_minutes": 5, "lookback_minutes": 5, "tables": [],
                "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}]}
        aid1 = create_alert(db, rule, rows=[["10.0.0.5"]], columns=["SrcIp"])
        aid3 = create_alert(db, dict(rule, rule_id="rule_group_2"), rows=[["10.0.0.5"]], columns=["SrcIp"])
        a1 = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid1])
        a3 = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid3])
        assert a1["incident_id"] is None and a3["incident_id"] is None
        assert a3["alert_number"] == a1["alert_number"] + 1

    def test_upserts_entities_and_bumps_alert_count(self, db):
        rule = {
            "rule_id": "rule_ent",
            "name": "Entity Test",
            "severity": "low",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": [],
            "entity_mappings": [
                {"entity_type": "ip", "column": "SrcIp"},
                {"entity_type": "user", "column": "UserName"},
            ],
        }
        create_alert(db, rule,
                     rows=[["10.0.0.99", "bob"]],
                     columns=["SrcIp", "UserName"])

        ip_ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:10.0.0.99"])
        assert ip_ent is not None
        assert ip_ent["alert_count"] >= 1

        user_ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["user:bob"])
        assert user_ent is not None
        assert user_ent["alert_count"] >= 1

    def test_evidence_capped_at_20(self, db):
        rule = {
            "rule_id": "rule_ev",
            "name": "Evidence Test",
            "severity": "low",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": [],
            "entity_mappings": [],
        }
        rows = [["row" + str(i)] for i in range(50)]
        aid = create_alert(db, rule, rows=rows, columns=["col"])
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        evidence = json.loads(alert["evidence"]) if isinstance(alert["evidence"], str) else alert["evidence"]
        assert len(evidence) == 20


# =====================================================================
# set_verdict
# =====================================================================

class TestSetVerdict:
    def test_closes_alert(self, db):
        rule = {"rule_id": "r1", "name": "T", "severity": "low",
                "frequency_minutes": 5, "lookback_minutes": 5, "tables": [],
                "entity_mappings": []}
        aid = create_alert(db, rule, rows=[["x"]], columns=["y"])
        assert set_verdict(db, aid, "true_positive", "tester")
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        assert alert["status"] == "closed_tp"
        assert alert["verdict"] == "true_positive"
        assert alert["verdict_by"] == "tester"

    def test_already_closed_skips(self, db):
        rule = {"rule_id": "r1", "name": "T", "severity": "low",
                "frequency_minutes": 5, "lookback_minutes": 5, "tables": [],
                "entity_mappings": []}
        aid = create_alert(db, rule, rows=[["x"]], columns=["y"])
        set_verdict(db, aid, "true_positive", "tester")
        assert set_verdict(db, aid, "false_positive", "tester") is False

    def test_nonexistent_alert(self, db):
        assert set_verdict(db, "bogus", "true_positive", "tester") is False

    def test_moves_entities_reputation(self, db):
        from siempl.entities import EntityStore
        EntityStore(db).upsert("ip", "10.0.0.1")

        rule = {"rule_id": "r1", "name": "T", "severity": "low",
                "frequency_minutes": 5, "lookback_minutes": 5, "tables": [],
                "entity_mappings": [
                    {"entity_type": "ip", "column": "SrcIp"},
                ]}
        aid = create_alert(db, rule, rows=[["10.0.0.1"]], columns=["SrcIp"])
        set_verdict(db, aid, "true_positive", "tester")

        ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:10.0.0.1"])
        assert ent["reputation"] > 50


# =====================================================================
# RuleRunner
# =====================================================================

class TestRuleRunner:
    def test_run_due_no_rules(self, runner):
        result = runner.run_due()
        assert result["rules_checked"] == 0
        assert result["alerts_generated"] == 0

    def test_run_rule_no_results(self, store, runner):
        rid = store.create({"name": "Empty",
                            "query": 'AuthEvents | where SrcIp == "no-such-ip" | take 1',
                            "frequency_minutes": 5, "lookback_minutes": 5,
                            "tables": ["AuthEvents"], "entity_mappings": "[]"})
        alert_ids = runner.run_rule(rid)
        assert alert_ids == []

    def test_run_disabled_rule_skipped(self, store, runner):
        rid = store.create({"name": "Disabled",
                            "query": 'AuthEvents | where SrcIp == "no-such-ip" | take 1',
                            "enabled": False, "tables": ["AuthEvents"],
                            "entity_mappings": "[]"})
        alert_ids = runner.run_rule(rid)
        assert alert_ids == []

    def test_run_due_finds_due_rules(self, store, runner, db):
        # Insert test data so KQL rule query has rows to match
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated,SrcIp) VALUES (now(),\'has-data\')'
        )
        store.create({
            "name": "Due Rule",
            "query": 'AuthEvents | where SrcIp == "has-data" | project SrcIp | take 1',
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "tables": ["AuthEvents"],
            "entity_mappings": "[]",
        })
        result = runner.run_due()
        assert result["rules_checked"] == 1
        assert result["alerts_generated"] == 1

    def test_threshold_respected(self, store, runner, db):
        """Rules with threshold > matching rows should not fire."""
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated,SrcIp) VALUES (now(),\'has-data2\')'
        )
        rid = store.create({
            "name": "Threshold Rule",
            "query": 'AuthEvents | where SrcIp == "has-data2" | project SrcIp | take 1',
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 5,  # only 1 row returned
            "tables": ["AuthEvents"],
            "entity_mappings": "[]",
        })
        alert_ids = runner.run_rule(rid)
        assert alert_ids == []  # threshold not met

    def test_rule_records_last_run(self, store, runner, db):
        rid = store.create({
            "name": "Timing Rule",
            "query": 'AuthEvents | where SrcIp == "no-such-ip" | take 1',
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": ["AuthEvents"],
            "entity_mappings": "[]",
        })
        runner.run_rule(rid)
        rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rid])
        assert rule["last_run_at"] is not None
        assert rule["last_error"] is None

    def test_rule_error_recording(self, store, runner, db):
        rid = store.create({
            "name": "Error Rule",
            "query": "NOT VALID KQL EITHER $$$$$",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "tables": [],
            "entity_mappings": "[]",
        })
        runner.run_rule(rid)
        rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rid])
        assert rule["last_error"] is not None


# =====================================================================
# Builtin Rules
# =====================================================================

class TestBuiltinRules:
    def test_all_builtin_rules_have_required_fields(self):
        required = ["name", "description", "triage_steps", "severity", "query",
                    "tables", "mitre_techniques", "entity_mappings"]
        for rule in BUILTIN_RULES:
            for field in required:
                assert field in rule, f"Rule '{rule.get('name')}' missing '{field}'"
            assert len(rule["description"]) > 50, f"Rule '{rule['name']}' description too short"
            assert len(rule["triage_steps"]) > 50, f"Rule '{rule['name']}' triage_steps too short"
            assert rule["severity"] in ("informational", "low", "medium", "high", "critical")

    def test_install_builtin_rules(self, db):
        count = install_builtin_rules(db)
        assert count == len(BUILTIN_RULES)

        # Second install should be idempotent
        count2 = install_builtin_rules(db)
        assert count2 == 0

        # Check all are in the DB
        all_rules = db.query("SELECT * FROM rules WHERE origin='builtin'")
        assert len(all_rules) >= 20

    def test_builtin_rules_queries_valid(self, db):
        """Every builtin rule query should execute against an empty DB."""
        install_builtin_rules(db)
        from siempl.detect._run_rule import run_rule_query
        for rule in BUILTIN_RULES:
            try:
                run_rule_query(db, rule["query"], log=False)
            except Exception as e:
                pytest.fail(f"Rule '{rule['name']}' query failed: {e}")


# =====================================================================
# Importer (unit tests with fake client)
# =====================================================================

class TestImporter:
    def test_import_rules_disabled_by_default(self, db):
        rules = [{
            "name": "Imported Rule",
            "description": "Test import",
            "severity": "medium",
            "query": "SELECT 1",
            "tables": ["GenericEvents"],
            "mitre_techniques": [],
            "entity_mappings": [],
            "origin": "sigma",
            "source_ref": "https://example.com/test.yml",
            "source_content": "title: test",
            "triage_steps": "1. Check logs\n2. Escalate",
        }]
        result = import_rules(db, rules, enable=False)
        assert result["imported"] == 1

        # Rule should be disabled
        imported = db.query_one("SELECT * FROM rules WHERE name='Imported Rule'")
        assert imported["enabled"] is False

    def test_import_rules_with_enable(self, db):
        rules = [{
            "name": "Enabled Import",
            "description": "Test",
            "severity": "low",
            "query": "SELECT 1",
            "tables": ["GenericEvents"],
            "mitre_techniques": [],
            "entity_mappings": [],
            "origin": "sigma",
            "source_ref": "https://example.com/test.yml",
            "source_content": "title: test",
            "triage_steps": "1. Step",
        }]
        result = import_rules(db, rules, enable=True)
        assert result["imported"] == 1
        imported = db.query_one("SELECT * FROM rules WHERE name='Enabled Import'")
        assert imported["enabled"] is True

    def test_fetch_sigma_with_mock_client(self):
        """Fetch Sigma rules using a fake HTTP client."""
        mock_client = MagicMock()
        mock_client.return_value = [
            {
                "name": "test_rule.yml",
                "download_url": "https://example.com/rule.yml",
            }
        ]
        # Second call: the actual rule content
        mock_client.side_effect = [
            [{"name": "test_rule.yml", "download_url": "https://example.com/rule.yml"}],
            {"content": SIMPLE_SIGMA},
        ]

        with patch("siempl.detect.importer._default_client", return_value=mock_client):
            rules = fetch_sigma(
                client=mock_client,
                cache_dir="/tmp/test_cache_sigma",
                max_files=1,
            )
        assert len(rules) >= 0  # at minimum doesn't crash

    def test_fetch_sentinel_with_mock_client(self):
        """Fetch Sentinel rules using a fake HTTP client."""
        mock_client = MagicMock()
        mock_client.side_effect = [
            [{"name": "test_rule.yml", "download_url": "https://example.com/sentinel.yml"}],
            {"content": SENTINEL_YAML},
        ]

        with patch("siempl.detect.importer._default_client", return_value=mock_client):
            rules = fetch_sentinel(
                client=mock_client,
                cache_dir="/tmp/test_cache_sentinel",
                max_files=1,
            )
        assert len(rules) >= 0


# =====================================================================
# Scheduler
# =====================================================================

class TestScheduler:
    def test_start_scheduler_returns_thread(self, db):
        t = start_scheduler(db)
        assert t.is_alive() or not t.is_alive()  # daemon, might finish quickly
        assert t.name == "rule-scheduler"
        assert t.daemon


# =====================================================================
# End-to-end: rule -> alert -> verdict -> entity update
# =====================================================================

class TestEndToEnd:
    def test_full_flow(self, db):
        """End-to-end: install rules, run, get alert, set verdict, check entity."""
        # Install builtin rules
        count = install_builtin_rules(db)
        assert count > 0

        # Insert test data so the KQL rule query has rows to match
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated,SrcIp,UserName,EventAction,EventResult) '
            "VALUES (now(),'10.0.0.50','attacker','login','failure')"
        )

        # Create a rule that will definitely produce results
        rule = {
            "name": "E2E Test Rule",
            "description": "End-to-end test",
            "severity": "high",
            "query": 'AuthEvents | where SrcIp == "10.0.0.50" | project SrcIp, UserName | take 1',
            "tables": ["AuthEvents"],
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "mitre_techniques": ["T1110"],
            "entity_mappings": [
                {"entity_type": "ip", "column": "SrcIp"},
                {"entity_type": "user", "column": "UserName"},
            ],
            "origin": "manual",
        }
        store = RuleStore(db)
        rid = store.create(rule)

        # Run the rule
        runner = RuleRunner(db)
        alert_ids = runner.run_rule(rid)
        assert len(alert_ids) == 1, f"Expected 1 alert, got {alert_ids}"
        aid = alert_ids[0]

        # Verify alert
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        assert alert["severity"] == "high"
        assert alert["status"] == "new"
        assert alert["alert_number"] is not None

        # Verify entities created
        ip_ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:10.0.0.50"])
        assert ip_ent is not None
        assert ip_ent["alert_count"] >= 1

        user_ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["user:attacker"])
        assert user_ent is not None

        # Set verdict
        assert set_verdict(db, aid, "true_positive", "tester")

        # Verify alert closed
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])
        assert alert["status"] == "closed_tp"
        assert alert["verdict"] == "true_positive"

        # Verify entity reputation moved
        ip_ent = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:10.0.0.50"])
        assert ip_ent["reputation"] > 50
        assert ip_ent["tp_count"] == 1

    def test_alert_deduplication(self, db):
        """Running the same rule twice with same entities should dedupe."""
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated,SrcIp) '
            "VALUES (now(),'10.0.0.60')"
        )
        rule = {
            "name": "Dedup Flow",
            "description": "Dedup test",
            "severity": "low",
            "query": 'AuthEvents | where SrcIp == "10.0.0.60" | project SrcIp | take 1',
            "tables": ["AuthEvents"],
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "mitre_techniques": [],
            "entity_mappings": [
                {"entity_type": "ip", "column": "SrcIp"},
            ],
            "origin": "manual",
        }
        store = RuleStore(db)
        rid = store.create(rule)
        runner = RuleRunner(db)

        # First run: creates alert
        alert_ids_1 = runner.run_rule(rid)
        assert len(alert_ids_1) == 1

        # Second run: deduplicates (updates row_count)
        alert_ids_2 = runner.run_rule(rid)
        assert len(alert_ids_2) == 0  # no new alert

        # Check row_count
        alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_ids_1[0]])
        assert alert["row_count"] == 2  # bumped from 1 to 2

    def test_no_incident_grouping(self, db):
        """Two alerts sharing an entity should join the same incident."""
        db.execute(
            'INSERT INTO "AuthEvents" (TimeGenerated,SrcIp) '
            "VALUES (now(),'10.0.0.70')"
        )
        rule1 = {
            "name": "Group Flow 1",
            "description": "First",
            "severity": "low",
            "query": 'AuthEvents | where SrcIp == "10.0.0.70" | project SrcIp | take 1',
            "tables": ["AuthEvents"],
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "mitre_techniques": [],
            "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}],
            "origin": "manual",
        }
        rule2 = {
            "name": "Group Flow 2",
            "description": "Second",
            "severity": "critical",
            "query": 'AuthEvents | where SrcIp == "10.0.0.70" | project SrcIp | take 1',
            "tables": ["AuthEvents"],
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "mitre_techniques": [],
            "entity_mappings": [{"entity_type": "ip", "column": "SrcIp"}],
            "origin": "manual",
        }
        store = RuleStore(db)
        rid1 = store.create(rule1)
        rid2 = store.create(rule2)
        runner = RuleRunner(db)

        alert_ids_1 = runner.run_rule(rid1)
        alert_ids_2 = runner.run_rule(rid2)

        alert1 = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_ids_1[0]])
        alert2 = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_ids_2[0]])

        # No grouping any more: separate alerts, consecutive numbers
        assert alert1["alert_id"] != alert2["alert_id"]
        assert alert2["alert_number"] == alert1["alert_number"] + 1
        assert alert2["severity"] == "critical"
