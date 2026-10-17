"""pySigma path: conversion, dialect, Extra fallback, runner, guards, discovery dry-run."""
from datetime import timedelta

import pytest

from siempl.db import Database, utcnow
from siempl.detect.engine import RuleRunner, RuleStore, UnsupportedRule, sigma_to_rule

WHOAMI = r"""title: Whoami All
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\whoami.exe'
    CommandLine|contains: ' /all'
  condition: sel
level: medium
"""

# real shape that used to compile to "true": 'all of selection_* and not 1 of filter_*'
ALL_OF_NOT = r"""title: Agent Abuse
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image: '\AgentExecutor.exe'
    - OriginalFileName: 'AgentExecutor.exe'
  selection_cli:
    CommandLine|contains:
      - ' -powershell'
  filter_main_parent:
    ParentImage|endswith: '\Intune.exe'
  condition: all of selection_* and not 1 of filter_main_*
level: high
"""

UNMAPPED = r"""title: Unmapped Field
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Weird.Field|contains: 'abc'
    Image|endswith: '\x.exe'
  condition: sel
"""

PARENT_ON_NETWORK = r"""title: Parent on net
logsource: {category: network_connection, product: windows}
detection:
  sel:
    ParentImage|endswith: '\a.exe'
  condition: sel
"""


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


def _proc(db, **kw):
    row = {"TimeGenerated": utcnow(), "SourceId": "t", "HostName": "h1"}
    row.update(kw)
    db.insert_events("ProcessEvents", [row])


def test_converts_to_sql_with_dialect_shims():
    r = sigma_to_rule(WHOAMI, "ref")
    assert r["query_lang"] == "sql" and r["tables"] == ["ProcessEvents"]
    assert "ILIKE" in r["query"] and "REGEXP" not in r["query"]
    assert r["source_content"] == WHOAMI


def test_match_everything_regression_all_of_and_not():
    r = sigma_to_rule(ALL_OF_NOT, "ref")
    assert "true" not in r["query"].lower().replace("trueor", "")
    assert "AgentExecutor" in r["query"] and "NOT" in r["query"].upper()


def test_old_translator_no_longer_emits_true(monkeypatch):
    # force the KQL fallback path and check the old regex bug is gone
    # sigma_to_rule looks _sigma_to_rule_pysigma up in its own module, so patch that module (not the engine facade).
    import siempl.detect._sigma_rule as e
    monkeypatch.setattr(e, "_sigma_to_rule_pysigma", lambda *a, **k: (_ for _ in ()).throw(UnsupportedRule("x")))
    r = sigma_to_rule(ALL_OF_NOT, "ref")
    assert r["query_lang"] == "kql"
    assert "(true)" not in r["query"]


def test_unmapped_field_uses_extra_and_runs(db):
    r = sigma_to_rule(UNMAPPED, "ref")
    assert "(Extra->>'Weird.Field')" in r["query"]
    _proc(db, ProcessPath="C:\\x.exe", Extra={"Weird.Field": "xxabcxx"})
    cur = db.cursor().execute(f'SELECT count(*) FROM ({r["query"]})')
    assert cur.fetchone()[0] == 1


def test_field_missing_on_table_is_refused():
    with pytest.raises(UnsupportedRule):
        sigma_to_rule(PARENT_ON_NETWORK, "ref")


def test_runner_executes_sql_rule_and_creates_alert(db):
    rule = sigma_to_rule(WHOAMI, "ref")
    rule.update(enabled=True, lookback_minutes=30)
    rid = RuleStore(db).create(rule)
    _proc(db, ProcessPath="C:\\Windows\\System32\\whoami.exe", ProcessName="whoami.exe", ProcessCmdLine="whoami /all")
    _proc(db, ProcessPath="C:\\Windows\\System32\\cmd.exe", ProcessName="cmd.exe", ProcessCmdLine="cmd /c dir")
    assert len(RuleRunner(db).run_rule(rid)) == 1
    assert db.query_one("SELECT query_lang FROM rules WHERE rule_id=?", [rid])["query_lang"] == "sql"


def test_runner_respects_lookback_window(db):
    rule = sigma_to_rule(WHOAMI, "ref")
    rule.update(enabled=True, lookback_minutes=5)
    rid = RuleStore(db).create(rule)
    _proc(db, TimeGenerated=utcnow() - timedelta(hours=3), ProcessPath="C:\\whoami.exe", ProcessCmdLine="whoami /all")
    assert RuleRunner(db).run_rule(rid) == []


def test_sql_rule_must_be_single_select(db):
    from siempl.detect._run_rule import run_rule_query
    from siempl.kql import KqlError
    with pytest.raises(KqlError):
        run_rule_query(db, 'SELECT * FROM ProcessEvents; DROP TABLE rules', query_lang="sql")
    with pytest.raises(KqlError):
        run_rule_query(db, 'DELETE FROM rules', query_lang="sql")
    # semicolon inside a string literal is fine
    assert run_rule_query(db, "SELECT * FROM ProcessEvents WHERE ProcessCmdLine ILIKE '%a;b%'", query_lang="sql").rows == []


def test_migrations_upgrade_old_db(tmp_path):
    import duckdb
    p = str(tmp_path / "old.duckdb")
    c = duckdb.connect(p)
    c.execute("CREATE TABLE rules (rule_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, query VARCHAR NOT NULL)")
    c.execute('CREATE TABLE "NetworkEvents" ("TimeGenerated" TIMESTAMP)')
    c.close()
    db = Database(p)
    cols = {r["column_name"] for r in db.query("SELECT column_name FROM information_schema.columns WHERE table_name='rules'")}
    assert "query_lang" in cols


def test_discovery_generate_dry_run_creates_no_rules(db):
    from siempl.agents.discovery import RuleDiscoveryAgent
    for i in range(150):
        _proc(db, TimeGenerated=utcnow() - timedelta(hours=i % 24), ProcessName=f"p{i%30}", HostName=f"h{i%5}")
    before = db.query_one("SELECT count(*) c FROM rules")["c"]
    res = RuleDiscoveryAgent(db, dry_run=True).run(mode="generate")
    assert res.status == "ok"
    assert db.query_one("SELECT count(*) c FROM rules")["c"] == before
    assert db.query_one("SELECT count(*) c FROM recommendations WHERE kind='new_rule'")["c"] >= 1


def test_discovery_generate_real_mode_creates_disabled_rules(db):
    from siempl.agents.discovery import RuleDiscoveryAgent
    for i in range(150):
        _proc(db, TimeGenerated=utcnow() - timedelta(hours=i % 24), ProcessName=f"p{i%30}", HostName=f"h{i%5}")
    RuleDiscoveryAgent(db, dry_run=False).run(mode="generate")
    rows = db.query("SELECT enabled FROM rules WHERE origin='ai_generated'")
    assert rows and not any(r["enabled"] for r in rows)
