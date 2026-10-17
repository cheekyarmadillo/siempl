"""Optimizer per-source noise detection (siempl/agents/_optimizer_sources.py)."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from siempl.agents._optimizer_sources import noisy_source_findings
from siempl.agents.optimizer import IngestionOptimizerAgent, apply_recommendation
from siempl.db import Database, utcnow
from siempl.ingest import _tiny_filter_match
from siempl.testdata.scenarios import load_scenarios


@pytest.fixture()
def db(tmp_path):
    return Database(str(tmp_path / "o.duckdb"))


def _rows(db, source_id, n, message="debug heartbeat ok seq=%d", code="HB"):
    now = utcnow() - timedelta(minutes=5)
    db.insert_events("Syslog", [
        {"TimeGenerated": now, "IngestTime": now, "SourceId": source_id, "SourceType": "syslog",
         "EventCode": code, "Message": message % i if "%d" in message else message} for i in range(n)])


def test_noisy_source_is_found(db):
    _rows(db, "chatty-1", 1200)
    found = noisy_source_findings(db)
    assert [f["source_id"] for f in found] == ["chatty-1"]
    assert found[0]["table"] == "Syslog" and found[0]["rows"] == 1200
    assert found[0]["filter"]["expression"].startswith('SourceId == "chatty-1" and ')


def test_row_threshold_boundary(db):
    _rows(db, "edge", 999)
    assert noisy_source_findings(db) == []
    _rows(db, "edge", 1)
    assert [f["source_id"] for f in noisy_source_findings(db)] == ["edge"]


def test_small_share_of_a_big_table_is_ignored(db):
    _rows(db, "big", 6000, message="login ok user=%d", code="A")
    _rows(db, "small", 1100)
    ids = [f["source_id"] for f in noisy_source_findings(db)]
    assert "small" not in ids


def test_alert_referenced_source_is_excluded(db):
    _rows(db, "needed", 1200)
    db.execute("INSERT INTO alerts(alert_id,title,severity,status,evidence) VALUES "
               "('a1','t','low','new', ?)", [json.dumps([{"SourceId": "needed"}])])
    assert noisy_source_findings(db) == []


def test_varied_messages_are_not_noise(db):
    now = utcnow() - timedelta(minutes=5)
    db.insert_events("Syslog", [
        {"TimeGenerated": now, "IngestTime": now, "SourceId": "varied", "SourceType": "syslog",
         "EventCode": str(i), "Message": f"unique message number {i} " + "x" * (i % 40)} for i in range(1200)])
    assert noisy_source_findings(db) == []


def test_unsafe_text_never_becomes_a_filter(db):
    _rows(db, "quotey", 1200, message='say "hello" == x and y contains z', code="Q")
    assert noisy_source_findings(db) == []


def test_recommendation_is_deduped(db):
    _rows(db, "chatty-1", 1200)
    IngestionOptimizerAgent(db).run(dry_run=False)
    IngestionOptimizerAgent(db).run(dry_run=False)
    n = db.query_one("SELECT COUNT(*) AS n FROM recommendations WHERE kind='ingest_filter' AND status='open'")["n"]
    assert n == 1


def test_scenario_chatty_source_gets_a_filter_rec(tmp_path):
    db = Database(str(tmp_path / "s.duckdb"))
    load_scenarios(db)
    IngestionOptimizerAgent(db).run(dry_run=False)
    rec = db.query_one("SELECT payload, target FROM recommendations WHERE kind='ingest_filter' AND status='open'")
    assert rec["target"] == "Syslog"
    assert json.loads(rec["payload"])["source_id"] == "scn-chatty-debug-syslog"


def test_approved_filter_drops_only_that_sources_rows(tmp_path):
    db = Database(str(tmp_path / "a.duckdb"))
    load_scenarios(db)
    IngestionOptimizerAgent(db).run(dry_run=False)
    rid = db.query_one("SELECT rec_id FROM recommendations WHERE kind='ingest_filter' AND status='open'")["rec_id"]
    assert apply_recommendation(db, rid, "user:test")["status"] == "applied"
    flt = db.query_one("SELECT table_name, expression FROM ingest_filters ORDER BY rowid DESC LIMIT 1") or {}
    assert flt.get("table_name") == "Syslog"
    sample = db.query_one('SELECT "EventCode", "Message" FROM "Syslog" WHERE "SourceId"=? LIMIT 1',
                          ["scn-chatty-debug-syslog"])
    fields = {"SourceId": "scn-chatty-debug-syslog", "EventCode": sample["EventCode"], "Message": sample["Message"]}
    assert _tiny_filter_match(flt["expression"], fields)
    assert not _tiny_filter_match(flt["expression"], {**fields, "SourceId": "other-source"})
