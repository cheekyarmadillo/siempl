"""Tests for rules, sources, and audit web routes.
Run with: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web_rules.py -q -v
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_web_rules_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        db = Database(str(Path(td) / "t.duckdb"))
        yield db
        db.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    app = create_app(db)
    return TestClient(app)


def seed_rules(db):
    db.execute(
        "INSERT INTO rules(rule_id,name,description,severity,query,tables,enabled,origin) VALUES (?,?,?,?,?,?,?,?)",
        ["rule_test1", "Test Rule 1", "desc1", "high", "AuthEvents | take 1",
         ["AuthEvents"], True, "builtin"])
    db.execute(
        "INSERT INTO rules(rule_id,name,description,severity,query,tables,enabled,origin) VALUES (?,?,?,?,?,?,?,?)",
        ["rule_test2", "Test Rule 2", "desc2", "low", "Syslog | take 1",
         ["Syslog"], False, "manual"])


# =====================================================================
# Rules pages
# =====================================================================

class TestRulesPages:
    def test_rules_list_empty(self, client):
        r = client.get("/rules")
        assert r.status_code == 200
        assert "Rules" in r.text

    def test_rules_list_with_data(self, client, db):
        seed_rules(db)
        r = client.get("/rules")
        assert r.status_code == 200
        assert "Test Rule 1" in r.text
        assert "Test Rule 2" in r.text

    def test_rules_filter_by_severity(self, client, db):
        seed_rules(db)
        r = client.get("/rules?severity=high")
        assert r.status_code == 200
        assert "Test Rule 1" in r.text
        assert "Test Rule 2" not in r.text

    def test_rule_detail(self, client, db):
        seed_rules(db)
        r = client.get("/rules/rule_test1")
        assert r.status_code == 200
        assert "Test Rule 1" in r.text

    def test_rule_edit_form(self, client, db):
        seed_rules(db)
        r = client.get("/rules/rule_test1/edit")
        assert r.status_code == 200
        assert "Edit Rule" in r.text

    def test_new_rule_form(self, client):
        r = client.get("/rules/new/edit")
        assert r.status_code == 200
        assert "New Rule" in r.text


# =====================================================================
# Rules API
# =====================================================================

class TestRulesApi:
    def test_create_rule(self, client, db):
        payload = {
            "name": "API Rule",
            "severity": "medium",
            "query": "AuthEvents | take 1",
            "frequency_minutes": 5,
            "lookback_minutes": 5,
            "threshold": 1,
            "enabled": True,
        }
        r = client.post("/api/rules", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["rule_id"].startswith("rule_")

    def test_get_rule(self, client, db):
        seed_rules(db)
        r = client.get("/api/rules/rule_test1")
        assert r.status_code == 200
        assert r.json()["name"] == "Test Rule 1"

    def test_update_rule(self, client, db):
        seed_rules(db)
        r = client.put("/api/rules/rule_test1", json={"name": "Updated"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        row = db.query_one("SELECT name FROM rules WHERE rule_id=?", ["rule_test1"])
        assert row["name"] == "Updated"

    def test_clone_rule(self, client, db):
        seed_rules(db)
        r = client.post("/api/rules/rule_test1/clone")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        cloned = db.query_one("SELECT * FROM rules WHERE rule_id=?", [data["rule_id"]])
        assert cloned["name"] == "Test Rule 1 (clone)"

    def test_enable_disable_rule(self, client, db):
        seed_rules(db)
        r = client.post("/api/rules/rule_test1/delete")
        assert r.status_code == 200
        row = db.query_one("SELECT enabled FROM rules WHERE rule_id=?", ["rule_test1"])
        assert row["enabled"] is False
        r2 = client.post("/api/rules/rule_test1/enable")
        assert r2.status_code == 200
        row2 = db.query_one("SELECT enabled FROM rules WHERE rule_id=?", ["rule_test1"])
        assert row2["enabled"] is True

    def test_test_query(self, client, db):
        # Insert data for KQL
        db.execute('INSERT INTO "AuthEvents" (TimeGenerated,SrcIp) VALUES (now(),\'1.2.3.4\')')
        payload = {"query": "AuthEvents | where SrcIp == '1.2.3.4' | project SrcIp"}
        r = client.post("/api/rules/test-query", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["row_count"] == 1

    def test_test_query_invalid(self, client):
        r = client.post("/api/rules/test-query", json={"query": "NOT VALID $$$"})
        assert r.status_code == 400
        data = r.json()
        assert data["ok"] is False

    def test_import_sigma_preview(self, client):
        yaml = """\
title: Test Sigma
logsource:
  category: process_creation
detection:
  sel:
    ProcessName|endswith: '\\cmd.exe'
  condition: sel
"""
        r = client.post("/api/rules/import-sigma", json={"yaml": yaml, "mode": "preview"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "Test Sigma" in data["preview"]["name"]

    def test_import_sigma_import(self, client):
        yaml = """\
title: Test Sigma Import
logsource:
  category: process_creation
detection:
  sel:
    ProcessName|endswith: '\\cmd.exe'
  condition: sel
"""
        r = client.post("/api/rules/import-sigma", json={"yaml": yaml, "mode": "import"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["rule_id"].startswith("rule_")

    def test_audit_written(self, client, db):
        r = client.post("/api/rules", json={
            "name": "Audit Rule", "severity": "medium",
            "query": "AuthEvents | take 1", "enabled": True,
        })
        assert r.status_code == 200
        audit = db.query("SELECT * FROM SiemplAudit WHERE Action='rule.create'")
        assert len(audit) >= 1


# =====================================================================
# Sources / ingestion pages
# =====================================================================

class TestSourcesPages:
    def test_sources_list_empty(self, client):
        r = client.get("/ingestion")
        assert r.status_code == 200

    def test_sources_create_and_list(self, client, db):
        r = client.post("/api/sources", json={
            "source_id": "syslog-prod", "name": "Prod Syslog",
            "kind": "syslog", "parser": "auto", "target_table": "Syslog",
            "config": {"udp_port": 5514}})
        assert r.status_code == 200
        r2 = client.get("/ingestion")
        assert r.status_code == 200
        assert "syslog-prod" in r2.text

    def test_source_pause_resume_delete(self, client, db):
        db.execute("INSERT INTO sources(source_id,name,kind,status) VALUES (?,?,?,?)",
                   ["src1", "S1", "file", "active"])
        r1 = client.post("/api/sources/src1/pause")
        assert r1.status_code == 200
        row1 = db.query_one("SELECT status FROM sources WHERE source_id=?", ["src1"])
        assert row1["status"] == "paused"
        r2 = client.post("/api/sources/src1/resume")
        assert r2.status_code == 200
        row2 = db.query_one("SELECT status FROM sources WHERE source_id=?", ["src1"])
        assert row2["status"] == "active"
        r3 = client.post("/api/sources/src1/delete")
        assert r3.status_code == 200
        row3 = db.query_one("SELECT * FROM sources WHERE source_id=?", ["src1"])
        assert row3 is None

    def test_filter_crud(self, client, db):
        r = client.post("/api/filters", json={
            "table_name": "AuthEvents", "expression": "EventCode == '4625'",
            "description": "Drop 4625", "enabled": True})
        assert r.status_code == 200
        data = r.json()
        fid = data["filter_id"]
        r2 = client.post(f"/api/filters/{fid}/delete")
        assert r2.status_code == 200
        rows = db.query("SELECT * FROM ingest_filters WHERE filter_id=?", [fid])
        assert len(rows) == 0

    def test_detect_parser(self, client):
        # windows_json line
        sample = '{"EventID": 4625, "event_data": {"TargetUserName": "bob"}}'
        r = client.post("/api/sources/detect-parser", json={"samples": [sample]})
        assert r.status_code == 200
        data = r.json()
        # Either we get candidates or ok response
        assert data["ok"] is True


# =====================================================================
# Audit page
# =====================================================================

class TestAuditPages:
    def test_audit_page_empty(self, client):
        r = client.get("/audit")
        assert r.status_code == 200
        assert "Audit Trail" in r.text

    def test_audit_after_rule_create(self, client, db):
        r = client.post("/api/rules", json={
            "name": "Audit Rule", "severity": "medium",
            "query": "AuthEvents | take 1", "enabled": True,
        })
        assert r.status_code == 200
        r2 = client.get("/audit")
        assert r2.status_code == 200
        assert "rule.create" in r2.text or "SiemplAudit" in r2.text

    def test_audit_filters(self, client, db):
        # seed audit entries
        from siempl.audit import record
        record(db, "user:web", "rule.create", "rule", "r1")
        record(db, "agent:triage", "alert.close", "alert", "a1", outcome="ok")
        r = client.get("/audit?actor_type=agent")
        assert r.status_code == 200
        assert "agent:triage" in r.text or "alert.close" in r.text


def test_rule_detail_renders_when_list_columns_are_null(tmp_path):
    """Regression: rules created via the API without tables/mitre used to 500 the detail page."""
    from fastapi.testclient import TestClient

    from siempl.db import Database
    from siempl.web import create_app
    db = Database(str(tmp_path / "t.duckdb"))
    c = TestClient(create_app(db))
    r = c.post("/api/rules", json={"name": "no-tables", "description": "d", "triage_steps": "1. x",
                                   "severity": "low", "query": "AuthEvents | take 1"})
    assert r.status_code == 200, r.text
    rid = r.json()["rule_id"]
    db.execute("UPDATE rules SET tables=NULL, mitre_tactics=NULL, mitre_techniques=NULL WHERE rule_id=?", [rid])
    assert c.get(f"/rules/{rid}").status_code == 200
    assert c.get(f"/rules/{rid}/edit").status_code == 200
