"""Alert JSON API: status/severity writes, preview, summary, verdict compat shim, retired incident routes.

Run: .venv/bin/python -m pytest tests/test_alerts_api.py -q
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_alerts_api_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        database = Database(str(Path(td) / "t.duckdb"))
        database.init_schema()
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db), follow_redirects=False)


def seed_alert(db, alert_id="al_1", status="new", severity="high", entities=None, evidence=None):
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,evidence,entities,"
        "created_at,updated_at,mitre_techniques) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [alert_id, "rule_x", f"Alert {alert_id}", severity, status, "desc",
         json.dumps(evidence or []), json.dumps(entities or []), utcnow(), utcnow(), ["T1110"]])


def seed_rule(db, rule_id="rule_x"):
    db.execute(
        "INSERT INTO rules(rule_id,name,query,severity,mitre_tactics) VALUES (?,?,?,?,?)",
        [rule_id, "Brute force on admin", "SecurityEvent | take 1", "high", ["credential_access"]])


def status_of(db, alert_id):
    return db.query_one("SELECT status FROM alerts WHERE alert_id=?", [alert_id])["status"]


def audit_actions(db):
    return [r["EventCode"] for r in db.query("SELECT EventCode FROM SiemplAudit")]


# ---- POST /api/alerts/{id}/status -------------------------------------------

def test_status_write_updates_row_and_audits(client, db):
    seed_alert(db)
    r = client.post("/api/alerts/al_1/status", json={"status": "active"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "status": "active"}
    assert status_of(db, "al_1") == "active"
    assert "alert.status" in audit_actions(db)


@pytest.mark.parametrize("bad", ["triaging", "closed", "escalated", "", None, 7])
def test_status_rejects_unknown_status(client, db, bad):
    seed_alert(db)
    r = client.post("/api/alerts/al_1/status", json={"status": bad})
    assert r.status_code == 400
    assert status_of(db, "al_1") == "new"


def test_status_rejects_malformed_body(client, db):
    seed_alert(db)
    r = client.post("/api/alerts/al_1/status", content=b"not json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    r2 = client.post("/api/alerts/al_1/status", json=["active"])
    assert r2.status_code == 400


def test_status_unknown_alert_is_404(client):
    r = client.post("/api/alerts/nope/status", json={"status": "active"})
    assert r.status_code == 404
    assert "error" in r.json()


def test_closing_applies_reputation_once_across_reopen(client, db):
    seed_alert(db, entities=[{"type": "ip", "value": "203.0.113.9"}])
    db.execute("INSERT INTO entities(entity_id,type,value,reputation,tp_count,fp_count,alert_count) "
               "VALUES ('ip:203.0.113.9','ip','203.0.113.9',50,0,0,0)")
    assert client.post("/api/alerts/al_1/status", json={"status": "closed_tp"}).status_code == 200
    assert client.post("/api/alerts/al_1/status", json={"status": "active"}).status_code == 200
    assert client.post("/api/alerts/al_1/status", json={"status": "closed_tp"}).status_code == 200
    row = db.query_one("SELECT tp_count, fp_count FROM entities WHERE entity_id='ip:203.0.113.9'")
    assert (row["tp_count"], row["fp_count"]) == (1, 0)


# ---- POST /api/alerts/{id}/severity -----------------------------------------

def test_severity_write(client, db):
    seed_alert(db, severity="low")
    r = client.post("/api/alerts/al_1/severity", json={"severity": "critical"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "severity": "critical"}
    assert db.query_one("SELECT severity FROM alerts WHERE alert_id='al_1'")["severity"] == "critical"
    assert "alert.severity" in audit_actions(db)


def test_severity_rejects_unknown_value(client, db):
    seed_alert(db, severity="low")
    r = client.post("/api/alerts/al_1/severity", json={"severity": "urgent"})
    assert r.status_code == 400
    assert db.query_one("SELECT severity FROM alerts WHERE alert_id='al_1'")["severity"] == "low"


def test_severity_unknown_alert_is_404(client):
    r = client.post("/api/alerts/nope/severity", json={"severity": "high"})
    assert r.status_code == 404


# ---- GET /api/alerts/{id}/preview -------------------------------------------

def test_preview_has_fields_rule_entities_evidence_comments_mitre(client, db):
    seed_rule(db)
    entities = [{"type": "user", "value": "admin"}]
    evidence = [{"row": i} for i in range(8)]
    seed_alert(db, entities=entities, evidence=evidence)
    db.execute("INSERT INTO alert_comments(comment_id,alert_id,author,body) VALUES ('c1','al_1','analyst','hi')")
    r = client.get("/api/alerts/al_1/preview")
    assert r.status_code == 200
    data = r.json()
    assert data["alert_id"] == "al_1"
    assert "alert_number" in data
    assert data["status"] == "new"
    assert data["rule_name"] == "Brute force on admin"
    assert data["entities"] == entities
    assert data["evidence"] == evidence[:5]
    assert [c["body"] for c in data["comments"]] == ["hi"]
    assert data["mitre"] == {"techniques": ["T1110"], "tactics": ["credential_access"]}
    assert "verdict" not in data


def test_preview_unknown_alert_is_404(client):
    assert client.get("/api/alerts/nope/preview").status_code == 404


# ---- GET /api/alerts/summary ------------------------------------------------

def test_summary_counts_open_by_severity_and_by_status(client, db):
    seed_alert(db, "a1", status="new", severity="high")
    seed_alert(db, "a2", status="active", severity="high")
    seed_alert(db, "a3", status="active", severity="low")
    seed_alert(db, "a4", status="closed_tp", severity="high")
    seed_alert(db, "a5", status="closed_fp", severity="medium")
    data = client.get("/api/alerts/summary").json()
    assert data["open_by_severity"] == {"high": 2, "low": 1}
    assert data["open_total"] == 3
    assert data["by_status"] == {"new": 1, "active": 2, "closed_tp": 1, "closed_fp": 1}


# ---- POST /api/alerts/{id}/verdict (compat shim) -----------------------------

@pytest.mark.parametrize("verdict,expected", [
    ("true_positive", "closed_tp"),
    ("false_positive", "closed_fp"),
    ("benign", "closed_fp"),
    ("escalate", "active"),
])
def test_verdict_shim_maps_to_status(client, db, verdict, expected):
    seed_alert(db)
    r = client.post("/api/alerts/al_1/verdict", json={"verdict": verdict})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert status_of(db, "al_1") == expected


@pytest.mark.parametrize("bad", ["bad_verdict", None, ["true_positive"]])
def test_verdict_shim_rejects_unknown_verdict(client, db, bad):
    seed_alert(db)
    r = client.post("/api/alerts/al_1/verdict", json={"verdict": bad})
    assert r.status_code == 400
    assert status_of(db, "al_1") == "new"


def test_verdict_shim_unknown_alert_is_404(client):
    r = client.post("/api/alerts/nope/verdict", json={"verdict": "true_positive"})
    assert r.status_code == 404


# ---- retired incident routes -------------------------------------------------

def test_incidents_page_redirects_to_alerts(client):
    r = client.get("/incidents")
    assert r.status_code == 307
    assert r.headers["location"] == "/alerts"


def test_incident_detail_redirects_to_alerts(client):
    r = client.get("/incidents/inc_123")
    assert r.status_code == 307
    assert r.headers["location"] == "/alerts"


def test_incidents_api_is_gone(client):
    assert client.post("/api/incidents/inc_1/status", json={"status": "closed"}).status_code == 404
    assert client.post("/api/incidents", json={"title": "x"}).status_code == 404


# ---- pages that use the new model -------------------------------------------

def test_alerts_page_offers_only_new_statuses_and_no_incident_link(client, db):
    seed_alert(db, status="closed_fp")
    r = client.get("/alerts?status=closed_fp")
    assert r.status_code == 200
    assert 'value="closed_fp" selected' in r.text
    assert 'value="triaging"' not in r.text
    assert 'href="/incidents"' not in r.text


def test_overview_counts_open_alerts(client, db):
    seed_alert(db, "a1", status="new")
    seed_alert(db, "a2", status="active")
    seed_alert(db, "a3", status="closed_tp")
    r = client.get("/")
    assert r.status_code == 200
    assert "Open alerts" in r.text
    assert '<span class="ov-kpi-value">2</span>' in r.text
