"""Full alert page (GET /alerts/{id}) and the owner endpoint.

Run: .venv/bin/python -m pytest tests/test_web_alert_detail.py -q
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_alert_detail_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        database = Database(str(Path(td) / "t.duckdb"))
        database.init_schema()
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db), follow_redirects=False)


def seed_alert(db, alert_id="al_1", status="new", owner=None):
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,evidence,entities,"
        "created_at,updated_at,mitre_techniques,alert_number,owner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [alert_id, "rule_x", f"Alert {alert_id}", "high", status, "desc",
         json.dumps([{"user": "bob", "count": 3}, {"user": "eve", "ip": "10.0.0.9"}]),
         json.dumps([{"type": "ip", "value": "1.2.3.4"}]), utcnow(), utcnow(), ["T1110"], 42, owner])
    db.execute("INSERT INTO rules(rule_id,name,description,query,mitre_tactics) VALUES (?,?,?,?,?)",
               ["rule_x", "Brute force", "Many failed logins", "SELECT 1", ["Credential Access"]])


def audit_rows(db, action, target):
    return db.query("SELECT Action, TargetId, RawEvent FROM SiemplAudit WHERE Action=? AND TargetId=?",
                    [action, target])


def history_section(html: str) -> str:
    match = re.search(r'id="history-table".*?</table>', html, re.S)
    return match.group(0) if match else ""


def test_page_renders_with_all_sections(db, client):
    seed_alert(db)
    resp = client.get("/alerts/al_1")
    assert resp.status_code == 200
    html = resp.text
    assert 'id="alert_number"' in html and "#42" in html
    assert "Alert al_1" in html
    for selector in ('id="status-select"', 'id="severity-select"', 'id="owner-input"', 'id="owner-save"',
                     'id="evidence-table"', 'id="comment-form"', 'id="mitre-block"'):
        assert selector in html, selector
    assert 'id="agent-panel"' in html and 'data-agent-scope="alert"' in html
    assert "/static/alert_detail.js" in html
    assert "Closed - True Positive" in html and "Closed - False Positive" in html
    assert "Brute force" in html and 'href="/rules/rule_x"' in html
    assert 'href="/entities/ip%3A1.2.3.4"' in html and ">ip:1.2.3.4</a>" in html
    assert "Credential Access" in html and "T1110" in html
    assert "<th>user</th>" in html and "<td>bob</td>" in html


def test_page_has_no_verdict_or_incident_wording(db, client):
    seed_alert(db)
    html = client.get("/alerts/al_1").text.lower()
    assert "verdict" not in html
    assert "incident" not in html
    assert "btn-tp" not in html and "btn-fp" not in html and "btn-benign" not in html
    assert "btn-escalate" not in html


def test_unknown_alert_is_404(client):
    resp = client.get("/alerts/nope")
    assert resp.status_code == 404
    assert "Alert not found" in resp.text


def test_owner_endpoint_sets_owner_and_audits(db, client):
    seed_alert(db)
    resp = client.post("/api/alerts/al_1/owner", json={"owner": " alice "})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "owner": "alice"}
    assert db.query_one("SELECT owner FROM alerts WHERE alert_id='al_1'")["owner"] == "alice"
    rows = audit_rows(db, "alert.owner", "al_1")
    assert len(rows) == 1
    assert json.loads(rows[0]["RawEvent"])["details"] == {"from": None, "to": "alice"}


def test_owner_endpoint_clears_owner_on_empty_string(db, client):
    seed_alert(db, owner="bob")
    resp = client.post("/api/alerts/al_1/owner", json={"owner": ""})
    assert resp.status_code == 200
    assert resp.json()["owner"] is None
    assert db.query_one("SELECT owner FROM alerts WHERE alert_id='al_1'")["owner"] is None


@pytest.mark.parametrize("payload", [
    {"no_owner_key": 1},
    {"owner": 7},
    {"owner": "x" * 81},
])
def test_owner_endpoint_rejects_bad_body(db, client, payload):
    seed_alert(db)
    resp = client.post("/api/alerts/al_1/owner", json=payload)
    assert resp.status_code == 400
    assert audit_rows(db, "alert.owner", "al_1") == []


def test_owner_endpoint_rejects_non_json(db, client):
    seed_alert(db)
    resp = client.post("/api/alerts/al_1/owner", content=b"not json",
                       headers={"content-type": "application/json"})
    assert resp.status_code == 400


def test_owner_endpoint_unknown_alert_is_404(db, client):
    resp = client.post("/api/alerts/missing/owner", json={"owner": "alice"})
    assert resp.status_code == 404
    assert audit_rows(db, "alert.owner", "missing") == []


def test_history_lists_status_change_newest_first(db, client):
    seed_alert(db)
    assert client.post("/api/alerts/al_1/status", json={"status": "closed_tp"}).status_code == 200
    assert client.post("/api/alerts/al_1/severity", json={"severity": "low"}).status_code == 200
    assert client.post("/api/alerts/al_1/owner", json={"owner": "carol"}).status_code == 200
    html = client.get("/alerts/al_1").text
    section = history_section(html)
    assert "<td>Status</td>" in section and "closed_tp" in section
    assert "<td>Severity</td>" in section and "<td>Owner</td>" in section
    assert section.index("<td>Owner</td>") < section.index("<td>Severity</td>") < section.index("<td>Status</td>")
    assert "carol" in section


def test_history_empty_when_no_changes(db, client):
    seed_alert(db)
    html = client.get("/alerts/al_1").text
    assert 'id="history-table"' not in html
    assert "No status, severity or owner changes yet." in html
