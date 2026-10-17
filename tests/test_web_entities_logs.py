"""Tests for entities and logs routes .

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web_entities_logs.py -q --tb=short
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _seed_entities(db: Database):
    now = utcnow()
    # All entity types, including awkward values
    for etype, value in [
        ("user", "admin"),
        ("host", "web01"),
        ("ip", "10.0.0.1"),
        ("process", "powershell.exe"),
        ("file_hash", "aabbccdd"),
        ("domain", "evil.com"),
        ("process", "/usr/bin/bash"),
        ("process", "foo bar.exe"),
        ("user", "domain\\user"),
    ]:
        eid = f"{etype}:{value.lower()}"
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            [eid, etype, value, 50, 1, 10, now, now])
    return now


def _seed_alert_with_entity(db: Database, alert_id: str, entities: list[dict]):
    now = utcnow()
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,verdict,created_at,updated_at,window_start,window_end,row_count,evidence,entities,incident_id,dedupe_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [alert_id, "rule_test", "Test alert", "medium", "new", None,
         now, now, now, now, 1,
         json.dumps([]),
         json.dumps(entities),
         None, alert_id])


def _seed_events(db: Database):
    now = utcnow()
    db.insert_events("AuthEvents", [
        {"TimeGenerated": now, "UserName": "admin", "SrcIp": "10.0.0.1", "EventResult": "failure", "HostName": "web01", "Message": "Login failed", "RawEvent": "raw"},
    ])


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_entlogs_") as td:
        os.environ["SIEMPL_HOME"] = td
        db = Database(str(Path(td) / "t.duckdb"))
        yield db
        db.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    app = create_app(db)
    return TestClient(app)


# ------------------------------------------------------------------
# BUG 1: process entity type (and all others with awkward values)
# ------------------------------------------------------------------

@pytest.mark.parametrize("etype", ["user", "host", "ip", "process", "file_hash", "domain"])
def test_entities_list_all_types(etype, client, db):
    _seed_entities(db)
    r = client.get(f"/entities?etype={etype}")
    assert r.status_code == 200, f"List failed for {etype}: {r.text[:200]}"
    assert etype in r.text.lower()


@pytest.mark.parametrize("eid", [
    "process:powershell.exe",
    "process:/usr/bin/bash",
    "process:foo bar.exe",
    "user:domain\\user",
])
def test_entity_detail_awkward_values(eid, client, db):
    _seed_entities(db)
    url = f"/entities/{quote(eid, safe='')}"
    r = client.get(url)
    assert r.status_code == 200, f"Detail failed for {eid}: {r.text[:200]}"
    # Should NOT be a redirect or Not Found page
    assert "not found" not in r.text.lower()


# ------------------------------------------------------------------
# Task 2: Last Detected column, sortable, tables + alerts
# ------------------------------------------------------------------

def test_entities_list_last_seen_and_sort(client, db):
    _seed_entities(db)
    # Sort by last_seen DESC
    r = client.get("/entities?sort=last_seen DESC")
    assert r.status_code == 200
    # HTML should contain relative time
    assert "ago" in r.text.lower() or "just now" in r.text.lower() or "<span title" in r.text


def test_entities_list_table_filter(client, db):
    _seed_entities(db)
    _seed_events(db)
    # Filter by AuthEvents table - admin should show up (UserName column maps to user entity)
    r = client.get("/entities?table_filter=AuthEvents")
    assert r.status_code == 200
    # At least one entity appears
    assert "admin" in r.text


def test_entities_list_has_alerts_filter(client, db):
    _seed_entities(db)
    _seed_alert_with_entity(db, "alert_1", [{"type": "ip", "value": "10.0.0.1"}])
    # Filter by has_alerts
    r = client.get("/entities?has_alerts=1")
    assert r.status_code == 200
    # Should show the ip entity
    assert "10.0.0.1" in r.text


# ------------------------------------------------------------------
# Task 3: Entity detail page shows tables, alerts, verdict history
# ------------------------------------------------------------------

def test_entity_detail_shows_tables(client, db):
    _seed_entities(db)
    _seed_events(db)
    r = client.get("/entities/user:admin")
    assert r.status_code == 200
    # Info panel should contain AuthEvents
    assert "AuthEvents" in r.text


def test_entity_detail_shows_alerts(client, db):
    _seed_entities(db)
    _seed_alert_with_entity(db, "alert_1", [{"type": "ip", "value": "10.0.0.1"}])
    r = client.get("/entities/ip:10.0.0.1")
    assert r.status_code == 200
    assert "Related Alerts" in r.text
    assert "alert_1" in r.text or "Test alert" in r.text


# ------------------------------------------------------------------
# Task 3 (cont): watch toggle + notes
# ------------------------------------------------------------------

def test_api_entity_watch(client, db):
    _seed_entities(db)
    r = client.put("/api/entities/ip:10.0.0.1/watch")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["watch"] is True


def test_api_entity_notes(client, db):
    _seed_entities(db)
    r = client.post("/api/entities/ip:10.0.0.1/notes", json={"notes": "Suspicious scanner"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ------------------------------------------------------------------
# Task 4: Logs page defaults + limit control + export
# ------------------------------------------------------------------

def test_logs_page_default_limit(client, db):
    _seed_events(db)
    r = client.get("/logs")
    assert r.status_code == 200
    # Should show limit dropdown
    assert "Limit" in r.text or "limit" in r.text.lower()


def test_api_query_limit_applied(client, db):
    # Seed many rows
    now = utcnow()
    rows = [{"TimeGenerated": now, "UserName": f"user_{i}", "Message": "test", "RawEvent": "raw"} for i in range(200)]
    db.insert_events("AuthEvents", rows)
    r = client.post("/api/query", json={"query": "AuthEvents | project UserName", "limit": 10})
    assert r.status_code == 200
    data = r.json()
    assert len(data["rows"]) <= 10


def test_api_export_csv(client, db):
    _seed_events(db)
    r = client.get("/api/export?query=AuthEvents+%7C+take+5&format=csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")
    body = r.text
    assert "UserName" in body or "TimeGenerated" in body


def test_api_export_json(client, db):
    _seed_events(db)
    r = client.get("/api/export?query=AuthEvents+%7C+take+5&format=json")
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    data = json.loads(r.text)
    assert isinstance(data, list)


def test_api_export_audit_logged(client, db):
    _seed_events(db)
    r = client.get("/api/export?query=AuthEvents+%7C+take+1&format=csv")
    assert r.status_code == 200
    # Check SiemplAudit
    rows = db.query("SELECT * FROM SiemplAudit WHERE Action = 'query.export'")
    assert len(rows) >= 1


# ------------------------------------------------------------------
# HTML smoke: no broken tags on key pages
# ------------------------------------------------------------------

def test_entities_html_wellformed(client, db):
    _seed_entities(db)
    r = client.get("/entities")
    assert r.status_code == 200
    # Basic sanity: no unclosed tags that would break layout
    assert "</table>" in r.text or "No entities" in r.text
    assert "</div>" in r.text


def test_logs_html_wellformed(client, db):
    _seed_events(db)
    r = client.get("/logs")
    assert r.status_code == 200
    assert "</textarea>" in r.text
    assert "</body>" in r.text
