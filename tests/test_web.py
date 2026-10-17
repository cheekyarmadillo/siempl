"""Web tests: smoke tests for all pages, JSON API endpoints, and demo data.

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web.py -q -v
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, new_id, utcnow

# ---- helpers ---------------------------------------------------------------


def seed_demo_data(db: Database) -> None:
    """Insert demo data into a clean database: alerts, incidents, rules, entities, sources."""
    now = utcnow()

    # Rules
    for i, (name, sev, query) in enumerate([
        ("Brute Force: AuthEvents Failure Spike", "high",
         "AuthEvents | where EventResult == 'failure' | summarize count() by bin(TimeGenerated, 5m), UserName | where count_ > 5"),
        ("Suspicious Process: PowerShell Encoded Command", "medium",
         "ProcessEvents | where ProcessName == 'powershell.exe' and ProcessCmdLine contains '-EncodedCommand'"),
        ("Network: High-Volume Outbound Bytes", "low",
         "NetworkEvents | where Direction == 'outbound' | summarize total_bytes=sum(BytesOut) by SrcIp | where total_bytes > 1000000"),
    ]):
        rid = f"rule_{i}"
        db.execute(
            "INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,frequency_minutes,lookback_minutes,threshold,enabled,origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [rid, name, f"Detects {name}", "1. Check the source IP\n2. Verify user context",
             sev, query, ["AuthEvents", "ProcessEvents", "NetworkEvents"], 5, 5, 1, True, "builtin"])

    # Entities
    for etype, value, rep in [
        ("ip", "10.0.0.1", 45), ("ip", "192.168.1.100", 55),
        ("ip", "203.0.113.42", 85), ("user", "administrator", 30),
        ("user", "svc_backup", 60), ("host", "web-server-01", 70),
        ("host", "db-prod-01", 40), ("process", "powershell.exe", 50),
    ]:
        eid = f"{etype}:{value.lower()}"
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            [eid, etype, value, rep, int(rep * 0.5), int(rep * 10), now, now])

    # Alerts (statuses: new | active | closed_tp | closed_fp; verdict is the derived internal column)
    evidence = [{"UserName": "admin", "SrcIp": "203.0.113.42", "TimeGenerated": str(now), "count": 12}]
    entities = [{"type": "ip", "value": "203.0.113.42"}, {"type": "user", "value": "admin"}]
    for i, (title, sev, status, verdict) in enumerate([
        ("Brute force detected on admin account", "high", "new", None),
        ("PowerShell encoded command execution", "medium", "active", None),
        ("High-volume outbound data transfer", "low", "closed_fp", "false_positive"),
    ]):
        aid = f"alert_{i}"
        db.execute(
            "INSERT INTO alerts(alert_id,rule_id,title,severity,status,verdict,verdict_by,description,window_start,window_end,row_count,evidence,entities,dedupe_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [aid, f"rule_{i}", title, sev, status, verdict, "user:web" if verdict else None,
             f"Alert: {title}", now, now, 12 if i == 0 else 1,
             json.dumps(evidence if i == 0 else []),
             json.dumps(entities if i == 0 else []),
             f"dedupe_{i}"])

    # Alert comments
    db.execute("INSERT INTO alert_comments(comment_id,alert_id,author,body) VALUES (?,?,?,?)",
               [new_id("cmt_"), "alert_0", "analyst_01", "Investigating. Source IP is from known malicious range."])

    # Sources
    db.execute("INSERT INTO sources(source_id,name,kind,parser,target_table,status,events_total) VALUES (?,?,?,?,?,?,?)",
               ["syslog_main", "Main Syslog", "syslog", "builtin_rfc5424", "Syslog", "active", 15000])

    # Table usage
    db.execute("INSERT INTO table_usage(day,table_name,rows_ingested) VALUES (CURRENT_DATE,'AuthEvents',5000)")
    db.execute("INSERT INTO table_usage(day,table_name,rows_ingested) VALUES (CURRENT_DATE-1,'AuthEvents',4500)")
    db.execute("INSERT INTO table_usage(day,table_name,rows_ingested) VALUES (CURRENT_DATE,'NetworkEvents',3000)")

    # Recommendations
    db.execute("INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,est_savings,status) VALUES (?,?,?,?,?,?,?,?,?)",
               [new_id("rec_"), "optimizer", "ingest_filter", "AuthEvents",
                "Drop noisy AuthEvents from monitoring agents",
                "These events account for 40% of volume with zero alerts",
                json.dumps({"expression": 'AppName == "monitoring-agent"'}),
                "~2000 rows/day", "open"])

    # Policy rows
    db.execute("INSERT OR REPLACE INTO agent_policy(agent,scope,scope_value,mode,can_close,can_escalate,can_remediate,can_create_temp_rules) VALUES (?,?,?,?,?,?,?,?)",
               ["triage", "severity", "low", "auto_close", True, True, False, True])

    # Agent runs
    db.execute("INSERT INTO agent_runs(run_id,agent,started_at,finished_at,status,dry_run,summary) VALUES (?,?,?,?,?,?,?)",
               ["run_demo1", "triage", now, now, "ok", True, "Triage completed: 1 alert reviewed, 1 TP"])


# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_web_test_") as td:
        dbfile = str(Path(td) / "t.duckdb")
        os.environ["SIEMPL_HOME"] = str(td)
        db = Database(dbfile)
        yield db
        db.close()


@pytest.fixture
def db_seeded(db):
    seed_demo_data(db)
    return db


@pytest.fixture
def client(db):
    from siempl.web import create_app
    app = create_app(db)
    return TestClient(app)


@pytest.fixture
def client_seeded(db_seeded):
    from siempl.web import create_app
    app = create_app(db_seeded)
    return TestClient(app)


# ---- smoke tests: every page returns 200 -----------------------------------


PAGES = [
    "/", "/logs", "/alerts", "/alerts?severity=high", "/alerts?status=new",
    "/rules", "/entities", "/entities?etype=ip", "/entities?q=admin",
    "/ingestion", "/agents", "/settings",
]


def _check_page(client, path, expected_status=200):
    r = client.get(path)
    assert r.status_code == expected_status, f"{path}: {r.status_code}"
    assert "html" in r.headers.get("content-type", "").lower() or r.status_code == 404


@pytest.mark.parametrize("path", PAGES)
def test_page_returns_200_empty_db(path, client):
    """Every page should return 200 even with an empty database (degraded gracefully)."""
    _check_page(client, path, 200)


@pytest.mark.parametrize("path", PAGES)
def test_page_returns_200_seeded(path, client_seeded):
    """Every page should return 200 with seeded demo data."""
    _check_page(client_seeded, path, 200)


def test_health_endpoint(client_seeded):
    r = client_seeded.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "modules" in data


# ---- detail pages ----------------------------------------------------------


def test_alert_detail_seeded(client_seeded):
    r = client_seeded.get("/alerts/alert_0")
    assert r.status_code == 200
    # Should contain alert title and entity chip
    assert "admin" in r.text.lower() or "brute" in r.text.lower()

    r2 = client_seeded.get("/alerts/nonexistent")
    assert r2.status_code == 404


def test_rule_detail_seeded(client_seeded):
    r = client_seeded.get("/rules/rule_0")
    assert r.status_code == 200
    assert "Brute Force" in r.text


def test_entity_detail_seeded(client_seeded):
    r = client_seeded.get("/entities/ip:203.0.113.42")
    assert r.status_code == 200
    assert "203.0.113.42" in r.text

    r2 = client_seeded.get("/entities/nonexistent:missing")
    assert r2.status_code == 404


# ---- API endpoints ---------------------------------------------------------


def test_api_alert_verdict(client_seeded):
    r = client_seeded.post("/api/alerts/alert_0/verdict",
                           json={"verdict": "true_positive"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # The compat verdict maps onto the status model: the alert is now closed_tp
    preview = client_seeded.get("/api/alerts/alert_0/preview").json()
    assert preview["status"] == "closed_tp"


def test_api_alert_verdict_invalid(client_seeded):
    r = client_seeded.post("/api/alerts/alert_0/verdict",
                           json={"verdict": "bad_verdict"})
    assert r.status_code == 400


def test_api_alert_comment(client_seeded):
    r = client_seeded.post("/api/alerts/alert_0/comment",
                           json={"body": "Test comment from pytest"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_rule_toggle(client_seeded):
    r = client_seeded.put("/api/rules/rule_0/toggle")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    # Should be disabled now (was enabled)
    assert data["enabled"] is False

    # Toggle back
    r2 = client_seeded.put("/api/rules/rule_0/toggle")
    assert r2.json()["enabled"] is True


def test_api_rule_update(client_seeded):
    r = client_seeded.put("/api/rules/rule_0",
                          json={"name": "Updated Rule Name"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_entity_watch(client_seeded):
    r = client_seeded.put("/api/entities/ip:203.0.113.42/watch")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_entity_notes(client_seeded):
    r = client_seeded.post("/api/entities/ip:203.0.113.42/notes",
                           json={"notes": "Known scanner"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_settings_update(client_seeded):
    r = client_seeded.post("/api/settings",
                           json={"agents_dry_run": False})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_policy_update(client_seeded):
    r = client_seeded.post("/api/settings/policy",
                           json={"agent": "triage", "scope": "global", "scope_value": "*",
                                 "mode": "auto_close"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_recommendation_action(client_seeded):
    # Get a rec from the seeded data
    r = client_seeded.get("/ingestion")
    assert r.status_code == 200
    import re
    m = re.search(r"recAction\('([^']+)',", r.text)
    if m:
        rec_id = m.group(1)
        r2 = client_seeded.post(f"/api/recommendations/{rec_id}/approve")
        assert r2.status_code == 200
        assert r2.json()["ok"] is True


def test_api_query_no_kql(client):
    """When KQL module is absent, /api/query returns 503. When present, returns 200."""
    from siempl.web.routes import _KQL
    r = client.post("/api/query", json={"query": "AuthEvents | take 5"})
    if _KQL is None:
        assert r.status_code == 503
    else:
        # KQL module is available, check response format
        assert r.status_code == 200
        data = r.json()
        assert "columns" in data or "error" in data


def test_api_retention_update(client_seeded):
    r = client_seeded.post("/api/ingestion/retention",
                           json={"table_name": "AuthEvents", "retention_days": 60})
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ---- Feature detection -----------------------------------------------------


def test_feature_detect_imports():
    """Verify the feature detection imports are structured correctly (don't crash)."""
    from siempl.web.routes import _mod_state
    state = _mod_state()
    assert isinstance(state, dict)
    # At minimum, agents base should be importable since siempl.agents.base exists
    assert state["agents"] is True


# ---- Static files ----------------------------------------------------------


def test_static_css(client):
    r = client.get("/static/siempl.css")
    assert r.status_code == 200
    assert "font-family" in r.text
    assert "backdrop-filter" in r.text.lower()


def test_static_htmx(client):
    r = client.get("/static/htmx.min.js")
    assert r.status_code == 200
    assert len(r.content) > 1000


# ---- Create_app contract ---------------------------------------------------


def test_create_app_returns_fastapi(db):
    from siempl.web import create_app
    app = create_app(db)
    assert app.title == "siempl"
    # FastAPI sub-routers are mounted inside Starlette apps/routes.
    # Check health endpoint directly with TestClient.
    from fastapi.testclient import TestClient
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
