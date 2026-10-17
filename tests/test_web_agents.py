"""Tests for agents web routes (routes_agents.py).

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web_agents.py -q
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow


def make_app(db):
    from siempl.web import create_app
    return create_app(db), TestClient(create_app(db))


def seed_demo_data(db):
    now = utcnow()
    db.execute(
        "INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,frequency_minutes,lookback_minutes,threshold,enabled,origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ["rule_0", "Brute Force", "Detects brute force", "1. Check IP", "high",
         "AuthEvents | where EventResult == 'failure'", ["AuthEvents"], 5, 5, 1, True, "builtin"])
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,created_at,updated_at,entities) VALUES (?,?,?,?,?,?,?,?,?)",
        ["alert_0", "rule_0", "Brute force", "high", "new", "desc", now, now,
         json.dumps([{"type": "ip", "value": "1.2.3.4"}])])
    db.execute(
        "INSERT INTO sources(source_id,name,kind,parser,target_table,status,events_total) VALUES (?,?,?,?,?,?,?)",
        ["src1", "Syslog Main", "syslog", "builtin_rfc5424", "Syslog", "active", 1000])
    db.execute(
        "INSERT INTO agent_runs(run_id,agent,status,dry_run,input_ref,summary,started_at) VALUES (?,?,?,?,?,?,?)",
        ["run_1", "triage", "ok", True, "alert_0", "verdict=needs_human", now])
    db.execute(
        "INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status) VALUES (?,?,?,?,?,?,?,?)",
        ["rec_1", "optimizer", "ingest_filter", "Syslog", "Filter cron noise",
         "High volume cron messages", json.dumps({"expression": "EventCode != 'cron'"}), "open"])


@pytest.fixture
def client():
    with tempfile.TemporaryDirectory() as td:
        os.environ["SIEMPL_HOME"] = td
        db = Database()
        seed_demo_data(db)
        _, client = make_app(db)
        yield client


class TestAgentsPage:
    def test_agents_page_renders(self, client):
        r = client.get("/agents")
        assert r.status_code == 200
        assert "Agents" in r.text
        assert "AI Engine" in r.text

    def test_agents_cards_present(self, client):
        r = client.get("/agents")
        assert "Source Onboarding" in r.text
        assert "Alert Triage" in r.text
        assert "Ingestion Optimization" in r.text

    def test_agents_detail_page(self, client):
        r = client.get("/agents/triage")
        assert r.status_code == 200
        assert "Alert Triage" in r.text
        assert "Run History" in r.text
        assert "Effective Policy" in r.text

    def test_agents_detail_404(self, client):
        r = client.get("/agents/nonexistent")
        assert r.status_code == 404


class TestAgentRunAPI:
    def test_run_agent_api(self, client):
        # Tuning agent is registered; with no data it runs ok
        r = client.post("/api/agents/tuning/run")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert "status" in data
        assert "run_id" in data

    def test_run_unknown_agent_returns_503(self, client):
        r = client.post("/api/agents/nonexistent/run")
        assert r.status_code == 503


class TestAgentToggleAPI:
    def test_toggle_log_alert(self, client):
        r = client.post("/api/agents/log_alert/toggle")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert data["enabled"] is True
        # toggle back
        r2 = client.post("/api/agents/log_alert/toggle")
        assert r2.json()["enabled"] is False

    def test_toggle_remediation(self, client):
        r = client.post("/api/agents/remediation/toggle")
        assert r.status_code == 200
        assert r.json()["enabled"] is True


class TestRecommendationApplyAPI:
    def test_apply_recommendation(self, client):
        # Need to fetch rec_id from real table since fixture uses seed
        db = None
        with tempfile.TemporaryDirectory() as td:
            os.environ["SIEMPL_HOME"] = td
            db = Database()
            seed_demo_data(db)
        # Instead, use the client to find the rec
        # But easier: just directly query via the app db
        # Skip unless we can access db behind client
        # tested below with direct db access

    def test_apply_ingest_filter_recommendation(self, client):
        # Insert a fresh rec via direct SQL so we know the id
        import os
        import tempfile

        from siempl.db import Database
        with tempfile.TemporaryDirectory() as td:
            os.environ["SIEMPL_HOME"] = td
            db = Database()
            seed_demo_data(db)
            _, c = make_app(db)
            rec = db.query_one("SELECT rec_id FROM recommendations WHERE kind='ingest_filter'")
            assert rec
            rid = rec["rec_id"]
            r = c.post(f"/api/recommendations/{rid}/apply")
            assert r.status_code == 200
            assert r.json()["ok"]
            # Should now exist in ingest_filters
            row = db.query_one("SELECT * FROM ingest_filters WHERE filter_id LIKE 'flt_%'")
            assert row

    def test_reject_recommendation(self, client):
        import os
        import tempfile

        from siempl.db import Database
        with tempfile.TemporaryDirectory() as td:
            os.environ["SIEMPL_HOME"] = td
            db = Database()
            seed_demo_data(db)
            _, c = make_app(db)
            rec = db.query_one("SELECT rec_id FROM recommendations WHERE kind='ingest_filter'")
            rid = rec["rec_id"]
            r = c.post(f"/api/recommendations/{rid}/reject")
            assert r.status_code == 200
            assert r.json()["ok"]
            rec2 = db.query_one("SELECT status FROM recommendations WHERE rec_id=?", [rid])
            assert rec2["status"] == "rejected"


class TestPolicyAPI:
    def test_policy_update(self, client):
        r = client.post("/api/settings/policy", json={
            "agent": "triage", "scope": "severity", "scope_value": "high",
            "mode": "auto_close", "can_close": True, "can_escalate": True,
            "can_remediate": False, "can_create_temp_rules": True,
        })
        assert r.status_code == 200
        assert r.json()["ok"]

    def test_policy_invalid_mode(self, client):
        r = client.post("/api/settings/policy", json={
            "agent": "triage", "scope": "global", "scope_value": "*", "mode": "banana"
        })
        assert r.status_code == 400
