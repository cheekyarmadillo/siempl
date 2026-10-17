"""Tests for routes_settings.py: audited settings, kill switch, model overrides.

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web_settings.py -q
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


@pytest.fixture
def client():
    with tempfile.TemporaryDirectory() as td:
        os.environ["SIEMPL_HOME"] = td
        db = Database()
        seed_demo_data(db)
        _, client = make_app(db)
        yield client


class TestSettingsPage:
    def test_settings_page_renders(self, client):
        r = client.get("/settings")
        assert r.status_code == 200
        assert "Settings" in r.text
        assert "AI Engine" in r.text
        assert "Kill Switch" in r.text or "KILL SWITCH" in r.text

    def test_settings_shows_agent_model_overrides(self, client):
        r = client.get("/settings")
        assert r.status_code == 200
        assert "Per-Agent Model Override" in r.text


class TestAuditedSettingsAPI:
    def test_update_ai_enabled(self, client):
        r = client.post("/api/settings", json={"ai_enabled": True})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert "ai_enabled" in data["changed"]

    def test_update_budget_and_caps(self, client):
        r = client.post("/api/settings", json={
            "ai_daily_usd_cap": 2.5,
            "ai_daily_token_cap": 100000,
            "ai_total_usd_budget": 50.0,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert set(data["changed"]) == {"ai_daily_usd_cap", "ai_daily_token_cap", "ai_total_usd_budget"}

    def test_invalid_type_rejected(self, client):
        r = client.post("/api/settings", json={"ai_daily_usd_cap": "banana"})
        assert r.status_code == 400
        data = r.json()
        assert not data["ok"]
        assert "ai_daily_usd_cap" in str(data["errors"])

    def test_agent_model_override(self, client):
        r = client.post("/api/agents/triage/model", json={"model": "google/gemini-3.8-flash"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert data["agent"] == "triage"
        assert data["model"] == "google/gemini-3.8-flash"

    def test_interval_setting(self, client):
        r = client.post("/api/settings", json={"agent_triage_interval_minutes": 10})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert "agent_triage_interval_minutes" in data["changed"]


class TestKillSwitch:
    def test_kill_switch_disables_ai_and_schedule(self, client):
        # First enable both
        client.post("/api/settings", json={"ai_enabled": True, "agent_schedule_enabled": True})
        r = client.post("/api/settings/kill-switch")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        assert data["ai_enabled"] is False
        assert data["agent_schedule_enabled"] is False


class TestAuditLogging:
    def test_settings_change_is_audited(self, client):
        import os
        import tempfile

        from siempl.db import Database
        with tempfile.TemporaryDirectory() as td:
            os.environ["SIEMPL_HOME"] = td
            db = Database()
            seed_demo_data(db)
            _, c = make_app(db)
            r = c.post("/api/settings", json={"ai_enabled": True})
            assert r.status_code == 200
            audit = db.query("SELECT * FROM SiemplAudit WHERE Action='settings.update' ORDER BY TimeGenerated DESC LIMIT 1")
            assert len(audit) == 1
            assert audit[0]["TargetType"] == "setting"

    def test_kill_switch_is_audited(self, client):
        import os
        import tempfile

        from siempl.db import Database
        with tempfile.TemporaryDirectory() as td:
            os.environ["SIEMPL_HOME"] = td
            db = Database()
            seed_demo_data(db)
            _, c = make_app(db)
            r = c.post("/api/settings/kill-switch")
            assert r.status_code == 200
            audit = db.query("SELECT * FROM SiemplAudit WHERE Action='settings.kill_switch' ORDER BY TimeGenerated DESC LIMIT 1")
            assert len(audit) == 1
