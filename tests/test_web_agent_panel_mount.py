"""Agent panel mounts: each page carries the container, the script include and the data attributes.

Also node --check on the browser components (skipped when node is not installed).
Run: .venv/bin/python -m pytest tests/test_web_agent_panel_mount.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow

STATIC = Path(__file__).resolve().parents[1] / "siempl" / "web" / "static"


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_agent_mount_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        database = Database(str(Path(td) / "t.duckdb"))
        database.init_schema()
        seed(database)
        yield database
        database.close()


def seed(db):
    now = utcnow()
    db.execute(
        "INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,frequency_minutes,"
        "lookback_minutes,threshold,enabled,origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ["rule_0", "Brute Force", "Detects brute force", "1. Check IP", "high",
         "AuthEvents | where EventResult == 'failure'", json.dumps(["AuthEvents"]), 5, 5, 1, True, "builtin"])
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,created_at,updated_at,entities) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ["al_1", "rule_0", "Brute force", "high", "new", "desc", now, now, "[]"])
    db.execute(
        "INSERT INTO sources(source_id,name,kind,target_table,status) VALUES (?,?,?,?,?)",
        ["src_1", "Edge syslog", "syslog", "SyslogEvents", "active"])


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db), follow_redirects=False)


def page(client, url):
    resp = client.get(url)
    assert resp.status_code == 200, url
    return resp.text


def test_agent_panel_script_is_served(client):
    resp = client.get("/static/agent_panel.js")
    assert resp.status_code == 200
    assert "window.AgentPanel" in resp.text


def test_alerts_list_drawer_container_and_scripts(client):
    html = page(client, "/alerts")
    assert 'id="agent-panel" data-agent-scope="alert"' in html
    assert '/static/agent_panel.js"' in html
    assert html.index("/static/agent_panel.js") < html.index("/static/alerts_drawer.js")


def test_alert_detail_mounts_alert_scope_for_this_alert(client):
    html = page(client, "/alerts/al_1")
    assert 'id="agent-panel" data-agent-scope="alert" data-agent-target="al_1"' in html
    assert '/static/agent_panel.js"' in html
    assert "AgentPanel.mountAll(document)" in html


def test_rule_detail_mounts_rule_scope_for_this_rule(client):
    html = page(client, "/rules/rule_0")
    assert 'id="agent-panel" data-agent-scope="rule" data-agent-target="rule_0"' in html
    assert '/static/agent_panel.js"' in html
    assert "AgentPanel.mountAll(document)" in html


def test_ingestion_agents_card_has_source_picker(client):
    html = page(client, "/ingestion")
    assert 'id="source-agents-card"' in html
    assert 'id="source-agent-pick"' in html
    assert '<option value="src_1">Edge syslog</option>' in html
    assert 'id="source-agent-panel" data-agent-scope="source" data-agent-target="src_1"' in html
    assert '/static/agent_panel.js"' in html


def test_logs_collapsible_agent_card(client):
    html = page(client, "/logs")
    assert '<details class="panel logs-agent-card" id="logs-agent-card">' in html
    assert 'id="logs-agent-panel" data-agent-scope="logs" data-agent-target="logs"' in html
    assert '/static/agent_panel.js"' in html


@pytest.mark.parametrize("name", ["agent_panel.js", "alerts_drawer.js"])
def test_node_check_passes(name):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    res = subprocess.run([node, "--check", str(STATIC / name)], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr


def test_agent_panel_js_never_uses_innerhtml():
    src = (STATIC / "agent_panel.js").read_text(encoding="utf-8")
    assert "innerHTML" not in src
    assert "insertAdjacentHTML" not in src
