"""Tests for the nav red dots (base.html + static/attention.js) and the agents attention queue.

No real LLM and no browser: checks the rendered HTML, the additive attention API fields, and JS syntax.
Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web_attention.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow

PORTALS = ("alerts", "rules", "ingestion", "logs", "agents")
JS_PATH = os.path.join(os.path.dirname(__file__), "..", "siempl", "web", "static", "attention.js")


def seed(db: Database) -> None:
    db.execute(
        "INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status) VALUES (?,?,?,?,?,?,?,?)",
        ["rec_tune", "tuning", "rule_tune", "rule_0", "Tighten threshold", "too noisy",
         json.dumps({"query": "AuthEvents | take 1"}), "open"])
    db.execute(
        "INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status) VALUES (?,?,?,?,?,?,?,?)",
        ["rec_inj", "triage", "injection_review", "alert_0", "Review injected text", "prompt-like text",
         json.dumps({}), "open"])
    db.execute(
        "INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status) VALUES (?,?,?,?,?,?,?,?)",
        ["rec_flt", "optimizer", "ingest_filter", "Syslog", "Filter cron noise", "volume",
         json.dumps({"expression": "EventCode != 'cron'"}), "open"])
    db.execute(
        "INSERT INTO agent_runs(run_id,agent,status,dry_run,input_ref,summary,started_at) VALUES (?,?,?,?,?,?,?)",
        ["run_wait", "log_alert", "waiting_approval", True, "logs", "needs OK", utcnow()])


@pytest.fixture
def env():
    with tempfile.TemporaryDirectory() as td:
        os.environ["SIEMPL_HOME"] = td
        db = Database()
        seed(db)
        from siempl.web import create_app
        yield db, TestClient(create_app(db))


def read_js() -> str:
    with open(JS_PATH, encoding="utf-8") as fh:
        return fh.read()


class TestNavDots:
    def test_base_has_all_five_dots(self, env):
        _, client = env
        html = client.get("/agents").text
        for portal in PORTALS:
            assert f'class="attn-dot" data-portal="{portal}"' in html
        assert html.count('class="attn-dot"') == 5

    def test_dots_start_hidden(self, env):
        _, client = env
        html = client.get("/logs").text
        assert html.count(" hidden ") >= 5

    def test_base_includes_attention_script(self, env):
        _, client = env
        assert '<script src="/static/attention.js"></script>' in client.get("/agents").text

    def test_script_is_served(self, env):
        _, client = env
        assert client.get("/static/attention.js").status_code == 200

    def test_script_refreshes_on_event_and_poll(self):
        js = read_js()
        assert "'attention-refresh'" in js
        assert "/api/agent-attention" in js
        assert "30000" in js
        assert "visibilitychange" in js

    def test_script_never_uses_innerhtml(self):
        assert "innerHTML" not in read_js()

    @pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
    def test_script_passes_node_check(self):
        proc = subprocess.run(["node", "--check", JS_PATH], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stderr


class TestAttentionApi:
    def test_additive_fields_present(self, env):
        _, client = env
        items = {i["id"]: i for i in client.get("/api/agent-attention").json()["items"]}
        assert {"rec_tune", "rec_inj", "rec_flt", "run_wait"} == set(items)
        for item in items.values():
            assert {"portal", "kind", "id", "title"} <= set(item)
            assert {"rec_id", "target", "rationale", "allowed", "blocked_reason"} <= set(item)
            assert item["allowed"] is (item["blocked_reason"] is None)

    def test_rec_fields_values(self, env):
        _, client = env
        items = {i["id"]: i for i in client.get("/api/agent-attention").json()["items"]}
        assert items["rec_tune"]["rec_id"] == "rec_tune"
        assert items["rec_tune"]["target"] == "rule_0"
        assert items["rec_tune"]["rationale"] == "too noisy"
        assert items["rec_inj"]["allowed"] is True  # injection_review is never policy-gated
        assert items["rec_inj"]["target"] == "alert_0"

    def test_run_item_not_actionable(self, env):
        _, client = env
        run = {i["id"]: i for i in client.get("/api/agent-attention").json()["items"]}["run_wait"]
        assert run["rec_id"] is None
        assert run["allowed"] is False
        assert run["blocked_reason"]

    def test_new_alert_does_not_count(self, env):
        db, client = env
        before = client.get("/api/agent-attention").json()["by_portal"]
        now = utcnow()
        db.execute("INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,created_at,updated_at,"
                   "evidence) VALUES (?,?,?,?,?,?,?,?,?)",
                   ["alert_new", "rule_0", "Fresh", "low", "new", "d", now, now, "[]"])
        assert client.get("/api/agent-attention").json()["by_portal"] == before


class TestAgentsQueue:
    def test_agents_page_renders_queue_container(self, env):
        _, client = env
        html = client.get("/agents").text
        assert 'id="attention-queue"' in html
        assert 'id="attention-queue-list"' in html
        assert "Needs your attention" in html
