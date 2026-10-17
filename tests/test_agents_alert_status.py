"""Triage agent writes alert status through alerts_status.set_status (closed_tp / closed_fp / active).

Covers the write paths in TriageAgent._close_alert / _escalate_alert, the dry-run guard, and the
triage queue (only status='new'). Uses no LLM: the helpers are called directly.
"""
from __future__ import annotations

import pytest

from siempl.agents.base import AgentResult, Policy
from siempl.agents.triage import TriageAgent, triage_new_alerts
from siempl.db import Database


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "t.duckdb"))
    database.init_schema()
    yield database
    database.close()


def _seed(db, alert_id, status="new", severity="low"):
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,evidence,entities,"
        "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,now(),now())",
        [alert_id, "r1", "Test", severity, status, "d", "[]", "[]"])
    return db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])


def _row(db, alert_id):
    return db.query_one("SELECT status, verdict, verdict_by FROM alerts WHERE alert_id=?", [alert_id])


def _policy(can_escalate=True):
    return Policy(mode="auto_close", can_close=True, can_escalate=can_escalate)


def test_close_false_positive_sets_closed_fp(db):
    alert = _seed(db, "a1")
    agent = TriageAgent(db, dry_run=False)
    agent._close_alert(AgentResult(), alert, {"verdict": "benign"})
    row = _row(db, "a1")
    assert row["status"] == "closed_fp"
    assert row["verdict"] == "false_positive"
    assert row["verdict_by"] == "agent:triage"


def test_close_true_positive_sets_closed_tp(db):
    alert = _seed(db, "a1")
    agent = TriageAgent(db, dry_run=False)
    agent._close_alert(AgentResult(), alert, {"verdict": "true_positive"})
    row = _row(db, "a1")
    assert row["status"] == "closed_tp"
    assert row["verdict"] == "true_positive"


def test_escalate_sets_active_and_clears_derived_verdict(db):
    alert = _seed(db, "a1", severity="high")
    agent = TriageAgent(db, dry_run=False)
    agent._escalate_alert(AgentResult(), alert, {"verdict": "true_positive"}, _policy())
    row = _row(db, "a1")
    assert row["status"] == "active"
    assert row["verdict"] is None


def test_escalate_respects_policy(db):
    alert = _seed(db, "a1", severity="high")
    agent = TriageAgent(db, dry_run=False)
    agent._escalate_alert(AgentResult(), alert, {"verdict": "true_positive"}, _policy(can_escalate=False))
    assert _row(db, "a1")["status"] == "new"


def test_dry_run_writes_nothing(db):
    alert = _seed(db, "a1")
    agent = TriageAgent(db, dry_run=True)
    res = AgentResult()
    agent._close_alert(res, alert, {"verdict": "benign"})
    agent._escalate_alert(res, alert, {"verdict": "true_positive"}, _policy())
    assert _row(db, "a1")["status"] == "new"
    assert [a["action"] for a in res.actions] == ["close_alert", "escalate_alert"]


def test_triage_queue_only_takes_new_alerts(db, monkeypatch):
    _seed(db, "fresh", status="new")
    _seed(db, "working", status="active")
    _seed(db, "done", status="closed_fp")
    db.execute("DELETE FROM agent_policy WHERE agent='triage'")
    db.execute("INSERT INTO agent_policy VALUES ('triage','global','*','off',TRUE,TRUE,FALSE,TRUE)")
    assert triage_new_alerts(db) == []  # policy off: nothing is queued at all

    db.execute("UPDATE agent_policy SET mode='recommend' WHERE agent='triage'")
    seen: list[str] = []

    def fake_run(self, input_ref=None, alert_id=None, **_kw):
        seen.append(alert_id)
        return AgentResult()

    monkeypatch.setattr(TriageAgent, "run", fake_run)
    triage_new_alerts(db)
    assert seen == ["fresh"]
