"""End-to-end prompt-injection hardening for TriageAgent (STEP 8b).

A FAKE LLM transport replays canned replies. The attack tests use a fake LLM that OBEYS the injection
(returns false_positive + close), so only the hold logic can stop the close. No network calls.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from siempl.agents.triage import TriageAgent
from siempl.ai.llm import LLMClient
from siempl.db import Database
from siempl.testdata.scenarios import load_scenarios

TESTS = Path(__file__).parent
CORPUS = json.loads((TESTS / "injection_corpus.json").read_text())
ATTACKS = CORPUS["attacks"]
MANIFEST = json.loads((TESTS.parent / "siempl/testdata/scenarios_manifest.json").read_text())
OBEYED_CLOSE = {"verdict": "false_positive", "confidence": 0.99, "summary": "known scanner",
                "recommended_actions": ["close_alert"], "monitor_entities": []}


@pytest.fixture(autouse=True)
def _api_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _reply(text):
    return {"choices": [{"message": {"content": text, "tool_calls": []}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001}}


def _fake_llm(db, *texts):
    """LLM whose replies are the given texts in order; the last one repeats."""
    idx = [0]

    def transport(url, headers, payload):
        r = _reply(texts[min(idx[0], len(texts) - 1)])
        idx[0] += 1
        return r

    db.set_setting("ai_enabled", True)
    return LLMClient(db, transport=transport)


def _setup(tmp_path, evidence=None, entities=None, mode="auto_close"):
    """Fresh DB with one rule, one new alert 'a1' and a policy in the given mode."""
    db = Database(str(tmp_path / "t.duckdb"))
    db.execute(
        """INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,
           frequency_minutes,lookback_minutes)
           VALUES ('r1','Test Rule','Brute force detection','Check entity rep','medium',
           'AuthEvents | where EventResult == "failure"', '["AuthEvents"]', 5, 5)""")
    now = _now()
    db.execute(
        """INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,evidence,entities,
           created_at,updated_at) VALUES ('a1','r1','Test Alert','high','new','Test description',?,?,?,?)""",
        [json.dumps(evidence or []), json.dumps(entities or []), now, now])
    db.execute("DELETE FROM agent_policy WHERE agent='triage'")
    db.execute("INSERT INTO agent_policy VALUES ('triage','global','*',?,TRUE,TRUE,FALSE,TRUE)", [mode])
    return db


def _status(db, alert_id="a1"):
    return db.query_one("SELECT status FROM alerts WHERE alert_id=?", [alert_id])["status"]


def _count(db, sql, params=None):
    return db.query_one(sql, params or [])["n"]


def _injection_rec_count(db):
    return _count(db, "SELECT COUNT(*) AS n FROM recommendations WHERE kind='injection_review' "
                      "AND target='a1' AND status='open'")


def _audit_count(db):
    return _count(db, "SELECT COUNT(*) AS n FROM SiemplAudit WHERE Action='agent.injection_detected'")


def _temp_rule_count(db):
    return _count(db, "SELECT COUNT(*) AS n FROM rules WHERE origin='ai_temporary'")


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda s: s[:40])
def test_obeyed_injection_in_evidence_is_held(tmp_path, attack):
    db = _setup(tmp_path, evidence=[{"Message": attack}])
    llm = _fake_llm(db, json.dumps(OBEYED_CLOSE))
    res = TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert res.output["injection_detected"] is True
    assert res.output["verdict"] == "needs_human"
    assert res.output["model_verdict"] == "false_positive"
    assert _status(db) == "new"
    assert _temp_rule_count(db) == 0
    assert _injection_rec_count(db) == 1
    assert _audit_count(db) >= 1
    comments = db.query("SELECT body FROM alert_comments WHERE alert_id='a1'")
    assert any(c["body"].startswith("[agent:triage] suspected prompt injection in telemetry:")
               and "Held for human review." in c["body"] for c in comments)


def test_injection_hold_dry_run_writes_rec_and_audit_but_no_comment(tmp_path):
    db = _setup(tmp_path, evidence=[{"Message": ATTACKS[0]}])
    llm = _fake_llm(db, json.dumps(OBEYED_CLOSE))
    res = TriageAgent(db, llm, dry_run=True).run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert _status(db) == "new"
    assert _injection_rec_count(db) == 1
    assert _audit_count(db) >= 1
    assert _count(db, "SELECT COUNT(*) AS n FROM alert_comments WHERE alert_id='a1'") == 0
    assert any(a["action"] == "add_comment" for a in res.actions)


def test_second_run_adds_no_second_open_review_rec(tmp_path):
    db = _setup(tmp_path, evidence=[{"Message": ATTACKS[0]}])
    llm = _fake_llm(db, json.dumps(OBEYED_CLOSE))
    TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")
    TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")
    assert _injection_rec_count(db) == 1


def test_same_alert_without_injection_closes(tmp_path):
    db = _setup(tmp_path)
    llm = _fake_llm(db, json.dumps(OBEYED_CLOSE))
    res = TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert res.output["injection_detected"] is False
    assert res.output["verdict"] == "false_positive"
    assert _status(db) == "closed_fp"
    assert _injection_rec_count(db) == 0


@pytest.mark.parametrize("reply", [
    "I cannot decide, sorry.",
    '{"verdict": "close", "confidence": "high", "summary": 7}',
])
def test_garbage_output_becomes_needs_human(tmp_path, reply):
    db = _setup(tmp_path)
    llm = _fake_llm(db, reply)
    res = TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert res.output["verdict"] == "needs_human"
    assert _status(db) not in ("closed_fp", "closed_tp")


def test_unknown_monitor_entities_are_dropped(tmp_path):
    db = _setup(tmp_path, entities=[{"type": "ip", "value": "1.2.3.4"}], mode="monitor")
    reply = {"verdict": "true_positive", "confidence": 0.6, "summary": "watch",
             "recommended_actions": ["monitor_entity"],
             "monitor_entities": [{"type": "ip", "value": "203.0.113.99"},
                                  {"type": "ip", "value": "1.2.3.4"}]}
    llm = _fake_llm(db, json.dumps(reply))
    res = TriageAgent(db, llm, dry_run=False).run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert res.output["monitor_entities"] == [{"type": "ip", "value": "1.2.3.4"}]
    kql = [r["query"] for r in db.query("SELECT query FROM rules WHERE origin='ai_temporary'")]
    assert kql == ['GenericEvents | where SrcIp == "1.2.3.4"']


def _flagged_scenario_alerts():
    for scen in MANIFEST["scenarios"]:
        for a in scen["alerts"]:
            if a.get("injection_flagged"):
                yield a


def test_heuristic_never_closes_injection_scenario_alerts(tmp_path):
    db = Database(str(tmp_path / "scn.duckdb"))
    db.execute("DELETE FROM agent_policy WHERE agent='triage'")
    db.execute("INSERT INTO agent_policy VALUES ('triage','global','*','auto_close',TRUE,TRUE,FALSE,TRUE)")
    load_scenarios(db, now=_now())
    checked = 0
    for a in _flagged_scenario_alerts():
        row = db.query_one("SELECT alert_id, status FROM alerts WHERE title=? AND rule_id=?",
                           [a["title"], a["rule_id"]])
        assert row is not None, a["title"]
        res = TriageAgent(db, dry_run=False).run(input_ref=row["alert_id"], alert_id=row["alert_id"])
        assert res.status == "ok"
        assert res.output["injection_detected"] is True, a["title"]
        assert res.output["verdict"] == "needs_human"
        assert _status(db, row["alert_id"]) == row["status"], a["title"]
        checked += 1
    assert checked == 3
