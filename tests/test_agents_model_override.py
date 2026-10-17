"""Test per-agent model override end-to-end.

Uses a fake transport asserting the payload model field.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from siempl.agents.triage import TriageAgent
from siempl.ai.llm import LLMClient
from siempl.db import Database


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def make_alert(db, alert_id="a1", rule_id="r1", severity="medium",
               entities=None, evidence=None, status="new"):
    db.execute(
        """INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,
           evidence,entities,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [alert_id, rule_id, "Test Alert", severity, status,
         "Test description",
         json.dumps(evidence or []),
         json.dumps(entities or []),
         _utc_now(), _utc_now()])


def make_rule(db, rule_id="r1", severity="medium"):
    db.execute(
        """INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,
           frequency_minutes,lookback_minutes)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        [rule_id, "Test Rule", "Desc", "Steps", severity,
         'AuthEvents | where EventResult == "failure"',
         json.dumps(["AuthEvents"]), 5, 5])


def test_model_override_used_in_payload(tmp_path, monkeypatch):
    """When agent_model_triage is set, the LLM payload must use that model."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    db = Database(str(tmp_path / "t.duckdb"))
    make_rule(db)
    make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

    captured = {}

    def capture_transport(url, headers, payload):
        captured["model"] = payload.get("model")
        captured["payload"] = payload
        return {
            "choices": [{"message": {"content": json.dumps({
                "verdict": "benign", "confidence": 0.9,
                "severity_adjustment": None, "summary": "OK",
                "evidence_refs": [], "recommended_actions": [],
                "monitor_entities": [], "monitor_patterns": [],
            }), "tool_calls": []}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
        }

    db.set_setting("ai_enabled", True)
    db.set_setting("agent_model_triage", "custom/model-42")

    llm = LLMClient(db, transport=capture_transport)
    agent = TriageAgent(db, llm)
    res = agent.run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert captured.get("model") == "custom/model-42"


def test_default_model_fallback_when_no_override(tmp_path, monkeypatch):
    """Without override, the payload uses ai_default_model."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    db = Database(str(tmp_path / "t.duckdb"))
    make_rule(db)
    make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

    captured = {}

    def capture_transport(url, headers, payload):
        captured["model"] = payload.get("model")
        return {
            "choices": [{"message": {"content": json.dumps({
                "verdict": "benign", "confidence": 0.9,
                "severity_adjustment": None, "summary": "OK",
                "evidence_refs": [], "recommended_actions": [],
                "monitor_entities": [], "monitor_patterns": [],
            }), "tool_calls": []}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
        }

    db.set_setting("ai_enabled", True)
    db.set_setting("ai_default_model", "default/fallback-model")
    # No agent_model_triage override

    llm = LLMClient(db, transport=capture_transport)
    agent = TriageAgent(db, llm)
    res = agent.run(input_ref="a1", alert_id="a1")

    assert res.status == "ok"
    assert captured.get("model") == "default/fallback-model"
