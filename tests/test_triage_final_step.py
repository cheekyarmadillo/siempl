"""Regression: a triage run that keeps calling tools must be forced to a verdict on the last step
instead of dying with source=step_cap_reached (seen live on the SSH-success-after-brute-force sample)."""
import json

from siempl.agents import triage as T
from siempl.ai.llm import LLMClient
from siempl.db import Database


def test_last_step_forces_verdict(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    db.set_setting("ai_enabled", True)
    db.execute("INSERT INTO alerts(alert_id,title,severity,status) VALUES ('a1','SSH success after brute force','high','new')")
    calls = []

    def transport(url, headers, payload):
        calls.append(payload)
        if payload.get("tools"):   # always wants another tool call
            return {"choices": [{"message": {"content": "", "tool_calls": [
                {"id": "c%d" % len(calls), "type": "function",
                 "function": {"name": "run_kql", "arguments": json.dumps({"query": "AuthEvents | take 1"})}}]}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001}}
        return {"choices": [{"message": {"content": json.dumps(
            {"verdict": "true_positive", "confidence": 0.9, "summary": "x", "recommended_actions": ["isolate_host"],
             "monitor_entities": [], "monitor_patterns": []})}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001}}

    agent = T.TriageAgent(db, LLMClient(db, transport=transport))
    res = agent.run(input_ref="a1", alert_id="a1")
    assert res.output.get("verdict") == "true_positive", res.output
    assert res.output.get("source") != "step_cap_reached"
    assert not calls[-1].get("tools")
