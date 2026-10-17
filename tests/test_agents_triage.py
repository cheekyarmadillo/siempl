"""Tests for TriageAgent, remediation stubs, and policy enforcement.

Uses a FAKE LLM transport/mocked LLMClient. AI-disabled path is tested without
any transport calls. No network calls are made.
"""

import json
from datetime import UTC, datetime

from siempl.agents.base import resolve_policy
from siempl.agents.log_alert import _normalise_template, _template_key
from siempl.agents.remediation import (
    block_ip,
    get_registry,
)
from siempl.agents.triage import (
    MAX_LLM_STEPS,
    TriageAgent,
    _extract_json,
    _heuristic_triage,
    triage_new_alerts,
)
from siempl.ai.llm import LLMClient
from siempl.db import Database

# ---- Helpers -------------------------------------------------------------------

def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def make_alert(db, alert_id="a1", rule_id="r1", severity="medium",
               entities=None, evidence=None, status="new"):
    """Helper: insert a test alert."""
    db.execute(
        """INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,
           evidence,entities,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [alert_id, rule_id, "Test Alert", severity, status,
         "Test description",
         json.dumps(evidence or []),
         json.dumps(entities or []),
         _utc_now(), _utc_now()])
    return db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])


def make_rule(db, rule_id="r1", severity="medium",
              description="Brute force detection",
              triage_steps="1. Check entity rep\n2. Review evidence rows"):
    """Helper: insert a test rule."""
    db.execute(
        """INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,
           frequency_minutes,lookback_minutes)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        [rule_id, "Test Rule", description, triage_steps, severity,
         'AuthEvents | where EventResult == "failure"',
         json.dumps(["AuthEvents"]), 5, 5])
    return db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])


def make_entity(db, entity_id="ip:1.2.3.4", etype="ip", value="1.2.3.4",
                reputation=50, tp_count=0, fp_count=0):
    """Helper: insert a test entity."""
    db.execute(
        """INSERT INTO entities(entity_id,type,value,reputation,tp_count,fp_count,
           first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)""",
        [entity_id, etype, value, reputation, tp_count, fp_count,
         _utc_now(), _utc_now()])


def fake_transport_factory(responses: list[dict]):
    """Return a Transport that cycles through the given responses."""
    idx = [0]

    def transport(url, headers, payload):
        r = responses[idx[0] % len(responses)]
        idx[0] += 1
        return r

    return transport


def fake_tool_response(text="", tool_calls=None):
    """Build a minimal OpenRouter-style response dict."""
    return {
        "choices": [{"message": {"content": text, "tool_calls": tool_calls or []}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
    }


def verdict_response_json(v=None):
    """Convenience: a JSON verdict response."""
    v = v or {
        "verdict": "benign",
        "confidence": 0.90,
        "severity_adjustment": None,
        "summary": "Looks benign",
        "evidence_refs": ["row_0"],
        "recommended_actions": [],
        "monitor_entities": [],
        "monitor_patterns": [],
    }
    return fake_tool_response(text=json.dumps(v))


# ---- JSON extraction tests ----------------------------------------------------

class TestJsonExtraction:
    def test_bare_object(self):
        assert _extract_json('{"a":1}') == {"a": 1}

    def test_code_fenced(self):
        text = '```json\n{"b":2}\n```'
        assert _extract_json(text) == {"b": 2}

    def test_code_fenced_no_lang(self):
        text = '```\n{"c":3}\n```'
        assert _extract_json(text) == {"c": 3}

    def test_garbage(self):
        assert _extract_json("not json at all") is None

    def test_empty(self):
        assert _extract_json("") is None

    def test_json_with_text_around(self):
        text = 'Here is my verdict:\n{"verdict":"benign"}\nHope this helps.'
        assert _extract_json(text) == {"verdict": "benign"}


# ---- Template normalisation tests ----------------------------------------------

class TestTemplateNormalisation:
    def test_ip_replaced(self):
        text = "Connection from 192.168.1.1"
        assert _normalise_template(text) == "Connection from <IP>"

    def test_numbers_replaced(self):
        text = "pid 12345 on port 22"
        result = _normalise_template(text)
        assert "<NUM>" in result
        assert "12345" not in result

    def test_identical_templates(self):
        a = "Failed password for root from 10.0.0.1 port 22"
        b = "Failed password for root from 10.0.0.99 port 2222"
        assert _template_key(a) == _template_key(b)

    def test_different_templates(self):
        a = "Failed password for root"
        b = "Accepted password for root"
        assert _template_key(a) != _template_key(b)


# ---- AI-disabled path tests ----------------------------------------------------

class TestAIDisabledPath:
    def test_ai_disabled_uses_heuristic(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))

        def boom(*a, **k):
            raise AssertionError("network touched")

        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}],
                   evidence=[{"row": 1}])
        make_entity(db, reputation=10, fp_count=3)

        llm = LLMClient(db, transport=boom)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        assert "heuristic" in res.output.get("source", "")
        assert res.output["confidence"] >= 0.50

    def test_ai_disabled_no_transport_calls(self, tmp_path):
        """Verify zero transport calls when AI is disabled (the kill switch)."""
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])
        make_entity(db, reputation=50)

        call_count = [0]

        def counting_transport(url, headers, payload):
            call_count[0] += 1
            return {"choices": [], "usage": {}}

        llm = LLMClient(db, transport=counting_transport)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        # AI is disabled by default, so transport should never be called
        assert call_count[0] == 0
        assert res.status == "ok"


# ---- LLM tool loop tests (fake transport) --------------------------------------

class TestLLMToolLoop:
    def test_single_step_verdict(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

        transport = fake_transport_factory([
            verdict_response_json({"verdict": "true_positive", "confidence": 0.92,
                                   "severity_adjustment": None,
                                   "summary": "Confirmed brute force",
                                   "evidence_refs": ["row_0"],
                                   "recommended_actions": ["block_ip"],
                                   "monitor_entities": [],
                                   "monitor_patterns": []}),
        ])
        llm = LLMClient(db, transport=transport)
        db.set_setting("ai_enabled", True)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        assert res.output["verdict"] == "true_positive"
        assert res.output["confidence"] == 0.92

    def test_verdict_with_code_fence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

        transport = fake_transport_factory([
            fake_tool_response(
                text='```json\n{"verdict":"false_positive","confidence":0.88,'
                     '"severity_adjustment":null,"summary":"FP",'
                     '"evidence_refs":["row_0"],"recommended_actions":[],'
                     '"monitor_entities":[],"monitor_patterns":[]}\n```'),
        ])
        llm = LLMClient(db, transport=transport)
        db.set_setting("ai_enabled", True)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        assert res.output["verdict"] == "false_positive"

    def test_invalid_json_fallbacks_to_needs_human(self, tmp_path, monkeypatch):
        """Garbage output should never crash; results in needs_human."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

        transport = fake_transport_factory([
            fake_tool_response(text="I'm not sure, can't produce JSON right now..."),
        ])
        llm = LLMClient(db, transport=transport)
        db.set_setting("ai_enabled", True)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        # After 1 step with no JSON, it asks again, then hits step cap
        assert res.status == "ok"
        # With no tools called and no JSON, should end at needs_human via step cap
        # or after the second ask. Either way, no crash.
        assert res.output["verdict"] in ("needs_human", None)
        # The output should have some result, not an error
        assert res.summary is not None

    def test_tool_calls_processed(self, tmp_path, monkeypatch):
        """Agent correctly processes tool calls before final verdict."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])
        make_entity(db, reputation=85, tp_count=5)

        transport = fake_transport_factory([
            # Step 1: call get_entity
            fake_tool_response(
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_entity",
                                 "arguments": '{"type":"ip","value":"1.2.3.4"}'},
                }],
            ),
            # Step 2: verdict after getting entity info
            verdict_response_json({"verdict": "true_positive", "confidence": 0.85,
                                   "severity_adjustment": None,
                                   "summary": "High rep IP confirmed",
                                   "evidence_refs": ["entity:ip:1.2.3.4"],
                                   "recommended_actions": ["block_ip"],
                                   "monitor_entities": [],
                                   "monitor_patterns": []}),
        ])
        llm = LLMClient(db, transport=transport)
        db.set_setting("ai_enabled", True)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        assert res.output["verdict"] == "true_positive"

    def test_step_cap_reached(self, tmp_path, monkeypatch):
        """After MAX_LLM_STEPS of tool calls without verdict, return needs_human."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

        # Create MAX_LLM_STEPS tool-call responses (each calls get_entity)
        responses = []
        for i in range(MAX_LLM_STEPS):
            responses.append(fake_tool_response(
                tool_calls=[{
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {"name": "get_entity",
                                 "arguments": '{"type":"ip","value":"1.2.3.4"}'},
                }],
            ))

        transport = fake_transport_factory(responses)
        llm = LLMClient(db, transport=transport)
        db.set_setting("ai_enabled", True)
        agent = TriageAgent(db, llm)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        assert res.output["verdict"] == "needs_human"
        assert "step" in res.output.get("source", "").lower()


# ---- Heuristic triage tests ---------------------------------------------------

class TestHeuristicTriage:
    def test_low_rep_benign(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        alert = make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}],
                           severity="low")
        entities = [{"entity_id": "ip:1.2.3.4", "type": "ip", "value": "1.2.3.4",
                     "reputation": 10, "tp_count": 0, "fp_count": 5}]
        v = _heuristic_triage(db, alert, None, entities)
        assert v["verdict"] == "false_positive"
        assert v["source"] == "heuristic"

    def test_high_rep_escalate(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        alert = make_alert(db, entities=[{"type": "ip", "value": "9.9.9.9"}],
                           severity="medium")
        entities = [{"entity_id": "ip:9.9.9.9", "type": "ip", "value": "9.9.9.9",
                     "reputation": 90, "tp_count": 10, "fp_count": 0}]
        v = _heuristic_triage(db, alert, None, entities)
        assert v["verdict"] == "needs_human"

    def test_critical_escalate(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        alert = make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}],
                           severity="critical")
        entities = [{"entity_id": "ip:1.2.3.4", "type": "ip", "value": "1.2.3.4",
                     "reputation": 50, "tp_count": 0, "fp_count": 0}]
        v = _heuristic_triage(db, alert, None, entities)
        assert v["verdict"] == "needs_human"

    def test_ambiguous(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        alert = make_alert(db, severity="medium")
        entities = [{"entity_id": "ip:1.2.3.4", "type": "ip", "value": "1.2.3.4",
                     "reputation": 50, "tp_count": 0, "fp_count": 0}]
        v = _heuristic_triage(db, alert, None, entities)
        assert v["verdict"] == "needs_human"
        assert v["confidence"] == 0.50


# ---- Policy matrix tests -------------------------------------------------------

class TestPolicyEnforcement:
    def test_mode_off_skips(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        # Override global policy to 'off'
        db.execute("DELETE FROM agent_policy WHERE agent='triage'")
        db.execute(
            "INSERT INTO agent_policy VALUES ('triage','global','*','off',TRUE,TRUE,FALSE,TRUE)")
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])

        agent = TriageAgent(db)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "skipped"
        assert "off" in res.summary.lower()

    def test_mode_recommend_comment_only(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM agent_policy WHERE agent='triage'")
        db.execute(
            "INSERT INTO agent_policy VALUES ('triage','global','*','recommend',TRUE,TRUE,FALSE,TRUE)")
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}])
        # Low-rep, low-sev entity -> heuristic will return benign
        make_entity(db, reputation=10, fp_count=5)

        agent = TriageAgent(db, dry_run=True)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        # In recommend mode with dry_run, should record a comment action
        actions = [a["action"] for a in res.actions]
        assert "add_comment" in actions
        # Should NOT close or escalate
        assert "close_alert" not in actions
        assert "escalate_alert" not in actions

    def test_mode_auto_close_benign(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM agent_policy WHERE agent='triage'")
        db.execute(
            "INSERT INTO agent_policy VALUES ('triage','global','*','auto_close',TRUE,TRUE,FALSE,TRUE)")
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}],
                   severity="low")
        make_entity(db, reputation=10, fp_count=5)

        agent = TriageAgent(db, dry_run=True)
        res = agent.run(input_ref="a1", alert_id="a1")

        assert res.status == "ok"
        actions = [a["action"] for a in res.actions]
        # Heuristic returns benign with high-ish confidence, policy says auto_close
        assert "close_alert" in actions

    def test_dry_run_no_mutation(self, tmp_path):
        """Verify dry_run performs NO database mutation."""
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM agent_policy WHERE agent='triage'")
        db.execute(
            "INSERT INTO agent_policy VALUES ('triage','global','*','auto_close',TRUE,TRUE,FALSE,TRUE)")
        make_rule(db)
        make_alert(db, entities=[{"type": "ip", "value": "1.2.3.4"}],
                   severity="low")
        make_entity(db, reputation=10, fp_count=5)

        # Record initial state
        alert_before = db.query_one("SELECT status, verdict FROM alerts WHERE alert_id='a1'")
        comments_before = db.query("SELECT count(*) AS cnt FROM alert_comments")
        rules_before = db.query("SELECT count(*) AS cnt FROM rules WHERE origin='ai_temporary'")

        agent = TriageAgent(db, dry_run=True)
        agent.run(input_ref="a1", alert_id="a1")

        # After dry_run, nothing should have changed
        alert_after = db.query_one("SELECT status, verdict FROM alerts WHERE alert_id='a1'")
        comments_after = db.query("SELECT count(*) AS cnt FROM alert_comments")
        rules_after = db.query("SELECT count(*) AS cnt FROM rules WHERE origin='ai_temporary'")

        assert alert_after["status"] == alert_before["status"]
        assert comments_after == comments_before
        assert rules_after == rules_before

    def test_policy_most_specific_wins(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute(
            "INSERT OR REPLACE INTO agent_policy VALUES ('triage','global','*','recommend',TRUE,TRUE,FALSE,TRUE)")
        db.execute(
            "INSERT OR REPLACE INTO agent_policy VALUES ('triage','severity','critical','auto_close',TRUE,TRUE,FALSE,TRUE)")
        db.execute(
            "INSERT OR REPLACE INTO agent_policy VALUES ('triage','rule','r1','off',TRUE,TRUE,FALSE,TRUE)")

        # Rule-specific wins
        p = resolve_policy(db, "triage", severity="critical", rule_id="r1")
        assert p.mode == "off"

        # Severity-specific wins over global
        p = resolve_policy(db, "triage", severity="critical", rule_id="r2")
        assert p.mode == "auto_close"

        # Global fallback
        p = resolve_policy(db, "triage", severity="medium", rule_id="r2")
        assert p.mode == "recommend"


# ---- Scheduler entry point tests ----------------------------------------------

class TestTriageNewAlerts:
    def test_respects_mode_off(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM agent_policy WHERE agent='triage'")
        db.execute(
            "INSERT INTO agent_policy VALUES ('triage','global','*','off',TRUE,TRUE,FALSE,TRUE)")
        make_rule(db)
        make_alert(db, alert_id="a1")
        make_alert(db, alert_id="a2")

        results = triage_new_alerts(db, limit=10)
        assert results == []

    def test_processes_up_to_limit(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        make_rule(db)
        for i in range(5):
            make_alert(db, alert_id=f"a{i}", entities=[{"type": "ip", "value": f"1.1.1.{i}"}])
            make_entity(db, entity_id=f"ip:1.1.1.{i}", reputation=10, fp_count=3)

        results = triage_new_alerts(db, limit=3)
        assert len(results) == 3
        for r in results:
            assert r.status in ("ok", "skipped")


# ---- Remediation stub tests ---------------------------------------------------

class TestRemediationStubs:
    def test_block_ip_is_stub(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        res = reg.invoke(db, "block_ip", "10.0.0.99", alert_id="a1")
        assert res["status"] == "stub"
        assert "stub: would block_ip" in res["message"]
        # Always dry_run=True in result
        assert res["dry_run"] is True

    def test_disable_user_is_stub(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        res = reg.invoke(db, "disable_user", "bob", alert_id="a1")
        assert res["status"] == "stub"
        assert "stub: would disable_user" in res["message"]

    def test_isolate_host_is_stub(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        res = reg.invoke(db, "isolate_host", "SRV01", alert_id="a1")
        assert res["status"] == "stub"

    def test_kill_process_is_stub(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        res = reg.invoke(db, "kill_process", "1234", alert_id="a1")
        assert res["status"] == "stub"

    def test_unknown_connector(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        res = reg.invoke(db, "nuke_city", "target", alert_id="a1")
        assert res["status"] == "error"
        assert "unknown connector" in res["message"]

    def test_stub_refuses_real_execution(self, tmp_path):
        """Even when called with dry_run=False, stubs ALWAYS log with dry_run=True."""
        db = Database(str(tmp_path / "t.duckdb"))
        res = block_ip(db, "1.2.3.4", dry_run=False)
        assert res["dry_run"] is True
        assert "stub" in res["status"]

    def test_remediation_logged(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()
        reg.invoke(db, "block_ip", "10.0.0.1", alert_id="a99")
        logs = db.query("SELECT * FROM remediation_log WHERE alert_id='a99'")
        assert len(logs) == 1
        assert logs[0]["action"] == "block_ip"
        assert logs[0]["target"] == "10.0.0.1"

    def test_registry_custom_connector(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        reg = get_registry()

        def custom_stub(db, target, alert_id="", dry_run=True, **kw):
            return _log_stub_func(db, "custom_action", target, alert_id=alert_id)

        # Use the internal helper directly
        from siempl.agents.remediation import _log_stub
        reg.register("custom_action",
                      lambda db, target, alert_id="", dry_run=True, **kw:
                      _log_stub(db, "custom_action", target, alert_id=alert_id, dry_run=True))

        res = reg.invoke(db, "custom_action", "test_target")
        assert res["status"] == "stub"
        assert "custom_action" in res["message"]


def _log_stub_func(db, action, target, alert_id=""):
    """Test helper using the internal log function."""
    from siempl.agents.remediation import _log_stub
    return _log_stub(db, action, target, alert_id=alert_id)


# ---- Missing alert tests ------------------------------------------------------

class TestErrorHandling:
    def test_missing_alert(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = TriageAgent(db)
        res = agent.run(input_ref="no_such_alert", alert_id="no_such_alert")
        assert res.status == "error"

    def test_empty_alert_id(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = TriageAgent(db)
        res = agent.run(input_ref="empty", alert_id="")
        assert res.status == "error"
