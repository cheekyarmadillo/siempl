"""Corpus-based prompt-injection tests for log_alert, discovery and onboarding.

A FAKE LLM that OBEYS the injection (flags/creates everything) is used, so only the hold logic can stop damage.
Each agent must (a) detect the injection, (b) not act automatically, (c) leave an injection_review recommendation.
Benign corpus entries must not trigger the hold. No network calls.
"""
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from siempl.agents.discovery import RuleDiscoveryAgent, _generate_baseline_rules
from siempl.agents.log_alert import LogAlertAgent
from siempl.agents.onboarding import OnboardingAgent
from siempl.ai.llm import LLMClient
from siempl.db import Database

CORPUS = json.loads((Path(__file__).parent / "injection_corpus.json").read_text())
ATTACKS = CORPUS["attacks"]
BENIGN = CORPUS["benign"]


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _reply(content):
    return {"choices": [{"message": {"content": content, "tool_calls": []}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001}}


def _obedient_logalert(url, headers, payload):
    keys = re.findall(r'"template_key":\s*"([^"]+)"', json.dumps(payload.get("messages", [])))
    return _reply(json.dumps([{"template_key": k, "suspicious": True, "reason": "obeyed", "severity": "high"}
                              for k in keys or ["fallback_key"]]))


OBEDIENT_RULE = [{"name": "Obeyed Rule", "description": "d", "triage_steps": "t", "severity": "low",
                  "query": "AuthEvents | where EventResult == \"failure\"", "tables": ["AuthEvents"],
                  "entity_mappings": []}]


@pytest.fixture(autouse=True)
def _restore_parser_registry():
    """Applying a mapping spec registers a parser globally; undo that so test order cannot matter."""
    from siempl.ingest import _parsers_core as core
    before = dict(core._registry)
    yield
    core._registry.clear()
    core._registry.update(before)


@pytest.fixture(autouse=True)
def _api_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")


def _db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


def _review_recs(db):
    return db.query("SELECT rec_id FROM recommendations WHERE kind='injection_review'")


# ---- log_alert ---------------------------------------------------------------

def _logalert_run(db, message):
    db.set_setting("log_alert_agent_enabled", True)
    db.set_setting("ai_enabled", True)
    db.insert_events("Syslog", [{"TimeGenerated": _now().isoformat(), "Message": message, "HostName": "h1"}])
    return LogAlertAgent(db, LLMClient(db, transport=_obedient_logalert)).run(table="Syslog")


@pytest.mark.parametrize("attack", ATTACKS)
def test_logalert_injected_log_creates_no_alerts(tmp_path, attack):
    db = _db(tmp_path)
    res = _logalert_run(db, "sshd[1]: " + attack)
    assert res.output.get("injection_detected") is True, attack
    assert res.output["alert_ids"] == []
    assert db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"] == 0
    assert _review_recs(db)


@pytest.mark.parametrize("text", BENIGN[:10])
def test_logalert_benign_log_is_not_held(tmp_path, text):
    db = _db(tmp_path)
    res = _logalert_run(db, text)
    assert not res.output.get("injection_detected")
    assert not _review_recs(db)


# ---- discovery ---------------------------------------------------------------

def _discovery_generate(db, user_name):
    db.set_setting("ai_enabled", True)
    db.insert_events("AuthEvents", [{"TimeGenerated": _now().isoformat(), "UserName": user_name,
                                     "EventResult": "failure", "HostName": "h1"}])
    llm = LLMClient(db, transport=lambda u, h, p: _reply(json.dumps(OBEDIENT_RULE)))
    agent = RuleDiscoveryAgent(db, llm, dry_run=False)
    _generate_baseline_rules(db, agent)
    return db.query("SELECT name FROM rules WHERE name='Obeyed Rule'")


def test_discovery_control_benign_data_accepts_llm_rule(tmp_path):
    assert _discovery_generate(_db(tmp_path), "alice")


@pytest.mark.parametrize("attack", ATTACKS)
def test_discovery_injected_data_creates_no_llm_rule(tmp_path, attack):
    db = _db(tmp_path)
    assert not _discovery_generate(db, attack)
    assert _review_recs(db)


# ---- onboarding --------------------------------------------------------------

def _onboard(db, samples):
    db.execute("INSERT INTO sources(source_id,name,parser,target_table,status) VALUES ('s1','s1','auto','GenericEvents','pending')")
    return OnboardingAgent(db, None, dry_run=False).run(source_id="s1", samples=samples)


@pytest.mark.parametrize("attack", ATTACKS)
def test_onboarding_injected_samples_are_never_auto_applied(tmp_path, attack):
    db = _db(tmp_path)
    res = _onboard(db, ["evt=login user=bob", f"evt=note msg={attack}", "evt=login user=amy"])
    assert res.output.get("injection_detected") is True, attack
    assert db.query_one("SELECT status FROM sources WHERE source_id='s1'")["status"] == "pending"
    assert _review_recs(db)


@pytest.mark.parametrize("text", BENIGN[:10])
def test_onboarding_benign_samples_not_held(tmp_path, text):
    res = _onboard(_db(tmp_path), [f"evt=login user=bob msg={text}"] * 3)
    assert not res.output.get("injection_detected")
