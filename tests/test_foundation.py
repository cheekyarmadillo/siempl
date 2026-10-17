import json

import pytest

from siempl.agents.base import resolve_policy
from siempl.ai.llm import AIDisabledError, LLMClient
from siempl.db import Database


def test_schema_and_insert(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    n = db.insert_events("AuthEvents", [{"UserName": "bob", "SrcIp": "1.2.3.4", "weird": 5}])
    assert n == 1
    r = db.query_one('SELECT UserName, Extra FROM "AuthEvents"')
    assert r["UserName"] == "bob" and json.loads(r["Extra"])["weird"] == 5
    assert db.get_setting("ai_enabled") is False


def test_ai_disabled_by_default_makes_no_network_call(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    def boom(*a, **k): raise AssertionError("network touched")
    with pytest.raises(AIDisabledError):
        LLMClient(db, transport=boom).chat([{"role": "user", "content": "x"}], agent="t")


def test_policy_resolution(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    assert resolve_policy(db, "triage", severity="high").mode == "recommend"
    db.execute("INSERT INTO agent_policy VALUES ('triage','severity','low','auto_close',TRUE,TRUE,FALSE,TRUE)")
    assert resolve_policy(db, "triage", severity="low").mode == "auto_close"
