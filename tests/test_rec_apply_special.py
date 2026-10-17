"""Applying entity_exclusion and onboard_source recommendations through the web apply path."""
import json

import pytest

from siempl.db import Database, new_id
from siempl.testdata.scenarios import load_scenarios
from siempl.web._agent_panel import KIND_CAPABILITY, RULE_KINDS, block_reason
from siempl.web.routes_agents import _apply_recommendation


@pytest.fixture(autouse=True)
def _restore_parser_registry():
    """Applying a mapping spec registers a parser globally; undo that so test order cannot matter."""
    from siempl.ingest import _parsers_core as core
    before = dict(core._registry)
    yield
    core._registry.clear()
    core._registry.update(before)


RULE = "scn_fp_any_failed_logon"
EXCL = {"exclude_entity": {"type": "user", "value": "svc_veeam_bkp", "column": "UserName", "count": 6}}
SRC = "scn-iot-gateway-raw"


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "t.duckdb"))
    load_scenarios(d)
    return d


def _rec(db, kind, target, payload):
    rid = new_id("rec_")
    db.execute("INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload) VALUES (?,?,?,?,?,?,?)",
               [rid, "tuning", kind, target, "t", "because", json.dumps(payload)])
    return rid


def _status(db, rid):
    return db.query_one("SELECT status FROM recommendations WHERE rec_id=?", [rid])["status"]


def _query(db):
    return db.query_one("SELECT query FROM rules WHERE rule_id=?", [RULE])["query"]


def test_entity_exclusion_is_applied_to_rule_query(db):
    before = _query(db)
    rid = _rec(db, "entity_exclusion", RULE, {"tune": EXCL})
    res = _apply_recommendation(db, rid)
    assert res["ok"], res
    row = db.query_one("SELECT query, tuning_history FROM rules WHERE rule_id=?", [RULE])
    assert '| where UserName !in ("svc_veeam_bkp")' in row["query"]
    assert before.split(" | ", 1)[1] in row["query"]  # original filters kept
    assert "svc_veeam_bkp" in str(row["tuning_history"])
    assert _status(db, rid) == "approved"


def test_entity_exclusion_nested_rule_payload_shape(db):
    rid = _rec(db, "entity_exclusion", RULE, {"rule": {"recommendation": EXCL}})
    assert _apply_recommendation(db, rid)["ok"]


def test_entity_exclusion_unsafe_column_writes_nothing(db):
    before = _query(db)
    bad = {"exclude_entity": {"column": "UserName) | drop", "value": "x"}}
    rid = _rec(db, "entity_exclusion", RULE, {"tune": bad})
    res = _apply_recommendation(db, rid)
    assert not res["ok"] and "unsafe" in res["message"]
    assert _query(db) == before
    assert _status(db, rid) == "open"


def test_entity_exclusion_quote_in_value_is_escaped(db):
    ex = {"exclude_entity": {"column": "UserName", "value": 'a"b', "type": "user"}}
    rid = _rec(db, "entity_exclusion", RULE, {"tune": ex})
    assert _apply_recommendation(db, rid)["ok"]
    assert 'a\\"b' in _query(db)


def test_entity_exclusion_without_payload_is_rejected(db):
    rid = _rec(db, "entity_exclusion", RULE, {})
    assert not _apply_recommendation(db, rid)["ok"]
    assert _status(db, rid) == "open"


def test_entity_exclusion_has_policy_entry():
    assert KIND_CAPABILITY["entity_exclusion"] == "can_remediate"
    assert "entity_exclusion" in RULE_KINDS

    class Pol:
        mode = "auto_close"
        can_remediate = False
    assert "can_remediate" in block_reason(Pol(), "tuning", "entity_exclusion")


def test_onboard_source_builtin_parser(db):
    rid = _rec(db, "onboard_source", SRC, {"parser": "syslog5424", "target_table": "Syslog"})
    assert _apply_recommendation(db, rid)["ok"]
    src = db.query_one("SELECT parser, target_table, status FROM sources WHERE source_id=?", [SRC])
    assert (src["parser"], src["target_table"], src["status"]) == ("syslog5424", "Syslog", "active")


def test_onboard_source_mapping_spec_creates_parser(db):
    spec = {"name": "mapping_test_spec", "format": "kv", "kv_delimiter": "|", "target_table": "GenericEvents",
            "fields": {"HostName": "dev"}, "constants": {}}
    rid = _rec(db, "onboard_source", SRC, {"spec": spec})
    assert _apply_recommendation(db, rid)["ok"]
    src = db.query_one("SELECT parser, target_table FROM sources WHERE source_id=?", [SRC])
    assert (src["parser"], src["target_table"]) == ("mapping_test_spec", "GenericEvents")
    assert db.query_one("SELECT name FROM parsers WHERE name='mapping_test_spec'")


def test_onboard_source_without_parser_or_spec_is_rejected(db):
    rid = _rec(db, "onboard_source", SRC, {})
    assert not _apply_recommendation(db, rid)["ok"]
    assert db.query_one("SELECT status FROM sources WHERE source_id=?", [SRC])["status"] == "pending"
    assert _status(db, rid) == "open"
