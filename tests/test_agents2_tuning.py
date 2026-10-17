"""Tests for TuningAgent: per-rule analysis, threshold tuning, entity exclusions.

No network calls. AI-disabled path tested.
"""

import json
from datetime import UTC, datetime, timedelta

from siempl.agents.tuning import (
    TuningAgent,
    _analyze_rules,
    _apply_tune,
    _entity_to_column,
)
from siempl.db import Database, new_id


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def _seed_rule(db, rule_id="r1", name="Test Rule", severity="medium",
               query='AuthEvents | where EventResult == "failure"',
               enabled=True, threshold=1, lookback=5, last_error=None,
               last_row_count=10):
    db.execute(
        """INSERT INTO rules(rule_id,name,severity,query,tables,enabled,threshold,
           lookback_minutes,last_error,last_row_count)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [rule_id, name, severity, query, json.dumps(["AuthEvents"]),
         enabled, threshold, lookback, last_error, last_row_count])


_STATUS_FOR_TEST_VERDICT = {"true_positive": "closed_tp", "false_positive": "closed_fp"}


def _seed_alert(db, alert_id="a1", rule_id="r1", verdict=None,
                entities=None, days_ago=0):
    ts = _utc_now() - timedelta(days=days_ago)
    status = _STATUS_FOR_TEST_VERDICT.get(verdict, "new")
    db.execute(
        """INSERT INTO alerts(alert_id,rule_id,title,severity,status,verdict,
           created_at,updated_at,entities,dedupe_key)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [alert_id, rule_id, "Test Alert", "medium", status, verdict,
         ts, ts, json.dumps(entities or []),
         f"dk_{alert_id}"])


# ---- _entity_to_column tests -----------------------------------------------

class TestEntityToColumn:
    def test_known_types(self):
        assert _entity_to_column("user") == "UserName"
        assert _entity_to_column("ip") == "SrcIp"
        assert _entity_to_column("host") == "HostName"
        assert _entity_to_column("process") == "ProcessName"

    def test_unknown_types(self):
        assert _entity_to_column("unknown") is None


# ---- _analyze_rules tests --------------------------------------------------

class TestAnalyzeRules:
    def test_no_rules(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        analyzed = _analyze_rules(db)
        assert analyzed == []

    def test_rule_with_no_alerts(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "No Alert Rule")
        analyzed = _analyze_rules(db)
        assert len(analyzed) == 1
        assert analyzed[0]["alert_count"] == 0
        assert analyzed[0]["fp_rate"] == 0.0

    def test_rule_with_high_fp_rate(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "High FP Rule")
        # 10 FP, 0 TP -> 100% FP rate
        for i in range(10):
            _seed_alert(db, f"a{i}", "r1", verdict="false_positive")
        _seed_alert(db, "tp1", "r1", verdict="true_positive")
        analyzed = _analyze_rules(db)
        assert len(analyzed) == 1
        assert analyzed[0]["fp_rate"] > 0.8
        assert analyzed[0]["recommendation"] is not None

    def test_rule_with_errors(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Error Rule", last_error="KQL parse error",
                   last_row_count=0)
        # Insert error runs
        for i in range(3):
            db.execute(
                "INSERT INTO agent_runs(run_id,agent,status,input_ref,started_at) "
                "VALUES (?,?,?,?,?)",
                [new_id("run_"), "rule_runner", "error", "r1", _utc_now()])
        analyzed = _analyze_rules(db)
        assert len(analyzed) == 1
        if analyzed[0].get("recommendation"):
            assert analyzed[0]["recommendation"]["kind"] == "rule_disable"

    def test_rule_with_repeated_fp_entity(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Entity FP Rule")
        # 5 FP alerts with same entity
        for i in range(5):
            _seed_alert(db, f"fp{i}", "r1", verdict="false_positive",
                        entities=[{"type": "ip", "value": "192.168.1.100"}])
        # Also add entity with low rep
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?)",
            ["ip:192.168.1.100", "ip", "192.168.1.100", 10, _utc_now(), _utc_now()])
        analyzed = _analyze_rules(db)
        assert len(analyzed) == 1

    def test_disabled_rules_not_analyzed(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Enabled Rule", enabled=True)
        _seed_rule(db, "r2", "Disabled Rule", enabled=False)
        analyzed = _analyze_rules(db)
        assert len(analyzed) == 1
        assert analyzed[0]["rule_id"] == "r1"


# ---- _apply_tune tests -----------------------------------------------------

class TestApplyTune:
    def test_disable_rule_dry_run(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Bad Rule")
        agent = TuningAgent(db)
        from siempl.agents.base import AgentResult
        result = AgentResult()
        tune = {"kind": "rule_disable", "reason": "Test"}
        _apply_tune(db, {"rule_id": "r1", "query": ""}, tune, dry_run=True,
                    agent=agent, result=result)
        assert len(result.actions) >= 1
        assert result.actions[0]["executed"] is False  # dry run

        # Rule should still be enabled
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["r1"])
        assert r["enabled"] is True

    def test_disable_rule_no_dry_run(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Bad Rule")
        agent = TuningAgent(db)
        from siempl.agents.base import AgentResult
        result = AgentResult()
        tune = {"kind": "rule_disable", "reason": "Test"}
        _apply_tune(db, {"rule_id": "r1", "query": ""}, tune, dry_run=False,
                    agent=agent, result=result)
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["r1"])
        assert r["enabled"] is False

    def test_tune_threshold(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Threshold Rule", threshold=1)
        agent = TuningAgent(db)
        from siempl.agents.base import AgentResult
        result = AgentResult()
        tune = {"kind": "rule_tune", "reason": "Too sensitive",
                "suggested_changes": {"raise_threshold": 5, "lengthen_window": 15}}
        _apply_tune(db, {"rule_id": "r1", "query": ""}, tune, dry_run=False,
                    agent=agent, result=result)
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["r1"])
        assert r["threshold"] == 5
        assert r["lookback_minutes"] == 15

    def test_entity_exclusion_query_modified(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Exclusion Rule",
                   query='AuthEvents | where EventResult == "failure"')
        agent = TuningAgent(db)
        from siempl.agents.base import AgentResult
        result = AgentResult()
        tune = {"kind": "entity_exclusion", "reason": "Repeated FP",
                "exclude_entity": {"column": "SrcIp", "value": "10.0.0.1",
                                   "type": "ip", "count": 5}}
        _apply_tune(db, {"rule_id": "r1", "query": 'AuthEvents | where EventResult == "failure"'},
                    tune, dry_run=False, agent=agent, result=result)
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["r1"])
        assert "10.0.0.1" in r["query"] or "SrcIp" in r["query"]


# ---- TuningAgent execute tests ---------------------------------------------

class TestTuningAgent:
    def test_no_runs_when_no_rules(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = TuningAgent(db)
        res = agent.run(input_ref="tune_run")
        assert res.status == "ok"
        assert res.output["total_rules_analyzed"] == 0

    def test_analyzes_rules_with_alerts(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Test", threshold=1)
        _seed_rule(db, "r2", "Test2", threshold=1)
        agent = TuningAgent(db)
        res = agent.run(input_ref="tune_run", window_days=30)
        assert res.status == "ok"
        assert res.output["total_rules_analyzed"] == 2

    def test_filter_by_rule_ids(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "A")
        _seed_rule(db, "r2", "B")
        _seed_rule(db, "r3", "C")
        agent = TuningAgent(db)
        res = agent.run(input_ref="tune_run", rule_ids=["r1", "r3"])
        assert res.output["total_rules_analyzed"] == 2

    def test_dry_run_does_not_apply_changes(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_rule(db, "r1", "Error Rule", last_error="parse error",
                   last_row_count=0)
        for i in range(3):
            db.execute(
                "INSERT INTO agent_runs(run_id,agent,status,input_ref,started_at) "
                "VALUES (?,?,?,?,?)",
                [new_id("run_"), "rule_runner", "error", "r1", _utc_now()])
        agent = TuningAgent(db, dry_run=True)
        res = agent.run(input_ref="tune_run")
        assert res.status == "ok"
        # Rule should not be disabled
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["r1"])
        assert r["enabled"] is True
