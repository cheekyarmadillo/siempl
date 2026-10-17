"""Tests for RuleDiscoveryAgent: validate_sources, import_web, generate modes.

No network calls. import_web uses no http_client (skipped gracefully).
"""

from datetime import UTC, datetime, timedelta

from siempl.agents.discovery import (
    RuleDiscoveryAgent,
    _fetch_and_import_rules,
    _generate_baseline_rules,
    _validate_source,
)
from siempl.db import Database


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def _seed_source(db, source_id="src1", status="active", parser=None,
                 target_table=None):
    db.execute(
        "INSERT OR REPLACE INTO sources(source_id,name,kind,status,parser,target_table) "
        "VALUES (?,?,?,?,?,?)",
        [source_id, source_id, "http", status, parser, target_table])


# ---- _validate_source tests ------------------------------------------------

class TestValidateSource:
    def test_source_not_found(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        result = _validate_source(db, "nonexistent")
        assert "error" in result

    def test_source_with_no_events(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "empty_src")
        result = _validate_source(db, "empty_src")
        assert len(result["findings"]) >= 1
        # Should warn about no events
        warnings = [f for f in result["findings"] if f["level"] == "warning"]
        assert any("No events" in w["message"] for w in warnings)

    def test_source_with_events(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "active_src")
        db.insert_events("AuthEvents", [{
            "TimeGenerated": _utc_now(), "SourceId": "active_src",
            "SourceType": "test_parser", "UserName": "bob", "SrcIp": "10.0.0.1",
            "Message": "test", "EventCode": "4624", "EventAction": "login",
            "EventResult": "success",
        }])
        result = _validate_source(db, "active_src")
        assert result["total_events"] > 0
        assert result["sourcetype"] == "AuthEvents"

    def test_null_rates_detected(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "sparse_src")
        # Insert events with NULL key columns
        for i in range(10):
            db.insert_events("AuthEvents", [{
                "TimeGenerated": _utc_now(), "SourceId": "sparse_src",
                "SourceType": "test", "Message": f"event {i}",
                "UserName": None, "SrcIp": None,
                "EventCode": "", "EventAction": "", "EventResult": "unknown",
            }])
        result = _validate_source(db, "sparse_src")
        # Should detect that UserName is 100% null
        findings = result["findings"]
        assert any(f.get("column") == "UserName" for f in findings)


# ---- _fetch_and_import_rules tests ----------------------------------------

class TestFetchAndImportRules:
    def test_no_http_client_skips(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = RuleDiscoveryAgent(db)
        result = _fetch_and_import_rules(db, agent, http_client=None)
        assert result["status"] == "skipped"
        assert result["imported"] == 0

    def test_skips_when_no_tables_have_data(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = RuleDiscoveryAgent(db)
        result = _fetch_and_import_rules(db, agent, http_client=object())
        assert result["imported"] == 0


# ---- _generate_baseline_rules tests ---------------------------------------

class TestGenerateBaselineRules:
    def test_empty_db_generates_no_rules(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = RuleDiscoveryAgent(db, dry_run=False)
        saved = _generate_baseline_rules(db, agent)
        # No data in ProcessEvents/AuthEvents means no baseline rules generated
        assert len(saved) == 0

    def test_process_events_generates_rare_process_rule(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        # Insert > 100 ProcessEvents
        for i in range(200):
            host = f"host{i % 10}"
            proc = f"proc{i % 20}"
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now() - timedelta(hours=i),
                "SourceId": "src1", "SourceType": "windows_json",
                "ProcessName": proc, "HostName": host,
                "Message": f"Process {proc} on {host}",
                "EventCode": "4688", "EventAction": "process_start",
                "EventResult": "success",
            }])
        agent = RuleDiscoveryAgent(db, dry_run=False)
        saved = _generate_baseline_rules(db, agent)
        # Should generate at least the "Rare Process" rule
        assert len(saved) >= 1
        names = [r["name"] for r in saved]
        assert any("Rare Process" in n for n in names)

    def test_auth_events_generates_first_seen_rule(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        for i in range(100):
            db.insert_events("AuthEvents", [{
                "TimeGenerated": _utc_now() - timedelta(hours=i),
                "SourceId": "src1", "SourceType": "test",
                "UserName": f"user{i % 10}", "HostName": f"host{i % 5}",
                "Message": f"Login by user{i % 10}",
                "EventCode": "4624", "EventAction": "login",
                "EventResult": "success",
            }])
        agent = RuleDiscoveryAgent(db, dry_run=False)
        saved = _generate_baseline_rules(db, agent)
        names = [r["name"] for r in saved]
        assert any("First Seen" in n or "Rare Process" in n for n in names)

    def test_generated_rules_are_disabled(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now() - timedelta(hours=i),
                "SourceId": "src1", "SourceType": "test",
                "ProcessName": f"proc{i % 20}", "HostName": f"host{i % 10}",
                "Message": "test", "EventCode": "4688",
                "EventAction": "process_start", "EventResult": "success",
            }])
        agent = RuleDiscoveryAgent(db, dry_run=False)
        saved = _generate_baseline_rules(db, agent)
        if saved:
            for r in saved:
                rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [r["rule_id"]])
                assert rule is not None
                assert rule["enabled"] is False  # always disabled on generation

    def test_duplicate_names_are_skipped(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now() - timedelta(hours=i),
                "SourceId": "src1", "SourceType": "test",
                "ProcessName": f"proc{i % 20}", "HostName": f"host{i % 10}",
                "Message": "test", "EventCode": "4688",
                "EventAction": "process_start", "EventResult": "success",
            }])
        agent = RuleDiscoveryAgent(db, dry_run=False)
        _generate_baseline_rules(db, agent)
        saved2 = _generate_baseline_rules(db, agent)
        # Second run shouldn't add duplicates
        assert len(saved2) == 0


# ---- RuleDiscoveryAgent execute tests --------------------------------------

class TestRuleDiscoveryAgent:
    def test_validate_sources_mode(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "src1")
        _seed_source(db, "src2")
        agent = RuleDiscoveryAgent(db, dry_run=False)
        res = agent.run(input_ref="disc_run", mode="validate_sources")
        assert res.status == "ok"
        assert res.output["total_sources"] == 2

    def test_import_web_mode_skips_without_client(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = RuleDiscoveryAgent(db, dry_run=False)
        res = agent.run(input_ref="disc_run", mode="import_web")
        assert res.status == "ok"
        assert res.output.get("status") == "skipped" or res.output.get("imported", 0) == 0

    def test_generate_mode_with_data(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now() - timedelta(hours=i),
                "SourceId": "src1", "SourceType": "test",
                "ProcessName": f"proc{i % 20}", "HostName": f"host{i % 10}",
                "Message": "test", "EventCode": "4688",
                "EventAction": "process_start", "EventResult": "success",
            }])
        agent = RuleDiscoveryAgent(db, dry_run=False)
        res = agent.run(input_ref="disc_gen", mode="generate")
        assert res.status == "ok"

    def test_unknown_mode_errors(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = RuleDiscoveryAgent(db, dry_run=False)
        res = agent.run(input_ref="disc_bad", mode="invalid_mode")
        assert res.status == "error"


class TestAcceptedRulesShapes:
    RULE = {"name": "n", "query": "AuthEvents | take 1", "tables": ["AuthEvents"]}

    def test_bare_list(self):
        from siempl.agents.discovery import _accepted_rules
        assert _accepted_rules([self.RULE], []) == [self.RULE]

    def test_wrapped_in_object(self):
        from siempl.agents.discovery import _accepted_rules
        assert _accepted_rules({"rules": [self.RULE]}, []) == [self.RULE]

    def test_single_bare_rule_object(self):
        from siempl.agents.discovery import _accepted_rules
        assert _accepted_rules(self.RULE, []) == [self.RULE]

    def test_malformed_or_held_yield_nothing(self):
        from siempl.agents.discovery import _accepted_rules
        assert _accepted_rules("text", []) == []
        assert _accepted_rules({"rules": "nope"}, []) == []
        assert _accepted_rules([{"name": "no query"}], []) == []
        assert _accepted_rules({"rules": [self.RULE]}, [{"rule": "x"}]) == []
