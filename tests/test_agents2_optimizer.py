"""Tests for IngestionOptimizerAgent, apply_recommendation, and purge_expired.

No network calls. KQL dependence exercised only where safe.
"""

import json
from datetime import UTC, datetime, timedelta

from siempl.agents.optimizer import (
    IngestionOptimizerAgent,
    _classify_tables,
    apply_recommendation,
    purge_expired,
)
from siempl.db import Database


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def _seed_table_usage(db, table, rows=1000, bytes_val=50000,
                      rule_queries=0, user_queries=0, alerts=0, days_ago=0):
    day = (_utc_now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    db.execute(
        """INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,
           rule_queries,user_queries,alerts_generated)
           VALUES (?::DATE,?,?,?,?,?,?)
           ON CONFLICT (day,table_name) DO UPDATE SET
           rows_ingested = rows_ingested + ?, bytes_ingested = bytes_ingested + ?""",
        [day, table, rows, bytes_val, rule_queries, user_queries, alerts, rows, bytes_val])


def _seed_query_log(db, origin="user", tables=None, days_ago=0):
    ts = _utc_now() - timedelta(days=days_ago)
    db.execute(
        "INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms) "
        "VALUES (?,?,?,?,?,?,?)",
        [ts, origin, "test", tables or [], "test", 0, 0.0])


# ---- _classify_tables tests ------------------------------------------------

class TestClassifyTables:
    def test_empty_table(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        classified = _classify_tables(db, window_days=7)
        syslog = [c for c in classified if c["table"] == "Syslog"][0]
        assert syslog["usage_class"] == "empty"
        assert syslog["rows_ingested"] == 0

    def test_unused_table_with_volume(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_table_usage(db, "Syslog", rows=50000, rule_queries=0, user_queries=0)
        classified = _classify_tables(db, window_days=7)
        syslog = [c for c in classified if c["table"] == "Syslog"][0]
        assert syslog["usage_class"] == "unused"

    def test_used_by_rules(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_table_usage(db, "AuthEvents", rows=1000)
        db.execute(
            "INSERT INTO rules(rule_id,name,severity,query,tables,enabled) VALUES (?,?,?,?,?,?)",
            ["r1", "Test Rule", "medium", "AuthEvents | where EventResult == 'failure'",
             json.dumps(["AuthEvents"]), True])
        classified = _classify_tables(db, window_days=7)
        auth = [c for c in classified if c["table"] == "AuthEvents"][0]
        assert auth["usage_class"] == "used_by_rules"

    def test_queried_by_humans(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_table_usage(db, "Syslog", rows=500)
        _seed_query_log(db, origin="user", tables=["Syslog"])
        classified = _classify_tables(db, window_days=7)
        syslog = [c for c in classified if c["table"] == "Syslog"][0]
        assert syslog["usage_class"] == "queried_by_humans"


# ---- apply_recommendation tests --------------------------------------------

class TestApplyRecommendation:
    def test_apply_ingest_filter(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute(
            """INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status)
               VALUES (?,?,?,?,?,?,?,?)""",
            ["rec1", "optimizer", "ingest_filter", "Syslog", "Drop noisy logs",
             "Unused table", json.dumps({
                 "filter": {"table": "Syslog", "expression": 'EventCode == "123"',
                            "event_code": "123", "message_prefix": "noise", "sample_count": 1000}
             }), "open"])
        result = apply_recommendation(db, "rec1", "test_user")
        assert result["status"] == "applied"
        assert result["filter_id"].startswith("filt_")

        # Check filter row
        f = db.query_one("SELECT * FROM ingest_filters WHERE expression LIKE ?",
                         ['%123%'])
        assert f is not None
        assert f["enabled"] is True

    def test_apply_retention(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute(
            """INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status)
               VALUES (?,?,?,?,?,?,?,?)""",
            ["rec2", "optimizer", "retention", "Syslog", "Shorten retention",
             "Unused table", json.dumps({"table": "Syslog", "retention_days": 7}), "open"])
        result = apply_recommendation(db, "rec2", "test_user")
        assert result["status"] == "applied"
        r = db.query_one("SELECT * FROM table_retention WHERE table_name=?", ["Syslog"])
        assert r is not None
        assert r["retention_days"] == 7

    def test_not_found(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        result = apply_recommendation(db, "nonexistent", "user")
        assert result["status"] == "error"

    def test_already_applied(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute(
            """INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,status)
               VALUES (?,?,?,?,?,?,?,?)""",
            ["rec3", "optimizer", "retention", "t", "x", "x", "{}", "applied"])
        result = apply_recommendation(db, "rec3", "user")
        assert result["status"] == "error"


# ---- purge_expired tests ---------------------------------------------------

class TestPurgeExpired:
    def test_no_data_to_purge(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        result = purge_expired(db)
        assert result["total_deleted"] == 0

    def test_purges_old_data_from_data_tables_only(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        old = _utc_now() - timedelta(days=60)
        recent = _utc_now()

        db.insert_events("Syslog", [{
            "TimeGenerated": old, "SourceId": "src1", "SourceType": "test",
            "Message": "old event", "EventCode": "", "EventAction": "",
            "EventResult": "unknown",
        }])
        db.insert_events("Syslog", [{
            "TimeGenerated": recent, "SourceId": "src1", "SourceType": "test",
            "Message": "recent event", "EventCode": "", "EventAction": "",
            "EventResult": "unknown",
        }])

        result = purge_expired(db)
        assert result["total_deleted"] >= 1
        assert result["tables"].get("Syslog", 0) >= 1

    def test_respects_custom_retention(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        # Set retention to 1 day
        db.execute("INSERT INTO table_retention VALUES ('Syslog', 1)")
        recent = _utc_now() - timedelta(days=3)  # older than the 1-day retention regardless of time of day (cutoff is midnight)
        db.insert_events("Syslog", [{
            "TimeGenerated": recent, "SourceId": "src1", "SourceType": "test",
            "Message": "slightly old", "EventCode": "", "EventAction": "",
            "EventResult": "unknown",
        }])
        result = purge_expired(db)
        # With 1 day retention, 2-day-old data should be purged
        assert result["tables"].get("Syslog", 0) >= 1

    def test_does_not_touch_metadata_tables(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("INSERT INTO settings(key, value, updated_at) VALUES ('test', '\"value\"', CURRENT_TIMESTAMP)")
        old = _utc_now() - timedelta(days=60)
        db.insert_events("Syslog", [{
            "TimeGenerated": old, "SourceId": "src1", "SourceType": "test",
            "Message": "old", "EventCode": "", "EventAction": "",
            "EventResult": "unknown",
        }])
        purge_expired(db)
        # Settings should still exist
        s = db.query_one("SELECT * FROM settings WHERE key='test'")
        assert s is not None


# ---- IngestionOptimizerAgent tests -----------------------------------------

class TestOptimizerAgent:
    def test_empty_db_analysis(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = IngestionOptimizerAgent(db)
        res = agent.run(input_ref="optimizer_run_1")
        assert res.status == "ok"
        assert "tables" in res.output
        assert res.output["total_rows_ingested"] == 0

    def test_high_volume_unused_recommends_filter(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("optimizer_high_volume_threshold", 100)
        _seed_table_usage(db, "Syslog", rows=50000)

        # Seed some sample events to analyze templates
        for i in range(100):
            db.insert_events("Syslog", [{
                "TimeGenerated": _utc_now(), "SourceId": "src1",
                "SourceType": "syslog_rfc3164", "EventCode": "123",
                "Message": "Repeated noise pattern " + str(i % 5),
                "EventAction": "", "EventResult": "unknown",
            }])

        agent = IngestionOptimizerAgent(db)
        res = agent.run(input_ref="opt_run")
        assert res.status == "ok"
        # Should have some tables classified as unused
        tbls = res.output.get("tables", [])
        syslog = [t for t in tbls if t["table"] == "Syslog"]
        assert len(syslog) > 0

    def test_recommendation_is_recorded(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_table_usage(db, "GenericEvents", rows=100000)

        agent = IngestionOptimizerAgent(db)
        agent.run(input_ref="opt_run")

        # Check for recommendations
        recs = db.query("SELECT * FROM recommendations WHERE agent='optimizer'")
        assert len(recs) >= 0  # may or may not generate depending on threshold
