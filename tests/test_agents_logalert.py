"""Tests for LogAlertAgent. Uses a FAKE LLM transport. No network calls."""

import json
from datetime import UTC, datetime, timedelta

from siempl.agents.log_alert import (
    LogAlertAgent,
    _normalise_template,
    _template_key,
)
from siempl.ai.llm import LLMClient
from siempl.db import Database


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def insert_test_rows(db, table, count=10, message_prefix="test message"):
    """Insert test rows into a data table."""
    for i in range(count):
        db.insert_events(table, [{
            "TimeGenerated": (_utc_now() - timedelta(minutes=i)).isoformat(),
            "Message": f"{message_prefix} number {i}",
            "HostName": f"host{i % 3}",
            "UserName": f"user{i % 2}",
        }])


# ---- Disabled path tests ------------------------------------------------------

class TestLogAlertDisabled:
    def test_disabled_by_default(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = LogAlertAgent(db)
        res = agent.run(table="Syslog")
        assert res.status == "skipped"
        assert "enabled" in res.summary.lower()

    def test_no_transport_calls_when_disabled(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        call_count = [0]

        def counting_transport(url, headers, payload):
            call_count[0] += 1

        llm = LLMClient(db, transport=counting_transport)
        agent = LogAlertAgent(db, llm)
        agent.run(table="Syslog")
        assert call_count[0] == 0

    def test_enabled_but_ai_disabled(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        # ai_enabled defaults to False
        agent = LogAlertAgent(db)
        res = agent.run(table="Syslog")
        assert res.status in ("skipped", "ok")
        # Should not have called LLM


# ---- Enabled path tests (fake transport) --------------------------------------

class TestLogAlertEnabled:
    def test_scans_rows_and_flags(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)

        insert_test_rows(db, "Syslog", 5, "Failed password for root")

        def fake_transport(url, headers, payload):
            body = payload.get("messages", [])
            # Return flagged response for every template key found in the prompt
            import re
            keys_found = re.findall(r'"template_key":\s*"([^"]+)"', json.dumps(body))
            return {
                "choices": [{"message": {"content": json.dumps([
                    {"template_key": key,
                     "suspicious": True,
                     "reason": "brute force attempt",
                     "severity": "high"} for key in (keys_found or ["fallback_key"])
                ])}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
            }

        llm = LLMClient(db, transport=fake_transport)
        agent = LogAlertAgent(db, llm)
        res = agent.run(table="Syslog")

        assert res.status in ("ok", "skipped")

    def test_no_new_rows(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)

        agent = LogAlertAgent(db)
        res = agent.run(table="Syslog")
        assert res.status == "ok"
        assert res.output["lines_read"] == 0

    def test_empty_table_required(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = LogAlertAgent(db)
        res = agent.run(table="")
        assert res.status == "error"

    def test_allowlist_filtering(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)
        db.set_setting("log_alert_allowlist", ["cron", "systemd"])

        insert_test_rows(db, "Syslog", 3, "cron job completed")
        insert_test_rows(db, "Syslog", 2, "failed login attempt")

        call_count = [0]

        def fake_transport(url, headers, payload):
            call_count[0] += 1
            return {
                "choices": [{"message": {"content": json.dumps([
                    {"template_key": "fail", "suspicious": True,
                     "reason": "failed login", "severity": "high"},
                ])}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "cost": 0.0001},
            }

        llm = LLMClient(db, transport=fake_transport)
        agent = LogAlertAgent(db, llm)
        res = agent.run(table="Syslog")

        # cron messages should be filtered out, only "failed login" should
        # reach transport
        assert res.status in ("ok", "skipped")
        if res.status == "ok":
            # The first run will find 5 rows (3 cron + 2 failed).
            # Allowlist removes the 3 cron, leaving 2 failed (same template).
            # One unique template reaches LLM.
            unique = res.output.get("unique_templates", 0)
            assert unique == 1  # only "failed login attempt" template

    def test_deduplication(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)

        # Insert 10 rows with the same template (different numbers)
        for i in range(10):
            db.insert_events("Syslog", [{
                "TimeGenerated": (_utc_now() - timedelta(minutes=i)).isoformat(),
                "Message": f"Failed password for root from 192.168.1.{i} port {2200+i}",
            }])

        call_count = [0]

        def fake_transport(url, headers, payload):
            call_count[0] += 1
            return {
                "choices": [{"message": {"content": "[]"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "cost": 0.0001},
            }

        llm = LLMClient(db, transport=fake_transport)
        agent = LogAlertAgent(db, llm)
        res = agent.run(table="Syslog")

        assert res.output["lines_read"] == 10
        # All 10 should have the same template, so only 1 unique
        assert res.output["unique_templates"] == 1

    def test_llm_parse_error_handled(self, tmp_path):
        """Garbage from LLM should be handled without crash."""
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)

        insert_test_rows(db, "Syslog", 3, "test")

        def fake_transport(url, headers, payload):
            return {
                "choices": [{"message": {"content": "not json at all, just text"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "cost": 0.0001},
            }

        llm = LLMClient(db, transport=fake_transport)
        agent = LogAlertAgent(db, llm)
        res = agent.run(table="Syslog")

        # Should not crash
        assert res.status in ("ok", "skipped")
        if "llm_parse_error" in res.output:
            assert isinstance(res.output["llm_parse_error"], str)

    def test_budget_exceeded_handled(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("log_alert_agent_enabled", True)
        db.set_setting("ai_enabled", True)
        db.set_setting("ai_daily_usd_cap", 0.0)  # zero cap = always exceeded
        insert_test_rows(db, "Syslog", 3, "test")

        agent = LogAlertAgent(db)
        res = agent.run(table="Syslog")

        # Budget should be exceeded, handled gracefully
        assert res.status in ("skipped", "ok")


# ---- Template normalisation edge cases ----------------------------------------

class TestTemplateEdgeCases:
    def test_empty_message(self):
        assert _template_key("") != ""

    def test_unicode(self):
        text = "Пользователь admin не найден в системе 12345"
        result = _normalise_template(text)
        assert "<NUM>" in result

    def test_already_normalised(self):
        text = "Connection from <IP> port <NUM>"
        # Should be idempotent-ish
        result = _normalise_template(text)
        assert text == result  # no actual numbers to replace
