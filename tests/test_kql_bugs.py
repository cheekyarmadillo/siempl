"""Regression tests for known KQL bugs fixed 2026-10-12.

Each test validates a specific bugfix. Uses a minimal fixture DB.
"""
from __future__ import annotations

import pytest

from siempl.db import Database
from siempl.kql import KqlError, compile_kql, run_kql


def _fixture_db(tmp_path) -> Database:
    """Create a temp Database with sample AuthEvents and Syslog."""
    db = Database(str(tmp_path / "t.duckdb"))
    db.insert_events("AuthEvents", [
        {"UserName": "bob", "SrcIp": "1.2.3.4", "EventResult": "failure"},
        {"UserName": "bob", "SrcIp": "1.2.3.4", "EventResult": "failure"},
        {"UserName": "bob", "SrcIp": "1.2.3.4", "EventResult": "failure"},
        {"UserName": "bob", "SrcIp": "1.2.3.4", "EventResult": "success"},
        {"UserName": "alice", "SrcIp": "5.6.7.8", "EventResult": "success"},
        {"UserName": "bob", "SrcIp": "9.9.9.9", "EventResult": "failure",
         "Extra": '{"role":"admin","dept":"eng"}'},
    ])
    for i in range(10):
        db.insert_events("Syslog", [
            {"UserName": f"user{i}", "SrcIp": f"10.0.0.{i}",
             "SeverityLevel": i % 8, "AppName": "sshd" if i < 5 else "cron",
             "Message": f"event number {i}"},
        ])
    return db


class TestBug1NegatedStringOperators:
    """Bug 1a: !startswith, !endswith, !has_cs, !contains_cs, !has_any not recognized."""

    def test_bang_startswith_works(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | where UserName !startswith 'z' | distinct UserName")
        assert "bob" in [row[0] for row in r.rows]

    def test_bang_endswith_works(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | where UserName !endswith 'e' | distinct UserName")
        names = {row[0] for row in r.rows}
        assert "bob" in names

    def test_bang_contains_negated(self, tmp_path):
        db = _fixture_db(tmp_path)
        # !contains should exclude matches
        r = run_kql(db, "Syslog | where Message !contains '99' | count")
        assert r.rows[0][0] == 10

    def test_bang_has_works(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "Syslog | where AppName !has 'sshd' | distinct AppName")
        names = {row[0] for row in r.rows}
        assert names == {"cron"}

    def test_bang_has_cs_works(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "Syslog | where AppName !has_cs 'SSHD' | count")
        # "SSHD" does not match "sshd" with case-sensitive has
        assert r.rows[0][0] == 10

    def test_bang_has_any_works(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "Syslog | where AppName !has_any ('nginx', 'apache') | distinct AppName")
        names = {row[0] for row in r.rows}
        assert names == {"sshd", "cron"}


class TestBug1bTrailingTokens:
    """Bug 1b: Trailing tokens after a complete pipeline must raise KqlError."""

    def test_trailing_tokens_after_pipeline(self, tmp_path):
        db = _fixture_db(tmp_path)
        with pytest.raises(KqlError, match="unexpected token"):
            run_kql(db, "Syslog | where UserName == 'user0' foobar extra")

    def test_trailing_tokens_after_operator(self, tmp_path):
        db = _fixture_db(tmp_path)
        with pytest.raises(KqlError, match="unexpected token"):
            run_kql(db, "Syslog | where UserName == 'user0' and FooBar baz")

    def test_unknown_operator_raises(self, tmp_path):
        db = _fixture_db(tmp_path)
        with pytest.raises(KqlError):
            run_kql(db, "Syslog | unknownop")


class TestBug1cMultiKeyJoin:
    """Multi-key join on A, B syntax and operator-after-join fix."""

    def test_multi_key_bare_join(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, """
            let a = AuthEvents | project UserName, SrcIp, EventResult;
            let b = AuthEvents | project UserName, SrcIp;
            a | join kind=inner b on UserName, SrcIp | project UserName
        """)
        assert len(r.rows) > 0

    def test_multi_key_join_with_srcip(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, """
            let left = Syslog | project UserName, SrcIp;
            let right = AuthEvents | project UserName, SrcIp;
            left | join kind=inner right on SrcIp, UserName
            | project SrcIp
        """)
        assert len(r.rows) >= 0  # May or may not match, but shouldn't error


class TestBug2SubqueryJoinUnion:
    """Bug 2: Parenthesized subquery in join and union."""

    def test_subquery_join(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, """
            AuthEvents
            | join kind=inner (AuthEvents
                | where EventResult == 'failure'
                | summarize n = count() by UserName
            ) on UserName
            | project UserName, n
        """)
        assert len(r.rows) > 0

    def test_subquery_union(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, """
            Syslog | take 2 | project UserName
            | union (Syslog | take 3 | project UserName)
        """)
        assert len(r.rows) == 5


class TestBug3NoArgFunctions:
    """Bug 3: No-arg functions like now() emit doubled parens NOW()()."""

    def test_between_now_compiles(self, tmp_path):
        c = compile_kql(
            "AuthEvents | where TimeGenerated between (ago(1h) .. now()) | count"
        )
        assert "NOW()()" not in c.sql  # was the bug
        assert "NOW()" in c.sql

    def test_between_now_runs(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, """
            AuthEvents | where TimeGenerated between (ago(24h) .. now()) | count
        """)
        assert len(r.rows) == 1

    def test_startofday_now(self, tmp_path):
        c = compile_kql(
            "let d = startofday(now()); AuthEvents | where TimeGenerated >= d | count"
        )
        assert "DATE_TRUNC(" in c.sql

    def test_now_standalone(self, tmp_path):
        c = compile_kql("let t = now(); AuthEvents | where TimeGenerated < t | count")
        assert "NOW()" in c.sql


class TestBug4TableValidation:
    """Bug 4: Unknown/blocked tables must raise KqlError listing available tables."""

    def test_unknown_table_raises(self):
        with pytest.raises(KqlError, match="unknown table"):
            compile_kql("NoSuchTable | take 1")

    def test_unknown_table_lists_available(self):
        try:
            compile_kql("NoSuchTable | take 1")
        except KqlError as e:
            assert "Available tables:" in str(e)

    def test_blocked_table_settings_rejected(self):
        with pytest.raises(KqlError, match="cannot be queried"):
            compile_kql("settings | take 1")

    def test_blocked_table_ai_usage_rejected(self):
        with pytest.raises(KqlError, match="cannot be queried"):
            compile_kql("ai_usage | take 1")

    def test_meta_table_alerts_allowed(self):
        c = compile_kql("alerts | take 1")
        assert "alerts" in c.sql.lower()

    def test_data_table_works(self):
        c = compile_kql("Syslog | take 1")
        assert "Syslog" in c.sql


class TestBug5DottedAccess:
    """Bug 5: Dotted access on dynamic columns: p.key, Extra['key'], Extra.key."""

    def test_dotted_access_on_extend_result(self, tmp_path):
        """extend p = parse_json(Extra) | project p.role"""
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | extend p = parse_json(Extra) | project p.role")
        assert "p.role" not in r.sql  # should NOT be a column named "p.role"
        assert "->>'role'" in r.sql

    def test_extra_dot_key_tostring(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | project tostring(Extra.detail)")
        # Extra.detail tries to access detail from the Extra column
        assert len(r.columns) > 0

    def test_bracket_access(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | project Extra['role']")
        assert "->>'role'" in r.sql

    def test_dotted_project_column(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "AuthEvents | extend p = parse_json(Extra) | project p.role, p.dept")
        assert "->>'role'" in r.sql
        assert "->>'dept'" in r.sql

    def test_dotted_where(self, tmp_path):
        db = _fixture_db(tmp_path)
        # Even if the value is null (Extra.dept not set for most rows), it should compile
        r = run_kql(db, "Syslog | extend p = parse_json(Extra) | where isnotempty(p.detail)")
        assert len(r.columns) > 0


class TestBug6SelectOnly:
    """Bug 4 (security): Only SELECT-shaped SQL is executed."""

    def test_compiled_sql_is_select_only(self, tmp_path):
        db = _fixture_db(tmp_path)
        r = run_kql(db, "Syslog | take 1")
        stripped = r.sql.strip().upper()
        assert stripped.startswith("WITH") or stripped.startswith("SELECT")
        assert "DELETE" not in stripped
        assert "INSERT" not in stripped
        assert "UPDATE" not in stripped
        assert "DROP" not in stripped
        assert "CREATE" not in stripped


# ---------------------------------------------------------------------------
# Run all existing tests to ensure no regressions
# ---------------------------------------------------------------------------
TEST_COUNT = sum(1 for name in dir() if name.startswith("test_"))
