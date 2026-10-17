"""in~ / !in~ must be case-insensitive on BOTH sides, run against real DuckDB.

Bug (present since before the 2026-10-13 refactor, confirmed against the pre-refactor compiler): the list items were
lowercased but the column was not, so `Message in~ ('abc')` matched only the stored value 'abc' and missed
'ABC' / 'Abc', and `in~ ('ABC')` matched nothing but lowercase rows. Detection rules using in~ silently
missed events. Also `!in~` did not parse at all.
"""
import duckdb
import pytest

from siempl.kql import compile_kql


@pytest.fixture
def con():
    c = duckdb.connect()
    c.execute("create table GenericEvents(Message varchar)")
    c.execute("insert into GenericEvents values ('ABC'),('abc'),('Abc'),('xyz')")
    return c


def run(con, q):
    return sorted(r[0] for r in con.execute(compile_kql(q).sql).fetchall())


def test_in_tilde_matches_any_case_lower_literal(con):
    assert run(con, "GenericEvents | where Message in~ ('abc') | project Message") == ["ABC", "Abc", "abc"]


def test_in_tilde_matches_any_case_upper_literal(con):
    assert run(con, "GenericEvents | where Message in~ ('ABC') | project Message") == ["ABC", "Abc", "abc"]


def test_in_tilde_multiple_values(con):
    assert run(con, "GenericEvents | where Message in~ ('Abc', 'XYZ') | project Message") == [
        "ABC", "Abc", "abc", "xyz"]


def test_not_in_tilde_parses_and_negates(con):
    assert run(con, "GenericEvents | where Message !in~ ('abc') | project Message") == ["xyz"]


def test_plain_in_stays_case_sensitive(con):
    assert run(con, "GenericEvents | where Message in ('abc') | project Message") == ["abc"]
    assert run(con, "GenericEvents | where Message !in ('abc') | project Message") == ["ABC", "Abc", "xyz"]
