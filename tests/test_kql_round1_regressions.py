"""Regression tests for behavior changes found after the 2026-10-13 KQL compiler/tokenizer refactor.

Found by compiling a 182-query corpus on the pre-refactor compiler and on the refactored tree
and diffing the SQL. The first two tests pin the ORIGINAL behavior and pass on
the original code; the third pins a deliberate bug fix.
"""
from siempl.kql import compile_kql

HEAD = 'WITH\n  _t0 AS (\n    SELECT * FROM "Syslog"\n  ),\n  _t1 AS (\n    SELECT * FROM _t0 WHERE '
TAIL = '\n  )SELECT * FROM _t1'


def test_double_equals_emits_single_equals():
    cq = compile_kql("Syslog | where UserName == 'test'")
    assert cq.sql == HEAD + '"UserName" = \'test\'' + TAIL
    assert "==" not in cq.sql


def test_in_tilde_tokenizes_and_compiles():
    # Round 1 broke tokenizing of in~ (fixed). The SQL below used to pin the original output, which lowercased
    # only the list items (a case-sensitivity bug); it now lowercases the column too. See tests/test_kql_in_tilde.py.
    cq = compile_kql('Syslog | where Message in~ ("a","b","c")')
    assert cq.sql == HEAD + 'LOWER(CAST("Message" AS VARCHAR)) IN (LOWER(\'a\'), LOWER(\'b\'), LOWER(\'c\'))' + TAIL
    assert cq.tables == {"Syslog"}


def test_not_tilde_is_case_insensitive_not_equal():
    """FIX (not a refactor): the original compiled '!~' to NOT ends_with(...) by accident (wrong results).
    '!~' must be the negation of '=~'."""
    eq = compile_kql('Syslog | where Message =~ "test"').sql
    ne = compile_kql('Syslog | where Message !~ "test"').sql
    assert "ends_with" not in ne
    assert ne == eq.replace(
        "WHERE (lower(", "WHERE NOT (lower(")
