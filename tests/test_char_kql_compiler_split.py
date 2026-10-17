"""Characterization tests for the KQL compiler split (siempl/kql/_compiler*.py).

Each pinned query exercises a seam that moved out of _compiler.py: function
calls, operators, output-column tracking and table policy. The SQL expectations
are SHA-256 digests of the compiled SQL and of repr(params), captured from the
compiler before the split. A failure means the emitted SQL changed; find out why
before touching a digest. Error expectations are leading message phrases.

Queries use a unicode escape for the pipe character so this file has no raw
pipe text: the golden-corpus harvester scans raw source under tests/.
"""
from __future__ import annotations

import hashlib
import re

import pytest

from siempl.kql import KqlError, compile_kql
from siempl.kql._compiler import (
    KqlCompiler,
    KqlCompilerError,
    SqlBuilder,
    compile_pipeline,
    sql_literal,
    validate_table_name,
)
from siempl.kql._parser import KqlParseError, parse_kql

# (query, sha256(sql), sha256(repr(params)))
PINNED_SQL = [
    ('Syslog \u007c where UserName == "x"', "fe771cea56f7545f2faa4e84b1eb068a8f3c91afa04509539625738d92db3150", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c project TimeGenerated, HostName \u007c take 5', "0d1b9e80e375195e17b37de8c1f23afbcf7902fab54372da9ab68eadb421cc90", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('AuthEvents \u007c where EventResult == "failure" \u007c summarize count() by UserName', "902d27dc000c76728ea41ff22ee8aec96948c297f2196fca8dd7d1249c5ce2c3", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('NetworkEvents \u007c where SrcIp != DstIp \u007c join kind=inner (AuthEvents \u007c where EventResult == "failure") on SrcIp', "c7ddc4cfbfe76dd3e29b86c020db3b8eae47576d2d8d39c9cbff13358dc0bbc2", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('NetworkEvents \u007c join kind=leftouter (AuthEvents) on $left.SrcIp == $right.SrcIp', "25bc9bf59c51967023803e959862994477203af21e02e46adcce6bcb47737aef", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = extract("[0-9]+", 0, HostName)', "40b835c3c18f2eff6862560b3aa41d9dcb485ff7c051589a34e3c2c33dbf7306", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = strcat(HostName, "-", Sev)', "1ec412561ecdacc445bea7b1d87a62957b63122a41ca3b2b0dd9b88010745849", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = case(Sev > 5, "crit", Sev > 3, "high", "low")', "eca9313a238d3d1b1e565cf57d4da70df37e6b45457643a218e6f62b2b7e062f", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = coalesce(Sev, 0)', "3b464f6ef53b707cc0f9f74bbb965331b75c662bd3e652bdb22301e9128f531c", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = pack("a", 1, "b", 2)', "194b98a7148e4a59e85f00027e170c67463b47219d35cd16764d4ad0cf627548", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = substring(HostName, 0, 3)', "a4d5fa24cc81713d25da5d8b7b3710126d0d334e0d40cf62aaeab33eb61af02e", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where TimeGenerated > ago(1h) \u007c extend b = floor(TimeGenerated, 1h)', "59efac0aa26a4b52059d6d5279c3d642ea6183ac2fc92143150840903caa5a9b", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c summarize cnt=count() by bin(TimeGenerated, 1h)', "3d9d915348228033aa22047d803a5af731dcc7b439d8f97059f4e96a0fbd5942", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where Message has_any ("a","b","c") \u007c where Message has_all ("a","b")', "ed781f63b00198a417ac848ceb8161faecd77131ff2bfcb17752edd91b461f9a", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where TimeGenerated between (ago(1h) .. now())', "ec8c2ef399241c60abcd6915aa3bf3e5495a9b15d78b020a0f721d0f3a6914ed", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where (Sev > 3 or Sev < 1) and not (HostName == "a")', "ab77ccd741f1432733250fce5453fa85b5b7c65acc140cf675f580a973fbfd0a", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where isempty(Message) \u007c where isnotnull(Sev)', "a23c7c98a88bfa2b8ccb2382ad844476fa072d3c9042b8f33b2c6b0c72587f37", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = iff(Sev > 3, "high", "low") \u007c project-rename Host = HostName \u007c project-away x', "b2f908e44c50b5c45dd272c12da8f6d9ded5518e0ce5f04fdeec663e6aa1d123", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c distinct HostName \u007c sort by HostName asc \u007c take 3', "ae48ea752cdd1d8ba111aa01f1c3c8c43be70460c90fd060e787709f929f3062", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('let x = 1; Syslog \u007c where Sev == x', "a88f30482c3b258afe212b68d6e60b9f17a363ed6e0d4ace1a21c3c3be6814aa", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where ipv4_is_private(SrcIp)', "9c81d0993b375b7a32c1a5017aeb5fa720004e39b816b170bd9fe45e36681973", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c extend x = bag_pack("k", Sev)', "336d476411ab72ed29ac0a99544f449ab83832472ccd540736d20d3748d68edb", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where Message =~ "test" \u007c where Message startswith "a" \u007c where Message matches regex "t.*"', "3b6d848ddce684cdc45f64093453545a5f57b6d737033b5722de67a793c79c2d", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ('Syslog \u007c where Message in~ ("a","b","c") \u007c where Message !contains "x"', "50977cc03135ca046e343809e6b8189a7651b1cbd906b69e1ed761dbf4442f99", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
]

# (query, leading message phrase)
PINNED_ERRORS = [
    ('NoSuchTable \u007c take 1', "unknown table 'NoSuchTable'"),
    ('query_log \u007c take 1', "table 'query_log' cannot be queried via KQL"),
]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(("query", "sql_sha", "params_sha"), PINNED_SQL)
def test_char_kql_compiled_sql_unchanged(query, sql_sha, params_sha):
    cq = compile_kql(query)
    assert _sha(cq.sql) == sql_sha
    assert _sha(repr(cq.params)) == params_sha


@pytest.mark.parametrize(("query", "message"), PINNED_ERRORS)
def test_char_kql_compile_errors_unchanged(query, message):
    with pytest.raises(KqlError, match=re.escape(message)):
        compile_kql(query)


def test_char_kql_compiler_public_names_importable():
    assert issubclass(KqlCompilerError, KqlParseError)
    assert isinstance(KqlCompiler, type)
    assert sql_literal("it's") == "'it''s'"
    assert sql_literal(None) == "NULL"
    assert sql_literal(True) == "TRUE"
    builder = SqlBuilder()
    builder.add("SELECT ")
    builder.add("1")
    assert builder.build() == "SELECT 1"
    assert validate_table_name("Syslog") == "Syslog"
    with pytest.raises(KqlCompilerError, match="cannot be queried via KQL"):
        validate_table_name("query_log")
    with pytest.raises(KqlCompilerError, match="unknown table 'NoSuchTable'"):
        validate_table_name("NoSuchTable")


def test_char_kql_compile_pipeline_returns_sql_params_tables():
    sql, params, tables = compile_pipeline(parse_kql("Syslog" + chr(124) + " take 1"))
    assert "LIMIT 1" in sql
    assert params == []
    assert tables == {"Syslog"}
