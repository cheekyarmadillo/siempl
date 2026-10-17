"""Onboarding: pipe-delimited key=value logs, mapping extras, and the coverage gate for auto-apply."""
import pytest

from siempl.agents._onboarding_delim import delimited_pairs, detect_kv_delimiter
from siempl.agents.onboarding import MIN_AUTO_APPLY_COVERAGE, OnboardingAgent
from siempl.db import Database
from siempl.ingest.mapping import MappingParser, validate_spec
from siempl.testdata.scenarios import load_scenarios

SRC = "scn-iot-gateway-raw"
LINE = "TLX|v2|dev=GW-7F21|evt=ZONE_ARM|zone=3|user=ops|ts=2026-10-14T23:13:50Z"


@pytest.fixture(autouse=True)
def _restore_parser_registry():
    """Applying a mapping spec registers a parser globally; undo that so test order cannot matter."""
    from siempl.ingest import _parsers_core as core
    before = dict(core._registry)
    yield
    core._registry.clear()
    core._registry.update(before)


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "t.duckdb"))
    d.set_setting("ai_enabled", False)
    load_scenarios(d)
    return d


def test_detects_pipe_delimiter_and_ignores_whitespace_kv():
    assert detect_kv_delimiter([LINE] * 4) == "|"
    assert detect_kv_delimiter(["src=1.1.1.1 dst=2.2.2.2 act=allow"] * 4) is None
    assert detect_kv_delimiter(["plain text line"] * 4) is None
    assert detect_kv_delimiter([]) is None


def test_delimited_pairs_skips_unkeyed_parts():
    assert delimited_pairs(LINE, "|")[0] == ("dev", "GW-7F21")
    assert all(k not in ("TLX", "v2") for k, _ in delimited_pairs(LINE, "|"))


def test_mapping_kv_delimiter_parses_records():
    spec = {"name": "m", "format": "kv", "kv_delimiter": "|", "target_table": "GenericEvents",
            "fields": {"HostName": "dev", "EventCode": "evt"}, "time": {"field": "ts", "format": "iso8601"}}
    assert validate_spec(spec) == []
    ev = MappingParser(spec).parse(LINE, "s")[0]
    assert ev.fields["HostName"] == "GW-7F21" and ev.fields["EventCode"] == "ZONE_ARM"


def test_mapping_validation_of_regex_and_delimiter_keys():
    assert validate_spec({"name": "m", "format": "regex", "target_table": "Syslog"}) == []  # no pattern: parses 0%
    assert validate_spec({"name": "m", "format": "regex", "regex_pattern": "(", "target_table": "Syslog"})
    assert validate_spec({"name": "m", "format": "kv", "kv_delimiter": "toolong", "target_table": "Syslog"})
    ok = {"name": "m", "format": "regex", "regex_pattern": r"(?P<u>\w+)", "target_table": "Syslog"}
    assert validate_spec(ok) == []


def test_onboarding_proposes_working_parser_for_scenario_source(db):
    res = OnboardingAgent(db, None, dry_run=True).run(source_id=SRC)
    assert res.status == "ok", res.summary
    spec, cov = res.output["spec"], res.output["coverage"]
    assert spec["format"] == "kv" and spec["kv_delimiter"] == "|"
    assert cov["coverage_pct"] == 100.0
    assert db.query_one("SELECT status FROM sources WHERE source_id=?", [SRC])["status"] == "pending"  # dry run


def test_onboarding_applies_when_not_dry_run_and_coverage_ok(db):
    res = OnboardingAgent(db, None, dry_run=False).run(source_id=SRC)
    assert res.output["applied"] is True
    src = db.query_one("SELECT parser, status FROM sources WHERE source_id=?", [SRC])
    assert src["status"] == "active" and src["parser"].startswith("mapping_")


def test_low_coverage_spec_is_not_auto_applied(db):
    db.execute('DELETE FROM "GenericEvents" WHERE "SourceId"=?', [SRC])
    junk = ["zzz qqq", "???", "no structure here at all", "lorem ipsum", "12345"]
    res = OnboardingAgent(db, None, dry_run=False).run(source_id=SRC, samples=junk)
    assert res.output["coverage"]["coverage_pct"] < MIN_AUTO_APPLY_COVERAGE
    assert res.output["applied"] is False and res.output["needs_human"] is True
    assert db.query_one("SELECT status FROM sources WHERE source_id=?", [SRC])["status"] == "pending"
    assert "NOT applied" in res.summary
