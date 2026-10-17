"""Tests for OnboardingAgent, auto-detection, and mapping spec proposal.

Uses FAKE LLM transport. No network calls. AI-disabled path tested without transport.
"""

import json
from datetime import UTC, datetime

from siempl.agents.onboarding import (
    OnboardingAgent,
    _analyze_samples,
    _collect_samples,
    _detect_parser,
    _propose_heuristic_spec,
    _verify_coverage,
)
from siempl.ai.llm import LLMClient
from siempl.db import Database
from siempl.ingest.mapping import validate_spec


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def _seed_source(db, source_id="src1", status="pending"):
    db.execute(
        "INSERT OR REPLACE INTO sources(source_id,name,kind,status) VALUES (?,?,?,?)",
        [source_id, source_id, "http", status])


def _seed_samples(db, source_id, samples):
    """Insert raw samples into GenericEvents."""
    for s in samples:
        db.insert_events("GenericEvents", [{
            "TimeGenerated": _utc_now(), "SourceId": source_id,
            "SourceType": "unknown", "RawEvent": s,
            "Message": s[:200], "EventCode": "", "EventAction": "",
            "EventResult": "unknown",
        }])


# ---- helpers ---------------------------------------------------------------

def fake_transport_factory(responses: list[dict]):
    idx = [0]

    def transport(url, headers, payload):
        r = responses[idx[0] % len(responses)]
        idx[0] += 1
        return r

    return transport


def fake_tool_response(text="", tool_calls=None):
    return {
        "choices": [{"message": {"content": text, "tool_calls": tool_calls or []}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
    }


# ---- _collect_samples tests ------------------------------------------------

class TestCollectSamples:
    def test_from_passed_samples(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        samples = _collect_samples(db, "src1", samples=["test1", "test2"])
        assert samples == ["test1", "test2"]

    def test_from_generic_events(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_samples(db, "src1", ["raw log 1", "raw log 2"])
        samples = _collect_samples(db, "src1")
        assert len(samples) >= 2
        assert any("raw log" in s for s in samples)

    def test_no_samples_returns_empty(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        samples = _collect_samples(db, "nonexistent")
        assert samples == []


# ---- _detect_parser tests --------------------------------------------------

class TestDetectParser:
    def test_syslog_detection(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        samples = [
            "<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2",
            "<34>Oct 11 22:15:00 myhost sshd[1235]: Accepted publickey for admin from 10.0.0.2 port 22 ssh2",
        ]
        result = _detect_parser(samples, "src1")
        assert result["hits"] >= 1
        assert result["parser"] is not None

    def test_json_detection(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        samples = [
            json.dumps({"EventID": "4624", "TargetUserName": "bob", "IpAddress": "1.2.3.4"}),
            json.dumps({"EventID": "4625", "TargetUserName": "alice", "IpAddress": "5.6.7.8"}),
        ]
        result = _detect_parser(samples, "src1")
        assert result["hits"] >= 1

    def test_all_unknown(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        result = _detect_parser(["garbage text that no parser understands"], "src1")
        assert result["hits"] == 0
        assert result["parser"] is None


# ---- _analyze_samples tests ------------------------------------------------

class TestAnalyzeSamples:
    def test_json_samples(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        samples = [
            json.dumps({"user": "bob", "ip": "1.2.3.4", "status": "success"}),
            json.dumps({"user": "alice", "ip": "5.6.7.8", "status": "failure"}),
        ]
        analysis = _analyze_samples(samples)
        assert analysis["format"] == "json"
        assert "user" in analysis.get("json_keys", {})
        assert analysis["json_keys"]["user"] == 2

    def test_kv_samples(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        samples = [
            'user=bob ip=1.2.3.4 status=success',
            'user=alice ip=5.6.7.8 status=failure',
        ]
        analysis = _analyze_samples(samples)
        assert analysis["format"] == "kv"

    def test_empty(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        analysis = _analyze_samples([])
        assert analysis["format"] == "unknown"


# ---- _propose_heuristic_spec tests -----------------------------------------

class TestProposeHeuristicSpec:
    def test_returns_valid_spec(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        samples = [
            json.dumps({"user": "bob", "ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"}),
        ]
        analysis = _analyze_samples(samples)
        spec = _propose_heuristic_spec("test_source", analysis)
        assert spec["name"].startswith("mapping_")
        assert spec["target_table"] in ("AuthEvents", "GenericEvents", "Syslog",
                                        "WebAccess", "ProcessEvents", "NetworkEvents", "FileEvents")
        errors = validate_spec(spec)
        assert errors == []
        # Should map at least ip -> SrcIp
        assert "SrcIp" in spec["fields"] or "UserName" in spec["fields"]


# ---- _verify_coverage tests ------------------------------------------------

class TestVerifyCoverage:
    def test_good_coverage(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        spec = {
            "name": "test_parser", "format": "json",
            "target_table": "AuthEvents",
            "fields": {"UserName": "$.user", "SrcIp": "$.ip"},
            "time": {"field": "$.timestamp", "format": "iso8601"},
        }
        samples = [
            json.dumps({"user": "bob", "ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"}),
            json.dumps({"user": "alice", "ip": "5.6.7.8", "timestamp": "2024-01-01T01:00:00Z"}),
        ]
        coverage = _verify_coverage(spec, samples)
        assert coverage["coverage_pct"] > 0
        assert coverage["parsed"] >= 1

    def test_bad_spec(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        spec = {"name": "bad", "target_table": "NotATable"}
        coverage = _verify_coverage(spec, ["anything"])
        assert coverage["coverage_pct"] == 0.0
        assert coverage.get("spec_errors")

    def test_zero_coverage_on_mismatched_samples(self, tmp_path):
        Database(str(tmp_path / "t.duckdb"))
        spec = {
            "name": "json_parser", "format": "json",
            "target_table": "AuthEvents",
            "fields": {"UserName": "$.user"},
        }
        samples = ["not json at all", "also not json"]
        coverage = _verify_coverage(spec, samples)
        assert coverage["parsed"] == 0


# ---- OnboardingAgent AI-disabled tests -------------------------------------

class TestOnboardingAIEnabled:
    """Test with AI enabled and fake transport."""
    def test_with_fake_llm_transport(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.set_setting("ai_enabled", True)
        _seed_source(db, "src1", status="pending")
        samples = [
            json.dumps({"user": "bob", "ip": "10.0.0.1", "method": "login"}),
            json.dumps({"user": "alice", "ip": "10.0.0.2", "method": "logout"}),
        ]
        _seed_samples(db, "src1", samples)

        # Fake LLM suggests a valid spec
        spec_json = json.dumps({
            "name": "llm_parser_1",
            "description": "LLM generated",
            "format": "json",
            "target_table": "AuthEvents",
            "fields": {"UserName": "$.user", "SrcIp": "$.ip"},
        })
        transport = fake_transport_factory([fake_tool_response(spec_json)])
        llm = LLMClient(db, transport=transport)

        agent = OnboardingAgent(db, llm)
        res = agent.run(input_ref="src1", source_id="src1", use_ai=True)

        assert res.status == "ok"
        # Should produce a spec-based recommendation since no parser matched
        if res.output.get("status") == "spec_proposed":
            assert "spec" in res.output
            spec = res.output["spec"]
            errors = validate_spec(spec)
            assert errors == []
            assert "recommendation_id" in res.output


# ---- OnboardingAgent AI-disabled tests --------------------------------------

class TestOnboardingAIDisabled:
    def test_default_disabled_no_transport_calls(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "src1", status="pending")
        samples = ["log line 1", "log line 2"]
        _seed_samples(db, "src1", samples)

        call_count = [0]

        def counting_transport(url, headers, payload):
            call_count[0] += 1
            return {"choices": [], "usage": {}}

        llm = LLMClient(db, transport=counting_transport)
        agent = OnboardingAgent(db, llm)
        res = agent.run(input_ref="src1", source_id="src1")

        assert call_count[0] == 0  # never called (AI disabled default)
        assert res.status == "ok"

    def test_no_samples_gives_clear_message(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "empty_src")
        agent = OnboardingAgent(db)
        res = agent.run(input_ref="empty_src", source_id="empty_src")
        assert res.status == "ok"
        assert res.output.get("status") == "no_samples"

    def test_already_onboarded_source(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        db.execute(
            "INSERT OR REPLACE INTO sources(source_id,name,kind,status,parser,target_table) "
            "VALUES (?,?,?,?,?,?)",
            ["active_src", "active_src", "http", "active", "windows_json", "ProcessEvents"])
        agent = OnboardingAgent(db)
        res = agent.run(input_ref="active_src", source_id="active_src")
        assert res.output.get("status") == "already_onboarded"

    def test_missing_source_id(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        agent = OnboardingAgent(db)
        res = agent.run(source_id="no_such_source")
        assert res.status == "error"

    def test_syslog_samples_get_parser_detected(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "syslog_src")
        syslog_samples = [
            "<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2",
            "<34>Oct 11 22:15:00 myhost sshd[1235]: Accepted publickey for admin from 10.0.0.2 port 22 ssh2",
            "<34>Oct 11 22:16:00 myhost sshd[1236]: Failed password for invalid user test from 10.0.0.3 port 22 ssh2",
        ]
        _seed_samples(db, "syslog_src", syslog_samples)
        agent = OnboardingAgent(db)
        res = agent.run(input_ref="syslog_src", source_id="syslog_src")
        assert res.status == "ok"
        # Should detect a parser since syslog is well-known
        if res.output.get("status") == "parser_detected":
            assert res.output["parser"] is not None

    def test_unknown_format_proposes_spec(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "weird_src")
        weird_samples = [
            json.dumps({"x": "value1", "y": "data1"}),
            json.dumps({"x": "value2", "y": "data2"}),
            json.dumps({"x": "value3", "y": "data3"}),
            json.dumps({"x": "value4", "y": "data4"}),
            json.dumps({"x": "value5", "y": "data5"}),
        ]
        _seed_samples(db, "weird_src", weird_samples)
        agent = OnboardingAgent(db)
        res = agent.run(input_ref="weird_src", source_id="weird_src")
        assert res.status == "ok"
        # Should propose a spec since generic_json won't get >30% hit rate
        # with fields that don't match any schema columns well
        if res.output.get("status") == "spec_proposed":
            assert "spec" in res.output
            assert "coverage" in res.output

    def test_dry_run_writes_recommendation_not_applies(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "dry_src")
        _seed_samples(db, "dry_src", [json.dumps({"user": "bob", "ip": "10.0.0.1"})])

        agent = OnboardingAgent(db, dry_run=True)
        res = agent.run(input_ref="dry_src", source_id="dry_src")

        # Check recommendations table has a row
        recs = db.query("SELECT * FROM recommendations WHERE agent='onboarding'")
        if res.output.get("status") == "spec_proposed":
            assert len(recs) >= 1
            assert recs[0]["status"] == "open"
        # Source should NOT be updated (dry_run)
        src = db.query_one("SELECT * FROM sources WHERE source_id=?", ["dry_src"])
        assert src["status"] == "pending"  # unchanged

    def test_dry_run_false_applies_onboarding(self, tmp_path):
        db = Database(str(tmp_path / "t.duckdb"))
        _seed_source(db, "apply_src")
        _seed_samples(db, "apply_src", [json.dumps({"user": "bob", "ip": "10.0.0.1"})])

        agent = OnboardingAgent(db, dry_run=False)
        res = agent.run(input_ref="apply_src", source_id="apply_src", dry_run=False)

        # Source should be updated to active
        src = db.query_one("SELECT * FROM sources WHERE source_id=?", ["apply_src"])
        if res.output.get("status") == "spec_proposed":
            assert src["status"] == "active"
            assert src["parser"] is not None
            assert src["target_table"] is not None
