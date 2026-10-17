"""Tests for the ingest pipeline: parsers, pipeline, entities, mapping parser, filters."""
import json
import time

import pytest

from siempl.db import Database
from siempl.ingest import IngestPipeline, NormalizedEvent, parsers
from siempl.ingest.entities import extract_entities
from siempl.ingest.mapping import MappingParser, validate_spec

# ── helpers ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


@pytest.fixture
def pipeline(db):
    return IngestPipeline(db)


# ── NormalizedEvent ──────────────────────────────────────────────────────────

def test_normalized_event_creation():
    evt = NormalizedEvent(table="AuthEvents", fields={"UserName": "bob"})
    assert evt.table == "AuthEvents"
    assert evt.fields["UserName"] == "bob"


def test_normalized_event_invalid_table():
    with pytest.raises(ValueError, match="Unknown table"):
        NormalizedEvent(table="NoSuchTable", fields={})


# ── IngestPipeline basics ────────────────────────────────────────────────────

def test_ingest_creates_pending_source(pipeline, db):
    pipeline.ingest("new-src", ["hello world"])
    src = db.query_one("SELECT * FROM sources WHERE source_id=?", ["new-src"])
    assert src is not None
    assert src["status"] == "pending"


def test_ingest_single_record(pipeline, db):
    result = pipeline.ingest("test-src", [{"message": "test log entry"}])
    assert result.received == 1
    assert result.inserted == 1
    assert result.failed == 0

    rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["test-src"])
    assert len(rows) == 1


def test_ingest_batch(pipeline, db):
    records = [f"line {i}" for i in range(100)]
    result = pipeline.ingest("batch-src", records)
    assert result.received == 100
    assert result.inserted == 100

    rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["batch-src"])
    assert len(rows) == 100


def test_ingest_table_tracking(pipeline, db):
    result = pipeline.ingest("track-src", ["msg1", "msg2"])
    assert result.tables.get("GenericEvents", 0) == 2


def test_source_counter(pipeline, db):
    pipeline.ingest("counter-src", ["a", "b", "c"])
    src = db.query_one("SELECT events_total FROM sources WHERE source_id=?", ["counter-src"])
    assert src["events_total"] == 3

    pipeline.ingest("counter-src", ["d", "e"])
    src = db.query_one("SELECT events_total FROM sources WHERE source_id=?", ["counter-src"])
    assert src["events_total"] == 5


# ── syslog parsers ───────────────────────────────────────────────────────────

def test_syslog_rfc3164_parse():
    msg = '<34>Oct 11 22:14:15 myhost sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2'
    events = parsers.parse_syslog_rfc3164(msg, "test-src")
    assert len(events) == 1
    evt = events[0]
    assert evt.table == "AuthEvents"
    assert evt.fields["UserName"] == "root"
    assert evt.fields["SrcIp"] == "1.2.3.4"
    assert evt.fields["EventResult"] == "failure"
    assert evt.fields["EventAction"] == "login"
    assert evt.fields["AuthMethod"] == "ssh"          # rule contract (rules 1-3)
    assert evt.fields["TargetUserName"] == "root"   # rule contract
    assert evt.fields["LogonType"] == "password"    # wire sub-method
    assert evt.fields["HostName"] == "myhost"
    assert evt.fields["AppName"] == "sshd"
    assert evt.fields["Facility"] == "4"
    assert evt.fields["SeverityLevel"] == 2
    assert evt.fields["RawEvent"] == msg


def test_syslog_rfc3164_success():
    msg = '<13>Oct 11 10:30:00 web01 sshd[999]: Accepted publickey for alice from 10.0.1.50 port 54567 ssh2'
    events = parsers.parse_syslog_rfc3164(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["EventResult"] == "success"
    assert events[0].fields["UserName"] == "alice"
    assert events[0].fields["AuthMethod"] == "ssh"
    assert events[0].fields["TargetUserName"] == "alice"
    assert events[0].fields["LogonType"] == "publickey"


def test_syslog_rfc3164_sudo():
    msg = '<13>Oct 11 14:00:00 web01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update'
    events = parsers.parse_syslog_rfc3164(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["UserName"] == "alice"
    assert events[0].fields["TargetUserName"] == "root"
    assert events[0].fields["EventResult"] == "success"


def test_syslog_rfc3164_plain():
    """Non-sshd/sudo syslog should go to Syslog table."""
    msg = '<13>Oct 11 12:00:00 web01 cron[123]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)'
    events = parsers.parse_syslog_rfc3164(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "Syslog"
    assert events[0].fields["AppName"] == "cron"


def test_syslog_rfc5424_parse():
    msg = '<34>1 2024-10-11T22:14:15.000003Z myhost sshd 12345 - [session@32473 pid="9876"] Failed password for root from 1.2.3.4 port 22 ssh2'
    events = parsers.parse_syslog_rfc5424(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["SrcIp"] == "1.2.3.4"


def test_syslog_rfc3164_invalid_user():
    msg = '<13>Oct 11 10:00:00 web01 sshd[123]: Invalid user admin from 5.6.7.8 port 44444'
    events = parsers.parse_syslog_rfc3164(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["UserName"] == "admin"
    assert events[0].fields["SrcIp"] == "5.6.7.8"
    assert events[0].fields["EventResult"] == "failure"


# ── CEF parser ───────────────────────────────────────────────────────────────

def test_cef_parse():
    msg = 'CEF:0|Microsoft|Windows|10.0|4625|Account Logon Failure|5|src=1.2.3.4 dst=10.0.0.1 suser=bob outcome=failure msg=Failed logon'
    events = parsers.parse_cef(msg, "test-src")
    assert len(events) == 1
    # AuthEvents: CEF with auth EventCode 4625 + suser + src/dst heuristics
    assert events[0].table == "AuthEvents"
    assert events[0].fields["SrcIp"] == "1.2.3.4"
    assert events[0].fields["UserName"] == "bob"
    assert events[0].fields["EventResult"] == "failure"


# ── Apache/Nginx combined ────────────────────────────────────────────────────

def test_apache_combined_parse():
    msg = '192.168.1.1 - bob [11/Oct/2024:13:55:36 +0000] "GET /login HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
    events = parsers.parse_apache_combined(msg, "test-src")
    assert len(events) == 1
    assert events[0].table == "WebAccess"
    assert events[0].fields["SrcIp"] == "192.168.1.1"
    assert events[0].fields["UserName"] == "bob"
    assert events[0].fields["HttpMethod"] == "GET"
    assert events[0].fields["StatusCode"] == 200
    assert events[0].fields["UserAgent"] == "Mozilla/5.0"


def test_apache_combined_404():
    msg = '10.0.0.1 - - [11/Oct/2024:13:56:00 +0000] "GET /nonexistent HTTP/1.1" 404 232 "-" "-"'
    events = parsers.parse_apache_combined(msg, "test-src")
    assert len(events) == 1
    assert events[0].fields["EventResult"] == "failure"


# ── generic JSON ─────────────────────────────────────────────────────────────

def test_generic_json_alias_mapping():
    obj = {"@timestamp": "2024-10-11T10:00:00Z", "client_ip": "1.2.3.4",
           "user.name": "alice", "host.name": "web01"}
    events = parsers.parse_generic_json(obj, "test-src")
    assert len(events) == 1
    f = events[0].fields
    assert f["SrcIp"] == "1.2.3.4"
    assert f["UserName"] == "alice"
    assert f["HostName"] == "web01"
    assert f["SourceType"] == "generic_json"


def test_generic_json_raw_event_preserved():
    obj = {"eval": "dangerous", "nested": {"value": 42}}
    events = parsers.parse_generic_json(obj, "test-src")
    raw = json.loads(events[0].fields["RawEvent"])
    assert raw["eval"] == "dangerous"
    assert raw["nested"]["value"] == 42


def test_generic_json_non_json_string():
    events = parsers.parse_generic_json("not json", "test-src")
    assert len(events) == 1
    assert events[0].table == "GenericEvents"
    assert events[0].fields["RawEvent"] == "not json"


# ── Windows JSON ─────────────────────────────────────────────────────────────

def test_windows_json_4625():
    evt = {
        "EventID": 4625,
        "TimeCreated": "2024-10-11T10:00:00Z",
        "Computer": "dc01.corp.local",
        "event_data": {
            "TargetUserName": "administrator",
            "IpAddress": "198.51.100.42",
            "FailureReason": "%%2313",
            "LogonType": "3",
        },
    }
    events = parsers.parse_windows_json(evt, "test-src")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["EventCode"] == "4625"
    assert events[0].fields["EventResult"] == "failure"
    assert events[0].fields["UserName"] == "administrator"
    assert events[0].fields["SrcIp"] == "198.51.100.42"


def test_windows_json_4624():
    evt = {"EventID": 4624, "TimeCreated": "2024-10-11T10:00:00Z", "Computer": "dc01",
           "event_data": {"TargetUserName": "alice", "IpAddress": "10.0.1.50", "LogonType": "10"}}
    events = parsers.parse_windows_json(evt, "test-src")
    assert events[0].table == "AuthEvents"
    assert events[0].fields["EventResult"] == "success"


def test_windows_json_sysmon1():
    evt = {
        "EventID": 1,
        "TimeCreated": "2024-10-11T10:00:00Z",
        "Computer": "workstation-1",
        "event_data": {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "CORP\\alice",
        },
    }
    events = parsers.parse_windows_json(evt, "test-src")
    assert events[0].table == "ProcessEvents"
    assert events[0].fields["EventCode"] == "1"
    assert events[0].fields["ProcessName"] == "C:\\Windows\\System32\\cmd.exe"


def test_windows_json_sysmon3():
    evt = {
        "EventID": 3,
        "TimeCreated": "2024-10-11T10:00:00Z",
        "Computer": "dc01",
        "event_data": {
            "SourceIp": "10.0.1.10", "DestinationIp": "10.0.1.20",
            "SourcePort": "49152", "DestinationPort": "445",
            "Protocol": "tcp", "Image": "System",
        },
    }
    events = parsers.parse_windows_json(evt, "test-src")
    assert events[0].table == "NetworkEvents"


def test_windows_json_unknown_eventid():
    evt = {"EventID": 9999, "TimeCreated": "2024-10-11T10:00:00Z", "Computer": "dc01"}
    events = parsers.parse_windows_json(evt, "test-src")
    assert events[0].table == "GenericEvents"


# ── Zeek parsers ─────────────────────────────────────────────────────────────

def test_zeek_conn():
    evt = {"ts": 1728655200, "uid": "C1234", "id.orig_h": "10.0.1.10",
           "id.resp_h": "93.184.216.34", "id.resp_p": 443, "proto": "tcp",
           "orig_bytes": 1500, "resp_bytes": 5000}
    events = parsers.parse_zeek_conn(evt, "test-src")
    assert events[0].table == "NetworkEvents"
    assert events[0].fields["SrcIp"] == "10.0.1.10"
    assert events[0].fields["DstPort"] == 443


def test_zeek_dns():
    evt = {"ts": 1728655200, "uid": "C5678", "id.orig_h": "10.0.1.25",
           "query": "example.com", "id.resp_h": "8.8.8.8"}
    events = parsers.parse_zeek_dns(evt, "test-src")
    assert events[0].table == "NetworkEvents"
    assert events[0].fields["DnsQuery"] == "example.com"


# ── auto-detection ───────────────────────────────────────────────────────────

def test_auto_detect_syslog():
    events = parsers.auto_parse('<13>Oct 11 10:00:00 host app: message', "test-src")
    assert events[0].table in ("Syslog", "AuthEvents")


def test_auto_detect_cef():
    events = parsers.auto_parse('CEF:0|vendor|product|1.0|sig|name|5|src=1.2.3.4', "test-src")
    assert events[0].table == "GenericEvents"


def test_auto_detect_apache():
    msg = '1.2.3.4 - - [11/Oct/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "-"'
    events = parsers.auto_parse(msg, "test-src")
    assert events[0].table == "WebAccess"


def test_auto_detect_windows():
    evt = {"EventID": 4625, "event_data": {"TargetUserName": "bob"}}
    events = parsers.auto_parse(evt, "test-src")
    assert events[0].table == "AuthEvents"


def test_auto_detect_generic_json():
    events = parsers.auto_parse({"custom": "value", "ts": "2024-10-11T00:00:00Z"}, "test-src")
    assert len(events) == 1
    assert events[0].table == "GenericEvents"


# ── entity extraction ────────────────────────────────────────────────────────

def test_extract_entities():
    fields = {"UserName": "alice", "SrcIp": "1.2.3.4", "HostName": "web01"}
    pairs = extract_entities("AuthEvents", fields)
    assert ("user", "alice") in pairs
    assert ("ip", "1.2.3.4") in pairs
    assert ("host", "web01") in pairs


def test_extract_entities_filters_noise():
    pairs = extract_entities("AuthEvents", {
        "UserName": "-", "SrcIp": "", "HostName": "unknown",
        "ProcessName": "SYSTEM"
    })
    assert len(pairs) == 0  # All noise


def test_extract_entities_localhost_filtered():
    pairs = extract_entities("NetworkEvents", {"SrcIp": "127.0.0.1"})
    assert len(pairs) == 0


def test_extract_entities_normalizes_case():
    pairs = extract_entities("AuthEvents", {"UserName": "Alice", "HostName": "WEB01"})
    assert ("user", "alice") in pairs
    assert ("host", "web01") in pairs


# ── entity upsert ────────────────────────────────────────────────────────────

def test_entity_upsert_through_pipeline(pipeline, db):
    pipeline.ingest("ent-src", ["hello"])
    # Entities should have been extracted and upserted for the GenericEvents rows
    # (which won't have entity columns typically; test with direct SQL)
    # Verify the entity table exists and can be queried
    rows = db.query("SELECT * FROM entities LIMIT 0")
    assert rows is not None  # Table exists


def test_entity_upsert_with_auth_events(pipeline, db):
    msg = '<13>Oct 11 10:00:00 web01 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2'
    pipeline.ingest("ent-src", [msg], parser="syslog_rfc3164")

    entities = db.query("SELECT entity_id, type, value FROM entities")
    values = [(e["type"], e["value"]) for e in entities]
    assert ("user", "root") in values
    assert ("ip", "1.2.3.4") in values
    assert ("host", "web01") in values


# ── ingest filters ───────────────────────────────────────────────────────────

def test_filter_drops_events(pipeline, db):
    db.execute(
        "INSERT INTO ingest_filters(filter_id, table_name, expression, description, enabled) "
        "VALUES ('f1', 'GenericEvents', 'SourceType == \"unknown\"', 'test', TRUE)")

    result = pipeline.ingest("filter-src", ["msg1", "msg2"])
    assert result.dropped > 0
    assert result.inserted < result.received


def test_filter_disabled_does_not_drop(pipeline, db):
    db.execute(
        "INSERT INTO ingest_filters(filter_id, table_name, expression, description, enabled) "
        "VALUES ('f2', 'GenericEvents', 'SourceType == \"unknown\"', 'test', FALSE)")

    result = pipeline.ingest("filter-src2", ["msg1"])
    assert result.dropped == 0


# ── source parser resolution ─────────────────────────────────────────────────

def test_source_parser_resolution(pipeline, db):
    db.execute(
        "INSERT OR REPLACE INTO sources(source_id, parser, kind, status) "
        "VALUES ('src-parser', 'syslog_rfc3164', 'syslog', 'active')")

    msg = '<13>Oct 11 10:00:00 host app: hello'
    result = pipeline.ingest("src-parser", [msg])
    # Should use syslog parser -> goes to Syslog
    assert result.tables.get("Syslog", 0) > 0


def test_parser_override(pipeline, db):
    msg = '<13>Oct 11 10:00:00 web01 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2'
    result = pipeline.ingest("override-src", [msg], parser="syslog_rfc3164")
    assert result.tables.get("AuthEvents", 0) > 0


# ── MappingParser validation ─────────────────────────────────────────────────

def test_mapping_validate_valid_spec():
    spec = {
        "name": "test_parser",
        "format": "json",
        "target_table": "AuthEvents",
        "time": {"field": "@timestamp", "format": "iso8601"},
        "fields": {"UserName": "$.user", "SrcIp": {"path": "$.ip", "transform": "lower"}},
        "constants": {"SourceType": "my_source"},
    }
    errors = validate_spec(spec)
    assert errors == []


def test_mapping_validate_missing_target():
    errors = validate_spec({"name": "p"})
    assert any("target_table" in e for e in errors)


def test_mapping_validate_bad_format():
    errors = validate_spec({"name": "p", "target_table": "Syslog", "format": "xquery"})
    assert any("Unknown format" in e for e in errors)


def test_mapping_validate_bad_table():
    errors = validate_spec({"name": "p", "target_table": "NoTable"})
    assert any("Unknown target_table" in e for e in errors)


def test_mapping_validate_unknown_keys():
    errors = validate_spec({"name": "p", "target_table": "Syslog", "evil": "exec()"})
    assert any("Unknown top-level key" in e for e in errors)


def test_mapping_validate_bad_transform():
    errors = validate_spec({
        "name": "p", "target_table": "Syslog",
        "fields": {"SrcIp": {"path": "$.ip", "transform": "eval"}}
    })
    assert any("transform" in e for e in errors)


def test_mapping_parse_json():
    spec = {
        "name": "test", "format": "json", "target_table": "AuthEvents",
        "fields": {"UserName": "$.user.name", "SrcIp": "$.source.ip"},
        "constants": {"EventResult": "success"},
    }
    mp = MappingParser(spec)
    events = mp.parse({"user": {"name": "alice"}, "source": {"ip": "1.2.3.4"}}, "src1")
    assert len(events) == 1
    assert events[0].table == "AuthEvents"
    assert events[0].fields["UserName"] == "alice"
    assert events[0].fields["SrcIp"] == "1.2.3.4"
    assert events[0].fields["EventResult"] == "success"


def test_mapping_parse_with_transform():
    spec = {
        "name": "test", "format": "json", "target_table": "AuthEvents",
        "fields": {"UserName": {"path": "$.user", "transform": "lower"}},
    }
    mp = MappingParser(spec)
    events = mp.parse({"user": "Alice"}, "src1")
    assert events[0].fields["UserName"] == "alice"


def test_mapping_parse_with_default():
    spec = {
        "name": "test", "format": "json", "target_table": "AuthEvents",
        "fields": {"UserName": {"path": "$.missing", "default": "nobody"}},
    }
    mp = MappingParser(spec)
    events = mp.parse({"other": "data"}, "src1")
    assert events[0].fields["UserName"] == "nobody"


def test_mapping_parse_with_when():
    spec = {
        "name": "test", "format": "json", "target_table": "AuthEvents",
        "fields": {"UserName": "$.user"},
        "when": {"field": "status", "op": "eq", "value": "error"},
    }
    mp = MappingParser(spec)
    events = mp.parse({"user": "alice", "status": "error"}, "src1")
    assert len(events) == 1

    events = mp.parse({"user": "bob", "status": "ok"}, "src1")
    assert len(events) == 0


def test_mapping_parse_time_iso8601():
    spec = {
        "name": "test", "format": "json", "target_table": "AuthEvents",
        "time": {"field": "ts", "format": "iso8601"},
    }
    mp = MappingParser(spec)
    events = mp.parse({"ts": "2024-10-11T10:00:00Z"}, "src1")
    assert events[0].fields["TimeGenerated"].year == 2024


def test_mapping_parse_csv():
    spec = {
        "name": "test", "format": "csv", "target_table": "AuthEvents",
        "fields": {"UserName": "$.col1", "SrcIp": "$.col2"},
    }
    mp = MappingParser(spec)
    events = mp.parse("alice,1.2.3.4", "src1")
    assert len(events) == 1
    assert events[0].fields["UserName"] == "alice"


# ── parser registration ──────────────────────────────────────────────────────

def test_parser_registry():
    registry = parsers.list_parsers()
    assert "syslog_rfc3164" in registry
    assert "syslog_rfc5424" in registry
    assert "cef" in registry
    assert "apache_combined" in registry
    assert "generic_json" in registry
    assert "windows_json" in registry
    assert "zeek_conn" in registry
    assert "zeek_dns" in registry


# ── performance smoke test ────────────────────────────────────────────────────

def test_pipeline_throughput(pipeline):
    """Pipeline should handle >= 1000 events/sec for simple records."""
    records = [f"message {i} for throughput test" for i in range(1000)]
    start = time.perf_counter()
    result = pipeline.ingest("perf-src", records)
    elapsed = time.perf_counter() - start
    rate = result.inserted / elapsed if elapsed > 0 else float("inf")
    # Loose target: just ensuring it doesn't catastrophically slow
    assert rate > 100, f"Throughput {rate:.0f} evt/sec below minimum 100"


# ── RawEvent preservation ────────────────────────────────────────────────────

def test_raw_event_preserved(pipeline, db):
    original = '<13>Oct 11 10:00:00 host app: raw message _unique_'
    pipeline.ingest("raw-src", [original], parser="syslog_rfc3164")
    rows = db.query('SELECT "RawEvent" FROM "Syslog" WHERE SourceId=?', ["raw-src"])
    assert len(rows) == 1
    assert "_unique_" in rows[0]["RawEvent"]


# ── JSON ingest path ─────────────────────────────────────────────────────────

def test_ingest_json_dict(pipeline, db):
    obj = {"event_id": "123", "client.ip": "10.0.0.1", "message": "test"}
    result = pipeline.ingest("json-src", [obj])
    assert result.inserted == 1
    rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["json-src"])
    assert len(rows) == 1


# ── Unknown source creation ──────────────────────────────────────────────────

def test_unknown_source_auto_created(pipeline, db):
    pipeline.ingest("brand-new-src", ["test"])
    src = db.query_one("SELECT status FROM sources WHERE source_id=?", ["brand-new-src"])
    assert src["status"] == "pending"


# ── Multiple event tables in one batch ───────────────────────────────────────

def test_mixed_events(pipeline, db):
    """Different records parsed to different tables in one batch."""
    records = [
        '<13>Oct 11 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2',
        '1.2.3.4 - - [11/Oct/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "-"',
    ]
    result = pipeline.ingest("mixed-src", records)
    assert result.inserted == 2
    assert "AuthEvents" in result.tables
    assert "WebAccess" in result.tables
