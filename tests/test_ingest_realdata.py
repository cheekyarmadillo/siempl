"""Ingest behavior tests on real DuckDB data.

Motivation: existing ingest tests validate parser output (NormalizedEvent
objects) but do not assert the actual rows after insertion into the DB.
These tests verify end-to-end: parse -> insert -> query -> assert rows.
"""
from __future__ import annotations

import pytest

from siempl.db import Database
from siempl.ingest import IngestPipeline


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


@pytest.fixture
def pipeline(db):
    return IngestPipeline(db)


# ── format: syslog RFC3164 ─────────────────────────────────────────────────

class TestSyslogRfc3164Ingest:
    def test_rfc3164_auth_events_inserted(self, db, pipeline):
        msg = ('<13>Oct 11 10:30:00 web01 sshd[999]: Accepted publickey for alice '
               'from 10.0.1.50 port 54567 ssh2')
        pipeline.ingest("syslog-src", [msg], parser="syslog_rfc3164")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["syslog-src"])
        assert len(rows) == 1
        assert rows[0]["UserName"] == "alice"
        assert rows[0]["EventResult"] == "success"
        assert rows[0]["AuthMethod"] == "ssh"
        assert rows[0]["SrcIp"] == "10.0.1.50"

    def test_rfc3164_multiple_rows(self, db, pipeline):
        msgs = [
            '<13>Oct 11 10:00:00 h1 sshd[1]: Accepted publickey for bob from 1.2.3.4 port 22 ssh2',
            '<13>Oct 11 10:01:00 h2 sshd[2]: Accepted publickey for carol from 5.6.7.8 port 22 ssh2',
        ]
        pipeline.ingest("multi-src", msgs, parser="syslog_rfc3164")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["multi-src"])
        assert len(rows) == 2
        names = {r["UserName"] for r in rows}
        assert names == {"bob", "carol"}

    def test_rfc3164_plain_app_goes_to_syslog(self, db, pipeline):
        msg = '<13>Oct 11 12:00:00 web01 cron[123]: hourly job started'
        pipeline.ingest("cron-src", [msg], parser="syslog_rfc3164")
        rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["cron-src"])
        assert len(rows) == 1
        assert rows[0]["AppName"] == "cron"


# ── format: syslog RFC5424 ──────────────────────────────────────────────────

class TestSyslogRfc5424Ingest:
    def test_rfc5424_inserted(self, db, pipeline):
        msg = ('<34>1 2024-10-11T22:14:15.000003Z myhost sshd 12345 - '
               '[session@32473 pid="9876"] Failed password for invalid user root from 1.2.3.4 port 22 ssh2')
        pipeline.ingest("rfc5424-src", [msg], parser="syslog_rfc5424")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["rfc5424-src"])
        assert len(rows) == 1
        assert rows[0]["UserName"] == "root"
        assert rows[0]["SrcIp"] == "1.2.3.4"


# ── format: CEF ─────────────────────────────────────────────────────────────

class TestCefIngest:
    def test_cef_auth_event_inserted(self, db, pipeline):
        msg = ('CEF:0|Microsoft|Windows|10.0|4625|Account Logon Failure|5|'
               'src=1.2.3.4 dst=10.0.0.1 suser=bob outcome=failure msg=Failed logon')
        pipeline.ingest("cef-src", [msg], parser="cef")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["cef-src"])
        assert len(rows) == 1
        assert rows[0]["UserName"] == "bob"
        assert rows[0]["SrcIp"] == "1.2.3.4"
        assert rows[0]["EventResult"] == "failure"

    def test_cef_network_event_inserted(self, db, pipeline):
        msg = ('CEF:0|Acme|Firewall|2.1|100|Connection allowed|5|'
               'src=10.0.0.5 spt=49500 dst=198.51.100.7 dpt=443 proto=TCP act=allow')
        pipeline.ingest("cef-net-src", [msg], parser="cef")
        rows = db.query('SELECT * FROM "NetworkEvents" WHERE SourceId=?', ["cef-net-src"])
        assert len(rows) == 1
        assert rows[0]["SrcIp"] == "10.0.0.5"
        assert rows[0]["DstIp"] == "198.51.100.7"
        assert rows[0]["DstPort"] == 443

    def test_cef_file_event_inserted(self, db, pipeline):
        msg = ('CEF:0|V|P|1|100|File|3|fname=secret.xlsx fileHash=deadbeef suser=mallory')
        pipeline.ingest("cef-file-src", [msg], parser="cef")
        rows = db.query('SELECT * FROM "FileEvents" WHERE SourceId=?', ["cef-file-src"])
        assert len(rows) == 1
        assert rows[0]["FilePath"] == "secret.xlsx"


# ── format: Apache combined ─────────────────────────────────────────────────

class TestApacheIngest:
    def test_apache_combined_web_access(self, db, pipeline):
        msg = ('192.168.1.1 - bob [11/Oct/2024:13:55:36 +0000] "GET /login HTTP/1.1" '
               '200 1234 "http://example.com" "Mozilla/5.0"')
        pipeline.ingest("apache-src", [msg], parser="apache_combined")
        rows = db.query('SELECT * FROM "WebAccess" WHERE SourceId=?', ["apache-src"])
        assert len(rows) == 1
        assert rows[0]["SrcIp"] == "192.168.1.1"
        assert rows[0]["UserName"] == "bob"
        assert rows[0]["HttpMethod"] == "GET"
        assert rows[0]["StatusCode"] == 200

    def test_apache_404_stored(self, db, pipeline):
        msg = ('10.0.0.1 - - [11/Oct/2024:13:56:00 +0000] "GET /nonexistent HTTP/1.1" '
               '404 232 "-" "-"')
        pipeline.ingest("apache-404-src", [msg], parser="apache_combined")
        rows = db.query('SELECT * FROM "WebAccess" WHERE SourceId=?', ["apache-404-src"])
        assert len(rows) == 1
        assert rows[0]["EventResult"] == "failure"


# ── format: generic JSON ───────────────────────────────────────────────────

class TestGenericJsonIngest:
    def test_generic_json_inserted(self, db, pipeline):
        obj = {"@timestamp": "2024-10-11T10:00:00Z", "client_ip": "1.2.3.4",
               "user.name": "alice", "host.name": "web01"}
        pipeline.ingest("json-src", [obj])
        rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["json-src"])
        assert len(rows) == 1
        assert rows[0]["SrcIp"] == "1.2.3.4"
        assert rows[0]["UserName"] == "alice"
        assert rows[0]["HostName"] == "web01"

    def test_generic_json_multiple_records(self, db, pipeline):
        records = [
            {"@timestamp": "2024-10-11T10:00:00Z", "client_ip": "1.1.1.1"},
            {"@timestamp": "2024-10-11T10:01:00Z", "client_ip": "2.2.2.2"},
        ]
        pipeline.ingest("json-multi-src", records)
        rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["json-multi-src"])
        assert len(rows) == 2
        ips = {r["SrcIp"] for r in rows}
        assert ips == {"1.1.1.1", "2.2.2.2"}


# ── format: Windows JSON ────────────────────────────────────────────────────

class TestWindowsJsonIngest:
    def test_windows_json_4625_inserted(self, db, pipeline):
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
        pipeline.ingest("win-src", [evt], parser="windows_json")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["win-src"])
        assert len(rows) == 1
        assert rows[0]["EventCode"] == "4625"
        assert rows[0]["EventResult"] == "failure"
        assert rows[0]["UserName"] == "administrator"

    def test_windows_json_sysmon1_process_events(self, db, pipeline):
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
        pipeline.ingest("win-proc-src", [evt], parser="windows_json")
        rows = db.query('SELECT * FROM "ProcessEvents" WHERE SourceId=?', ["win-proc-src"])
        assert len(rows) == 1
        assert rows[0]["ProcessName"] == "C:\\Windows\\System32\\cmd.exe"

    def test_windows_json_sysmon3_network(self, db, pipeline):
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
        pipeline.ingest("win-net-src", [evt], parser="windows_json")
        rows = db.query('SELECT * FROM "NetworkEvents" WHERE SourceId=?', ["win-net-src"])
        assert len(rows) == 1
        assert rows[0]["SrcIp"] == "10.0.1.10"
        assert rows[0]["DstPort"] == 445


# ── format: Zeek ────────────────────────────────────────────────────────────

class TestZeekIngest:
    def test_zeek_conn_network(self, db, pipeline):
        evt = {"ts": 1728655200, "uid": "C1234", "id.orig_h": "10.0.1.10",
               "id.resp_h": "93.184.216.34", "id.resp_p": 443, "proto": "tcp",
               "orig_bytes": 1500, "resp_bytes": 5000}
        pipeline.ingest("zeek-src", [evt], parser="zeek_conn")
        rows = db.query('SELECT * FROM "NetworkEvents" WHERE SourceId=?', ["zeek-src"])
        assert len(rows) == 1
        assert rows[0]["SrcIp"] == "10.0.1.10"
        assert rows[0]["DstPort"] == 443

    def test_zeek_dns_network(self, db, pipeline):
        evt = {"ts": 1728655200, "uid": "C5678", "id.orig_h": "10.0.1.25",
               "query": "example.com", "id.resp_h": "8.8.8.8"}
        pipeline.ingest("zeek-dns-src", [evt], parser="zeek_dns")
        rows = db.query('SELECT * FROM "NetworkEvents" WHERE SourceId=?', ["zeek-dns-src"])
        assert len(rows) == 1
        assert rows[0]["DnsQuery"] == "example.com"


# ── auto-detect path ─────────────────────────────────────────────────────────

class TestAutoDetectIngest:
    def test_auto_detect_syslog(self, db, pipeline):
        result = pipeline.ingest("auto-syslog", ['<13>Oct 11 10:00:00 host sshd: hello'], parser="auto")
        assert "Syslog" in result.tables or "AuthEvents" in result.tables
        total = db.query_one('SELECT count(*) AS n FROM "Syslog" WHERE SourceId=?', ["auto-syslog"])
        if total is None or total["n"] == 0:
            total = db.query_one('SELECT count(*) AS n FROM "AuthEvents" WHERE SourceId=?', ["auto-syslog"])
        assert total is not None and total["n"] > 0

    def test_auto_detect_apache(self, db, pipeline):
        msg = '1.2.3.4 - - [11/Oct/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "-"'
        pipeline.ingest("auto-apache", [msg], parser="auto")
        rows = db.query('SELECT * FROM "WebAccess" WHERE SourceId=?', ["auto-apache"])
        assert len(rows) == 1

    def test_auto_detect_windows(self, db, pipeline):
        evt = {"EventID": 4625, "event_data": {"TargetUserName": "bob"},
               "TimeCreated": "2024-10-11T10:00:00Z"}
        pipeline.ingest("auto-win", [evt], parser="auto")
        rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["auto-win"])
        assert len(rows) == 1

    def test_auto_detect_cef(self, db, pipeline):
        msg = 'CEF:0|vendor|product|1.0|sig|name|5|src=1.2.3.4'
        pipeline.ingest("auto-cef", [msg], parser="auto")
        # CEF may go to GenericEvents depending on detect-parser ranking
        total = 0
        for tbl in ("GenericEvents", "AuthEvents", "NetworkEvents"):
            r = db.query_one(f'SELECT count(*) AS n FROM "{tbl}" WHERE SourceId=?', ["auto-cef"])
            if r:
                total += r["n"]
        assert total > 0

    def test_mixed_formats_one_batch(self, db, pipeline):
        records = [
            '<13>Oct 11 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2',
            '1.2.3.4 - - [11/Oct/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "-"',
        ]
        result = pipeline.ingest("mixed-src", records)
        assert result.inserted == 2
        assert "AuthEvents" in result.tables
        assert "WebAccess" in result.tables


# ── entity extraction ───────────────────────────────────────────────────────

class TestEntityExtractionIngest:
    def test_entities_created_from_syslog(self, db, pipeline):
        msg = ('<13>Oct 11 10:00:00 web01 sshd[123]: Failed password for root '
               'from 1.2.3.4 port 22 ssh2')
        pipeline.ingest("ent-src", [msg], parser="syslog_rfc3164")
        entities = db.query("SELECT entity_id, type, value FROM entities")
        values = {(e["type"], e["value"]) for e in entities}
        assert ("user", "root") in values
        assert ("ip", "1.2.3.4") in values
        assert ("host", "web01") in values

    def test_entities_created_from_cef(self, db, pipeline):
        msg = ('CEF:0|MS|Windows|10|4625|Fail|5|src=5.5.5.5 suser=mallory '
               'outcome=failure')
        pipeline.ingest("ent-cef-src", [msg], parser="cef")
        entities = db.query("SELECT type, value FROM entities")
        values = {(e["type"], e["value"]) for e in entities}
        assert ("user", "mallory") in values
        assert ("ip", "5.5.5.5") in values

    def test_entities_created_from_apache(self, db, pipeline):
        # Use a public TEST-NET IP; RFC1918 IPs are filtered as "localhost"
        msg = ('203.0.113.55 - alice [11/Oct/2024:10:00:00 +0000] "GET / HTTP/1.1" '
               '200 123 "-" "Mozilla"')
        pipeline.ingest("ent-apache-src", [msg], parser="apache_combined")
        entities = db.query("SELECT type, value FROM entities")
        values = {(e["type"], e["value"]) for e in entities}
        assert ("user", "alice") in values
        assert ("ip", "203.0.113.55") in values
