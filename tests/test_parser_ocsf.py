"""OCSF parser: class routing, field mapping, Extra preservation, auto-detect, end-to-end ingest + KQL."""
import json

from siempl.db import Database
from siempl.ingest import IngestPipeline, parsers
from siempl.ingest.ocsf import parse_ocsf

T = 1760313600000  # 2025-10-13T00:00:00Z in epoch ms

PROCESS = {
    "class_uid": 1007, "class_name": "Process Activity", "category_uid": 1, "activity_id": 1, "type_uid": 100701,
    "time": T, "severity_id": 3, "status_id": 1, "message": "proc start",
    "metadata": {"version": "1.3.0", "product": {"name": "EDR", "vendor_name": "Acme"}},
    "device": {"hostname": "ws-01", "ip": "10.0.0.5"},
    "actor": {"user": {"name": "alice"}},
    "process": {"pid": 4242, "cmd_line": "powershell -enc SQBFAFgA", "file": {"name": "powershell.exe",
                "path": "C:\\Windows\\System32\\powershell.exe", "hashes": [{"algorithm": "MD5", "value": "m"},
                {"algorithm": "SHA-256", "value": "abc123"}]},
                "parent_process": {"pid": 100, "cmd_line": "winword.exe", "file": {"name": "winword.exe"}}},
}
AUTH_FAIL = {
    "class_uid": 3002, "category_uid": 3, "activity_id": 1, "time": T, "status_id": 2, "status_detail": "bad password",
    "severity_id": 2, "src_endpoint": {"ip": "203.0.113.9", "port": 51000}, "dst_endpoint": {"ip": "10.0.0.2", "hostname": "dc1"},
    "user": {"name": "bob"}, "logon_type_id": 3, "auth_protocol": "Kerberos", "metadata": {"version": "1.3.0"},
}
NETWORK = {
    "class_uid": 4001, "category_uid": 4, "activity_id": 6, "time": T, "status_id": 1,
    "src_endpoint": {"ip": "10.0.0.5", "port": 49500}, "dst_endpoint": {"ip": "198.51.100.7", "port": 443},
    "connection_info": {"protocol_name": "TCP", "direction_id": 2}, "traffic": {"bytes_in": 100, "bytes_out": 2000},
    "actor": {"process": {"pid": 77, "name": "curl", "file": {"path": "/usr/bin/curl"}}}, "metadata": {"version": "1.3.0"},
}
HTTP = {
    "class_uid": 4002, "category_uid": 4, "activity_id": 3, "time": T, "status_id": 1,
    "src_endpoint": {"ip": "192.0.2.10"}, "dst_endpoint": {"ip": "10.0.0.9", "hostname": "web1"},
    "http_request": {"http_method": "post", "url": {"url_string": "https://web1/login?x=1", "path": "/login"},
                     "user_agent": "curl/8", "referrer": "https://r"},
    "http_response": {"code": 401, "length": 321}, "metadata": {"version": "1.3.0"},
}
DNS = {
    "class_uid": 4003, "category_uid": 4, "activity_id": 1, "time": T, "src_endpoint": {"ip": "10.0.0.5"},
    "query": {"hostname": "evil.example.com", "type": "A"}, "metadata": {"version": "1.3.0"},
}
FILE = {
    "class_uid": 1001, "category_uid": 1, "activity_id": 4, "time": T, "status_id": 1, "device": {"hostname": "srv"},
    "file": {"name": "secrets.xlsx", "path": "/home/a/secrets.xlsx", "hashes": [{"algorithm": "SHA-1", "value": "sha1v"}]},
    "actor": {"user": {"name": "mallory"}, "process": {"pid": 9, "name": "rm", "cmd_line": "rm secrets.xlsx"}},
}
FINDING = {"class_uid": 2004, "category_uid": 2, "activity_id": 1, "time": T, "severity_id": 4,
           "finding_info": {"title": "Suspicious thing"}, "metadata": {"version": "1.3.0"}}


def one(raw):
    out = parse_ocsf(raw, "src")
    assert len(out) == 1
    return out[0]


def test_process_activity():
    e = one(PROCESS)
    f = e.fields
    assert e.table == "ProcessEvents" and f["EventCode"] == "1007" and f["EventAction"] == "process_start"
    assert f["HostName"] == "ws-01" and f["UserName"] == "alice" and f["EventResult"] == "success"
    assert f["ProcessName"] == "powershell.exe" and f["ProcessId"] == 4242
    assert f["ProcessPath"].endswith("powershell.exe") and f["ProcessCmdLine"].startswith("powershell -enc")
    assert f["FileHash"] == "abc123"          # sha256 preferred over md5
    assert f["ParentProcessName"] == "winword.exe" and f["ParentProcessId"] == 100
    assert f["TimeGenerated"].year == 2025 and f["TimeGenerated"].tzinfo is None
    assert f["Extra"]["severity"] == "medium" and f["Extra"]["metadata"]["product"]["vendor_name"] == "Acme"


def test_authentication_failure():
    e = one(AUTH_FAIL)
    f = e.fields
    assert e.table == "AuthEvents" and f["EventAction"] == "login" and f["EventResult"] == "failure"
    assert f["SrcIp"] == "203.0.113.9" and f["SrcPort"] == 51000 and f["DstIp"] == "10.0.0.2"
    assert f["UserName"] == "bob" and f["LogonType"] == "3" and f["AuthMethod"] == "Kerberos"
    assert f["FailureReason"] == "bad password"


def test_network_activity_with_process_context():
    e = one(NETWORK)
    f = e.fields
    assert e.table == "NetworkEvents" and f["DstPort"] == 443 and f["Protocol"] == "tcp"
    assert f["Direction"] == "outbound" and f["BytesIn"] == 100 and f["BytesOut"] == 2000
    assert f["ProcessName"] == "curl" and f["ProcessId"] == 77 and f["ProcessPath"] == "/usr/bin/curl"


def test_http_activity():
    e = one(HTTP)
    f = e.fields
    assert e.table == "WebAccess" and f["HttpMethod"] == "POST" and f["StatusCode"] == 401 and f["Bytes"] == 321
    assert f["UrlPath"] == "/login" and f["Url"].startswith("https://web1/login") and f["UserAgent"] == "curl/8"


def test_dns_and_file_and_unknown_class():
    d = one(DNS)
    assert d.table == "NetworkEvents" and d.fields["DnsQuery"] == "evil.example.com" and d.fields["EventAction"] == "dns_query"
    fl = one(FILE)
    assert fl.table == "FileEvents" and fl.fields["FilePath"] == "/home/a/secrets.xlsx" and fl.fields["FileName"] == "secrets.xlsx"
    assert fl.fields["EventAction"] == "file_delete" and fl.fields["Operation"] == "file_delete"
    assert fl.fields["FileHash"] == "sha1v" and fl.fields["UserName"] == "mallory" and fl.fields["ProcessName"] == "rm"
    g = one(FINDING)
    assert g.table == "GenericEvents" and g.fields["Extra"]["finding_info"]["title"] == "Suspicious thing"
    assert g.fields["Extra"]["severity"] == "high"


def test_timestamp_variants_and_bad_json():
    assert one({**FINDING, "time": 1760313600}).fields["TimeGenerated"].year == 2025        # seconds
    assert one({**FINDING, "time": "2025-10-13T00:00:00Z"}).fields["TimeGenerated"].year == 2025
    bad = parse_ocsf("not json", "s")
    assert bad[0].table == "GenericEvents"


def test_array_and_autodetect():
    arr = json.dumps([PROCESS, AUTH_FAIL])
    out = parsers.auto_parse(arr, "s")
    assert [e.table for e in out] == ["ProcessEvents", "AuthEvents"]
    assert parsers.auto_parse(json.dumps(NETWORK), "s")[0].table == "NetworkEvents"
    assert "ocsf" in parsers.list_parsers()
    # plain JSON that is not OCSF still goes to generic_json
    assert parsers.auto_parse(json.dumps({"hello": "world"}), "s")[0].table == "GenericEvents"
    # windows-style JSON is not hijacked
    assert parsers.auto_parse(json.dumps({"EventID": 4688, "Channel": "Security"}), "s")[0].fields["SourceType"] != "ocsf"


def test_end_to_end_ingest_and_query(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    db.execute("INSERT INTO sources(source_id,name,kind,parser,target_table,status) VALUES ('o','o','http','auto','GenericEvents','active')")
    res = IngestPipeline(db).ingest("o", [json.dumps(x) for x in (PROCESS, AUTH_FAIL, NETWORK, HTTP, DNS, FILE, FINDING)])
    assert res.inserted == 7 and res.failed == 0
    from siempl.kql import run_kql
    r = run_kql(db, "AuthEvents | where EventResult == 'failure' | project UserName, SrcIp, FailureReason", origin="user", log=False)
    assert r.rows == [["bob", "203.0.113.9", "bad password"]]
    r = run_kql(db, "ProcessEvents | where ProcessName == 'powershell.exe' | project HostName, ParentProcessName", origin="user", log=False)
    assert r.rows == [["ws-01", "winword.exe"]]
    # unmapped OCSF attributes are reachable through Extra
    row = db.query_one("SELECT Extra->>'severity' sev, Extra->'metadata'->'product'->>'vendor_name' v FROM ProcessEvents")
    assert row["sev"] == "medium" and row["v"] == "Acme"
    # entity extraction worked for ocsf-derived rows
    assert db.query_one("SELECT count(*) c FROM entities WHERE value IN ('alice','203.0.113.9','ws-01')")["c"] >= 3
