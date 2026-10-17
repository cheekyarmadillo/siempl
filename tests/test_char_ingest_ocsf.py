"""Golden-master characterization tests for siempl.ingest.ocsf._one.

These tests capture the exact current behavior BEFORE any refactoring.
If a refactoring changes output, the characterization test fails immediately.
"""
from __future__ import annotations

import datetime as _dt
import json
import time

import pytest

from siempl.ingest import ocsf as ocsf_module
from siempl.ingest.ocsf import _one, parse_ocsf

T = 1760313600000  # 2025-10-13T00:00:00Z in epoch ms


def _norm(evt):
    """Convert to serializable dict for golden-master comparison."""
    return {"table": evt.table, "fields": {k: str(v) if v is not None else None for k, v in evt.fields.items()}}


def test_char_ocsf_process():
    obj = {
        "class_uid": 1007, "class_name": "Process Activity", "category_uid": 1, "activity_id": 1, "type_uid": 100701,
        "time": T, "severity_id": 3, "status_id": 1, "message": "proc start",
        "metadata": {"version": "1.3.0", "product": {"name": "EDR", "vendor_name": "Acme"}},
        "device": {"hostname": "ws-01", "ip": "10.0.0.5"},
        "actor": {"user": {"name": "alice"}},
        "process": {"pid": 4242, "cmd_line": "powershell -enc SQBFAUgA", "file": {"name": "powershell.exe",
                    "path": "C:\\Windows\\System32\\powershell.exe", "hashes": [{"algorithm": "MD5", "value": "m"},
                    {"algorithm": "SHA-256", "value": "abc123"}]},
                    "parent_process": {"pid": 100, "cmd_line": "winword.exe", "file": {"name": "winword.exe"}}},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "ProcessEvents"
    assert evt.fields["ProcessName"] == "powershell.exe"
    assert evt.fields["ProcessId"] == 4242
    assert evt.fields["FileHash"] == "abc123"
    assert evt.fields["ParentProcessName"] == "winword.exe"
    assert evt.fields["ParentProcessId"] == 100
    assert "IntegrityLevel" not in evt.fields
    assert evt.fields["UserName"] == "alice"


def test_char_ocsf_auth_failure():
    obj = {
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "time": T, "status_id": 2, "status_detail": "bad password",
        "severity_id": 2, "src_endpoint": {"ip": "203.0.113.9", "port": 51000}, "dst_endpoint": {"ip": "10.0.0.2", "hostname": "dc1"},
        "user": {"name": "bob"}, "logon_type_id": 3, "auth_protocol": "Kerberos", "metadata": {"version": "1.3.0"},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "AuthEvents"
    assert evt.fields["UserName"] == "bob"
    assert evt.fields["TargetUserName"] == "bob"
    assert evt.fields["SrcIp"] == "203.0.113.9"
    assert evt.fields["SrcPort"] == 51000
    assert evt.fields["DstIp"] == "10.0.0.2"
    assert "DstPort" not in evt.fields
    assert evt.fields["LogonType"] == "3"
    assert evt.fields["AuthMethod"] == "Kerberos"
    assert evt.fields["FailureReason"] == "bad password"


def test_char_ocsf_network():
    obj = {
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "time": T, "status_id": 1,
        "src_endpoint": {"ip": "10.0.0.5", "port": 49500}, "dst_endpoint": {"ip": "198.51.100.7", "port": 443},
        "connection_info": {"protocol_name": "TCP", "direction_id": 2}, "traffic": {"bytes_in": 100, "bytes_out": 2000},
        "actor": {"process": {"pid": 77, "name": "curl", "file": {"path": "/usr/bin/curl"}}}, "metadata": {"version": "1.3.0"},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "NetworkEvents"
    assert evt.fields["Protocol"] == "tcp"
    assert evt.fields["Direction"] == "outbound"
    assert evt.fields["BytesIn"] == 100
    assert evt.fields["BytesOut"] == 2000
    assert evt.fields["ProcessName"] == "curl"
    assert evt.fields["ProcessId"] == 77
    assert evt.fields["ProcessPath"] == "/usr/bin/curl"


def test_char_ocsf_http():
    obj = {
        "class_uid": 4002, "category_uid": 4, "activity_id": 3, "time": T, "status_id": 1,
        "src_endpoint": {"ip": "192.0.2.10"}, "dst_endpoint": {"ip": "10.0.0.9", "hostname": "web1"},
        "http_request": {"http_method": "post", "url": {"url_string": "https://web1/login?x=1", "path": "/login"},
                         "user_agent": "curl/8", "referrer": "https://r"},
        "http_response": {"code": 401, "length": 321}, "metadata": {"version": "1.3.0"},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "WebAccess"
    assert evt.fields["HttpMethod"] == "POST"
    assert evt.fields["Url"] == "https://web1/login?x=1"
    assert evt.fields["UrlPath"] == "/login"
    assert evt.fields["StatusCode"] == 401
    assert evt.fields["Bytes"] == 321
    assert evt.fields["EventAction"] == "request"


def test_char_ocsf_dns():
    obj = {
        "class_uid": 4003, "category_uid": 4, "activity_id": 1, "time": T, "src_endpoint": {"ip": "10.0.0.5"},
        "query": {"hostname": "evil.example.com", "type": "A"}, "metadata": {"version": "1.3.0"},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "NetworkEvents"
    assert evt.fields["DnsQuery"] == "evil.example.com"
    assert evt.fields["Domain"] == "evil.example.com"


def test_char_ocsf_file():
    obj = {
        "class_uid": 1001, "category_uid": 1, "activity_id": 4, "time": T, "status_id": 1, "device": {"hostname": "srv"},
        "file": {"name": "secrets.xlsx", "path": "/home/a/secrets.xlsx", "hashes": [{"algorithm": "SHA-1", "value": "sha1v"}]},
        "actor": {"user": {"name": "mallory"}, "process": {"pid": 9, "name": "rm", "cmd_line": "rm secrets.xlsx"}},
    }
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "FileEvents"
    assert evt.fields["FilePath"] == "/home/a/secrets.xlsx"
    assert evt.fields["FileName"] == "secrets.xlsx"
    assert evt.fields["FileHash"] == "sha1v"
    assert evt.fields["Operation"] == "file_delete"
    assert evt.fields["ProcessName"] == "rm"


def test_char_ocsf_unknown_class():
    obj = {"class_uid": 2004, "category_uid": 2, "activity_id": 1, "time": T, "severity_id": 4,
           "finding_info": {"title": "Suspicious thing"}, "metadata": {"version": "1.3.0"}}
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "GenericEvents"
    assert evt.fields["EventCode"] == "2004"
    assert evt.fields["Extra"]["finding_info"]["title"] == "Suspicious thing"
    assert evt.fields["Extra"]["severity"] == "high"


def test_char_ocsf_missing_fields():
    """Edge case: minimal object with only class_uid."""
    obj = {"class_uid": 1007, "time": T}
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "ProcessEvents"
    assert evt.fields["EventAction"] == ""
    assert evt.fields["EventResult"] == "unknown"


def test_char_ocsf_unicode():
    obj = {"class_uid": 3002, "time": T, "user": {"name": "用户名"}, "message": "失败"}
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.fields["UserName"] == "用户名"
    assert evt.fields["Message"] == "失败"


def test_char_ocsf_malformed_process():
    """Edge case: process field is not a dict."""
    obj = {"class_uid": 1007, "time": T, "process": "not_a_dict"}
    evt = _one(obj, "src", json.dumps(obj))
    assert evt.table == "ProcessEvents"
    assert "ProcessName" not in evt.fields


# ---------------------------------------------------------------------------
# Golden-master table over the public parse_ocsf entry point. Covers every table branch of _one
# (ProcessEvents, FileEvents, AuthEvents, NetworkEvents, WebAccess, generic with/without process),
# class/category routing fallbacks, time coercion and the raw-text fallbacks.
# GOLDEN was captured from the code BEFORE the _one refactor. Do not hand-edit to make it pass.
# ---------------------------------------------------------------------------

FIXED_NOW = _dt.datetime(2026, 1, 2, 3, 4, 5)

GOLDEN_CASES: dict[str, object] = {
    "process_parent_integrity_hash": {
        "class_uid": 1007, "category_uid": 1, "activity_id": 2, "time": T, "status_id": 1,
        "process": {"pid": 7, "name": "sh", "integrity": "High", "cmd_line": "sh -c x",
                    "file": {"path": "/bin/sh", "hashes": [{"algorithm": "MD5", "value": "m5"}, "junk",
                                                          {"algorithm": "sha1", "value": "s1"}]},
                    "user": {"name": "root"},
                    "parent_process": {"pid": "abc", "name": "init", "file": {"path": "/sbin/init"}}},
    },
    "process_user_from_process_when_actor_missing": {
        "class_uid": 1007, "activity_id": 4, "time": T, "process": {"pid": "12", "file": {"name": "inj.exe"}},
        "actor": {"process": {"name": "ignored"}}, "device": {"name": "host-b"},
    },
    "process_activity_name_fallback": {
        "class_uid": 1007, "activity_id": 99, "activity_name": "Custom Thing  Here", "time": T,
        "process": {"name": "x.exe"},
    },
    "process_no_activity_at_all": {"class_uid": 1007, "time": T, "severity_id": 9, "message": None},
    "file_hash_preference_and_path_only": {
        "class_uid": 1001, "activity_id": 3, "time": T, "status_id": 2,
        "file": {"path": "C:\\Users\\a\\doc.txt",
                 "hashes": [{"algorithm": "md5", "value": "m"}, {"algorithm": "weird", "value": "w"},
                            {"algorithm": "SHA256", "value": "sha"}, {"algorithm": "sha-1", "value": None}]},
        "actor": {"process": {"name": "word.exe", "pid": 3, "cmd_line": "word"}},
    },
    "file_name_only_no_hashes": {
        "class_uid": 1001, "activity_id": 5, "time": T, "file": {"name": "report.pdf"},
        "process": {"file": {"path": "/opt/app/bin"}},
    },
    "auth_success_no_failure_reason": {
        "class_uid": 3002, "activity_id": 1, "time": T, "status_id": 1, "status_detail": "should be ignored",
        "logon_type": "Network", "auth_protocol_id": 2, "src_endpoint": {"ip": "10.1.1.1"},
        "dst_user": {"name": "svc-x"},
    },
    "auth_failure_status_string_and_code": {
        "class_uid": 3002, "time": T, "status": "Denied", "status_code": 401, "user": {"name": "eve"},
        "logon_type_id": 10,
    },
    "auth_failure_no_reason_fields": {"class_uid": 3001, "time": T, "status_id": 2, "activity_id": 9},
    "network_protocol_num_and_textual_direction": {
        "class_uid": 4001, "activity_id": 7, "time": T, "connection_info": {"protocol_num": 6, "direction": "Inbound"},
        "traffic": {"bytes_in": "5", "bytes_out": None}, "dst_endpoint": {"hostname": "api.example", "port": "x"},
    },
    "network_direction_id_lateral_and_unknown": {
        "class_uid": 4005, "time": T, "connection_info": {"protocol_name": "UDP", "direction_id": 3},
        "src_endpoint": {"ip": "10.0.0.1", "port": 53},
    },
    "network_direction_unknown_number": {
        "class_uid": 4006, "time": T, "connection_info": {"direction_id": 9, "protocol_name": "ICMP"},
    },
    "network_domain_from_dst_hostname": {
        "class_uid": 4007, "time": T, "dst_endpoint": {"hostname": "cdn.example.net"},
        "src_endpoint": {"hostname": "ws9"}, "traffic": {"bytes_out": 77},
    },
    "http_path_only_and_zero_length": {
        "class_uid": 4002, "activity_id": 9, "time": T, "http_request": {"url": {"path": "/a/b"}},
        "http_response": {"code": "200", "length": 0}, "traffic": {"bytes_out": 512},
        "http_response_extra": None,
    },
    "http_non_dict_request_and_response": {
        "class_uid": 4002, "activity_id": 2, "time": T, "http_request": "GET /", "http_response": None,
        "http_method": "get",
    },
    "generic_finding_with_process_context": {
        "class_uid": 2004, "category_uid": 2, "activity_id": 1, "time": T, "severity_id": 0,
        "actor": {"process": {"name": "scanner", "cmd_line": "scan --all", "pid": 11}},
        "finding_info": {"title": "x"},
    },
    "generic_no_process_context": {"class_uid": 6001, "category_uid": 6, "time": T, "message": "api call"},
    "category_fallback_file_auth_network": {"class_uid": 9999, "category_uid": 1, "time": T},
    "category_fallback_auth": {"class_uid": 9998, "category_uid": 3, "time": T},
    "category_fallback_network": {"class_uid": 4999, "category_uid": 4, "time": T},
    "class_uid_missing_category_only": {"category_uid": 3, "time": T, "user": {"name": "u"}},
    "time_float_seconds": {"class_uid": 1007, "time": 1760313600.5},
    "time_iso_with_offset": {"class_uid": 1007, "time": "2025-10-13T02:00:00+02:00"},
    "time_iso_naive": {"class_uid": 1007, "time": "2025-10-13T00:00:00"},
    "time_numeric_string": {"class_uid": 1007, "time": "1760313600000"},
    "time_garbage_string": {"class_uid": 1007, "time": "xyz"},
    "time_bool_and_none": {"class_uid": 1007, "time": True},
    "time_fallback_to_start_time": {"class_uid": 1007, "start_time": T, "time": None},
    "time_zero_and_empty": {"class_uid": 1007, "time": 0},
    "time_empty_string": {"class_uid": 1007, "time": ""},
    "time_overflow": {"class_uid": 1007, "time": 1e20},
    "severity_names_and_extras": {
        "class_uid": 3002, "time": T, "severity_id": 6, "logon_type": "Interactive", "status_code": 0,
        "auth_protocol": "NTLM", "unmapped_key": {"a": [1, 2]}, "http_request": "not-a-dict",
    },
    "severity_unknown_number": {"class_uid": 2004, "time": T, "severity_id": 42, "status": "ok"},
    "unicode_message_and_user": {"class_uid": 3002, "time": T, "user": {"name": "ü"}, "message": "失败"},
    "message_from_metadata_event_code": {
        "class_uid": 2004, "time": T, "metadata": {"event_code": "EC-1", "version": "1.3.0"},
    },
    "parse_ocsf_invalid_json_string": "{broken json",
    "parse_ocsf_json_string_object": json.dumps({"class_uid": 3002, "time": T, "status_id": 2, "user": {"name": "z"}}),
    "parse_ocsf_list_skips_non_dict": [{"class_uid": 1007, "time": T}, "junk", {"class_uid": 4003, "time": T}],
    "parse_ocsf_scalar_input": 7,
}

# ---- GOLDEN ----
GOLDEN_OCSF: dict[str, object] = {'process_parent_integrity_hash': [{'table': 'ProcessEvents',
                                    'fields': [('TimeGenerated',
                                                'datetime',
                                                'datetime.datetime(2025, 10, 13, 0, 0)'),
                                               ('SourceId', 'str', "'src1'"),
                                               ('SourceType', 'str', "'ocsf'"),
                                               ('EventCode', 'str', "'1007'"),
                                               ('EventAction', 'str', "'process_terminate'"),
                                               ('EventResult', 'str', "'success'"),
                                               ('UserName', 'str', "'root'"),
                                               ('Message', 'str', "''"),
                                               ('RawEvent',
                                                'str',
                                                '\'{"class_uid": 1007, "category_uid": 1, "activity_id": 2, '
                                                '"time": 1760313600000, "status_id": 1, "process": {"pid": '
                                                '7, "name": "sh", "integrity": "High", "cmd_line": "sh -c '
                                                'x", "file": {"path": "/bin/sh", "hashes": [{"algorithm": '
                                                '"MD5", "value": "m5"}, "junk", {"algorithm": "sha1", '
                                                '"value": "s1"}]}, "user": {"name": "root"}, '
                                                '"parent_process": {"pid": "abc", "name": "init", "file": '
                                                '{"path": "/sbin/init"}}}}\''),
                                               ('ProcessName', 'str', "'sh'"),
                                               ('ProcessCmdLine', 'str', "'sh -c x'"),
                                               ('ProcessPath', 'str', "'/bin/sh'"),
                                               ('ProcessId', 'int', '7'),
                                               ('FileHash', 'str', "'s1'"),
                                               ('ParentProcessName', 'str', "'init'"),
                                               ('IntegrityLevel', 'str', "'High'"),
                                               ('Extra',
                                                'dict',
                                                "{'class_uid': 1007, 'category_uid': 1, 'process': {'pid': "
                                                "7, 'name': 'sh', 'integrity': 'High', 'cmd_line': 'sh -c "
                                                "x', 'file': {'path': '/bin/sh', 'hashes': [{'algorithm': "
                                                "'MD5', 'value': 'm5'}, 'junk', {'algorithm': 'sha1', "
                                                "'value': 's1'}]}, 'user': {'name': 'root'}, "
                                                "'parent_process': {'pid': 'abc', 'name': 'init', 'file': "
                                                "{'path': '/sbin/init'}}}}")]}],
 'process_user_from_process_when_actor_missing': [{'table': 'ProcessEvents',
                                                   'fields': [('TimeGenerated',
                                                               'datetime',
                                                               'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                              ('SourceId', 'str', "'src1'"),
                                                              ('SourceType', 'str', "'ocsf'"),
                                                              ('EventCode', 'str', "'1007'"),
                                                              ('EventAction', 'str', "'process_inject'"),
                                                              ('EventResult', 'str', "'unknown'"),
                                                              ('HostName', 'str', "'host-b'"),
                                                              ('Message', 'str', "''"),
                                                              ('RawEvent',
                                                               'str',
                                                               '\'{"class_uid": 1007, "activity_id": 4, '
                                                               '"time": 1760313600000, "process": {"pid": '
                                                               '"12", "file": {"name": "inj.exe"}}, "actor": '
                                                               '{"process": {"name": "ignored"}}, "device": '
                                                               '{"name": "host-b"}}\''),
                                                              ('ProcessName', 'str', "'inj.exe'"),
                                                              ('ProcessPath', 'str', "'inj.exe'"),
                                                              ('ProcessId', 'int', '12'),
                                                              ('Extra',
                                                               'dict',
                                                               "{'class_uid': 1007, 'actor': {'process': "
                                                               "{'name': 'ignored'}}, 'device': {'name': "
                                                               "'host-b'}, 'process': {'pid': '12', 'file': "
                                                               "{'name': 'inj.exe'}}}")]}],
 'process_activity_name_fallback': [{'table': 'ProcessEvents',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('EventCode', 'str', "'1007'"),
                                                ('EventAction', 'str', "'custom_thing__here'"),
                                                ('EventResult', 'str', "'unknown'"),
                                                ('Message', 'str', "'Custom Thing  Here'"),
                                                ('RawEvent',
                                                 'str',
                                                 '\'{"class_uid": 1007, "activity_id": 99, "activity_name": '
                                                 '"Custom Thing  Here", "time": 1760313600000, "process": '
                                                 '{"name": "x.exe"}}\''),
                                                ('ProcessName', 'str', "'x.exe'"),
                                                ('Extra',
                                                 'dict',
                                                 "{'class_uid': 1007, 'process': {'name': 'x.exe'}}")]}],
 'process_no_activity_at_all': [{'table': 'ProcessEvents',
                                 'fields': [('TimeGenerated',
                                             'datetime',
                                             'datetime.datetime(2025, 10, 13, 0, 0)'),
                                            ('SourceId', 'str', "'src1'"),
                                            ('SourceType', 'str', "'ocsf'"),
                                            ('EventCode', 'str', "'1007'"),
                                            ('EventAction', 'str', "''"),
                                            ('EventResult', 'str', "'unknown'"),
                                            ('Message', 'str', "''"),
                                            ('RawEvent',
                                             'str',
                                             '\'{"class_uid": 1007, "time": 1760313600000, "severity_id": 9, '
                                             '"message": null}\''),
                                            ('Extra',
                                             'dict',
                                             "{'class_uid': 1007, 'severity_id': 9, 'severity': '9'}")]}],
 'file_hash_preference_and_path_only': [{'table': 'FileEvents',
                                         'fields': [('TimeGenerated',
                                                     'datetime',
                                                     'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                    ('SourceId', 'str', "'src1'"),
                                                    ('SourceType', 'str', "'ocsf'"),
                                                    ('EventCode', 'str', "'1001'"),
                                                    ('EventAction', 'str', "'file_update'"),
                                                    ('EventResult', 'str', "'failure'"),
                                                    ('Message', 'str', "''"),
                                                    ('RawEvent',
                                                     'str',
                                                     '\'{"class_uid": 1001, "activity_id": 3, "time": '
                                                     '1760313600000, "status_id": 2, "file": {"path": '
                                                     '"C:\\\\\\\\Users\\\\\\\\a\\\\\\\\doc.txt", "hashes": '
                                                     '[{"algorithm": "md5", "value": "m"}, {"algorithm": '
                                                     '"weird", "value": "w"}, {"algorithm": "SHA256", '
                                                     '"value": "sha"}, {"algorithm": "sha-1", "value": '
                                                     'null}]}, "actor": {"process": {"name": "word.exe", '
                                                     '"pid": 3, "cmd_line": "word"}}}\''),
                                                    ('FilePath', 'str', "'C:\\\\Users\\\\a\\\\doc.txt'"),
                                                    ('FileName', 'str', "'doc.txt'"),
                                                    ('FileHash', 'str', "'sha'"),
                                                    ('Operation', 'str', "'file_update'"),
                                                    ('ProcessName', 'str', "'word.exe'"),
                                                    ('ProcessCmdLine', 'str', "'word'"),
                                                    ('ProcessId', 'int', '3'),
                                                    ('Extra',
                                                     'dict',
                                                     "{'class_uid': 1001, 'actor': {'process': {'name': "
                                                     "'word.exe', 'pid': 3, 'cmd_line': 'word'}}, 'file': "
                                                     "{'path': 'C:\\\\Users\\\\a\\\\doc.txt', 'hashes': "
                                                     "[{'algorithm': 'md5', 'value': 'm'}, {'algorithm': "
                                                     "'weird', 'value': 'w'}, {'algorithm': 'SHA256', "
                                                     "'value': 'sha'}, {'algorithm': 'sha-1', 'value': "
                                                     'None}]}}')]}],
 'file_name_only_no_hashes': [{'table': 'FileEvents',
                               'fields': [('TimeGenerated',
                                           'datetime',
                                           'datetime.datetime(2025, 10, 13, 0, 0)'),
                                          ('SourceId', 'str', "'src1'"),
                                          ('SourceType', 'str', "'ocsf'"),
                                          ('EventCode', 'str', "'1001'"),
                                          ('EventAction', 'str', "'file_rename'"),
                                          ('EventResult', 'str', "'unknown'"),
                                          ('Message', 'str', "''"),
                                          ('RawEvent',
                                           'str',
                                           '\'{"class_uid": 1001, "activity_id": 5, "time": 1760313600000, '
                                           '"file": {"name": "report.pdf"}, "process": {"file": {"path": '
                                           '"/opt/app/bin"}}}\''),
                                          ('FilePath', 'str', "'report.pdf'"),
                                          ('FileName', 'str', "'report.pdf'"),
                                          ('Operation', 'str', "'file_rename'"),
                                          ('ProcessName', 'str', "'bin'"),
                                          ('ProcessPath', 'str', "'/opt/app/bin'"),
                                          ('Extra',
                                           'dict',
                                           "{'class_uid': 1001, 'file': {'name': 'report.pdf'}, 'process': "
                                           "{'file': {'path': '/opt/app/bin'}}}")]}],
 'auth_success_no_failure_reason': [{'table': 'AuthEvents',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('EventCode', 'str', "'3002'"),
                                                ('EventAction', 'str', "'login'"),
                                                ('EventResult', 'str', "'success'"),
                                                ('SrcIp', 'str', "'10.1.1.1'"),
                                                ('Message', 'str', "''"),
                                                ('RawEvent',
                                                 'str',
                                                 '\'{"class_uid": 3002, "activity_id": 1, "time": '
                                                 '1760313600000, "status_id": 1, "status_detail": "should be '
                                                 'ignored", "logon_type": "Network", "auth_protocol_id": 2, '
                                                 '"src_endpoint": {"ip": "10.1.1.1"}, "dst_user": {"name": '
                                                 '"svc-x"}}\''),
                                                ('TargetUserName', 'str', "'svc-x'"),
                                                ('LogonType', 'str', "'Network'"),
                                                ('AuthMethod', 'str', "'2'"),
                                                ('Extra',
                                                 'dict',
                                                 "{'class_uid': 3002, 'src_endpoint': {'ip': '10.1.1.1'}, "
                                                 "'logon_type': 'Network', 'status_detail': 'should be "
                                                 "ignored'}")]}],
 'auth_failure_status_string_and_code': [{'table': 'AuthEvents',
                                          'fields': [('TimeGenerated',
                                                      'datetime',
                                                      'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                     ('SourceId', 'str', "'src1'"),
                                                     ('SourceType', 'str', "'ocsf'"),
                                                     ('EventCode', 'str', "'3002'"),
                                                     ('EventAction', 'str', "''"),
                                                     ('EventResult', 'str', "'failure'"),
                                                     ('UserName', 'str', "'eve'"),
                                                     ('Message', 'str', "''"),
                                                     ('RawEvent',
                                                      'str',
                                                      '\'{"class_uid": 3002, "time": 1760313600000, '
                                                      '"status": "Denied", "status_code": 401, "user": '
                                                      '{"name": "eve"}, "logon_type_id": 10}\''),
                                                     ('TargetUserName', 'str', "'eve'"),
                                                     ('LogonType', 'str', "'10'"),
                                                     ('FailureReason', 'str', "'401'"),
                                                     ('Extra',
                                                      'dict',
                                                      "{'class_uid': 3002, 'logon_type_id': 10, "
                                                      "'status_code': 401}")]}],
 'auth_failure_no_reason_fields': [{'table': 'AuthEvents',
                                    'fields': [('TimeGenerated',
                                                'datetime',
                                                'datetime.datetime(2025, 10, 13, 0, 0)'),
                                               ('SourceId', 'str', "'src1'"),
                                               ('SourceType', 'str', "'ocsf'"),
                                               ('EventCode', 'str', "'3001'"),
                                               ('EventAction', 'str', "'account_lock'"),
                                               ('EventResult', 'str', "'failure'"),
                                               ('Message', 'str', "''"),
                                               ('RawEvent',
                                                'str',
                                                '\'{"class_uid": 3001, "time": 1760313600000, "status_id": '
                                                '2, "activity_id": 9}\''),
                                               ('Extra', 'dict', "{'class_uid': 3001}")]}],
 'network_protocol_num_and_textual_direction': [{'table': 'NetworkEvents',
                                                 'fields': [('TimeGenerated',
                                                             'datetime',
                                                             'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                            ('SourceId', 'str', "'src1'"),
                                                            ('SourceType', 'str', "'ocsf'"),
                                                            ('EventCode', 'str', "'4001'"),
                                                            ('EventAction', 'str', "'listen'"),
                                                            ('EventResult', 'str', "'unknown'"),
                                                            ('Message', 'str', "''"),
                                                            ('RawEvent',
                                                             'str',
                                                             '\'{"class_uid": 4001, "activity_id": 7, '
                                                             '"time": 1760313600000, "connection_info": '
                                                             '{"protocol_num": 6, "direction": "Inbound"}, '
                                                             '"traffic": {"bytes_in": "5", "bytes_out": '
                                                             'null}, "dst_endpoint": {"hostname": '
                                                             '"api.example", "port": "x"}}\''),
                                                            ('Protocol', 'str', "'6'"),
                                                            ('Direction', 'str', "'inbound'"),
                                                            ('BytesIn', 'int', '5'),
                                                            ('Domain', 'str', "'api.example'"),
                                                            ('Extra',
                                                             'dict',
                                                             "{'class_uid': 4001, 'dst_endpoint': "
                                                             "{'hostname': 'api.example', 'port': 'x'}}")]}],
 'network_direction_id_lateral_and_unknown': [{'table': 'NetworkEvents',
                                               'fields': [('TimeGenerated',
                                                           'datetime',
                                                           'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                          ('SourceId', 'str', "'src1'"),
                                                          ('SourceType', 'str', "'ocsf'"),
                                                          ('EventCode', 'str', "'4005'"),
                                                          ('EventAction', 'str', "''"),
                                                          ('EventResult', 'str', "'unknown'"),
                                                          ('SrcIp', 'str', "'10.0.0.1'"),
                                                          ('SrcPort', 'int', '53'),
                                                          ('Message', 'str', "''"),
                                                          ('RawEvent',
                                                           'str',
                                                           '\'{"class_uid": 4005, "time": 1760313600000, '
                                                           '"connection_info": {"protocol_name": "UDP", '
                                                           '"direction_id": 3}, "src_endpoint": {"ip": '
                                                           '"10.0.0.1", "port": 53}}\''),
                                                          ('Protocol', 'str', "'udp'"),
                                                          ('Direction', 'str', "'lateral'"),
                                                          ('Extra',
                                                           'dict',
                                                           "{'class_uid': 4005, 'src_endpoint': {'ip': "
                                                           "'10.0.0.1', 'port': 53}}")]}],
 'network_direction_unknown_number': [{'table': 'NetworkEvents',
                                       'fields': [('TimeGenerated',
                                                   'datetime',
                                                   'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                  ('SourceId', 'str', "'src1'"),
                                                  ('SourceType', 'str', "'ocsf'"),
                                                  ('EventCode', 'str', "'4006'"),
                                                  ('EventAction', 'str', "''"),
                                                  ('EventResult', 'str', "'unknown'"),
                                                  ('Message', 'str', "''"),
                                                  ('RawEvent',
                                                   'str',
                                                   '\'{"class_uid": 4006, "time": 1760313600000, '
                                                   '"connection_info": {"direction_id": 9, "protocol_name": '
                                                   '"ICMP"}}\''),
                                                  ('Protocol', 'str', "'icmp'"),
                                                  ('Direction', 'str', "'9'"),
                                                  ('Extra', 'dict', "{'class_uid': 4006}")]}],
 'network_domain_from_dst_hostname': [{'table': 'NetworkEvents',
                                       'fields': [('TimeGenerated',
                                                   'datetime',
                                                   'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                  ('SourceId', 'str', "'src1'"),
                                                  ('SourceType', 'str', "'ocsf'"),
                                                  ('EventCode', 'str', "'4007'"),
                                                  ('EventAction', 'str', "''"),
                                                  ('EventResult', 'str', "'unknown'"),
                                                  ('HostName', 'str', "'ws9'"),
                                                  ('Message', 'str', "''"),
                                                  ('RawEvent',
                                                   'str',
                                                   '\'{"class_uid": 4007, "time": 1760313600000, '
                                                   '"dst_endpoint": {"hostname": "cdn.example.net"}, '
                                                   '"src_endpoint": {"hostname": "ws9"}, "traffic": '
                                                   '{"bytes_out": 77}}\''),
                                                  ('BytesOut', 'int', '77'),
                                                  ('Domain', 'str', "'cdn.example.net'"),
                                                  ('Extra',
                                                   'dict',
                                                   "{'class_uid': 4007, 'src_endpoint': {'hostname': 'ws9'}, "
                                                   "'dst_endpoint': {'hostname': 'cdn.example.net'}}")]}],
 'http_path_only_and_zero_length': [{'table': 'WebAccess',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('EventCode', 'str', "'4002'"),
                                                ('EventAction', 'str', "'request'"),
                                                ('EventResult', 'str', "'unknown'"),
                                                ('Message', 'str', "''"),
                                                ('RawEvent',
                                                 'str',
                                                 '\'{"class_uid": 4002, "activity_id": 9, "time": '
                                                 '1760313600000, "http_request": {"url": {"path": "/a/b"}}, '
                                                 '"http_response": {"code": "200", "length": 0}, "traffic": '
                                                 '{"bytes_out": 512}, "http_response_extra": null}\''),
                                                ('Url', 'str', "'/a/b'"),
                                                ('UrlPath', 'str', "'/a/b'"),
                                                ('StatusCode', 'int', '200'),
                                                ('Bytes', 'int', '512'),
                                                ('Extra',
                                                 'dict',
                                                 "{'class_uid': 4002, 'http_response_extra': None, "
                                                 "'http_request': {'url': {'path': '/a/b'}}, "
                                                 "'http_response': {'code': '200', 'length': 0}}")]}],
 'http_non_dict_request_and_response': [{'table': 'WebAccess',
                                         'fields': [('TimeGenerated',
                                                     'datetime',
                                                     'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                    ('SourceId', 'str', "'src1'"),
                                                    ('SourceType', 'str', "'ocsf'"),
                                                    ('EventCode', 'str', "'4002'"),
                                                    ('EventAction', 'str', "'request'"),
                                                    ('EventResult', 'str', "'unknown'"),
                                                    ('Message', 'str', "''"),
                                                    ('RawEvent',
                                                     'str',
                                                     '\'{"class_uid": 4002, "activity_id": 2, "time": '
                                                     '1760313600000, "http_request": "GET /", '
                                                     '"http_response": null, "http_method": "get"}\''),
                                                    ('Extra',
                                                     'dict',
                                                     "{'class_uid': 4002, 'http_method': 'get'}")]}],
 'generic_finding_with_process_context': [{'table': 'GenericEvents',
                                           'fields': [('TimeGenerated',
                                                       'datetime',
                                                       'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                      ('SourceId', 'str', "'src1'"),
                                                      ('SourceType', 'str', "'ocsf'"),
                                                      ('EventCode', 'str', "'2004'"),
                                                      ('EventAction', 'str', "''"),
                                                      ('EventResult', 'str', "'unknown'"),
                                                      ('Message', 'str', "''"),
                                                      ('RawEvent',
                                                       'str',
                                                       '\'{"class_uid": 2004, "category_uid": 2, '
                                                       '"activity_id": 1, "time": 1760313600000, '
                                                       '"severity_id": 0, "actor": {"process": {"name": '
                                                       '"scanner", "cmd_line": "scan --all", "pid": 11}}, '
                                                       '"finding_info": {"title": "x"}}\''),
                                                      ('ProcessName', 'str', "'scanner'"),
                                                      ('ProcessCmdLine', 'str', "'scan --all'"),
                                                      ('Extra',
                                                       'dict',
                                                       "{'class_uid': 2004, 'category_uid': 2, "
                                                       "'severity_id': 0, 'finding_info': {'title': 'x'}, "
                                                       "'actor': {'process': {'name': 'scanner', 'cmd_line': "
                                                       "'scan --all', 'pid': 11}}, 'severity': "
                                                       "'unknown'}")]}],
 'generic_no_process_context': [{'table': 'GenericEvents',
                                 'fields': [('TimeGenerated',
                                             'datetime',
                                             'datetime.datetime(2025, 10, 13, 0, 0)'),
                                            ('SourceId', 'str', "'src1'"),
                                            ('SourceType', 'str', "'ocsf'"),
                                            ('EventCode', 'str', "'6001'"),
                                            ('EventAction', 'str', "''"),
                                            ('EventResult', 'str', "'unknown'"),
                                            ('Message', 'str', "'api call'"),
                                            ('RawEvent',
                                             'str',
                                             '\'{"class_uid": 6001, "category_uid": 6, "time": '
                                             '1760313600000, "message": "api call"}\''),
                                            ('Extra', 'dict', "{'class_uid': 6001, 'category_uid': 6}")]}],
 'category_fallback_file_auth_network': [{'table': 'FileEvents',
                                          'fields': [('TimeGenerated',
                                                      'datetime',
                                                      'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                     ('SourceId', 'str', "'src1'"),
                                                     ('SourceType', 'str', "'ocsf'"),
                                                     ('EventCode', 'str', "'9999'"),
                                                     ('EventAction', 'str', "''"),
                                                     ('EventResult', 'str', "'unknown'"),
                                                     ('Message', 'str', "''"),
                                                     ('RawEvent',
                                                      'str',
                                                      '\'{"class_uid": 9999, "category_uid": 1, "time": '
                                                      "1760313600000}'"),
                                                     ('Operation', 'str', "''"),
                                                     ('Extra',
                                                      'dict',
                                                      "{'class_uid': 9999, 'category_uid': 1}")]}],
 'category_fallback_auth': [{'table': 'AuthEvents',
                             'fields': [('TimeGenerated',
                                         'datetime',
                                         'datetime.datetime(2025, 10, 13, 0, 0)'),
                                        ('SourceId', 'str', "'src1'"),
                                        ('SourceType', 'str', "'ocsf'"),
                                        ('EventCode', 'str', "'9998'"),
                                        ('EventAction', 'str', "''"),
                                        ('EventResult', 'str', "'unknown'"),
                                        ('Message', 'str', "''"),
                                        ('RawEvent',
                                         'str',
                                         '\'{"class_uid": 9998, "category_uid": 3, "time": 1760313600000}\''),
                                        ('Extra', 'dict', "{'class_uid': 9998, 'category_uid': 3}")]}],
 'category_fallback_network': [{'table': 'NetworkEvents',
                                'fields': [('TimeGenerated',
                                            'datetime',
                                            'datetime.datetime(2025, 10, 13, 0, 0)'),
                                           ('SourceId', 'str', "'src1'"),
                                           ('SourceType', 'str', "'ocsf'"),
                                           ('EventCode', 'str', "'4999'"),
                                           ('EventAction', 'str', "''"),
                                           ('EventResult', 'str', "'unknown'"),
                                           ('Message', 'str', "''"),
                                           ('RawEvent',
                                            'str',
                                            '\'{"class_uid": 4999, "category_uid": 4, "time": '
                                            "1760313600000}'"),
                                           ('Extra', 'dict', "{'class_uid': 4999, 'category_uid': 4}")]}],
 'class_uid_missing_category_only': [{'table': 'AuthEvents',
                                      'fields': [('TimeGenerated',
                                                  'datetime',
                                                  'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                 ('SourceId', 'str', "'src1'"),
                                                 ('SourceType', 'str', "'ocsf'"),
                                                 ('EventCode', 'str', "''"),
                                                 ('EventAction', 'str', "''"),
                                                 ('EventResult', 'str', "'unknown'"),
                                                 ('UserName', 'str', "'u'"),
                                                 ('Message', 'str', "''"),
                                                 ('RawEvent',
                                                  'str',
                                                  '\'{"category_uid": 3, "time": 1760313600000, "user": '
                                                  '{"name": "u"}}\''),
                                                 ('TargetUserName', 'str', "'u'"),
                                                 ('Extra', 'dict', "{'category_uid': 3}")]}],
 'time_float_seconds': [{'table': 'ProcessEvents',
                         'fields': [('TimeGenerated',
                                     'datetime',
                                     'datetime.datetime(2025, 10, 13, 0, 0, 0, 500000)'),
                                    ('SourceId', 'str', "'src1'"),
                                    ('SourceType', 'str', "'ocsf'"),
                                    ('EventCode', 'str', "'1007'"),
                                    ('EventAction', 'str', "''"),
                                    ('EventResult', 'str', "'unknown'"),
                                    ('Message', 'str', "''"),
                                    ('RawEvent', 'str', '\'{"class_uid": 1007, "time": 1760313600.5}\''),
                                    ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_iso_with_offset': [{'table': 'ProcessEvents',
                           'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                      ('SourceId', 'str', "'src1'"),
                                      ('SourceType', 'str', "'ocsf'"),
                                      ('EventCode', 'str', "'1007'"),
                                      ('EventAction', 'str', "''"),
                                      ('EventResult', 'str', "'unknown'"),
                                      ('Message', 'str', "''"),
                                      ('RawEvent',
                                       'str',
                                       '\'{"class_uid": 1007, "time": "2025-10-13T02:00:00+02:00"}\''),
                                      ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_iso_naive': [{'table': 'ProcessEvents',
                     'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                ('SourceId', 'str', "'src1'"),
                                ('SourceType', 'str', "'ocsf'"),
                                ('EventCode', 'str', "'1007'"),
                                ('EventAction', 'str', "''"),
                                ('EventResult', 'str', "'unknown'"),
                                ('Message', 'str', "''"),
                                ('RawEvent', 'str', '\'{"class_uid": 1007, "time": "2025-10-13T00:00:00"}\''),
                                ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_numeric_string': [{'table': 'ProcessEvents',
                          'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                     ('SourceId', 'str', "'src1'"),
                                     ('SourceType', 'str', "'ocsf'"),
                                     ('EventCode', 'str', "'1007'"),
                                     ('EventAction', 'str', "''"),
                                     ('EventResult', 'str', "'unknown'"),
                                     ('Message', 'str', "''"),
                                     ('RawEvent', 'str', '\'{"class_uid": 1007, "time": "1760313600000"}\''),
                                     ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_garbage_string': [{'table': 'ProcessEvents',
                          'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                     ('SourceId', 'str', "'src1'"),
                                     ('SourceType', 'str', "'ocsf'"),
                                     ('EventCode', 'str', "'1007'"),
                                     ('EventAction', 'str', "''"),
                                     ('EventResult', 'str', "'unknown'"),
                                     ('Message', 'str', "''"),
                                     ('RawEvent', 'str', '\'{"class_uid": 1007, "time": "xyz"}\''),
                                     ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_bool_and_none': [{'table': 'ProcessEvents',
                         'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                    ('SourceId', 'str', "'src1'"),
                                    ('SourceType', 'str', "'ocsf'"),
                                    ('EventCode', 'str', "'1007'"),
                                    ('EventAction', 'str', "''"),
                                    ('EventResult', 'str', "'unknown'"),
                                    ('Message', 'str', "''"),
                                    ('RawEvent', 'str', '\'{"class_uid": 1007, "time": true}\''),
                                    ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_fallback_to_start_time': [{'table': 'ProcessEvents',
                                  'fields': [('TimeGenerated',
                                              'datetime',
                                              'datetime.datetime(2025, 10, 13, 0, 0)'),
                                             ('SourceId', 'str', "'src1'"),
                                             ('SourceType', 'str', "'ocsf'"),
                                             ('EventCode', 'str', "'1007'"),
                                             ('EventAction', 'str', "''"),
                                             ('EventResult', 'str', "'unknown'"),
                                             ('Message', 'str', "''"),
                                             ('RawEvent',
                                              'str',
                                              '\'{"class_uid": 1007, "start_time": 1760313600000, "time": '
                                              "null}'"),
                                             ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_zero_and_empty': [{'table': 'ProcessEvents',
                          'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(1970, 1, 1, 0, 0)'),
                                     ('SourceId', 'str', "'src1'"),
                                     ('SourceType', 'str', "'ocsf'"),
                                     ('EventCode', 'str', "'1007'"),
                                     ('EventAction', 'str', "''"),
                                     ('EventResult', 'str', "'unknown'"),
                                     ('Message', 'str', "''"),
                                     ('RawEvent', 'str', '\'{"class_uid": 1007, "time": 0}\''),
                                     ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_empty_string': [{'table': 'ProcessEvents',
                        'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                   ('SourceId', 'str', "'src1'"),
                                   ('SourceType', 'str', "'ocsf'"),
                                   ('EventCode', 'str', "'1007'"),
                                   ('EventAction', 'str', "''"),
                                   ('EventResult', 'str', "'unknown'"),
                                   ('Message', 'str', "''"),
                                   ('RawEvent', 'str', '\'{"class_uid": 1007, "time": ""}\''),
                                   ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'time_overflow': [{'table': 'ProcessEvents',
                    'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                               ('SourceId', 'str', "'src1'"),
                               ('SourceType', 'str', "'ocsf'"),
                               ('EventCode', 'str', "'1007'"),
                               ('EventAction', 'str', "''"),
                               ('EventResult', 'str', "'unknown'"),
                               ('Message', 'str', "''"),
                               ('RawEvent', 'str', '\'{"class_uid": 1007, "time": 1e+20}\''),
                               ('Extra', 'dict', "{'class_uid': 1007}")]}],
 'severity_names_and_extras': [{'table': 'AuthEvents',
                                'fields': [('TimeGenerated',
                                            'datetime',
                                            'datetime.datetime(2025, 10, 13, 0, 0)'),
                                           ('SourceId', 'str', "'src1'"),
                                           ('SourceType', 'str', "'ocsf'"),
                                           ('EventCode', 'str', "'3002'"),
                                           ('EventAction', 'str', "''"),
                                           ('EventResult', 'str', "'unknown'"),
                                           ('Message', 'str', "''"),
                                           ('RawEvent',
                                            'str',
                                            '\'{"class_uid": 3002, "time": 1760313600000, "severity_id": 6, '
                                            '"logon_type": "Interactive", "status_code": 0, "auth_protocol": '
                                            '"NTLM", "unmapped_key": {"a": [1, 2]}, "http_request": '
                                            '"not-a-dict"}\''),
                                           ('LogonType', 'str', "'Interactive'"),
                                           ('AuthMethod', 'str', "'NTLM'"),
                                           ('Extra',
                                            'dict',
                                            "{'class_uid': 3002, 'severity_id': 6, 'unmapped_key': {'a': [1, "
                                            "2]}, 'severity': 'fatal', 'logon_type': 'Interactive', "
                                            "'auth_protocol': 'NTLM', 'status_code': 0}")]}],
 'severity_unknown_number': [{'table': 'GenericEvents',
                              'fields': [('TimeGenerated',
                                          'datetime',
                                          'datetime.datetime(2025, 10, 13, 0, 0)'),
                                         ('SourceId', 'str', "'src1'"),
                                         ('SourceType', 'str', "'ocsf'"),
                                         ('EventCode', 'str', "'2004'"),
                                         ('EventAction', 'str', "''"),
                                         ('EventResult', 'str', "'success'"),
                                         ('Message', 'str', "''"),
                                         ('RawEvent',
                                          'str',
                                          '\'{"class_uid": 2004, "time": 1760313600000, "severity_id": 42, '
                                          '"status": "ok"}\''),
                                         ('Extra',
                                          'dict',
                                          "{'class_uid': 2004, 'severity_id': 42, 'severity': '42'}")]}],
 'unicode_message_and_user': [{'table': 'AuthEvents',
                               'fields': [('TimeGenerated',
                                           'datetime',
                                           'datetime.datetime(2025, 10, 13, 0, 0)'),
                                          ('SourceId', 'str', "'src1'"),
                                          ('SourceType', 'str', "'ocsf'"),
                                          ('EventCode', 'str', "'3002'"),
                                          ('EventAction', 'str', "''"),
                                          ('EventResult', 'str', "'unknown'"),
                                          ('UserName', 'str', "'ü'"),
                                          ('Message', 'str', "'失败'"),
                                          ('RawEvent',
                                           'str',
                                           '\'{"class_uid": 3002, "time": 1760313600000, "user": {"name": '
                                           '"\\\\u00fc"}, "message": "\\\\u5931\\\\u8d25"}\''),
                                          ('TargetUserName', 'str', "'ü'"),
                                          ('Extra', 'dict', "{'class_uid': 3002}")]}],
 'message_from_metadata_event_code': [{'table': 'GenericEvents',
                                       'fields': [('TimeGenerated',
                                                   'datetime',
                                                   'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                  ('SourceId', 'str', "'src1'"),
                                                  ('SourceType', 'str', "'ocsf'"),
                                                  ('EventCode', 'str', "'2004'"),
                                                  ('EventAction', 'str', "''"),
                                                  ('EventResult', 'str', "'unknown'"),
                                                  ('Message', 'str', "'EC-1'"),
                                                  ('RawEvent',
                                                   'str',
                                                   '\'{"class_uid": 2004, "time": 1760313600000, "metadata": '
                                                   '{"event_code": "EC-1", "version": "1.3.0"}}\''),
                                                  ('Extra',
                                                   'dict',
                                                   "{'class_uid': 2004, 'metadata': {'event_code': 'EC-1', "
                                                   "'version': '1.3.0'}}")]}],
 'parse_ocsf_invalid_json_string': [{'table': 'GenericEvents',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('Message', 'str', "'{broken json'"),
                                                ('RawEvent', 'str', "'{broken json'"),
                                                ('EventCode', 'str', "''"),
                                                ('EventAction', 'str', "''"),
                                                ('EventResult', 'str', "'unknown'")]}],
 'parse_ocsf_json_string_object': [{'table': 'AuthEvents',
                                    'fields': [('TimeGenerated',
                                                'datetime',
                                                'datetime.datetime(2025, 10, 13, 0, 0)'),
                                               ('SourceId', 'str', "'src1'"),
                                               ('SourceType', 'str', "'ocsf'"),
                                               ('EventCode', 'str', "'3002'"),
                                               ('EventAction', 'str', "''"),
                                               ('EventResult', 'str', "'failure'"),
                                               ('UserName', 'str', "'z'"),
                                               ('Message', 'str', "''"),
                                               ('RawEvent',
                                                'str',
                                                '\'{"class_uid": 3002, "time": 1760313600000, "status_id": '
                                                '2, "user": {"name": "z"}}\''),
                                               ('TargetUserName', 'str', "'z'"),
                                               ('Extra', 'dict', "{'class_uid': 3002}")]}],
 'parse_ocsf_list_skips_non_dict': [{'table': 'ProcessEvents',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('EventCode', 'str', "'1007'"),
                                                ('EventAction', 'str', "''"),
                                                ('EventResult', 'str', "'unknown'"),
                                                ('Message', 'str', "''"),
                                                ('RawEvent',
                                                 'str',
                                                 '\'{"class_uid": 1007, "time": 1760313600000}\''),
                                                ('Extra', 'dict', "{'class_uid': 1007}")]},
                                    {'table': 'NetworkEvents',
                                     'fields': [('TimeGenerated',
                                                 'datetime',
                                                 'datetime.datetime(2025, 10, 13, 0, 0)'),
                                                ('SourceId', 'str', "'src1'"),
                                                ('SourceType', 'str', "'ocsf'"),
                                                ('EventCode', 'str', "'4003'"),
                                                ('EventAction', 'str', "''"),
                                                ('EventResult', 'str', "'unknown'"),
                                                ('Message', 'str', "''"),
                                                ('RawEvent',
                                                 'str',
                                                 '\'{"class_uid": 4003, "time": 1760313600000}\''),
                                                ('Extra', 'dict', "{'class_uid': 4003}")]}],
 'parse_ocsf_scalar_input': []}
# ---- /GOLDEN ----


@pytest.fixture
def _pinned_clock(monkeypatch):
    monkeypatch.setattr(ocsf_module, "_utcnow", lambda: FIXED_NOW)
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _golden_snapshot(events) -> list:
    return [{"table": e.table,
             "fields": [(k, type(v).__name__, repr(v)) for k, v in e.fields.items()]} for e in events]


@pytest.mark.parametrize("name", list(GOLDEN_CASES))
def test_char_ocsf_golden(name, _pinned_clock):
    assert _golden_snapshot(parse_ocsf(GOLDEN_CASES[name], "src1")) == GOLDEN_OCSF[name]


def test_char_ocsf_golden_covers_every_case():
    assert set(GOLDEN_OCSF) == set(GOLDEN_CASES)
