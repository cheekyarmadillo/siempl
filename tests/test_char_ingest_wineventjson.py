"""Golden-master characterization tests for siempl.ingest.parsers.parse_windows_json.

The GOLDEN table below was captured from the code BEFORE the parse_windows_json refactor. Each entry
is the exact table, key order, Python type and repr() of every field. A refactor that changes any of
those fails here. Do not edit GOLDEN by hand to make a test pass; if output is wrong, fix the code.
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
import time

import pytest

from siempl.ingest.parsers import parse_windows_json

FIXED_NOW = _dt.datetime(2026, 1, 2, 3, 4, 5)

CASES: dict[str, object] = {
    # OTRF Security-Datasets style flat Sysmon 1, ISO timestamp with millis, Windows paths
    "sysmon1_flat_otrf": {
        "EventID": 1, "Computer": "WS01.lab", "@timestamp": "2025-10-13T08:00:00.123Z",
        "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami", "ProcessId": 4321,
        "ParentImage": "C:\\Windows\\explorer.exe", "ParentProcessId": 1000, "ParentCommandLine": "explorer.exe",
        "Hashes": "SHA256=AB12", "IntegrityLevel": "Medium", "User": "LAB\\alice", "message": "Process Create",
    },
    # Winlogbeat style: event_id as int, host.name, nested event_data, extra top-level keys
    "winlogbeat_4624_nested": {
        "event_id": 4624, "@timestamp": "2025-10-13T08:01:00Z", "host": {"name": "dc01"},
        "message": "An account was successfully logged on", "tags": ["auth", "win"],
        "event_data": {"TargetUserName": "bob", "IpAddress": "10.0.0.8", "LogonType": "10",
                       "AuthenticationPackageName": "Kerberos"},
    },
    # 4625 failure, TimeCreated timestamp, capitalised fields, null extra key
    "event_4625_failure_flat": {
        "EventID": "4625", "TimeCreated": "2025-10-13T08:02:00Z", "Computer": "dc01",
        "TargetUserName": "admin", "IpAddress": "203.0.113.5", "LogonType": 3, "Status": "0xC000006D",
        "FailureReason": "Unknown user name", "AuthenticationPackageName": "NTLM", "extra": None,
    },
    # Sysmon 3 network with string and int ports, ip fields via source.ip style aliases
    "sysmon3_network_ports": {
        "EventID": 3, "@timestamp": "2025-10-13T08:03:00Z", "SourceIp": "10.0.0.5",
        "DestinationIp": "198.51.100.7", "SourcePort": "49500", "DestinationPort": 443,
        "Protocol": "tcp", "Image": "C:\\x\\curl.exe",
    },
    # Sysmon 3 with zero/empty ports and empty ips: ports become None, ips become ""
    "sysmon3_zero_and_empty": {
        "EventID": 3, "SourceIp": "10.0.0.5", "SourcePort": "0", "DestinationPort": "",
        "DestinationIp": "", "@timestamp": "2025-10-13T08:04:00Z",
    },
    # Sysmon 11 file create: TargetFilename, Hashes, Image
    "sysmon11_file_create": {
        "EventID": 11, "@timestamp": "2025-10-13T08:05:00Z", "TargetFilename": "C:\\Users\\a\\Downloads\\x.exe",
        "Hashes": "SHA1=ABCD", "Image": "C:\\Windows\\explorer.exe",
    },
    # Sysmon 22 DNS with event_data nesting
    "sysmon22_dns_event_data": {
        "event_id": 22, "@timestamp": "2025-10-13T08:06:00Z",
        "event_data": {"QueryName": "evil.example.com", "Image": "chrome.exe"},
    },
    # dotted-key event.code and nested dns.question.name resolved through the dotted-path lookup
    "sysmon22_dotted_paths": {
        "event.code": 22, "dns": {"question": {"name": "a.example"}}, "process": {"name": "svc.exe"},
        "@timestamp": "2025-10-13T08:07:00Z",
    },
    # unknown EventID, empty message -> default message text, GenericEvents
    "unknown_event_9999": {"EventID": 9999, "Computer": "WS02", "message": ""},
    # EventData (capitalised) container instead of event_data
    "eventdata_capitalised_container": {
        "EventID": 4799, "EventData": {"TargetUserName": "x", "IpAddress": "10.2.2.2"}, "Computer": "WS02",
    },
    # EventID only inside event_data; Sysmon 1 via edata lookup
    "event_id_only_in_event_data": {
        "event_data": {"EventID": "1", "Image": "a.exe", "ProcessId": "77", "CommandLine": "a"},
        "@timestamp": "2025-10-13T08:08:00Z",
    },
    # 'Id' key inside event_data is the last fallback for EventID -> Sysmon 3
    "event_id_Id_key_in_event_data": {"event_data": {"Id": 3, "SourceIp": "10.9.9.9"}},
    # malformed JSON string -> fallback GenericEvents with Message = raw text
    "malformed_json_string": "{not json",
    # malformed string longer than 1000 chars -> Message truncated to 1000
    "malformed_long_string": "x" * 1500,
    # valid JSON string input is parsed like a dict
    "valid_json_string": json.dumps({"EventID": 4625, "TargetUserName": "carol", "IpAddress": "10.1.1.1",
                                     "@timestamp": "2025-10-13T08:09:00Z"}),
    # list input (top-level JSON array) -> no events
    "list_input": [{"EventID": 1}],
    # int input -> no events
    "int_input": 42,
    # JSON string holding an array -> no events
    "json_array_string": "[1, 2, 3]",
    # null / whitespace-only values are treated as missing
    "whitespace_and_null_values": {
        "EventID": 4625, "TargetUserName": "   ", "IpAddress": None, "Status": "",
        "LogonType": None, "AuthenticationPackageName": "NTLM", "message": None, "Computer": "  ",
    },
    # event_data present but not a dict -> fields read from the top-level object
    "event_data_not_dict": {"EventID": 4624, "event_data": "oops", "TargetUserName": "carol",
                            "IpAddress": "10.1.1.1"},
    # nested arrays / objects in unrelated keys; numeric process id as string
    "nested_arrays_4688": {
        "EventID": 4688, "tags": ["a", {"b": 1}], "@timestamp": "2025-10-13T08:10:00Z",
        "event_data": {"NewProcessName": "C:\\a\\b.exe", "NewProcessId": "420", "CommandLine": "b.exe -x",
                       "ParentProcessName": "C:\\a\\parent.exe", "ParentProcessId": "1", "User": "LAB\\svc"},
    },
    # 4688 via dotted process.* keys and host.name, pid 0 -> None
    "process_dotted_keys": {
        "event.code": "4688", "process": {"pid": 555, "name": "bash", "command_line": "bash -c id",
                                          "parent": {"pid": 1}},
        "host": {"name": "linux-ish"}, "user": {"name": "root"}, "@timestamp": "2025-10-13T08:11:00Z",
    },
    "zero_process_id": {"EventID": 1, "ProcessId": "0", "NewProcessId": None, "Image": "x.exe"},
    # timestamp that cannot be parsed -> utcnow fallback
    "timestamp_unparseable": {"EventID": 1, "@timestamp": "not-a-date"},
    # epoch-milliseconds timestamp under 'timestamp'
    "timestamp_epoch_ms": {"EventID": 1, "timestamp": 1760313600000},
    # extras: unmapped top-level keys kept, mapped/column keys dropped, nested dict kept as-is
    "extra_fields_kept": {
        "EventID": 4624, "custom_top": "keep me", "winlog": {"channel": "Security"}, "message": "logon",
        "@timestamp": "2025-10-13T08:12:00Z",
        "event_data": {"TargetUserName": "d", "ExtraEdata": "not extra"},
    },
    # Sysmon 8 CreateRemoteThread -> ProcessEvents with no action mapping
    "sysmon8_remote_thread": {"EventID": 8, "SourceImage": "a.exe", "TargetImage": "b.exe"},
    # unicode strings in user name, computer and message
    "unicode_values": {"EventID": 4625, "TargetUserName": "用户", "Computer": "工作站",
                       "message": "失败 ✓"},
}

# ---- GOLDEN ----
GOLDEN: dict[str, object] = {'sysmon1_flat_otrf': [{'table': 'ProcessEvents',
                        'fields': [('TimeGenerated',
                                    'datetime',
                                    'datetime.datetime(2025, 10, 13, 8, 0, 0, 123000)'),
                                   ('SourceId', 'str', "'src1'"),
                                   ('SourceType', 'str', "'windows_json'"),
                                   ('EventCode', 'str', "'1'"),
                                   ('EventAction', 'str', "'process_start'"),
                                   ('EventResult', 'str', "'unknown'"),
                                   ('HostName', 'str', "'WS01.lab'"),
                                   ('Message', 'str', "'Process Create'"),
                                   ('RawEvent',
                                    'str',
                                    '\'{"EventID": 1, "Computer": "WS01.lab", "@timestamp": '
                                    '"2025-10-13T08:00:00.123Z", "Image": '
                                    '"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\cmd.exe", "CommandLine": "cmd '
                                    '/c whoami", "ProcessId": 4321, "ParentImage": '
                                    '"C:\\\\\\\\Windows\\\\\\\\explorer.exe", "ParentProcessId": 1000, '
                                    '"ParentCommandLine": "explorer.exe", "Hashes": "SHA256=AB12", '
                                    '"IntegrityLevel": "Medium", "User": "LAB\\\\\\\\alice", "message": '
                                    '"Process Create"}\''),
                                   ('ProcessName', 'str', "'C:\\\\Windows\\\\System32\\\\cmd.exe'"),
                                   ('ProcessPath', 'str', "'C:\\\\Windows\\\\System32\\\\cmd.exe'"),
                                   ('ProcessCmdLine', 'str', "'cmd /c whoami'"),
                                   ('ProcessId', 'int', '4321'),
                                   ('ParentProcessName', 'str', "'C:\\\\Windows\\\\explorer.exe'"),
                                   ('ParentProcessId', 'int', '1000'),
                                   ('ParentCmdLine', 'str', "'explorer.exe'"),
                                   ('FileHash', 'str', "'SHA256=AB12'"),
                                   ('IntegrityLevel', 'str', "'Medium'"),
                                   ('UserName', 'str', "'LAB\\\\alice'"),
                                   ('Extra',
                                    'dict',
                                    "{'EventID': 1, 'Computer': 'WS01.lab', '@timestamp': "
                                    "'2025-10-13T08:00:00.123Z', 'Image': "
                                    "'C:\\\\Windows\\\\System32\\\\cmd.exe', 'CommandLine': 'cmd /c whoami', "
                                    "'ParentImage': 'C:\\\\Windows\\\\explorer.exe', 'ParentCommandLine': "
                                    "'explorer.exe', 'Hashes': 'SHA256=AB12', 'User': 'LAB\\\\alice', "
                                    "'message': 'Process Create'}")]}],
 'winlogbeat_4624_nested': [{'table': 'AuthEvents',
                             'fields': [('TimeGenerated',
                                         'datetime',
                                         'datetime.datetime(2025, 10, 13, 8, 1)'),
                                        ('SourceId', 'str', "'src1'"),
                                        ('SourceType', 'str', "'windows_json'"),
                                        ('EventCode', 'str', "'4624'"),
                                        ('EventAction', 'str', "'login'"),
                                        ('EventResult', 'str', "'success'"),
                                        ('HostName', 'str', "'dc01'"),
                                        ('Message', 'str', "'An account was successfully logged on'"),
                                        ('RawEvent',
                                         'str',
                                         '\'{"event_id": 4624, "@timestamp": "2025-10-13T08:01:00Z", "host": '
                                         '{"name": "dc01"}, "message": "An account was successfully logged '
                                         'on", "tags": ["auth", "win"], "event_data": {"TargetUserName": '
                                         '"bob", "IpAddress": "10.0.0.8", "LogonType": "10", '
                                         '"AuthenticationPackageName": "Kerberos"}}\''),
                                        ('UserName', 'str', "'bob'"),
                                        ('TargetUserName', 'str', "'bob'"),
                                        ('SrcIp', 'str', "'10.0.0.8'"),
                                        ('LogonType', 'str', "'10'"),
                                        ('FailureReason', 'str', "''"),
                                        ('AuthMethod', 'str', "'Kerberos'"),
                                        ('Extra',
                                         'dict',
                                         "{'event_id': 4624, '@timestamp': '2025-10-13T08:01:00Z', 'host': "
                                         "{'name': 'dc01'}, 'message': 'An account was successfully logged "
                                         "on', 'tags': ['auth', 'win'], 'event_data': {'TargetUserName': "
                                         "'bob', 'IpAddress': '10.0.0.8', 'LogonType': '10', "
                                         "'AuthenticationPackageName': 'Kerberos'}}")]}],
 'event_4625_failure_flat': [{'table': 'AuthEvents',
                              'fields': [('TimeGenerated',
                                          'datetime',
                                          'datetime.datetime(2025, 10, 13, 8, 2)'),
                                         ('SourceId', 'str', "'src1'"),
                                         ('SourceType', 'str', "'windows_json'"),
                                         ('EventCode', 'str', "'4625'"),
                                         ('EventAction', 'str', "'login'"),
                                         ('EventResult', 'str', "'failure'"),
                                         ('HostName', 'str', "'dc01'"),
                                         ('Message', 'str', "'Windows EventID 4625'"),
                                         ('RawEvent',
                                          'str',
                                          '\'{"EventID": "4625", "TimeCreated": "2025-10-13T08:02:00Z", '
                                          '"Computer": "dc01", "TargetUserName": "admin", "IpAddress": '
                                          '"203.0.113.5", "LogonType": 3, "Status": "0xC000006D", '
                                          '"FailureReason": "Unknown user name", '
                                          '"AuthenticationPackageName": "NTLM", "extra": null}\''),
                                         ('UserName', 'str', "'admin'"),
                                         ('TargetUserName', 'str', "'admin'"),
                                         ('SrcIp', 'str', "'203.0.113.5'"),
                                         ('LogonType', 'str', "'3'"),
                                         ('FailureReason', 'str', "'Unknown user name'"),
                                         ('AuthMethod', 'str', "'NTLM'"),
                                         ('Extra',
                                          'dict',
                                          "{'EventID': '4625', 'TimeCreated': '2025-10-13T08:02:00Z', "
                                          "'Computer': 'dc01', 'IpAddress': '203.0.113.5', 'Status': "
                                          "'0xC000006D', 'AuthenticationPackageName': 'NTLM', 'extra': "
                                          'None}')]}],
 'sysmon3_network_ports': [{'table': 'NetworkEvents',
                            'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 3)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('EventCode', 'str', "'3'"),
                                       ('EventAction', 'str', "'network_connect'"),
                                       ('EventResult', 'str', "'unknown'"),
                                       ('HostName', 'str', "''"),
                                       ('Message', 'str', "'Windows EventID 3'"),
                                       ('RawEvent',
                                        'str',
                                        '\'{"EventID": 3, "@timestamp": "2025-10-13T08:03:00Z", "SourceIp": '
                                        '"10.0.0.5", "DestinationIp": "198.51.100.7", "SourcePort": "49500", '
                                        '"DestinationPort": 443, "Protocol": "tcp", "Image": '
                                        '"C:\\\\\\\\x\\\\\\\\curl.exe"}\''),
                                       ('SrcIp', 'str', "'10.0.0.5'"),
                                       ('DstIp', 'str', "'198.51.100.7'"),
                                       ('SrcPort', 'int', '49500'),
                                       ('DstPort', 'int', '443'),
                                       ('Protocol', 'str', "'tcp'"),
                                       ('DnsQuery', 'str', "''"),
                                       ('ProcessName', 'str', "'C:\\\\x\\\\curl.exe'"),
                                       ('Extra',
                                        'dict',
                                        "{'EventID': 3, '@timestamp': '2025-10-13T08:03:00Z', 'SourceIp': "
                                        "'10.0.0.5', 'DestinationIp': '198.51.100.7', 'SourcePort': '49500', "
                                        "'DestinationPort': 443, 'Image': 'C:\\\\x\\\\curl.exe'}")]}],
 'sysmon3_zero_and_empty': [{'table': 'NetworkEvents',
                             'fields': [('TimeGenerated',
                                         'datetime',
                                         'datetime.datetime(2025, 10, 13, 8, 4)'),
                                        ('SourceId', 'str', "'src1'"),
                                        ('SourceType', 'str', "'windows_json'"),
                                        ('EventCode', 'str', "'3'"),
                                        ('EventAction', 'str', "'network_connect'"),
                                        ('EventResult', 'str', "'unknown'"),
                                        ('HostName', 'str', "''"),
                                        ('Message', 'str', "'Windows EventID 3'"),
                                        ('RawEvent',
                                         'str',
                                         '\'{"EventID": 3, "SourceIp": "10.0.0.5", "SourcePort": "0", '
                                         '"DestinationPort": "", "DestinationIp": "", "@timestamp": '
                                         '"2025-10-13T08:04:00Z"}\''),
                                        ('SrcIp', 'str', "'10.0.0.5'"),
                                        ('DstIp', 'str', "''"),
                                        ('SrcPort', 'NoneType', 'None'),
                                        ('DstPort', 'NoneType', 'None'),
                                        ('Protocol', 'str', "''"),
                                        ('DnsQuery', 'str', "''"),
                                        ('ProcessName', 'str', "''"),
                                        ('Extra',
                                         'dict',
                                         "{'EventID': 3, 'SourceIp': '10.0.0.5', 'SourcePort': '0', "
                                         "'DestinationPort': '', 'DestinationIp': '', '@timestamp': "
                                         "'2025-10-13T08:04:00Z'}")]}],
 'sysmon11_file_create': [{'table': 'FileEvents',
                           'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 5)'),
                                      ('SourceId', 'str', "'src1'"),
                                      ('SourceType', 'str', "'windows_json'"),
                                      ('EventCode', 'str', "'11'"),
                                      ('EventAction', 'str', "'file_create'"),
                                      ('EventResult', 'str', "'unknown'"),
                                      ('HostName', 'str', "''"),
                                      ('Message', 'str', "'Windows EventID 11'"),
                                      ('RawEvent',
                                       'str',
                                       '\'{"EventID": 11, "@timestamp": "2025-10-13T08:05:00Z", '
                                       '"TargetFilename": '
                                       '"C:\\\\\\\\Users\\\\\\\\a\\\\\\\\Downloads\\\\\\\\x.exe", "Hashes": '
                                       '"SHA1=ABCD", "Image": "C:\\\\\\\\Windows\\\\\\\\explorer.exe"}\''),
                                      ('FilePath', 'str', "'C:\\\\Users\\\\a\\\\Downloads\\\\x.exe'"),
                                      ('FileName', 'str', "'C:\\\\Users\\\\a\\\\Downloads\\\\x.exe'"),
                                      ('FileHash', 'str', "'SHA1=ABCD'"),
                                      ('ProcessName', 'str', "'C:\\\\Windows\\\\explorer.exe'"),
                                      ('Extra',
                                       'dict',
                                       "{'EventID': 11, '@timestamp': '2025-10-13T08:05:00Z', "
                                       "'TargetFilename': 'C:\\\\Users\\\\a\\\\Downloads\\\\x.exe', "
                                       "'Hashes': 'SHA1=ABCD', 'Image': 'C:\\\\Windows\\\\explorer.exe'}")]}],
 'sysmon22_dns_event_data': [{'table': 'NetworkEvents',
                              'fields': [('TimeGenerated',
                                          'datetime',
                                          'datetime.datetime(2025, 10, 13, 8, 6)'),
                                         ('SourceId', 'str', "'src1'"),
                                         ('SourceType', 'str', "'windows_json'"),
                                         ('EventCode', 'str', "'22'"),
                                         ('EventAction', 'str', "'dns_query'"),
                                         ('EventResult', 'str', "'unknown'"),
                                         ('HostName', 'str', "''"),
                                         ('Message', 'str', "'Windows EventID 22'"),
                                         ('RawEvent',
                                          'str',
                                          '\'{"event_id": 22, "@timestamp": "2025-10-13T08:06:00Z", '
                                          '"event_data": {"QueryName": "evil.example.com", "Image": '
                                          '"chrome.exe"}}\''),
                                         ('SrcIp', 'str', "''"),
                                         ('DstIp', 'str', "''"),
                                         ('SrcPort', 'NoneType', 'None'),
                                         ('DstPort', 'NoneType', 'None'),
                                         ('Protocol', 'str', "''"),
                                         ('DnsQuery', 'str', "'evil.example.com'"),
                                         ('ProcessName', 'str', "'chrome.exe'"),
                                         ('Extra',
                                          'dict',
                                          "{'event_id': 22, '@timestamp': '2025-10-13T08:06:00Z', "
                                          "'event_data': {'QueryName': 'evil.example.com', 'Image': "
                                          "'chrome.exe'}}")]}],
 'sysmon22_dotted_paths': [{'table': 'GenericEvents',
                            'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 7)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('EventCode', 'str', "''"),
                                       ('EventAction', 'str', "''"),
                                       ('EventResult', 'str', "'unknown'"),
                                       ('HostName', 'str', "''"),
                                       ('Message', 'str', "'Windows EventID '"),
                                       ('RawEvent',
                                        'str',
                                        '\'{"event.code": 22, "dns": {"question": {"name": "a.example"}}, '
                                        '"process": {"name": "svc.exe"}, "@timestamp": '
                                        '"2025-10-13T08:07:00Z"}\''),
                                       ('Extra',
                                        'dict',
                                        "{'event.code': 22, 'dns': {'question': {'name': 'a.example'}}, "
                                        "'process': {'name': 'svc.exe'}, '@timestamp': "
                                        "'2025-10-13T08:07:00Z'}")]}],
 'unknown_event_9999': [{'table': 'GenericEvents',
                         'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                    ('SourceId', 'str', "'src1'"),
                                    ('SourceType', 'str', "'windows_json'"),
                                    ('EventCode', 'str', "'9999'"),
                                    ('EventAction', 'str', "''"),
                                    ('EventResult', 'str', "'unknown'"),
                                    ('HostName', 'str', "'WS02'"),
                                    ('Message', 'str', "'Windows EventID 9999'"),
                                    ('RawEvent',
                                     'str',
                                     '\'{"EventID": 9999, "Computer": "WS02", "message": ""}\''),
                                    ('Extra',
                                     'dict',
                                     "{'EventID': 9999, 'Computer': 'WS02', 'message': ''}")]}],
 'eventdata_capitalised_container': [{'table': 'GenericEvents',
                                      'fields': [('TimeGenerated',
                                                  'datetime',
                                                  'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                                 ('SourceId', 'str', "'src1'"),
                                                 ('SourceType', 'str', "'windows_json'"),
                                                 ('EventCode', 'str', "'4799'"),
                                                 ('EventAction', 'str', "''"),
                                                 ('EventResult', 'str', "'unknown'"),
                                                 ('HostName', 'str', "'WS02'"),
                                                 ('Message', 'str', "'Windows EventID 4799'"),
                                                 ('RawEvent',
                                                  'str',
                                                  '\'{"EventID": 4799, "EventData": {"TargetUserName": "x", '
                                                  '"IpAddress": "10.2.2.2"}, "Computer": "WS02"}\''),
                                                 ('Extra',
                                                  'dict',
                                                  "{'EventID': 4799, 'EventData': {'TargetUserName': 'x', "
                                                  "'IpAddress': '10.2.2.2'}, 'Computer': 'WS02'}")]}],
 'event_id_only_in_event_data': [{'table': 'ProcessEvents',
                                  'fields': [('TimeGenerated',
                                              'datetime',
                                              'datetime.datetime(2025, 10, 13, 8, 8)'),
                                             ('SourceId', 'str', "'src1'"),
                                             ('SourceType', 'str', "'windows_json'"),
                                             ('EventCode', 'str', "'1'"),
                                             ('EventAction', 'str', "'process_start'"),
                                             ('EventResult', 'str', "'unknown'"),
                                             ('HostName', 'str', "''"),
                                             ('Message', 'str', "'Windows EventID 1'"),
                                             ('RawEvent',
                                              'str',
                                              '\'{"event_data": {"EventID": "1", "Image": "a.exe", '
                                              '"ProcessId": "77", "CommandLine": "a"}, "@timestamp": '
                                              '"2025-10-13T08:08:00Z"}\''),
                                             ('ProcessName', 'str', "'a.exe'"),
                                             ('ProcessPath', 'str', "'a.exe'"),
                                             ('ProcessCmdLine', 'str', "'a'"),
                                             ('ProcessId', 'int', '77'),
                                             ('ParentProcessName', 'str', "''"),
                                             ('ParentProcessId', 'NoneType', 'None'),
                                             ('ParentCmdLine', 'str', "''"),
                                             ('FileHash', 'str', "''"),
                                             ('IntegrityLevel', 'str', "''"),
                                             ('UserName', 'str', "''"),
                                             ('Extra',
                                              'dict',
                                              "{'event_data': {'EventID': '1', 'Image': 'a.exe', "
                                              "'ProcessId': '77', 'CommandLine': 'a'}, '@timestamp': "
                                              "'2025-10-13T08:08:00Z'}")]}],
 'event_id_Id_key_in_event_data': [{'table': 'NetworkEvents',
                                    'fields': [('TimeGenerated',
                                                'datetime',
                                                'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                               ('SourceId', 'str', "'src1'"),
                                               ('SourceType', 'str', "'windows_json'"),
                                               ('EventCode', 'str', "'3'"),
                                               ('EventAction', 'str', "'network_connect'"),
                                               ('EventResult', 'str', "'unknown'"),
                                               ('HostName', 'str', "''"),
                                               ('Message', 'str', "'Windows EventID 3'"),
                                               ('RawEvent',
                                                'str',
                                                '\'{"event_data": {"Id": 3, "SourceIp": "10.9.9.9"}}\''),
                                               ('SrcIp', 'str', "'10.9.9.9'"),
                                               ('DstIp', 'str', "''"),
                                               ('SrcPort', 'NoneType', 'None'),
                                               ('DstPort', 'NoneType', 'None'),
                                               ('Protocol', 'str', "''"),
                                               ('DnsQuery', 'str', "''"),
                                               ('ProcessName', 'str', "''"),
                                               ('Extra',
                                                'dict',
                                                "{'event_data': {'Id': 3, 'SourceIp': '10.9.9.9'}}")]}],
 'malformed_json_string': [{'table': 'GenericEvents',
                            'fields': [('TimeGenerated',
                                        'datetime',
                                        'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('Message', 'str', "'{not json'"),
                                       ('RawEvent', 'str', "'{not json'"),
                                       ('EventCode', 'str', "''"),
                                       ('EventAction', 'str', "''"),
                                       ('EventResult', 'str', "'unknown'")]}],
 'malformed_long_string': [{'table': 'GenericEvents',
                            'fields': [('TimeGenerated',
                                        'datetime',
                                        'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('Message',
                                        'str',
                                        "'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"),
                                       ('RawEvent',
                                        'str',
                                        "'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"),
                                       ('EventCode', 'str', "''"),
                                       ('EventAction', 'str', "''"),
                                       ('EventResult', 'str', "'unknown'")]}],
 'valid_json_string': [{'table': 'AuthEvents',
                        'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 9)'),
                                   ('SourceId', 'str', "'src1'"),
                                   ('SourceType', 'str', "'windows_json'"),
                                   ('EventCode', 'str', "'4625'"),
                                   ('EventAction', 'str', "'login'"),
                                   ('EventResult', 'str', "'failure'"),
                                   ('HostName', 'str', "''"),
                                   ('Message', 'str', "'Windows EventID 4625'"),
                                   ('RawEvent',
                                    'str',
                                    '\'{"EventID": 4625, "TargetUserName": "carol", "IpAddress": "10.1.1.1", '
                                    '"@timestamp": "2025-10-13T08:09:00Z"}\''),
                                   ('UserName', 'str', "'carol'"),
                                   ('TargetUserName', 'str', "'carol'"),
                                   ('SrcIp', 'str', "'10.1.1.1'"),
                                   ('LogonType', 'str', "''"),
                                   ('FailureReason', 'str', "''"),
                                   ('AuthMethod', 'str', "''"),
                                   ('Extra',
                                    'dict',
                                    "{'EventID': 4625, 'IpAddress': '10.1.1.1', '@timestamp': "
                                    "'2025-10-13T08:09:00Z'}")]}],
 'list_input': [],
 'int_input': [],
 'json_array_string': [],
 'whitespace_and_null_values': [{'table': 'AuthEvents',
                                 'fields': [('TimeGenerated',
                                             'datetime',
                                             'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                            ('SourceId', 'str', "'src1'"),
                                            ('SourceType', 'str', "'windows_json'"),
                                            ('EventCode', 'str', "'4625'"),
                                            ('EventAction', 'str', "'login'"),
                                            ('EventResult', 'str', "'failure'"),
                                            ('HostName', 'str', "''"),
                                            ('Message', 'str', "'Windows EventID 4625'"),
                                            ('RawEvent',
                                             'str',
                                             '\'{"EventID": 4625, "TargetUserName": "   ", "IpAddress": '
                                             'null, "Status": "", "LogonType": null, '
                                             '"AuthenticationPackageName": "NTLM", "message": null, '
                                             '"Computer": "  "}\''),
                                            ('UserName', 'str', "''"),
                                            ('TargetUserName', 'str', "''"),
                                            ('SrcIp', 'str', "''"),
                                            ('LogonType', 'str', "''"),
                                            ('FailureReason', 'str', "''"),
                                            ('AuthMethod', 'str', "'NTLM'"),
                                            ('Extra',
                                             'dict',
                                             "{'EventID': 4625, 'IpAddress': None, 'Status': '', "
                                             "'AuthenticationPackageName': 'NTLM', 'message': None, "
                                             "'Computer': '  '}")]}],
 'event_data_not_dict': [{'table': 'AuthEvents',
                          'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                     ('SourceId', 'str', "'src1'"),
                                     ('SourceType', 'str', "'windows_json'"),
                                     ('EventCode', 'str', "'4624'"),
                                     ('EventAction', 'str', "'login'"),
                                     ('EventResult', 'str', "'success'"),
                                     ('HostName', 'str', "''"),
                                     ('Message', 'str', "'Windows EventID 4624'"),
                                     ('RawEvent',
                                      'str',
                                      '\'{"EventID": 4624, "event_data": "oops", "TargetUserName": "carol", '
                                      '"IpAddress": "10.1.1.1"}\''),
                                     ('UserName', 'str', "'carol'"),
                                     ('TargetUserName', 'str', "'carol'"),
                                     ('SrcIp', 'str', "'10.1.1.1'"),
                                     ('LogonType', 'str', "''"),
                                     ('FailureReason', 'str', "''"),
                                     ('AuthMethod', 'str', "''"),
                                     ('Extra',
                                      'dict',
                                      "{'EventID': 4624, 'event_data': 'oops', 'IpAddress': '10.1.1.1'}")]}],
 'nested_arrays_4688': [{'table': 'ProcessEvents',
                         'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 10)'),
                                    ('SourceId', 'str', "'src1'"),
                                    ('SourceType', 'str', "'windows_json'"),
                                    ('EventCode', 'str', "'4688'"),
                                    ('EventAction', 'str', "'process_start'"),
                                    ('EventResult', 'str', "'unknown'"),
                                    ('HostName', 'str', "''"),
                                    ('Message', 'str', "'Windows EventID 4688'"),
                                    ('RawEvent',
                                     'str',
                                     '\'{"EventID": 4688, "tags": ["a", {"b": 1}], "@timestamp": '
                                     '"2025-10-13T08:10:00Z", "event_data": {"NewProcessName": '
                                     '"C:\\\\\\\\a\\\\\\\\b.exe", "NewProcessId": "420", "CommandLine": '
                                     '"b.exe -x", "ParentProcessName": "C:\\\\\\\\a\\\\\\\\parent.exe", '
                                     '"ParentProcessId": "1", "User": "LAB\\\\\\\\svc"}}\''),
                                    ('ProcessName', 'str', "'C:\\\\a\\\\b.exe'"),
                                    ('ProcessPath', 'str', "''"),
                                    ('ProcessCmdLine', 'str', "'b.exe -x'"),
                                    ('ProcessId', 'int', '420'),
                                    ('ParentProcessName', 'str', "'C:\\\\a\\\\parent.exe'"),
                                    ('ParentProcessId', 'int', '1'),
                                    ('ParentCmdLine', 'str', "''"),
                                    ('FileHash', 'str', "''"),
                                    ('IntegrityLevel', 'str', "''"),
                                    ('UserName', 'str', "'LAB\\\\svc'"),
                                    ('Extra',
                                     'dict',
                                     "{'EventID': 4688, 'tags': ['a', {'b': 1}], '@timestamp': "
                                     "'2025-10-13T08:10:00Z', 'event_data': {'NewProcessName': "
                                     "'C:\\\\a\\\\b.exe', 'NewProcessId': '420', 'CommandLine': 'b.exe -x', "
                                     "'ParentProcessName': 'C:\\\\a\\\\parent.exe', 'ParentProcessId': '1', "
                                     "'User': 'LAB\\\\svc'}}")]}],
 'process_dotted_keys': [{'table': 'GenericEvents',
                          'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 11)'),
                                     ('SourceId', 'str', "'src1'"),
                                     ('SourceType', 'str', "'windows_json'"),
                                     ('EventCode', 'str', "''"),
                                     ('EventAction', 'str', "''"),
                                     ('EventResult', 'str', "'unknown'"),
                                     ('HostName', 'str', "'linux-ish'"),
                                     ('Message', 'str', "'Windows EventID '"),
                                     ('RawEvent',
                                      'str',
                                      '\'{"event.code": "4688", "process": {"pid": 555, "name": "bash", '
                                      '"command_line": "bash -c id", "parent": {"pid": 1}}, "host": {"name": '
                                      '"linux-ish"}, "user": {"name": "root"}, "@timestamp": '
                                      '"2025-10-13T08:11:00Z"}\''),
                                     ('Extra',
                                      'dict',
                                      "{'event.code': '4688', 'process': {'pid': 555, 'name': 'bash', "
                                      "'command_line': 'bash -c id', 'parent': {'pid': 1}}, 'host': {'name': "
                                      "'linux-ish'}, 'user': {'name': 'root'}, '@timestamp': "
                                      "'2025-10-13T08:11:00Z'}")]}],
 'zero_process_id': [{'table': 'ProcessEvents',
                      'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                 ('SourceId', 'str', "'src1'"),
                                 ('SourceType', 'str', "'windows_json'"),
                                 ('EventCode', 'str', "'1'"),
                                 ('EventAction', 'str', "'process_start'"),
                                 ('EventResult', 'str', "'unknown'"),
                                 ('HostName', 'str', "''"),
                                 ('Message', 'str', "'Windows EventID 1'"),
                                 ('RawEvent',
                                  'str',
                                  '\'{"EventID": 1, "ProcessId": "0", "NewProcessId": null, "Image": '
                                  '"x.exe"}\''),
                                 ('ProcessName', 'str', "'x.exe'"),
                                 ('ProcessPath', 'str', "'x.exe'"),
                                 ('ProcessCmdLine', 'str', "''"),
                                 ('ProcessId', 'NoneType', 'None'),
                                 ('ParentProcessName', 'str', "''"),
                                 ('ParentProcessId', 'NoneType', 'None'),
                                 ('ParentCmdLine', 'str', "''"),
                                 ('FileHash', 'str', "''"),
                                 ('IntegrityLevel', 'str', "''"),
                                 ('UserName', 'str', "''"),
                                 ('Extra',
                                  'dict',
                                  "{'EventID': 1, 'NewProcessId': None, 'Image': 'x.exe'}")]}],
 'timestamp_unparseable': [{'table': 'ProcessEvents',
                            'fields': [('TimeGenerated',
                                        'datetime',
                                        'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('EventCode', 'str', "'1'"),
                                       ('EventAction', 'str', "'process_start'"),
                                       ('EventResult', 'str', "'unknown'"),
                                       ('HostName', 'str', "''"),
                                       ('Message', 'str', "'Windows EventID 1'"),
                                       ('RawEvent', 'str', '\'{"EventID": 1, "@timestamp": "not-a-date"}\''),
                                       ('ProcessName', 'str', "''"),
                                       ('ProcessPath', 'str', "''"),
                                       ('ProcessCmdLine', 'str', "''"),
                                       ('ProcessId', 'NoneType', 'None'),
                                       ('ParentProcessName', 'str', "''"),
                                       ('ParentProcessId', 'NoneType', 'None'),
                                       ('ParentCmdLine', 'str', "''"),
                                       ('FileHash', 'str', "''"),
                                       ('IntegrityLevel', 'str', "''"),
                                       ('UserName', 'str', "''"),
                                       ('Extra', 'dict', "{'EventID': 1, '@timestamp': 'not-a-date'}")]}],
 'timestamp_epoch_ms': [{'table': 'ProcessEvents',
                         'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                    ('SourceId', 'str', "'src1'"),
                                    ('SourceType', 'str', "'windows_json'"),
                                    ('EventCode', 'str', "'1'"),
                                    ('EventAction', 'str', "'process_start'"),
                                    ('EventResult', 'str', "'unknown'"),
                                    ('HostName', 'str', "''"),
                                    ('Message', 'str', "'Windows EventID 1'"),
                                    ('RawEvent', 'str', '\'{"EventID": 1, "timestamp": 1760313600000}\''),
                                    ('ProcessName', 'str', "''"),
                                    ('ProcessPath', 'str', "''"),
                                    ('ProcessCmdLine', 'str', "''"),
                                    ('ProcessId', 'NoneType', 'None'),
                                    ('ParentProcessName', 'str', "''"),
                                    ('ParentProcessId', 'NoneType', 'None'),
                                    ('ParentCmdLine', 'str', "''"),
                                    ('FileHash', 'str', "''"),
                                    ('IntegrityLevel', 'str', "''"),
                                    ('UserName', 'str', "''"),
                                    ('Extra', 'dict', "{'EventID': 1, 'timestamp': 1760313600000}")]}],
 'extra_fields_kept': [{'table': 'AuthEvents',
                        'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2025, 10, 13, 8, 12)'),
                                   ('SourceId', 'str', "'src1'"),
                                   ('SourceType', 'str', "'windows_json'"),
                                   ('EventCode', 'str', "'4624'"),
                                   ('EventAction', 'str', "'login'"),
                                   ('EventResult', 'str', "'success'"),
                                   ('HostName', 'str', "''"),
                                   ('Message', 'str', "'logon'"),
                                   ('RawEvent',
                                    'str',
                                    '\'{"EventID": 4624, "custom_top": "keep me", "winlog": {"channel": '
                                    '"Security"}, "message": "logon", "@timestamp": "2025-10-13T08:12:00Z", '
                                    '"event_data": {"TargetUserName": "d", "ExtraEdata": "not extra"}}\''),
                                   ('UserName', 'str', "'d'"),
                                   ('TargetUserName', 'str', "'d'"),
                                   ('SrcIp', 'str', "''"),
                                   ('LogonType', 'str', "''"),
                                   ('FailureReason', 'str', "''"),
                                   ('AuthMethod', 'str', "''"),
                                   ('Extra',
                                    'dict',
                                    "{'EventID': 4624, 'custom_top': 'keep me', 'winlog': {'channel': "
                                    "'Security'}, 'message': 'logon', '@timestamp': '2025-10-13T08:12:00Z', "
                                    "'event_data': {'TargetUserName': 'd', 'ExtraEdata': 'not extra'}}")]}],
 'sysmon8_remote_thread': [{'table': 'ProcessEvents',
                            'fields': [('TimeGenerated',
                                        'datetime',
                                        'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                       ('SourceId', 'str', "'src1'"),
                                       ('SourceType', 'str', "'windows_json'"),
                                       ('EventCode', 'str', "'8'"),
                                       ('EventAction', 'str', "''"),
                                       ('EventResult', 'str', "'unknown'"),
                                       ('HostName', 'str', "''"),
                                       ('Message', 'str', "'Windows EventID 8'"),
                                       ('RawEvent',
                                        'str',
                                        '\'{"EventID": 8, "SourceImage": "a.exe", "TargetImage": "b.exe"}\''),
                                       ('ProcessName', 'str', "''"),
                                       ('ProcessPath', 'str', "''"),
                                       ('ProcessCmdLine', 'str', "''"),
                                       ('ProcessId', 'NoneType', 'None'),
                                       ('ParentProcessName', 'str', "''"),
                                       ('ParentProcessId', 'NoneType', 'None'),
                                       ('ParentCmdLine', 'str', "''"),
                                       ('FileHash', 'str', "''"),
                                       ('IntegrityLevel', 'str', "''"),
                                       ('UserName', 'str', "''"),
                                       ('Extra',
                                        'dict',
                                        "{'EventID': 8, 'SourceImage': 'a.exe', 'TargetImage': 'b.exe'}")]}],
 'unicode_values': [{'table': 'AuthEvents',
                     'fields': [('TimeGenerated', 'datetime', 'datetime.datetime(2026, 1, 2, 3, 4, 5)'),
                                ('SourceId', 'str', "'src1'"),
                                ('SourceType', 'str', "'windows_json'"),
                                ('EventCode', 'str', "'4625'"),
                                ('EventAction', 'str', "'login'"),
                                ('EventResult', 'str', "'failure'"),
                                ('HostName', 'str', "'工作站'"),
                                ('Message', 'str', "'失败 ✓'"),
                                ('RawEvent',
                                 'str',
                                 '\'{"EventID": 4625, "TargetUserName": "\\\\u7528\\\\u6237", "Computer": '
                                 '"\\\\u5de5\\\\u4f5c\\\\u7ad9", "message": "\\\\u5931\\\\u8d25 '
                                 '\\\\u2713"}\''),
                                ('UserName', 'str', "'用户'"),
                                ('TargetUserName', 'str', "'用户'"),
                                ('SrcIp', 'str', "''"),
                                ('LogonType', 'str', "''"),
                                ('FailureReason', 'str', "''"),
                                ('AuthMethod', 'str', "''"),
                                ('Extra',
                                 'dict',
                                 "{'EventID': 4625, 'Computer': '工作站', 'message': '失败 ✓'}")]}]}
# ---- /GOLDEN ----


@pytest.fixture(autouse=True)
def _pinned_clock_and_tz(monkeypatch):
    """Fixed fallback clock, and TZ=UTC so datetime.fromtimestamp output is stable."""
    # _utcnow is looked up in each parser module (parsers were split into _parsers_*.py), so freeze them all.
    for mod_name, mod in list(sys.modules.items()):
        if (mod_name == "siempl.ingest.parsers" or mod_name.startswith("siempl.ingest._parsers_")) and hasattr(
            mod, "_utcnow"
        ):
            monkeypatch.setattr(mod, "_utcnow", lambda: FIXED_NOW)
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def snapshot(events) -> list:
    """Exact, order-preserving, type-aware image of parser output."""
    return [{"table": e.table,
             "fields": [(k, type(v).__name__, repr(v)) for k, v in e.fields.items()]} for e in events]


@pytest.mark.parametrize("name", list(CASES))
def test_char_wineventjson_golden(name):
    assert snapshot(parse_windows_json(CASES[name], "src1")) == GOLDEN[name]


def test_char_wineventjson_golden_covers_every_case():
    assert set(GOLDEN) == set(CASES)


def test_char_wineventjson_dict_input_is_not_mutated():
    raw = json.loads(json.dumps(CASES["sysmon1_flat_otrf"]))
    before = json.dumps(raw, sort_keys=True)
    parse_windows_json(raw, "src1")
    assert json.dumps(raw, sort_keys=True) == before


@pytest.mark.parametrize("raw", [
    {"EventID": 3, "SourcePort": "abc"},
    {"EventID": 1, "ProcessId": "abc"},
    {"EventID": 1, "ParentProcessId": "x1"},
])
def test_char_wineventjson_nonnumeric_numeric_field_raises_current_behavior(raw):
    """Pins CURRENT behavior: a non-numeric value in a numeric column raises ValueError from int().

    This is a known latent bug (one bad record aborts the parse). It is pinned here so the refactor
    cannot change it silently. Fixing it is a separate, deliberate behavior change.
    """
    with pytest.raises(ValueError):
        parse_windows_json(raw, "src1")
