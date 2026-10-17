"""Static lookup tables for Sigma and Sentinel conversion (log source -> table, field -> column)."""
from __future__ import annotations

# logsource category -> our table
SIGMA_LOGSOURCE_TABLE: dict[str, str] = {
    "process_creation": "ProcessEvents",
    "file_event": "FileEvents",
    "network_connection": "NetworkEvents",
    "dns_query": "NetworkEvents",
    "web": "WebAccess",
    "authentication": "AuthEvents",
    "sysmon": "ProcessEvents",     # default; refine with service
    "syslog": "Syslog",
}


# Also map by `product` when category is missing
SIGMA_PRODUCT_TABLE: dict[str, str] = {
    "windows": "ProcessEvents",
    "linux": "Syslog",
    "sysmon": "ProcessEvents",
}


# Sigma field name -> our column name
SIGMA_FIELD_MAP: dict[str, str] = {
    # Process
    "Image": "ProcessPath",
    "CommandLine": "ProcessCmdLine",
    "OriginalFileName": "ProcessName",
    "ProcessName": "ProcessName",
    "ParentImage": "ParentProcessName",
    "ParentCommandLine": "ParentCmdLine",
    "ParentProcessName": "ParentProcessName",
    "ProcessId": "ProcessId",
    "ParentProcessId": "ParentProcessId",
    "IntegrityLevel": "IntegrityLevel",
    "Hashes": "FileHash",
    # User
    "User": "UserName",
    "TargetUserName": "TargetUserName",
    # Network
    "DestinationIp": "DstIp",
    "SourceIp": "SrcIp",
    "DestinationPort": "DstPort",
    "SourcePort": "SrcPort",
    "Initiated": "Direction",
    "Protocol": "Protocol",
    # DNS / URL
    "QueryName": "DnsQuery",
    "c-uri": "Url",
    "Url": "Url",
    "Domain": "Domain",
    # File
    "TargetFilename": "FilePath",
    "FileName": "FileName",
    # Syslog
    "Hostname": "HostName",
    # Generic
    "EventID": "EventCode",
    "EventType": "EventAction",
}


# Sentinel table -> our table, using EventID disambiguation where possible
SENTINEL_TABLE_MAP: dict[str, str] = {
    "SecurityEvent": "AuthEvents",          # 4624/4625 by default
    "Syslog": "Syslog",
    "CommonSecurityLog": "GenericEvents",
    "SigninLogs": "AuthEvents",
    "AuditLogs": "AuthEvents",
    "OfficeActivity": "GenericEvents",
    "AzureActivity": "GenericEvents",
    "DeviceEvents": "GenericEvents",
    "DeviceProcessEvents": "ProcessEvents",
    "DeviceNetworkEvents": "NetworkEvents",
    "DeviceFileEvents": "FileEvents",
    "DeviceLogonEvents": "AuthEvents",
    "EmailEvents": "GenericEvents",
    "AlertEvidence": "GenericEvents",
    "DnsEvents": "NetworkEvents",
    "W3CIISLog": "WebAccess",
    "WindowsEvent": "GenericEvents",
}


# Sentinel column -> our column (best-effort)
SENTINEL_COLUMN_MAP: dict[str, str] = {
    "EventID": "EventCode",
    "Account": "UserName",
    "TargetAccount": "TargetUserName",
    "Computer": "HostName",
    "IpAddress": "SrcIp",
    "SourceIp": "SrcIp",
    "DestinationIp": "DstIp",
    "ProcessName": "ProcessName",
    "CommandLine": "ProcessCmdLine",
    "ParentProcessName": "ParentProcessName",
    "ProcessId": "ProcessId",
    "ParentProcessId": "ParentProcessId",
    "Url": "Url",
    "Domain": "Domain",
    "DnsQuery": "DnsQuery",
    "Port": "DstPort",
    "SourcePort": "SrcPort",
    "DestinationPort": "DstPort",
    "Protocol": "Protocol",
    "LogonType": "LogonType",
    "Activity": "EventAction",
    "FileName": "FileName",
    "FilePath": "FilePath",
    "FolderPath": "FilePath",
    "SHA256": "FileHash",
    "MD5": "FileHash",
    "InitiatingProcessName": "ParentProcessName",
    "InitiatingProcessCommandLine": "ParentCmdLine",
    "AccountName": "UserName",
    "SubjectUserName": "UserName",
    "TargetUserName": "TargetUserName",
    "NewProcessName": "ProcessPath",
    "ParentProcess": "ParentProcessName",
    "Process": "ProcessPath",
    "UserAgent": "UserAgent",
    "StatusCode": "StatusCode",
    "RemoteIP": "SrcIp",
    "LocalIP": "DstIp",
    "SyslogMessage": "Message",
}
