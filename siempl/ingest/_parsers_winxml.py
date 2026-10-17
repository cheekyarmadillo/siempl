"""Windows Event Log XML parser."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ._parsers_core import _parse_json_timestamp, _utcnow, register
from ._parsers_windows import WIN_EVENT_ACTION, WIN_EVENT_TABLE
from .types import NormalizedEvent

# -- Windows XML parser -------------------------------------------------------


def _xml_int(val):
    """Parse int from Windows XML, handling hex strings (0xe7c)."""
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            return int(s, 16)  # Windows XML often has hex ProcessIds
        except ValueError:
            return None


@register("windows_xml")
def parse_windows_xml(raw, source_id):
    """Parse Windows Event Log XML to the same tables as windows_json.
    Handles single events and multi-event EVTX-export streams.
    Uses regex extraction to avoid split() matching inside <EventID> tags."""
    msg = raw if isinstance(raw, str) else str(raw)
    now = _utcnow()
    xml_text = msg.strip()
    if "<" not in xml_text or "Event" not in xml_text:
        return [
            NormalizedEvent(
                table="GenericEvents",
                fields={
                    "TimeGenerated": now,
                    "SourceId": source_id,
                    "SourceType": "windows_xml",
                    "Message": msg[:1000],
                    "RawEvent": msg,
                    "EventCode": "",
                    "EventAction": "",
                    "EventResult": "unknown",
                    "HostName": "",
                },
            )
        ]
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    for m in re.finditer(r"<Event\b.*?</Event>", xml_text, re.DOTALL):
        xml_doc = m.group(0)
        try:
            root = ET.fromstring(xml_doc)
        except ET.ParseError:
            continue
        sys_elem = root.find("e:System", ns)
        if sys_elem is None:
            sys_elem = root.find("System")
        if sys_elem is None:
            continue

        def _xml_find(path, attr=None, default=""):
            el = sys_elem.find(f"e:{path}", ns)
            if el is None:
                el = sys_elem.find(path)
            if el is None:
                return default
            if attr:
                return el.get(attr, default)
            return el.text or default

        event_id = _xml_find("EventID", default="")
        target = WIN_EVENT_TABLE.get(event_id, "GenericEvents")
        event_action = WIN_EVENT_ACTION.get(event_id, "")
        event_result = "success" if event_id == "4624" else ("failure" if event_id == "4625" else "unknown")
        ts = now
        ts_str = _xml_find("TimeCreated", attr="SystemTime", default="")
        if ts_str:
            dt = _parse_json_timestamp(ts_str)
            if dt:
                ts = dt
        hostname = _xml_find("Computer")
        fields = {
            "TimeGenerated": ts,
            "SourceId": source_id,
            "SourceType": "windows_xml",
            "EventCode": event_id,
            "EventAction": event_action,
            "EventResult": event_result,
            "HostName": hostname,
            "Message": f"Windows EventID {event_id}",
            "RawEvent": xml_doc,
        }
        # Extract EventData/Data elements
        evd = root.find("e:EventData", ns)
        if evd is None:
            evd = root.find("EventData")
        edata = {}
        if evd is not None:
            items = evd.findall("e:Data", ns)
            if not items:
                items = evd.findall("Data")
            for d in items:
                name = d.get("Name") or d.get("name", "")
                if name:
                    edata[name] = d.text or ""
        # Same mapping as windows_json
        if target == "AuthEvents":
            fields["UserName"] = edata.get("TargetUserName", edata.get("SubjectUserName", ""))
            fields["TargetUserName"] = fields["UserName"] or edata.get("TargetUserName", "")
            fields["SrcIp"] = edata.get("IpAddress", "")
            fields["LogonType"] = edata.get("LogonType", "")
            fields["FailureReason"] = edata.get("FailureReason", edata.get("Status", ""))
            fields["AuthMethod"] = edata.get("AuthenticationPackageName", "")
        elif target == "ProcessEvents":
            fields["ProcessName"] = edata.get("NewProcessName", edata.get("Image", ""))
            fields["ProcessPath"] = edata.get("Image", edata.get("NewProcessName", ""))
            fields["ProcessCmdLine"] = edata.get("CommandLine", "")
            fields["ProcessId"] = _xml_int(edata.get("NewProcessId", edata.get("ProcessId", 0)))
            fields["ParentProcessName"] = edata.get("ParentProcessName", edata.get("ParentImage", ""))
            fields["ParentProcessId"] = _xml_int(edata.get("ParentProcessId", 0))
            fields["ParentCmdLine"] = edata.get("ParentCommandLine", "")
            fields["FileHash"] = edata.get("Hashes", "")
            fields["IntegrityLevel"] = edata.get("IntegrityLevel", "")
            fields["UserName"] = edata.get("User", edata.get("SubjectUserName", ""))
        elif target == "NetworkEvents":
            fields["SrcIp"] = edata.get("SourceIp", edata.get("IpAddress", ""))
            fields["DstIp"] = edata.get("DestinationIp", "")
            fields["SrcPort"] = _xml_int(edata.get("SourcePort", 0))
            fields["DstPort"] = _xml_int(edata.get("DestinationPort", 0))
            fields["Protocol"] = edata.get("Protocol", "")
            fields["DnsQuery"] = edata.get("QueryName", edata.get("DnsQuery", ""))
            fields["ProcessName"] = edata.get("Image", "")
        elif target == "FileEvents":
            fields["FilePath"] = edata.get("TargetFilename", edata.get("FilePath", ""))
            fields["FileName"] = edata.get("TargetFilename", edata.get("FileName", ""))
            fields["FileHash"] = edata.get("Hashes", "")
            fields["ProcessName"] = edata.get("Image", "")
        mapped_columns = {
            "TimeGenerated",
            "SourceId",
            "SourceType",
            "EventCode",
            "EventAction",
            "EventResult",
            "HostName",
            "Message",
            "RawEvent",
            "Extra",
        }
        extra = {k: v for k, v in edata.items() if k not in fields and k not in mapped_columns}
        fields["Extra"] = extra
        events.append(NormalizedEvent(table=target, fields=fields))
    if not events:
        return [
            NormalizedEvent(
                table="GenericEvents",
                fields={
                    "TimeGenerated": now,
                    "SourceId": source_id,
                    "SourceType": "windows_xml",
                    "Message": msg[:1000],
                    "RawEvent": msg,
                    "EventCode": "",
                    "EventAction": "",
                    "EventResult": "unknown",
                    "HostName": "",
                },
            )
        ]
    return events
