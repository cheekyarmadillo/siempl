## Available tools

You have access to the following tools. Call them via tool_calls when you need information
not already present in the evidence rows.

### run_kql(query: str) -> QueryResult

Run a read-only KQL query against the event tables. The query must start with a table name
and `| where` clause. You may use `take`, `summarize`, `count`, `order by`, `project`,
`extend`, `ago()`, `startofday()`, `bin()`, `distinct`, and `mv-expand`.

**Row cap:** queries automatically limit to 2000 rows. If you need a targeted query, use
`where` filters aggressively.

**Tables available:** Syslog, AuthEvents, ProcessEvents, NetworkEvents, WebAccess, FileEvents, GenericEvents.
Common columns: TimeGenerated, HostName, UserName, SrcIp, DstIp, ProcessName, ProcessCmdLine.

**Examples:**
```
AuthEvents | where UserName == "bob" and TimeGenerated > ago(1h) | take 50
ProcessEvents | where HostName == "SRV01" and ProcessName == "powershell.exe" | take 100
NetworkEvents | where DstIp == "10.0.0.5" and Direction == "outbound" | take 50
```

### get_entity(type: str, value: str) -> EntityRecord

Look up an entity by type and value. Returns:
- entity_id, type, value, first_seen, last_seen
- reputation (0=benign .. 100=malicious, 50=unknown)
- tp_count, fp_count, alert_count, event_count
- attributes (JSON), watch (bool), notes

Valid types: user, host, ip, process, file_hash, domain.

### get_related_alerts(entity_id: str) -> list[AlertSummary]

Returns recent alerts (last 90 days, max 50) where the given entity appeared.
Each summary includes: alert_id, title, severity, verdict, created_at, rule_id.

### lookup_ip_reputation(ip: str) -> IPReputation

Look up an IP address in the local entity store. Returns the entity record if found,
plus a note that external TI connectors (AbuseIPDB, VirusTotal) are NOT implemented.
The reputation value already reflects prior alert verdicts applied to this IP.

This is a stub that reads the local entity store only. Extension point: replace with
real TI connector calls once external API keys and safety checks are in place.