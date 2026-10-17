#!/usr/bin/env python3
"""Snapshot the SQL the KQL compiler emits for a broad corpus of queries (tests/, siempl/ source, docs/KQL.md, hand-written set).
Usage: python scripts/kql_corpus_snapshot.py OUT.json   (run from a repo root; normally via scripts/compare_kql_vs_ref.sh)"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.getcwd())

SIEMPL_HOME = tempfile.mkdtemp()
os.environ["SIEMPL_HOME"] = SIEMPL_HOME

from siempl.kql import compile_kql


def harvest_from_file(path: str) -> list[str]:
    results = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        text = f.read()
    # Find triple-quoted KQL strings
    for m in re.finditer(r'(?s)("""|\'\'\')(.*?)\1', text):
        inner = m.group(2)
        if "|" in inner or any(op in inner for op in ("where","project","summarize")):
            results.append(inner.strip())
    # Find single/double quoted strings with pipe keywords
    for m in re.finditer(r'(?s)([rR]?)"([^"\\]*(?:\\.[^"\\]*)*)"', text):
        inner = m.group(2).replace('\\n','\n').replace('\\t','\t').replace('\\"','"')
        if "|" in inner and len(inner) > 10:
            results.append(inner)
    for m in re.finditer(r"(?s)([rR]?)'([^'\\]*(?:\\.[^'\\]*)*)'", text):
        inner = m.group(2).replace('\\n','\n').replace('\\t','\t').replace("\\'","'")
        if "|" in inner and len(inner) > 10:
            results.append(inner)
    # YAML dict query values
    for line in text.splitlines():
        m = re.match(r"\s*[\"']?query[\"']?\s*[:=]\s*[\"'](.+)[\"']\s*,?\s*$", line)
        if m:
            results.append(m.group(1))
    return [r.strip() for r in results if r.strip() and len(r.strip())>5]

def harvest_builtin_queries() -> list[str]:
    results = []
    for root, dirs, files in os.walk("siempl"):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(r'(?s)("""|\'\'\')(.*?)\1', text):
                inner = m.group(2)
                if "|" in inner and any(op in inner.lower() for op in ("where","project","summarize","take","extend","join","union","count","distinct")):
                    results.append(inner.strip())
            for m in re.finditer(r'(?s)["\']query["\']\s*[:=]\s*["\'](.+?)["\']', text):
                q = m.group(1)
                if "|" in q:
                    results.append(q)
            for m in re.finditer(r'(?s)["\']kql["\']\s*[:=]\s*["\'](.+?)["\']', text):
                q = m.group(1)
                if "|" in q:
                    results.append(q)
    for root, dirs, files in os.walk("siempl"):
        for fn in files:
            if fn.endswith((".yaml",".yml")):
                with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                for m in re.finditer(r'(?m)^query:\s*(.+)$', text):
                    q = m.group(1).strip()
                    if "|" in q:
                        results.append(q)
    return [r.strip() for r in results if r.strip() and len(r.strip())>5]

def harvest_docs() -> list[str]:
    path = "docs/KQL.md"
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    results = []
    in_code = False
    buf = []
    for line in text.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                s = "\n".join(buf).strip()
                if s and "|" in s:
                    results.append(s)
                buf = []
            in_code = not in_code
            continue
        if in_code:
            buf.append(line)
    return results

all_queries = set()
for root, dirs, files in os.walk("tests"):
    for fn in files:
        if not fn.endswith(".py"):
            continue
        for q in harvest_from_file(os.path.join(root, fn)):
            all_queries.add(q)
for q in harvest_builtin_queries():
    all_queries.add(q)
for q in harvest_docs():
    all_queries.add(q)

# Extra minimal set to increase coverage
extras = [
    'Syslog | where Sev == 5 | project TimeGenerated, HostName, Message | take 10',
    'AuthEvents | where EventResult == "failure" | summarize count() by UserName',
    'ProcessEvents | where ProcessName contains "cmd" | extend UpperName = toupper(ProcessName)',
    'WebAccess | where StatusCode >= 400 | summarize dcount(SrcIp) by DstPort',
    'NetworkEvents | where SrcIp != DstIp | join kind=inner (AuthEvents | where EventResult == "failure") on SrcIp',
    'Syslog | where Message matches regex "test" | project TimeGenerated',
    'Syslog | where Message startswith "abc" | where Message endswith "xyz" | where Message contains "m" | where Message has "word" | where Message has_cs "WORD"',
    'Syslog | where Message has_any ("a","b","c") | where Message has_all ("a","b")',
    'Syslog | contains "test"',
    'let x = 1; Syslog | where Sev == x',
    'Syslog | project-away Message, Sev',
    'Syslog | project-rename Host = HostName',
    'Syslog | project-reorder TimeGenerated, HostName, Message, Sev',
    'Syslog | mv-expand col1',
    'Syslog | sort by TimeGenerated desc, HostName asc',
    'Syslog | top 5 by TimeGenerated',
    'Syslog | limit 10',
    'union Syslog, AuthEvents',
    'Syslog | search "test"',
    'Syslog | parse Message with * ": " Code',
    'Syslog | distinct HostName',
    'Syslog | summarize cnt=count() by bin(TimeGenerated, 1h)',
    'Syslog | where TimeGenerated between (ago(1h) .. now())',
    'Syslog | where isempty(Message) | where isnotempty(Message) | where isnull(Sev) | where isnotnull(Sev)',
    'Syslog | extend x = iff(Sev > 3, "high", "low")',
    'Syslog | extend x = case(Sev > 5, "crit", Sev > 3, "high", "low")',
    'Syslog | extend x = coalesce(Sev, 0)',
    'Syslog | extend x = strcat(HostName, "-", Sev)',
    'Syslog | extend x = strlen(HostName)',
    'Syslog | extend x = substring(HostName, 0, 3)',
    'Syslog | extend x = tolower(HostName)',
    'Syslog | extend x = toupper(HostName)',
    'Syslog | extend x = replace_string(HostName, "a", "b")',
    'Syslog | extend x = split(HostName, ".")',
    'Syslog | extend x = extract("[0-9]+", 0, HostName)',
    'Syslog | extend x = parse_json(\'{"a":1}\')',
    'Syslog | extend x = array_length(split(HostName, "."))',
    'Syslog | extend x = pack("a", 1, "b", 2)',
    'Syslog | extend x = range(0, 10, 1)',
    'Syslog | extend x = toscalar(Syslog | take 1 | project Sev)',
    'Syslog | where ipv4_is_private(SrcIp)',
    'Syslog | where cidr_contains(SrcIp, "10.0.0.0/8")',
    'let x = toscalar(Syslog | summarize max(Sev)); Syslog | where Sev < x',
    'Syslog | extend x = now()',
    'Syslog | extend x = ago(1h)',
    'Syslog | extend x = datetime("2024-01-01")',
    'Syslog | extend x = floor(TimeGenerated, 1h)',
    'Syslog | extend x = startofday(TimeGenerated)',
    'Syslog | extend x = format_datetime(TimeGenerated, "%Y-%m-%d")',
    'Syslog | where Message =~ "test"',
    'Syslog | where Message !~ "test"',
    'Syslog | where Message in ("a","b","c")',
    'Syslog | where Message !in ("a","b","c")',
    'Syslog | where Message in~ ("a","b","c")',
    'Syslog | where Message !contains "x"',
    'Syslog | where Message !contains_cs "X"',
    'Syslog | where Message !has "x"',
    'Syslog | where Message !has_cs "X"',
    'Syslog | where Message !startswith "x"',
    'Syslog | where Message !endswith "x"',
    'Syslog | where Message !has_any ("a","b")',
]
for q in extras:
    all_queries.add(q)

results = {}
errors = []
for q in sorted(all_queries, key=len):
    try:
        cq = compile_kql(q)
        results[q] = {"sql": cq.sql, "params": cq.params, "tables": sorted(cq.tables)}
    except Exception as e:
        errors.append({"query": q, "error": str(e)})

ordered = {"ok": {k: results[k] for k in sorted(results)}, "errors": errors}
out_path = sys.argv[1]
with open(out_path, "w") as f:
    json.dump(ordered, f, indent=2, sort_keys=True, default=str)
print(f"Wrote {len(results)} OK, {len(errors)} errors to {out_path}")
