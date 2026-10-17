# Sample Data

`siempl/testdata/sample.py` provides `load_samples(db, seed=42)` and `clear_samples(db)`.

## Usage

```python
from siempl.testdata.sample import load_samples, clear_samples

load_samples(db, seed=42)   # idempotent — running twice adds nothing
clear_samples(db)           # removes ONLY sample-marked rows
```

## What gets loaded

- **9 rules** (origin=manual):
  - 2 intentionally noisy (`sample_any_failed_login`, `sample_dns_tunnel`) for tuning agent exercise
  - 1 disabled (`sample_disabled_rule`)
  - 1 temporary with future `expires_at` (`sample_temp_monitor`)
  - 1 on an empty table (`sample_no_data_table` on FileEvents)
  - 1 on a rarely-queried table (`sample_never_queried` on Syslog)
  - 3 normal severity rules with good triage_steps
- **24 alerts** across severities with mixed statuses and verdicts:
  - Several closed false_positive (tuning feedback + entity reputation)
  - Several true_positive
  - Several new untriaged (clearly malicious SSH kill-chain, clearly benign vuln scanner, ambiguous guest-wifi)
- **3 incidents**:
  - kill-chain (brute force → success → PowerShell → Mimikatz)
  - closed FP campaign
  - empty placeholder
- **20 entities** with varied reputations; one watch-listed (`ip:203.0.113.42`)
- **Raw logs** in GenericEvents: `acme-vpn` key=value lines, `custom-app` JSON lines (for onboarding agent)
- **Table usage skew** for optimizer: WebAccess (huge, 0 rule queries), Syslog (unused), AuthEvents (heavily queried)
- **query_log** entries
- **2 ingest_filters** (one enabled, one disabled)
- **3 recommendations** open (ingest_filter, retention, rule_disable)
- **table_retention** row for Syslog

All rows are identifiable by id prefix (`sample_`) or notes (`sample`).

## Web UI

- `/samples` — dedicated page with **Load sample data** and **Clear sample data** buttons
- `/api/testdata/samples` — POST to load (body `{"seed": 42}`)
- `/api/testdata/samples/clear` — POST to clear

All actions audited as `actor=user:web action=samples.load|samples.clear`.

## Scenarios (agent evaluation)

`siempl/testdata/scenarios.py` adds seven scenarios from the last 24 hours, with rules and alerts created through the normal paths (`RuleStore`, `create_alert`, `set_status`):

- `brute_force_to_compromise`: spray, RDP success, encoded PowerShell, new local admin (4 alerts)
- `lateral_movement`: NTLM fan-out, SMB ADMIN$, RDP (3 alerts)
- `data_exfil`: bulk TLS to a rare IP, DNS tunnel-like labels, benign sync client (3 alerts)
- `noisy_false_positive`: backup account, 8 hosts, one low alert per host, 6 closed_fp (8 alerts)
- `prompt_injection_attempts`: three true positives with injection text in logs (3 alerts)
- `chatty_source`: 4000 debug Syslog rows, for the optimizer
- `new_unparsed_source`: pending source with raw GenericEvents lines, for onboarding

```python
from siempl.testdata.scenarios import load_scenarios, reset_scenarios, scenario_manifest

load_scenarios(db)                 # idempotent; skips scenarios already loaded
reset_scenarios(db)                # removes only scn-* sources/rows and scn_* rules/alerts
scenario_manifest()                # expected triage per alert (scenarios_manifest.json)
```

Tags: event rows have `SourceId` `scn-<name>`, rules have ids `scn_*`. Web: `/samples` buttons, `POST` and `DELETE` `/api/samples/scenarios`.

Reset limits: SiemplAudit keeps the `scenarios.load` and `scenarios.reset` records, and the `table_usage` bump is reversed on today's row only (best effort). Alert numbers are not reused.
