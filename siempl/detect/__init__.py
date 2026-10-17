"""Detection engine: rule management, Sigma/Sentinel import, rule scheduling,
alert/incident creation, and built-in rules.

Public API
----------
RuleStore(db)                    — CRUD for rules table
sigma_to_rule(yaml_text, ref)    — Sigma YAML → rule dict
sentinel_to_rule(yaml_text, ref) — Sentinel YAML → rule dict
RuleRunner(db)                   — runs due rules, creates alerts
create_alert(db, rule, rows, cols) → alert_id | None
set_verdict(db, alert_id, verdict, by) → bool
start_scheduler(db)              → daemon thread
UnsupportedRule                  — raised when conversion not possible

Sub-modules
-----------
siempl.detect.engine            — core implementation
siempl.detect.importer          — fetch + cache + import from GitHub
siempl.detect.builtin           — 20+ hand-written KQL rules
"""

from .engine import (
    RuleRunner,
    RuleStore,
    UnsupportedRule,
    create_alert,
    sentinel_to_rule,
    set_verdict,
    sigma_to_rule,
    start_scheduler,
)
