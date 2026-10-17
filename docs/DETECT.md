# Detection engine: source layout

## Source layout (split 2026-10-13)

`siempl/detect/engine.py` used to hold the whole detection engine (1310 lines). It is now a thin facade: it re-exports every
name it used to define, so `from siempl.detect.engine import RuleStore, sigma_to_rule, ...` is unchanged. The code lives
in one module per concern. All 47 definitions were moved verbatim (verified by comparing the syntax tree of each one);
only the section banner comments and the module docstring were replaced by per-module docstrings.

| Module | Contents | Depends on |
|---|---|---|
| `_core.py` | `UnsupportedRule`, JSON column helpers (`_json`, `_json_list`, `_from_json`), `_escape_sql_str` | nothing in the package |
| `_rule_store.py` | `RuleStore`: CRUD for the rules table | core |
| `_convert_maps.py` | Sigma and Sentinel lookup tables (log source -> table, field -> column) | nothing |
| `_sigma_kql.py` | Sigma detection -> KQL condition translation (modifiers, `N of` expansion, condition parser) | core, maps |
| `_convert_common.py` | helpers shared by both converters (timeframe, triage template, entity mappings) | nothing |
| `_sigma_rule.py` | `sigma_to_rule` (pySigma first, hand translator as fallback) | sigma_kql, convert_common, maps, core |
| `_sentinel.py` | `sentinel_to_rule` | convert_common, maps, core |
| `_alerts.py` | `create_alert`, entity extraction, incident grouping, `set_verdict` | core |
| `_runner.py` | `RuleRunner`, `start_scheduler` | alerts, core, `_run_rule` |

Dependencies only point downward (core at the bottom); there are no import cycles. `builtin.py`, `importer.py`,
`sigma_backend.py` and `_run_rule.py` were not changed.

## Rules for working here

- **Monkeypatching:** patch the module that *owns* the function, not the `engine` facade. `sigma_to_rule` looks
  `_sigma_to_rule_pysigma` up in `siempl.detect._sigma_rule`; patching `engine._sigma_to_rule_pysigma` does nothing.
- **Loggers** are per module now (`siempl.detect._runner`, `siempl.detect._alerts` ...), not `siempl.detect.engine`.
  Nothing in the repo filtered on the old name.
- New code goes in the module that owns the concern; do not add definitions to `engine.py`.
