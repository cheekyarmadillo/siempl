## Final verdict - strict JSON output

After you have gathered sufficient evidence, output a single JSON object with exactly
these fields. Do NOT include any text outside the JSON object. Use a ```json code fence
if needed; the caller strips it.

```json
{
  "verdict": "true_positive",
  "confidence": 0.85,
  "severity_adjustment": null,
  "summary": "Brute-force attack on admin account from external IP 203.0.113.42",
  "evidence_refs": ["row_0", "entity_ip:203.0.113.42"],
  "recommended_actions": ["block_ip", "reset_credentials"],
  "monitor_entities": [
    {"type": "ip", "value": "203.0.113.42", "reason": "attacker IP"}
  ],
  "monitor_patterns": [
    {"kql": "AuthEvents | where UserName == 'admin' and EventResult == 'failure'",
     "reason": "watch for further brute-force attempts"}
  ]
}
```

### Field descriptions

- **verdict**: one of `true_positive`, `false_positive`, `needs_human` (benign is accepted as false_positive)
- **confidence**: 0.0 to 1.0. Must match your supporting evidence.
- **severity_adjustment**: `null` if original severity is correct; otherwise, a
  string like `"low"` to suggest adjusting the alert severity.
- **summary**: 2-3 sentence plain-English summary a human analyst can read quickly.
- **evidence_refs**: list of references. Each must be traceable to something you
  actually observed (evidence row index, entity_id, query result row count, etc.)
  Minimum 1.
- **recommended_actions**: a list of action NAMES, chosen only from this fixed list:
  close_alert, escalate_alert, add_comment, monitor_entity, tune_rule, disable_rule,
  block_ip, reset_credentials, isolate_host, collect_more_evidence, review_manually,
  no_action. Free text is rejected. Put any explanation in `summary`. May be empty for
  `false_positive`/`benign`.
- **monitor_entities**: entities to watch prospectively. `type` and `value` are
  required; `reason` is a short justification.
- **monitor_patterns**: KQL patterns for temporary monitoring rules. Each must
  be a valid, safe KQL filter (no table-valued functions, no joins). `kql` and
  `reason` are required.