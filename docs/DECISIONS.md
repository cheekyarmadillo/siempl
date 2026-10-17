# Decisions log (ADR-style)

Dated records of product and architecture decisions. Newest last. Each entry: context, decision, reasons, consequences.

---

## D-2026-10-12-1: KQL box stays for analysts and hand-written rules

**Status:** accepted

**Context.** The Rules page has a KQL query box, and the spec asks for a KQL-capable store. Sigma rules and
Sentinel rules arrive in other languages. The question was whether to keep KQL as the only rule language.

**Decision.** Keep the KQL editor and the Test Query button. KQL is the language analysts type and the
language of hand-written rules (`origin = manual`).

**Reasons.** Analysts already think in KQL against the same tables. The spec requires KQL. KQL is the
language our own engine executes today.

**Consequences.** The engine must keep a KQL compiler and executor. Non-KQL content is converted or stored
as source (see D-2026-10-12-2).

---

## D-2026-10-12-2: Sigma via pySigma is the primary content path

**Status:** accepted (2026-10-12)

**Context.** Our own Sigma-to-KQL importer converts about 1503 of 1543 rules. The spike found that 100
of those converted rules compile to a condition of just `true` and match every row, which is a real bug.
pySigma converts all 1543 and has an SQL backend.

**Decision.** Sigma rules are converted with pySigma (SQL backend, DuckDB dialect shims). The Sigma source
and generated SQL are stored. The KQL box stays for analysts (D-2026-10-12-1). The own-importer path is
retired once the pySigma integration lands; the match-everything bug is fixed in the meantime regardless.

**Measured numbers** (from the pySigma spike; 1,543 rules, process_creation, file_event,
network_connection, dns_query; windows + linux):

- Converts: pySigma 1543/1543. Ours 1503/1543 (40 unsupported: 36 "1 of" patterns with no matches, 4 recursion limit).
- pySigma SQL executes on DuckDB for 1543/1543 after 3 dialect shims (REGEXP to regexp_matches, LIKE to ILIKE, keep ESCAPE).
- Ours: 100 of 1503 imported rules compile to `true`; 143 contain a literal `true`.
- On test data (1375 rules compared): agree 1272 (1265 both zero), disagree 103; in 98 of those ours matches every row.
- Seeded attacks (certutil download, encoded powershell, whoami): pySigma finds 14 rules; ours matches the same count on only 7.

**Reasons.** Coverage (1543 vs 1503), correctness (the `true` bug), and a maintained upstream grammar instead
of our own modifier code.

**Open risks.**
- Schema: NetworkEvents and FileEvents have no process-image column, so Image/ParentImage fields can't be expressed
  there (about 126 rules). Needs a schema decision, not an engine change.
- Unmapped fields: our engine falls back to Extra; the pySigma pipeline needs a custom transformation to match (not built).
- Aggregation and correlation rules (count() by ...) were not evaluated.
- Regex semantics (RE2 vs PCRE), CIDR and base64offset were only spot-checked by conversion success.
- The sqlite backend targets Zircolite. DuckDB works only through our three shims. Hit-count agreement is evidence, not proof.
- The seeded-attack check used 3 rows; small.

---

## D-2026-10-12-3: Sentinel is by hand only

**Status:** accepted

**Context.** Bulk import of the Azure-Sentinel repository was a goal. An earlier probe converted 1 of 41 sampled
rules. Our measurement on 64 Detections/SecurityEvent files: 36 are migration stubs with no query (the
rule body lives under Solutions/), 1 converts (and that conversion is weak), 27 hit KQL feature gaps.

**Decision.** Drop bulk Sentinel import as a goal. Keep single-paste import (preview, then import disabled),
the converter as-is, and a how-to for adapting one rule by hand. Details and limits in docs/SENTINEL.md.

**Reasons.** Low yield per effort. Most of the corpus needs KQL features we do not have, and the mapping
by name is not trustworthy without review.

**Consequences.** No automated Sentinel sync. Sentinel rules get a warning on import. Any effort on Sentinel
is a KQL feature decision (D-2026-10-12-4), not an import decision.

---

## D-2026-10-12-4: KQL feature work only on demand

**Status:** accepted

**Decision.** Add KQL operators (parse, union, join with comma keys, subquery forms) only when a rule the
user actually wants needs them. No speculative coverage work.

**Reasons.** Each operator is engine work with its own correctness risk. Sigma through pySigma covers most of
the detection corpus without them.

---

## D-2026-10-12-5: Import rules: every import lands disabled, deduped, audited

**Status:** accepted

**Decision.** One Import dialog on the Rules page handles Sigma, Sentinel and KQL, with a preview step.
All imports are created with `enabled = false`. A duplicate (same source hash or same name) is rejected with
409. Every attempt writes a `rule.import` audit row with format and result. URL import accepts https only, from
github.com or raw.githubusercontent.com, one .yml/.yaml file, with a 10 s timeout and a 1 MB cap, and does not
follow redirects.

**Consequences.** `enabled` in the import-sigma body is now ignored. Duplicate imports that used to create a
second rule now return 409.

---

## Open risks (cross-cutting)

- Imported rules are disabled and nobody has reviewed the existing imported set.
- Converted Sentinel queries compile but may reference columns that do not exist in our tables.
- The Sigma `true` bug is in the current importer until the pySigma path replaces it.
