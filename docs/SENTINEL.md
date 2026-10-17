# Microsoft Sentinel rules: honest status

Decision (2026-10-12): Sentinel is **by hand only**. No bulk import of the Azure-Sentinel
repository. Sigma (via pySigma) is the primary content path; see docs/DECISIONS.md.

## What works

- **Single paste import** in the Rules page import dialog (format "Microsoft Sentinel YAML"),
  or `POST /api/rules/import-sentinel {yaml, preview}`. Preview shows name, severity, tables,
  the converted query (read-only), convertibility, and the reason when it is not convertible.
  Imports are created **disabled**, deduped by name and source hash, and audited (`rule.import`).
- The converter maps the common table names (`SecurityEvent` to `AuthEvents`, `Syslog`,
  `CommonSecurityLog` to `GenericEvents`, and so on) and column names by name. It rewrites the
  query text and checks that it compiles with our KQL engine.
- Every Sentinel import gets a warning: mapping is by name, verify the results before enabling.

## Measured limits (2026-10-12)

Sample: all 64 files in `Detections/SecurityEvent/` of Azure/Azure-Sentinel master
(fetched from raw.githubusercontent.com). Raw sample data is not included in this repo.

| Outcome | Count | Why |
|---|---|---|
| No `query` field | 36 | Migration stubs. The file says "As part of content migration, this file is moved" and points to `Solutions/<pack>/Analytic Rules/`. The rule body is not in this folder. |
| Compiles after mapping | 1 | `FakeComputerAccountCreated`. It converts, but it is a weak result: see below. |
| KQL feature gap | 27 | `parse`, `union`, `join ... (subquery) on A, B` (the Solutions file fails on the comma list after `on`), subqueries starting with `(`, unmapped operators. |

An earlier probe (1 of 41) matches this: the "no query" failures are stubs, not a parser bug.

Caveat on the one "success": `FakeComputerAccountCreated` converts to
`AuthEvents | where "EventCode" == 4720 ...` with columns such as `SubjectAccount`,
`TargetDomainName` and `SubjectLogonId` passed through unmapped. It compiles, but nobody has checked
that those columns exist in `AuthEvents` or that event 4720 is ingested. **Compiles is not correct.**

Stubs: the Solutions-path file exists (checked `Solutions/Windows Security Events/Analytic Rules/ExcessiveLogonFailures.yaml`)
but fails on `join ... on EventID, Account, ...` (multi-key join with a comma list). So the right file still often fails.

## How to hand-adapt one rule

1. Get the real rule body. If the Detections file is a stub (no `query:` key), open the path in its
   description under `Solutions/`. Use the raw.githubusercontent.com URL for that file.
2. Paste the YAML into Rules, format "Microsoft Sentinel YAML", click Preview.
   If it is not convertible, the reason is shown. Typical fixes:
   - Replace `parse` with `extend` plus `split`/`extract`, or drop it.
   - Replace `union` with a separate rule, or query one table.
   - Rewrite a `join ... on A, B` as a single-key join or as a `summarize` over one table.
   - Replace unknown tables with a table that exists in siempl (see the Data page).
3. Once it previews as convertible, check the query against real data with the **Test Query** button
   on the rule form. Confirm the columns exist and the rows make sense.
4. Fix the description and triage steps (the preview warns when they are empty).
5. Import (disabled). Enable only after a test run looks right.

Alternative when the rule is simple: write the KQL by hand in the same dialog with format
"KQL / plain query". That skips the converter entirely.
