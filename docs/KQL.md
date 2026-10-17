# KQL Module

Kusto Query Language (KQL) compiler and runner for siempl.

## Architecture

- `_tokenizer.py` — Lexer: KQL source → token stream
- `_parser.py` — Recursive-descent parser: tokens → AST. `KqlParser`, `parse_kql()` and every AST class are still importable from here.
  Split on 2026-10-13 (was 1230 lines); every definition moved verbatim, corpus SQL identical:
  - `_nodes.py` — the AST dataclasses and `KqlParseError`
  - `_parser_base.py` — `_ParserBase`: token cursor (current/lookahead/consume/match/expect, error helper)
  - `_parser_ops.py` — `_OperatorParsers`: statements (let, pipeline, subqueries) and every tabular operator
  - `_parser_exprs.py` — `_ExprParsers`: expression precedence ladder, function calls, dynamic literals, column lists
  `KqlParser` is assembled from the three mixins; the mixins call each other through `self`.
- `_compiler.py` — AST → DuckDB SQL (CTE chain): `KqlCompiler` (pipeline/operator orchestration), `compile_pipeline()`,
  table-name validation. Public names (`KqlCompiler`, `SqlBuilder`, `sql_literal`, `KqlCompilerError`, `FUNCTION_MAP`,
  `validate_table_name`) are still importable from here.
  Split on 2026-10-13 (was 1342 lines) into mixins/helpers; behavior and emitted SQL unchanged
  (verified on a 182-query corpus):
  - `_compiler_sql.py` — `KqlCompilerError`, `sql_literal`, `SqlBuilder` (SQL output primitives)
  - `_compiler_columns.py` — `_ColumnsMixin`: output-column tracking per operator (dispatch table)
  - `_compiler_funcs.py` — `_FuncsMixin` + `FUNCTION_MAP`: KQL function call → DuckDB mapping
  - `_compiler_ops.py` — `_OpsMixin`: binary/logical/string operators (dispatch table)
- `_executor.py` — Secure SQL execution (SELECT-only, timeout, row cap)
- `__init__.py` — Public API: `compile_kql()`, `run_kql()`, `parse_kql()`

## Fix log

### 2026-10-12 — Bug fixes round 1

**Bug 1a: Negated string operators not recognized.** `KEYWORDS`, `STRING_BINARY_OPS`, and `_STRING_BINARY_OPS` missing `!startswith`, `!endswith`, `!has_cs`, `!contains_cs`, `!has_any`. Added all negated variants.

**Bug 1b: Parser silently drops trailing tokens.** `KqlParser.parse()` now checks `self.current.type != TokenType.EOF` and raises `KqlParseError` ("unexpected token X at position N") for unconsumed tokens. Previously, `!startswith 'z'` after an expression would be silently ignored.

**Bug 1c: Tokenizer mis-handled `!` prefix.** `!startswith` was tokenized as `KEYWORD("not")` + `KEYWORD("startswith")` — two separate tokens. Fixed `!`-fallthrough in `KqlTokenizer`: when next char is alpha, read the full `!identifier` as one token and check KEYWORDS. Also removed old hardcoded `c/h/i` fallthrough.

**Bug 1d: Multi-key join `on A, B`.** `_parse_join` now handles comma-separated bare column names as shorthand for `$left.X == $right.X and $left.Y == $right.Y`. Single key falls through to full expression parsing.

**Bug 2: Parenthesized subquery in join/union.** `_parse_join` and `_parse_union` both call `_parse_subquery()` when they see `LPAREN`. Subqueries are stored as synthetic `LetStatement` with generated names like `_sq0` and compiled as CTEs by the existing tabular-let machinery. Subquery join path in `_compile_join_body` now checks `_bare_join_keys()` for `USING` clauses.

**Bug 3: `now()` emitted `NOW()()`.** `_compile_func_call` had a template collision: the `else` branch wraps mapping with `mapping(...)` even when no args exist. Fixed to three-way branch: `{` in mapping → interpolate; args present → wrap as call; no args and no `{` → emit mapping directly (e.g., `NOW()`).

**Bug 4: Unknown tables leak DuckDB errors.** Added `validate_table_name()` in `_compiler.py`: rejects unknown tables with `KqlError` listing available tables (dynamic from schema + hardcoded data tables + readable meta tables: alerts, incidents, entities, rules, sources). Blocks sensitive meta tables (settings, ai_usage, api_keys, query_log, table_usage). Called from `_compile_source`.

**Bug 5: Dotted access on dynamic columns.** Changed `_parse_primary` to always pass results through `_parse_suffix()` which handles `.key` and `['key']` access. Removed `.` from identifier character set in tokenizer so `p.detail` tokenizes as three tokens. Added `_parse_suffix` method. Updated `_parse_column_list` to rewind identifiers and parse full expressions (including suffixed dot/bracket access), and to try expression parsing for KEYWORD tokens (handles `tostring(Extra.detail)` in project).
### 2026-10-12 — Bug fixes round 2 (golden suite: 9 failures fixed)

**`project-rename` direction swapped.** KQL syntax is `project-rename NewName = OldName`; the parser was treating the first identifier as the *old* name, emitting `EXCLUDE ("Host"), "Host" AS "HostName"`. `_parse_project_rename` now parses new name first.

**`percentile()` arguments swapped.** `FUNCTION_MAP` emitted `QUANTILE_CONT(50/100.0, col)`; DuckDB requires `QUANTILE_CONT(col, fraction)` with a constant fraction. Fixed to `QUANTILE_CONT({0}, {1}/100.0)` (also `percentilew`, `percentiles`).

**`matches regex` emitted invalid infix SQL.** The compiler produced `"col" REGEXP_MATCHES(pattern, 'i')`. Now emits `regexp_matches(CAST(col AS VARCHAR), pattern)` — function form, case-sensitive per KQL semantics.

**`toscalar(<query>)` unsupported.** `let x = toscalar(T | summarize ...)` failed to parse ("expected RPAREN, got |"). `_parse_toscalar` now parses the inner pipeline, registers it as a synthetic subquery CTE (same machinery as parenthesized join subqueries), and the compiler emits `(SELECT * FROM "_sqN" LIMIT 1)` as a scalar subquery.

**Summarize aggregation expressions.** `summarize max(Sev) - 2` (aggregate arithmetic, needed by the Sentinel `toscalar` idiom) failed to parse. `_parse_agg_list` now parses full expressions with optional `Alias =` prefix (identifier followed directly by `=`); the compiler compiles them via `_compile_expr`. `_parse_primary` also accepts keywords that are both pipe operators and functions (e.g. `count`) as function calls when directly followed by `(`.

**Join right-side duplicate columns.** Kusto renames colliding right-side columns with a `1` suffix (`UserName` → `UserName1`); DuckDB keeps duplicates, breaking later references. The compiler now tracks output column names through pipeline stages (base-table columns come from `siempl.schema`) and, for `ON` joins where both sides' columns are known, emits `SELECT left.*, _jr."col" AS "col1", ...` with Kusto-style renaming. Parenthesized subqueries / tabular lets on the right side are now referenced as their already-emitted top-level CTEs (previously inlined a second copy and compiled `$left`/`$right` refs to invalid `"$left"."col"` SQL).

**Compile/parse errors not written to `query_log`.** `run_kql` re-raised `KqlParseError` (incl. unknown-table `KqlCompilerError`) and execution `KqlError` without logging, so `query_log.error` rows only appeared for unexpected exceptions. All failure paths now insert a `query_log` row with the error message.

**`now()` SQL casing.** `FUNCTION_MAP["now"]` emitted lowercase `now()`; normalized to `NOW()` (matches the bug-suite's SQL-text assertions; DuckDB is case-insensitive so runtime behavior is unchanged).
