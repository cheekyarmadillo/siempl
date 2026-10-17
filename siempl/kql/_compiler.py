"""KQL -> DuckDB SQL compiler.

Transforms the AST produced by the parser into a single, readable DuckDB SQL
query using CTEs for each pipeline stage.

Security: produces SELECT-only queries. All table/column references are
quoted with double quotes to prevent injection through names.

The compiler is split into sibling modules: _compiler_sql (builder, literal,
error), _compiler_tables (table policy), _compiler_columns, _compiler_funcs and
_compiler_ops (mixins). KqlCompiler inherits from the mixins.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from ._compiler_columns import _ColumnsMixin
from ._compiler_funcs import FUNCTION_MAP, TIMESPAN_ARG2, VARARG_FUNCTIONS, _FuncsMixin
from ._compiler_ops import _OpsMixin
from ._compiler_sql import KqlCompilerError, SqlBuilder, sql_literal
from ._parser import (
    BetweenExpr,
    BinaryOp,
    CaseExpr,
    ColumnRef,
    Count,
    Distinct,
    DollarRef,
    Expr,
    Extend,
    FuncCall,
    IndexAccess,
    Join,
    LetRef,
    Limit,
    Literal,
    MvExpand,
    Node,
    Parse,
    Pipeline,
    Project,
    ProjectAway,
    ProjectRename,
    ProjectReorder,
    Render,
    Search,
    Sort,
    StarExpr,
    Summarize,
    TableRef,
    Take,
    Top,
    UnaryOp,
    Union,
    Where,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ALL_QUERYABLE_TABLES",
    "BLOCKED_TABLES",
    "DATA_TABLE_NAMES",
    "FUNCTION_MAP",
    "KqlCompiler",
    "KqlCompilerError",
    "READABLE_META_TABLES",
    "SqlBuilder",
    "TIMESPAN_ARG2",
    "VARARG_FUNCTIONS",
    "compile_pipeline",
    "sql_literal",
    "validate_table_name",
]

# Data tables that can be queried
DATA_TABLE_NAMES = {
    "Syslog", "AuthEvents", "NetworkEvents", "ProcessEvents",
    "FileEvents", "WebAccess", "GenericEvents",
}

# Meta tables that are readable in KQL (not writable, but queryable)
READABLE_META_TABLES = {
    "alerts", "incidents", "entities", "rules", "sources",
}

# Meta tables that are BLOCKED from KQL queries
BLOCKED_TABLES = {
    "settings", "ai_usage", "api_keys", "query_log", "table_usage",
}

ALL_QUERYABLE_TABLES = DATA_TABLE_NAMES | READABLE_META_TABLES

def validate_table_name(name: str) -> str:
    """Validate a table name, raising KqlCompilerError if unknown or blocked."""
    from siempl import schema as _schema_mod
    # Try loading dynamic tables from schema module
    try:
        dynamic_tables = set(_schema_mod.DATA_TABLES.keys())
    except Exception:
        dynamic_tables = set()
    all_data = dynamic_tables | DATA_TABLE_NAMES
    all_readable = all_data | READABLE_META_TABLES
    if name in BLOCKED_TABLES:
        raise KqlCompilerError(
            f"table '{name}' cannot be queried via KQL"
        )
    if name not in all_readable:
        available = sorted(all_readable)
        hint = ", ".join(available[:10])
        if len(available) > 10:
            hint += f", ... ({len(available)} total)"
        raise KqlCompilerError(
            f"unknown table '{name}'. Available tables: {hint}"
        )
    return name


class KqlCompiler(_ColumnsMixin, _FuncsMixin, _OpsMixin):
    """Compiles a KQL Pipeline AST into DuckDB SQL.

    Produces a CTE chain:
        WITH _t0 AS (SELECT * FROM "Table")
        SELECT ... FROM _tN [LIMIT n]

    Uses parameterized queries where practical to prevent injection.
    """

    def __init__(self, pipeline: Pipeline, now: datetime | None = None):
        self.pipeline = pipeline
        from ..db import utcnow as _utcnow
        self.now = now or _utcnow()
        self.cte_idx = 0
        self.sql = SqlBuilder()
        self.let_bindings: dict[str, Expr | Pipeline] = {}
        self.tables: set[str] = set()
        self.current_table = ""  # alias for the current CTE
        # Output column names of the current pipeline stage (None = unknown).
        # Used to rename duplicate right-side join columns per Kusto rules.
        self.columns: list[str] | None = None
        # Columns of each compiled tabular let/subquery CTE, by name.
        self.let_columns: dict[str, list[str] | None] = {}

    def compile(self) -> tuple[str, list, set[str]]:
        """Returns (sql, params, tables_used)."""
        # Register let bindings
        # Tabular lets become top-level CTEs named after the let (so later lets, the main
        # source and joins can reference them as tables). Compiled by a sub-compiler.
        let_ctes: list[str] = []
        for let in self.pipeline.let_bindings:
            self.let_bindings[let.name] = let.value
            if isinstance(let.value, Pipeline):
                sub = KqlCompiler(let.value, self.now)
                sub.let_bindings = dict(self.let_bindings)
                sub.let_columns = self.let_columns  # share; earlier lets visible
                sub_sql, _p, sub_tabs = sub.compile()
                self.tables |= sub_tabs
                self.let_columns[let.name] = sub.columns
                let_ctes.append('  "' + let.name + '" AS (' + chr(10) + sub_sql + chr(10) + '  )')
        self._has_lets = bool(let_ctes)

        # Track source table
        source = self.pipeline.source
        if isinstance(source, TableRef):
            self.tables.add(source.name)

        # Open WITH
        self.sql.add("WITH\n")
        if let_ctes:
            self.sql.add(",\n".join(let_ctes))

        # Compile source as first CTE
        self.current_table = self._next_cte()
        self._compile_source(self.current_table, source)

        # Compile each pipeline operator
        for op in self.pipeline.operators:
            if isinstance(op, Render):
                # Ignore render — it doesn't affect data
                continue
            next_cte = self._next_cte()
            self._compile_operator(next_cte, op)
            self.current_table = next_cte
            if not isinstance(op, Join):
                self._update_columns(op)

        # Final SELECT with LIMIT
        self.sql.add(f'SELECT * FROM {self.current_table}')
        params = list(self.sql.params)
        self.tables -= {n for n, v in self.let_bindings.items() if isinstance(v, Pipeline)}
        return self.sql.build(), params, self.tables

    def _next_cte(self) -> str:
        name = f"_t{self.cte_idx}"
        self.cte_idx += 1
        return name

    def _cte_header(self, name: str, prefix: str = ",\n") -> None:
        """Emit CTE prefix: ,\n  name AS ("""
        if self.cte_idx > 1 or getattr(self, "_has_lets", False):
            self.sql.add(prefix)
        self.sql.add(f"  {name} AS (\n    ")

    def _cte_footer(self) -> None:
        self.sql.add("\n  )")

    # -------------------------------------------------------------------
    # Source compilation
    # -------------------------------------------------------------------

    def _schema_columns(self, name: str) -> list[str] | None:
        """Static column list for a base data table (None if unknown)."""
        try:
            from siempl import schema as _schema_mod
            if name in _schema_mod.DATA_TABLES:
                return [c[0] for c in _schema_mod.table_columns(name)]
        except Exception:
            logger.debug("_schema_columns: ignored error", exc_info=True)
        return None

    def _compile_source(self, cte_name: str, source: TableRef | LetRef) -> None:
        self._cte_header(cte_name)
        if isinstance(source, TableRef):
            # Check if this is actually a let binding
            if source.name in self.let_bindings:
                let_val = self.let_bindings[source.name]
                if isinstance(let_val, Pipeline):
                    # Tabular let: emitted as a top-level CTE; reference it
                    self.sql.add('SELECT * FROM "' + source.name + '"')
                    self.columns = self.let_columns.get(source.name)
                    self._cte_footer()
                    return
                if isinstance(let_val, Expr):
                    # Scalar let in a table position: treat as SELECT expr
                    b = SqlBuilder()
                    self._compile_expr(b, let_val)
                    self.sql.add(f"SELECT {b.build()} AS Value")
                    self.columns = ["Value"]
                    self._cte_footer()
                    return
            # Validate table name (Bug 4)
            validate_table_name(source.name)
            self.tables.add(source.name)
            self.columns = self._schema_columns(source.name)
            self.sql.add(f'SELECT * FROM "{source.name}"')
        elif isinstance(source, LetRef):
            if source.name in self.let_bindings:
                let_val = self.let_bindings[source.name]
                if isinstance(let_val, Pipeline):
                    self.sql.add('SELECT * FROM "' + source.name + '"')
                    self.columns = self.let_columns.get(source.name)
                    self._cte_footer()
                    return
                if isinstance(let_val, Expr):
                    b = SqlBuilder()
                    self._compile_expr(b, let_val)
                    self.sql.add(f"SELECT {b.build()} AS Value")
                    self.columns = ["Value"]
                    self._cte_footer()
                    return
            raise KqlCompilerError(f"undefined let binding: {source.name}")
        self._cte_footer()

    def _compile_let_pipeline(self, pipeline: Pipeline) -> None:
        """Compile a tabular let binding inline as a subquery."""
        # Track source tables from the let binding
        if isinstance(pipeline.source, TableRef):
            self.tables.add(pipeline.source.name)
        # Build the CTE chain for this sub-pipeline inline
        # We need to produce a series of nested CTEs but they must be scoped
        # For simplicity, emit a single nested subquery with CTEs
        # Actually, DuckDB supports nested WITH clauses
        self.sql.add("\n    WITH\n")
        saved_idx = self.cte_idx
        self.cte_idx = 0
        # First CTE
        inner_name = "_s0"
        self.cte_idx = 1
        self.sql.add(f"      {inner_name} AS (SELECT * FROM \"{pipeline.source.name}\")")
        current = inner_name
        for op in pipeline.operators:
            if isinstance(op, Render):
                continue
            next_name = f"_s{self.cte_idx}"
            self.cte_idx += 1
            # We need to compile the operator relative to current table
            saved_current = self.current_table
            self.current_table = current
            self._cte_header(next_name, ",\n      ")
            self._compile_op_body(op)
            self._cte_footer()
            current = next_name
            self.current_table = saved_current
        self.sql.add(f"\n    SELECT * FROM {current}")
        self.cte_idx = saved_idx

    # -------------------------------------------------------------------
    # Operator compilation
    # -------------------------------------------------------------------

    def _compile_operator(self, cte_name: str, op: Node) -> None:
        self._cte_header(cte_name, ",\n")
        self._compile_op_body(op)
        self._cte_footer()

    def _compile_op_body(self, op: Node) -> None:
        prev = self.current_table
        if isinstance(op, Where):
            b = SqlBuilder()
            self._compile_expr(b, op.condition)
            self.sql.add(f"SELECT * FROM {prev} WHERE {b.build()}")
            self._merge_params(b)
        elif isinstance(op, Project):
            self._compile_project_body(prev, op)
        elif isinstance(op, ProjectAway):
            self._compile_project_away_body(prev, op)
        elif isinstance(op, ProjectRename):
            self._compile_project_rename_body(prev, op)
        elif isinstance(op, ProjectReorder):
            # No-op
            self.sql.add(f"SELECT * FROM {prev}")
        elif isinstance(op, Extend):
            self._compile_extend_body(prev, op)
        elif isinstance(op, Summarize):
            self._compile_summarize_body(prev, op)
        elif isinstance(op, Count):
            self.sql.add(f"SELECT COUNT(*) AS Count_ FROM {prev}")
        elif isinstance(op, Distinct):
            cols_b = SqlBuilder()
            for i, col in enumerate(op.columns):
                if i > 0:
                    cols_b.add(", ")
                self._compile_expr(cols_b, col)
            self.sql.add(f"SELECT DISTINCT {cols_b.build()} FROM {prev}")
            self._merge_params(cols_b)
        elif isinstance(op, Take):
            self.sql.add(f"SELECT * FROM {prev} LIMIT {op.count}")
        elif isinstance(op, Limit):
            self.sql.add(f"SELECT * FROM {prev} LIMIT {op.count}")
        elif isinstance(op, Top):
            b = SqlBuilder()
            self._compile_expr(b, op.by_expr)
            asc = "ASC" if op.ascending else "DESC"
            self.sql.add(f"SELECT * FROM {prev} ORDER BY {b.build()} {asc} LIMIT {op.count}")
            self._merge_params(b)
        elif isinstance(op, Sort):
            self._compile_sort_body(prev, op)
        elif isinstance(op, Join):
            self._compile_join_body(prev, op)
        elif isinstance(op, Union):
            self._compile_union_body(prev, op)
        elif isinstance(op, MvExpand):
            self._compile_mv_expand_body(prev, op)
        elif isinstance(op, Search):
            self._compile_search_body(prev, op)
        elif isinstance(op, Parse):
            # No-op: parse is stubbed
            self.sql.add(f"SELECT * FROM {prev}")
        else:
            raise KqlCompilerError(f"unknown operator: {type(op).__name__}")

    def _compile_project_body(self, prev: str, op: Project) -> None:
        cols_b = SqlBuilder()
        has_star = False
        non_star = []
        for col in op.columns:
            if isinstance(col, StarExpr):
                has_star = True
            else:
                non_star.append(col)

        if has_star:
            cols_b.add(f"{prev}.*")
            if non_star:
                cols_b.add(", ")
                # Extra columns after star — they'll be additional computed columns
                # Actually in KQL, project col1, col2 means SELECT col1, col2 only
                # So star without other columns means SELECT *

        for i, col in enumerate(non_star):
            if i > 0:
                cols_b.add(", ")
            if isinstance(col, BinaryOp) and col.op == "=":
                # Col = expr (rename/computed)
                # Left side could be ColumnRef or another expression
                b = SqlBuilder()
                self._compile_expr(b, col.right)
                if isinstance(col.left, ColumnRef):
                    cols_b.add(f"{b.build()} AS \"{col.left.name}\"")
                else:
                    cols_b.add(f"{b.build()} AS \"col{i}\"")
                self._merge_params(b)
            else:
                self._compile_expr(cols_b, col)

        self.sql.add(f"SELECT {cols_b.build()} FROM {prev}")
        self._merge_params(cols_b)

    def _compile_project_away_body(self, prev: str, op: ProjectAway) -> None:
        # We need to list all columns except the ones to remove
        # Since we don't know the schema at compile time, use EXCLUDE
        exclude_cols = ", ".join(f'"{c}"' for c in op.columns if c != "*")
        if exclude_cols:
            self.sql.add(f"SELECT * EXCLUDE ({exclude_cols}) FROM {prev}")
        else:
            self.sql.add(f"SELECT * FROM {prev}")

    def _compile_project_rename_body(self, prev: str, op: ProjectRename) -> None:
        # SELECT * EXCLUDE (old...) , old AS new, ...
        if not op.renames:
            self.sql.add(f"SELECT * FROM {prev}")
            return
        old_names = ", ".join(f'"{old}"' for old, _ in op.renames)
        rename_cols = ", ".join(f'"{old}" AS "{new}"' for old, new in op.renames)
        self.sql.add(f"SELECT * EXCLUDE ({old_names}), {rename_cols} FROM {prev}")

    def _compile_extend_body(self, prev: str, op: Extend) -> None:
        extras = []
        extra_params = []
        for name, expr in op.assignments:
            b = SqlBuilder()
            self._compile_expr(b, expr)
            extras.append(f'{b.build()} AS "{name}"')
            extra_params.extend(b.params)
        self.sql.add(f"SELECT *, {', '.join(extras)} FROM {prev}")
        self.sql._params.extend(extra_params)

    def _compile_summarize_body(self, prev: str, op: Summarize) -> None:
        parts = []
        for alias, func in op.aggregations:
            b = SqlBuilder()
            self._compile_expr(b, func)
            col_name = alias or self._agg_default_alias(func)
            parts.append(f'{b.build()} AS "{col_name}"')
            self._merge_params(b)

        select = ", ".join(parts) if parts else "COUNT(*) AS Count_"
        group_parts = []

        if op.bin_expr:
            b = SqlBuilder()
            self._compile_expr(b, op.bin_expr)
            group_parts.append(b.build())
            self._merge_params(b)

        for col in op.by_columns:
            b = SqlBuilder()
            self._compile_expr(b, col)
            group_parts.append(b.build())
            self._merge_params(b)

        if group_parts:
            self.sql.add(f"SELECT {', '.join(group_parts)}, {select} FROM {prev} GROUP BY {', '.join(group_parts)}")
        else:
            self.sql.add(f"SELECT {select} FROM {prev}")

    def _compile_sort_body(self, prev: str, op: Sort) -> None:
        parts = []
        for expr, asc in op.columns:
            b = SqlBuilder()
            self._compile_expr(b, expr)
            parts.append(f"{b.build()} {'ASC' if asc else 'DESC'}")
            self._merge_params(b)
        self.sql.add(f"SELECT * FROM {prev} ORDER BY {', '.join(parts)}")

    def _compile_join_body(self, prev: str, op: Join) -> None:
        join_type = {
            "INNER": "INNER JOIN",
            "LEFTOUTER": "LEFT JOIN",
            "FULLOUTER": "FULL JOIN",
            "RIGHTOUTER": "RIGHT JOIN",
        }.get(op.kind.upper(), "INNER JOIN")

        # Resolve the right side. Tabular lets and parenthesized subqueries are
        # already emitted as top-level CTEs, so both cases are name references.
        if isinstance(op.right, TableRef):
            if op.right.name not in self.let_bindings:
                validate_table_name(op.right.name)
                self.tables.add(op.right.name)
            right_sql = f'"{op.right.name}"'
            right_cols = (self.let_columns.get(op.right.name)
                          if op.right.name in self.let_bindings
                          else self._schema_columns(op.right.name))
        else:  # LetRef (tabular let or synthetic subquery)
            if op.right.name not in self.let_bindings:
                raise KqlCompilerError(f"undefined let binding: {op.right.name}")
            right_sql = f'"{op.right.name}"'
            right_cols = self.let_columns.get(op.right.name)

        keys = self._bare_join_keys(op.condition)
        if keys:
            using = ", ".join('"' + k + '"' for k in keys)
            self.sql.add(f"SELECT * FROM {prev} {join_type} {right_sql} USING ({using})")
            left_cols = self.columns
            if left_cols is not None and right_cols is not None:
                key_set = set(keys)
                self.columns = (list(keys)
                                + [c for c in left_cols if c not in key_set]
                                + [c for c in right_cols if c not in key_set])
            else:
                self.columns = None
            return

        b = SqlBuilder()
        self._compile_join_condition(b, op.condition, prev, "_jr")
        cond = b.build()

        left_cols = self.columns
        if left_cols is not None and right_cols is not None:
            # Kusto: right-side columns whose names collide with the left get a
            # numeric "1" suffix (e.g. UserName -> UserName1).
            seen = set(left_cols)
            selects = []
            new_cols = list(left_cols)
            for c in right_cols:
                n = c
                while n in seen:
                    n = n + "1"
                seen.add(n)
                selects.append(f'_jr."{c}" AS "{n}"')
                new_cols.append(n)
            self.sql.add(
                f"SELECT {prev}.*, {', '.join(selects)} "
                f"FROM {prev} {join_type} {right_sql} AS _jr ON {cond}"
            )
            self.columns = new_cols
        else:
            self.sql.add(
                f"SELECT * FROM {prev} {join_type} {right_sql} AS _jr ON {cond}"
            )
            self.columns = None
        self._merge_params(b)

    def _bare_join_keys(self, expr) -> list[str]:
        """KQL `join ... on A, B`: bare column names mean equality on same-named columns."""
        if isinstance(expr, ColumnRef):
            return [expr.name]
        if isinstance(expr, BinaryOp) and expr.op == "and":
            l, r = self._bare_join_keys(expr.left), self._bare_join_keys(expr.right)
            return l + r if l and r else []
        return []

    def _compile_join_condition(self, b: SqlBuilder, expr: Expr, left_alias: str, right_alias: str) -> None:
        if isinstance(expr, BinaryOp):
            if expr.op in ("==", "!=", "<", ">", "<=", ">=", "and", "or"):
                self._compile_join_condition(b, expr.left, left_alias, right_alias)
                b.add(f" {expr.op} ")
                self._compile_join_condition(b, expr.right, left_alias, right_alias)
            else:
                self._compile_join_expr(b, expr, left_alias, right_alias)
        elif isinstance(expr, DollarRef):
            if expr.side == "left":
                b.add(f'{left_alias}."{expr.column}"')
            else:
                b.add(f'{right_alias}."{expr.column}"')
        elif isinstance(expr, ColumnRef):
            b.add(f'"{expr.name}"')
        else:
            self._compile_join_expr(b, expr, left_alias, right_alias)

    def _compile_join_expr(self, b: SqlBuilder, expr: Expr, left_alias: str, right_alias: str) -> None:
        """Compile a single join expression node, replacing $left/$right."""
        if isinstance(expr, DollarRef):
            if expr.side == "left":
                b.add(f'{left_alias}."{expr.column}"')
            else:
                b.add(f'{right_alias}."{expr.column}"')
        else:
            self._compile_expr(b, expr)

    def _compile_union_body(self, prev: str, op: Union) -> None:
        right_name = ""
        if isinstance(op.right, TableRef):
            right_name = f'"{op.right.name}"'
            self.tables.add(op.right.name)
        else:
            right_name = f'"{op.right.name}"'
        self.sql.add(f"SELECT * FROM {prev} UNION ALL SELECT * FROM {right_name}")

    def _compile_mv_expand_body(self, prev: str, op: MvExpand) -> None:
        col = f'"{op.column}"'
        self.sql.add(
            f"SELECT * FROM {prev}, LATERAL UNNEST({col}) AS _mv({col})"
        )

    def _compile_search_body(self, prev: str, op: Search) -> None:
        # Search all string columns for term.
        # Use concat_ws to build a searchable text from VARCHAR columns.
        term = op.term.replace("%", "\\%").replace("_", "\\_")
        param = self.sql.add_param(term)
        # Search all columns by converting row to JSON then string-matching
        self.sql.add(
            f"SELECT * FROM {prev} WHERE "
            f"regexp_matches(CAST(row(*) AS VARCHAR)::JSON->>'$', {param}, 'i')"
        )

    # -------------------------------------------------------------------
    # Expression compilation
    # -------------------------------------------------------------------

    def _compile_expr(self, b: SqlBuilder, expr: Expr) -> None:
        if isinstance(expr, Literal):
            self._compile_literal(b, expr)
        elif isinstance(expr, ColumnRef):
            # Check if this is a let binding reference (scalar substitution)
            if expr.name in self.let_bindings:
                let_val = self.let_bindings[expr.name]
                if isinstance(let_val, Expr):
                    self._compile_expr(b, let_val)
                else:
                    b.add(f'"{expr.name}"')
            else:
                b.add(f'"{expr.name}"')
        elif isinstance(expr, StarExpr):
            b.add("*")
        elif isinstance(expr, BinaryOp):
            self._compile_binary_op(b, expr)
        elif isinstance(expr, UnaryOp):
            self._compile_unary_op(b, expr)
        elif isinstance(expr, BetweenExpr):
            self._compile_between(b, expr)
        elif isinstance(expr, FuncCall):
            self._compile_func_call(b, expr)
        elif isinstance(expr, DollarRef):
            if expr.side == "left":
                b.add(f'"$left"."{expr.column}"')
            else:
                b.add(f'"$right"."{expr.column}"')
        elif isinstance(expr, IndexAccess):
            self._compile_index_access(b, expr)
        elif isinstance(expr, CaseExpr):
            self._compile_case(b, expr)
        else:
            raise KqlCompilerError(f"unsupported expression: {type(expr).__name__}")

    def _compile_literal(self, b: SqlBuilder, lit: Literal) -> None:
        if lit.kind == "string":
            param = b.add_param(lit.value)
            b.add(param)
        elif lit.kind == "number":
            b.add(str(lit.value))
        elif lit.kind == "bool":
            b.add("TRUE" if lit.value else "FALSE")
        elif lit.kind == "null":
            b.add("NULL")
        elif lit.kind == "timespan":
            val, unit = lit.value
            unit_map = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY",
                        "ms": "MILLISECOND", "microsecond": "MICROSECOND", "tick": "MILLISECOND"}
            u = unit_map.get(unit, unit.upper())
            b.add(f"INTERVAL {val} {u}")
        elif lit.kind == "dynamic":
            if isinstance(lit.value, (dict, list)):
                param = b.add_param(json.dumps(lit.value))
                b.add(f"CAST({param} AS JSON)")
            else:
                param = b.add_param(str(lit.value))
                b.add(f"CAST({param} AS JSON)")
        else:
            param = b.add_param(str(lit.value))

    def _compile_index_access(self, b: SqlBuilder, access: IndexAccess) -> None:
        """Compile expr[key] or expr.key (JSON/dynamic access)."""
        self._compile_expr(b, access.obj)
        if isinstance(access.key, int):
            b.add(f"[{access.key}]")
        else:
            # Property access on JSON: obj->>'key' or obj->'key'
            b.add(f"->>'{access.key}'")

    def _compile_case(self, b: SqlBuilder, case: CaseExpr) -> None:
        """Compile CASE expression."""
        b.add("CASE")
        for cond, val in zip(case.conditions, case.values):
            b.add(" WHEN ")
            self._compile_expr(b, cond)
            b.add(" THEN ")
            self._compile_expr(b, val)
        if case.default is not None:
            b.add(" ELSE ")
            self._compile_expr(b, case.default)
        b.add(" END")

    def _sub_sql(self, expr) -> str:
        sb = SqlBuilder()
        self._compile_expr(sb, expr)
        return sb.build()

    def _merge_params(self, other: SqlBuilder) -> None:
        """Merge params from a sub-builder.

        NOTE: Callers MUST renumber $N refs BEFORE calling this, or use
        _compile_sub that handles renumbering automatically.
        This method just extends the param list.
        """
        self.sql._params.extend(other.params)

    def _compile_sub(self, expr) -> str:
        """Compile an expression into a sub-builder with renumbered params.

        Returns SQL text with $N placeholders renumbered to follow the
        main builder's current params.
        """
        import re
        b = SqlBuilder()
        self._compile_expr(b, expr)
        offset = len(self.sql._params)
        self.sql._params.extend(b.params)
        if offset == 0:
            return b.build()
        return re.sub(
            r'\$(\d+)',
            lambda m: f'${offset + int(m.group(1))}',
            b.build(),
        )


def compile_pipeline(pipeline: Pipeline, now: datetime | None = None) -> tuple[str, list, set[str]]:
    """Compile a parsed KQL pipeline into (sql, params, tables)."""
    compiler = KqlCompiler(pipeline, now)
    return compiler.compile()
