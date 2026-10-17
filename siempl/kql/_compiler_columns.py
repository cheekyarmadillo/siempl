"""Output-column tracking for the KQL compiler (mixin).

Tracks the output column names of each pipeline stage so a join can rename
duplicate right-side columns the way Kusto does. None means unknown.
"""
from __future__ import annotations

from typing import Any

from ._parser import (
    BinaryOp,
    ColumnRef,
    Count,
    Distinct,
    Expr,
    Extend,
    FuncCall,
    IndexAccess,
    Limit,
    MvExpand,
    Node,
    Parse,
    Project,
    ProjectAway,
    ProjectRename,
    ProjectReorder,
    Render,
    Search,
    Sort,
    StarExpr,
    Summarize,
    Take,
    Top,
    Union,
    Where,
)


class _ColumnsMixin:
    """Output-column tracking. Mixed into KqlCompiler; reads and writes self.columns."""

    def _expr_output_name(self, expr: Expr) -> str | None:
        """Best-effort output column name for a projected expression."""
        if isinstance(expr, ColumnRef):
            return expr.name
        if isinstance(expr, BinaryOp) and expr.op == "=" and isinstance(expr.left, ColumnRef):
            return expr.left.name
        if isinstance(expr, IndexAccess):
            return self._expr_output_name(expr.obj)
        return None

    def _update_columns(self, op: Node) -> None:
        """Track output column names through pipeline operators."""
        handler = self._COLUMN_HANDLERS.get(type(op))
        if handler is None:
            self.columns = None
        else:
            handler(self, op)

    def _cols_unchanged(self, op: Node) -> None:
        pass

    def _cols_project(self, op: Project) -> None:
        if any(isinstance(c, StarExpr) for c in op.columns):
            self._cols_project_star(op)
            return
        names = [self._expr_output_name(c) for c in op.columns]
        self.columns = None if any(n is None for n in names) else list(names)

    def _cols_project_star(self, op: Project) -> None:
        named = [self._expr_output_name(c) for c in op.columns if not isinstance(c, StarExpr)]
        if self.columns is None or any(n is None for n in named):
            self.columns = None
            return
        self.columns = self.columns + [n for n in named if n]

    def _cols_project_away(self, op: ProjectAway) -> None:
        cols = self.columns
        if cols is not None:
            self.columns = [c for c in cols if c not in op.columns]

    def _cols_project_rename(self, op: ProjectRename) -> None:
        cols = self.columns
        if cols is not None:
            mapping = dict(op.renames)
            self.columns = [mapping.get(c, c) for c in cols]

    def _cols_extend(self, op: Extend) -> None:
        cols = self.columns
        if cols is not None:
            self.columns = cols + [n for n, _ in op.assignments]

    def _cols_summarize(self, op: Summarize) -> None:
        by_names = [self._expr_output_name(c) for c in op.by_columns]
        agg_names = [a or self._agg_default_alias(f) for a, f in op.aggregations]
        if op.bin_expr is not None:
            by_names = [self._expr_output_name(op.bin_expr)] + by_names
        if any(n is None for n in by_names):
            self.columns = None
        else:
            self.columns = list(by_names) + agg_names

    def _cols_count(self, op: Count) -> None:
        self.columns = ["Count_"]

    def _cols_distinct(self, op: Distinct) -> None:
        names = [self._expr_output_name(c) for c in op.columns]
        self.columns = None if any(n is None for n in names) else list(names)

    def _agg_default_alias(self, func: Expr) -> str:
        """Generate a default column alias for an aggregation expression."""
        if not isinstance(func, FuncCall):
            if isinstance(func, ColumnRef):
                return func.name
            return "Expr_"
        name = func.name.lower()
        if name == "count" and not func.args:
            return "Count_"
        if func.args:
            first = func.args[0]
            if isinstance(first, ColumnRef):
                return f"{name}_{first.name}"
            if isinstance(first, StarExpr):
                return f"{name}_"
            return f"{name}_"
        return f"{name}_"

    _COLUMN_HANDLERS: dict[type, Any] = {
        Where: _cols_unchanged,
        Take: _cols_unchanged,
        Limit: _cols_unchanged,
        Top: _cols_unchanged,
        Sort: _cols_unchanged,
        Render: _cols_unchanged,
        Parse: _cols_unchanged,
        ProjectReorder: _cols_unchanged,
        Search: _cols_unchanged,
        MvExpand: _cols_unchanged,
        Project: _cols_project,
        ProjectAway: _cols_project_away,
        ProjectRename: _cols_project_rename,
        Extend: _cols_extend,
        Summarize: _cols_summarize,
        Count: _cols_count,
        Distinct: _cols_distinct,
        Union: _cols_unchanged,
    }
