"""Operator compilation for the KQL compiler (mixin).

Binary operators (logical, comparison, arithmetic, string matching, in and
matches), unary operators and BETWEEN.
"""
from __future__ import annotations

from typing import Any

from ._compiler_sql import KqlCompilerError, SqlBuilder
from ._parser import (
    BetweenExpr,
    BinaryOp,
    ColumnRef,
    FuncCall,
    UnaryOp,
)

_STRING_OP_TEMPLATES: dict[str, str] = {
    "=~": "(lower({lv}) = lower({rv}))",
    "contains": "contains(lower({lv}), lower({rv}))",
    "contains_cs": "contains({lv}, {rv})",
    "has": r"regexp_matches({lv}, '\b' || regexp_escape({rv}) || '\b', 'i')",
    "has_cs": r"regexp_matches({lv}, '\b' || regexp_escape({rv}) || '\b')",
    "startswith": "starts_with(lower({lv}), lower({rv}))",
    "endswith": "ends_with(lower({lv}), lower({rv}))",
    "startswith_cs": "starts_with({lv}, {rv})",
    "endswith_cs": "ends_with({lv}, {rv})",
}


class _OpsMixin:
    """Operator compilation. Mixed into KqlCompiler; uses its _compile_expr."""

    def _compile_logical_operand(self, b: SqlBuilder, expr, parent: str) -> None:
        """Compile an operand of AND/OR, parenthesizing a nested logical op
        of the other kind.  SQL binds AND tighter than OR, so dropping the
        parentheses the AST encodes (e.g. `(A or B) and not C`) would change
        the meaning to `A or (B and not C)`."""
        if isinstance(expr, BinaryOp) and expr.op in ("and", "or") and expr.op != parent:
            b.add("(")
            self._compile_expr(b, expr)
            b.add(")")
        else:
            self._compile_expr(b, expr)

    def _compile_binary_op(self, b: SqlBuilder, op: BinaryOp) -> None:
        if op.op == "=":
            if isinstance(op.right, ColumnRef):
                b.add(f'"{op.right.name}"')
            else:
                self._compile_expr(b, op.right)
            return
        handler = self._BINARY_OP_HANDLERS.get(op.op)
        if handler is None:
            raise KqlCompilerError(f"unknown binary operator: {op.op}")
        handler(self, b, op)

    def _handle_logical(self, b: SqlBuilder, op: BinaryOp) -> None:
        self._compile_logical_operand(b, op.left, parent=op.op)
        b.add(" AND " if op.op == "and" else " OR ")
        self._compile_logical_operand(b, op.right, parent=op.op)

    def _handle_comparison(self, b: SqlBuilder, op: BinaryOp) -> None:
        self._compile_expr(b, op.left)
        sql_op = "=" if op.op == "==" else op.op  # KQL '==' is SQL '='
        b.add(f" {sql_op} ")
        self._compile_expr(b, op.right)

    def _handle_arithmetic(self, b: SqlBuilder, op: BinaryOp) -> None:
        self._compile_expr(b, op.left)
        b.add(f" {op.op} ")
        self._compile_expr(b, op.right)

    def _handle_string(self, b: SqlBuilder, op: BinaryOp) -> None:
        neg = op.op.startswith("!")
        name = op.op.lstrip("!")
        if name == "~":  # '!~' is the negation of '=~'
            name = "=~"
        if name in ("has_any", "has_all"):
            L = self._sub_sql(op.left)
            if isinstance(op.right, FuncCall) and op.right.name == "_list":
                terms = [self._sub_sql(x) for x in op.right.args]
            else:
                terms = [self._sub_sql(op.right)]
            conds = [
                r"regexp_matches(CAST(%s AS VARCHAR), '\b' || regexp_escape(CAST(%s AS VARCHAR)) || '\b', 'i')"
                % (L, t)
                for t in terms
            ]
            joiner = " OR " if name == "has_any" else " AND "
            sql = "(" + (joiner.join(conds) if conds else "FALSE") + ")"
        else:
            L = self._sub_sql(op.left)
            R = self._sub_sql(op.right)
            lv = f"CAST({L} AS VARCHAR)"
            rv = f"CAST({R} AS VARCHAR)"
            template = _STRING_OP_TEMPLATES[name].format(lv=lv, rv=rv)
            sql = template
        b.add(("NOT " if neg else "") + sql)

    def _handle_in(self, b: SqlBuilder, op: BinaryOp) -> None:
        neg = op.op.startswith("!")
        caseless = op.op.endswith("~")
        if caseless:
            # KQL in~ is case-insensitive on both sides: the list items are lowercased below, so the column
            # must be too, otherwise stored values with any uppercase letter never match.
            b.add("LOWER(CAST(")
            self._compile_expr(b, op.left)
            b.add(" AS VARCHAR))")
        else:
            self._compile_expr(b, op.left)
        b.add(" NOT IN (" if neg else " IN (")
        args = (
            op.right.args
            if isinstance(op.right, FuncCall) and op.right.name == "_list"
            else [op.right]
        )
        for i, arg in enumerate(args):
            if i > 0:
                b.add(", ")
            if caseless:
                b.add("LOWER(")
                self._compile_expr(b, arg)
                b.add(")")
            else:
                self._compile_expr(b, arg)
        b.add(")")

    def _handle_matches(self, b: SqlBuilder, op: BinaryOp) -> None:
        L = self._sub_sql(op.left)
        R = self._sub_sql(op.right)
        b.add(f"regexp_matches(CAST({L} AS VARCHAR), {R})")

    def _compile_unary_op(self, b: SqlBuilder, op: UnaryOp) -> None:
        if op.op == "not":
            b.add("NOT (")
            self._compile_expr(b, op.operand)
            b.add(")")
        elif op.op == "-":
            b.add("-")
            self._compile_expr(b, op.operand)
        elif op.op == "isempty":
            b.add("(")
            self._compile_expr(b, op.operand)
            b.add(" IS NULL OR ")
            self._compile_expr(b, op.operand)
            b.add(" = '')")
        elif op.op == "isnotempty":
            b.add("(")
            self._compile_expr(b, op.operand)
            b.add(" IS NOT NULL AND ")
            self._compile_expr(b, op.operand)
            b.add(" != '')")
        elif op.op == "isnull":
            self._compile_expr(b, op.operand)
            b.add(" IS NULL")
        elif op.op == "isnotnull":
            self._compile_expr(b, op.operand)
            b.add(" IS NOT NULL")
        else:
            raise KqlCompilerError(f"unknown unary operator: {op.op}")

    def _compile_between(self, b: SqlBuilder, expr: BetweenExpr) -> None:
        self._compile_expr(b, expr.expr)
        b.add(" BETWEEN ")
        self._compile_expr(b, expr.low)
        b.add(" AND ")
        self._compile_expr(b, expr.high)

    _BINARY_OP_HANDLERS: dict[str, Any] = {
        "and": _handle_logical,
        "or": _handle_logical,
        "==": _handle_comparison,
        "!=": _handle_comparison,
        "<": _handle_comparison,
        ">": _handle_comparison,
        "<=": _handle_comparison,
        ">=": _handle_comparison,
        "+": _handle_arithmetic,
        "-": _handle_arithmetic,
        "*": _handle_arithmetic,
        "/": _handle_arithmetic,
        "%": _handle_arithmetic,
        "=~": _handle_string,
        "!~": _handle_string,
        "contains": _handle_string,
        "!contains": _handle_string,
        "contains_cs": _handle_string,
        "!contains_cs": _handle_string,
        "has": _handle_string,
        "!has": _handle_string,
        "has_cs": _handle_string,
        "!has_cs": _handle_string,
        "startswith": _handle_string,
        "!startswith": _handle_string,
        "endswith": _handle_string,
        "!endswith": _handle_string,
        "startswith_cs": _handle_string,
        "!startswith_cs": _handle_string,
        "endswith_cs": _handle_string,
        "!endswith_cs": _handle_string,
        "has_any": _handle_string,
        "!has_any": _handle_string,
        "has_all": _handle_string,
        "!has_all": _handle_string,
        "in": _handle_in,
        "!in": _handle_in,
        "in~": _handle_in,
        "!in~": _handle_in,
        "matches": _handle_matches,
    }
