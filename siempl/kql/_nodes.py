"""KQL AST node classes (dataclasses) and the parse error type, split out of _parser.py."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Node:
    pass


@dataclass
class Pipeline(Node):
    """A complete KQL query: a source table/let plus piped operators."""
    source: TableRef | LetRef
    operators: list[Node] = field(default_factory=list)
    let_bindings: list[LetStatement] = field(default_factory=list)

    def __repr__(self):
        ops = ", ".join(type(o).__name__ for o in self.operators)
        return f"Pipeline(source={self.source}, ops=[{ops}])"


@dataclass
class LetStatement(Node):
    name: str
    value: Expr | Pipeline


@dataclass
class TableRef(Node):
    """Reference to a data table by name."""
    name: str


@dataclass
class LetRef(Node):
    """Reference to a let-bound expression/table."""
    name: str


@dataclass
class Expr(Node):
    """Base for expression nodes."""


@dataclass
class Literal(Expr):
    value: Any       # str, int, float, bool, None, dict, list
    kind: str = ""   # "string", "number", "timespan", "bool", "null", "dynamic"


@dataclass
class ColumnRef(Expr):
    name: str


@dataclass
class StarExpr(Expr):
    """Wildcard * for project/select all columns."""


@dataclass
class BinaryOp(Expr):
    left: Expr
    op: str          # e.g., "==", "and", "contains", "in", "matches"
    right: Expr


@dataclass
class UnaryOp(Expr):
    op: str          # "not", "!", "+", "-"
    operand: Expr


@dataclass
class BetweenExpr(Expr):
    expr: Expr
    low: Expr
    high: Expr


@dataclass
class FuncCall(Expr):
    name: str
    args: list[Expr] = field(default_factory=list)


@dataclass
class IndexAccess(Expr):
    """Array index access or dynamic property access: expr[key] or expr.key"""
    obj: Expr
    key: str | int


@dataclass
class DollarRef(Expr):
    """$left.Column or $right.Column reference."""
    side: str        # "left" or "right"
    column: str


@dataclass
class CaseExpr(Expr):
    """case(pred1, val1, pred2, val2, ..., default)"""
    conditions: list[Expr]
    values: list[Expr]
    default: Expr | None = None


@dataclass
class Where(Node):
    condition: Expr


@dataclass
class Project(Node):
    columns: list[Expr]   # ColumnRef, StarExpr, or BinaryOp(name=expr) for rename


@dataclass
class ProjectAway(Node):
    columns: list[str]


@dataclass
class ProjectRename(Node):
    renames: list[tuple[str, str]]   # [(old_name, new_name), ...]


@dataclass
class ProjectReorder(Node):
    """Ignored — no-op for compatibility with Sentinel KQL."""
    columns: list[str] = field(default_factory=list)


@dataclass
class Extend(Node):
    assignments: list[tuple[str, Expr]]   # [(name, expr), ...]


@dataclass
class Summarize(Node):
    aggregations: list[tuple[str | None, Expr]]   # [(alias, agg expr)]
    by_columns: list[Expr] = field(default_factory=list)
    bin_expr: Expr | None = None   # bin(column, timespan) expression


@dataclass
class Count(Node):
    """count operator (counts rows)."""


@dataclass
class Distinct(Node):
    columns: list[Expr]


@dataclass
class Take(Node):
    count: int


@dataclass
class Limit(Node):
    count: int


@dataclass
class Top(Node):
    count: int
    by_expr: Expr
    ascending: bool = False


@dataclass
class Sort(Node):
    columns: list[tuple[Expr, bool]]   # [(expr, ascending), ...]


@dataclass
class Join(Node):
    right: TableRef | LetRef
    kind: str          # "inner" or "leftouter"
    condition: Expr
    # Optional: on_keys as parsed from "$left.X == $right.Y" style


@dataclass
class Union(Node):
    right: TableRef | LetRef


@dataclass
class MvExpand(Node):
    column: str
    to_type: str | None = None


@dataclass
class Render(Node):
    """Ignored: render operator and its arguments."""
    args: list[str] = field(default_factory=list)


@dataclass
class Search(Node):
    term: str


@dataclass
class Parse(Node):
    """parse operator: parse column with pattern — stubbed (no-op)."""
    column: str
    pattern: str = ""
    args: list[str] = field(default_factory=list)


class KqlParseError(SyntaxError):
    """Parse/semantic error with a user-presentable message."""
