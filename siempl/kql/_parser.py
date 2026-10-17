"""KQL parser: recursive-descent from token stream -> AST.

Produces a hierarchy of AST nodes that the compiler transforms to SQL.

AST node types (all dataclasses):
  - Pipeline: pipeline of tabular operators
  - TableRef: reference to a data table
  - LetBinding: name = <tabular_query> or name = <scalar_expr>
  - BinaryOp, UnaryOp: expression operators
  - FuncCall: function invocation
  - ColumnRef: column name reference
  - Literal: string, number, timespan, bool, null, dynamic
  - LetRef: reference to a let-bound name
  - DollarRef: $left.Column or $right.Column (join keys)
  - IndexAccess: expr[index] or expr.key (for dynamic)
  - operators (Where, Project, ProjectAway, ProjectRename, Extend,
    Summarize, Count, Distinct, Take, Limit, Top, Sort, Join, Union,
    MvExpand, Render, Search, Parse, LetStatement)

Grammar (simplified):
  query          = {let_statement ";"} pipeline
  let_statement  = "let" IDENTIFIER "=" (scalar_expr | pipeline)
  pipeline       = tabular_source {"|" operator}
  tabular_source = table_name | IDENTIFIER  -- (let reference or table name)
  operator       = WHERE expr
                 | PROJECT column_list
                 | PROJECT_AWAY column_list
                 | PROJECT_RENAME (col=NEWNAME), ...
                 | EXTEND (col=expr), ...
                 | SUMMARIZE [agg_list] ["by" group_list]
                 | COUNT
                 | DISTINCT column_list
                 | TAKE number | LIMIT number
                 | TOP number "by" expr ["asc"|"desc"]
                 | SORT "by" sort_list | ORDER "by" sort_list
                 | JOIN ["kind" "=" ("inner"|"leftouter")] source "on" expr
                 | UNION source
                 | MV_EXPAND col ["to" "typeof" type]
                 | RENDER ...
                 | SEARCH string
  expr           = or_expr
"""
from __future__ import annotations

# Public import path is unchanged: everything that used to be defined here is re-exported. KqlParser is now assembled
# from three mixins; see docs/KQL.md for the layout.
# ruff: noqa: F401, E402
from ._nodes import (
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
    KqlParseError,
    LetRef,
    LetStatement,
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
from ._parser_base import _ParserBase
from ._parser_exprs import _ExprParsers
from ._parser_ops import _OperatorParsers
from ._tokenizer import AGG_FUNCTIONS, PIPE_OPERATORS, SCALAR_FUNCTIONS, Token, TokenType, tokenize


class KqlParser(_ParserBase, _OperatorParsers, _ExprParsers):
    """Recursive-descent parser for KQL.

    Tokens are consumed left-to-right. lookahead() peeks at the next
    token; consume() eats it and returns it; match() conditionally
    consumes a token of the given type/keyword.
    """


def parse_kql(query: str) -> Pipeline:
    """Parse a KQL query string into an AST Pipeline."""
    tokens = tokenize(query)
    parser = KqlParser(tokens)
    return parser.parse()
