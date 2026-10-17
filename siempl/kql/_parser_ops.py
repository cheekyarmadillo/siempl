"""KqlParser mixin: statements (let, pipeline, subqueries) and every tabular operator (where, project, summarize, join, ...)."""
from __future__ import annotations

from ._nodes import (
    BinaryOp,
    Count,
    Distinct,
    DollarRef,
    Expr,
    Extend,
    FuncCall,
    Join,
    KqlParseError,
    LetRef,
    LetStatement,
    Limit,
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
    Summarize,
    TableRef,
    Take,
    Top,
    Union,
    Where,
)
from ._tokenizer import TokenType


class _OperatorParsers:
    """Statement and tabular-operator parsing."""

    def parse(self) -> Pipeline:
        """query = {let_statement ";"} pipeline"""
        let_bindings: list[LetStatement] = []

        # Parse optional let statements
        while self._is_keyword("let"):
            let_bindings.append(self._parse_let())
            if self.current.type == TokenType.SEMI:
                self.consume()  # eat semicolon
            # Multiple let statements separated by ;
            while self.current.type == TokenType.SEMI:
                self.consume()
            # If semicolons were trailing, we may be at pipe now

        # Now parse the pipeline
        pipeline = self._parse_pipeline()
        pipeline.let_bindings = let_bindings
        # Attach any parenthesized subqueries parsed during the pipeline as synthetic lets
        pipeline.let_bindings.extend(
            LetStatement(name, sq) for name, sq in self._subqueries
        )
        # Bug 1b: ensure no unconsumed tokens remain
        if self.current.type != TokenType.EOF:
            tok = self.current
            self._error(f"unexpected token '{tok.value}' at position {tok.pos}")
        return pipeline

    def _parse_let(self) -> LetStatement:
        """let Name = (scalar_expr | pipeline)"""
        self.expect(TokenType.KEYWORD, "let")
        name = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.EQ)
        # Try to distinguish: if the RHS looks like a table reference or piped query,
        # parse as pipeline; otherwise parse as scalar expression.
        # Heuristic: if first token is an identifier (table name or let ref) followed by |,
        # or followed by EOF/;, it's tabular.
        save = self.pos
        try:
            # Try parsing as pipeline
            val = self._parse_pipeline()
            return LetStatement(name, val)
        except KqlParseError:
            # Rewind, parse as scalar expression
            self.pos = save
            val = self._parse_expr()
            return LetStatement(name, val)

    def _parse_pipeline(self) -> Pipeline:
        """pipeline = tabular_source {"|" operator}"""
        source = self._parse_tabular_source()
        operators: list[Node] = []
        while self._is_pipe():
            self.consume()  # eat |
            # Check for empty pipe or expression pipe
            if self.current.type == TokenType.EOF:
                self._error("unexpected end after pipe")
            op = self._parse_operator()
            if op is not None:
                operators.append(op)
        return Pipeline(source=source, operators=operators)

    def _parse_tabular_source(self) -> TableRef | LetRef:
        """tabular_source = table_name | IDENTIFIER"""
        # Table names could also be function calls in KQL? No, tabular operators
        # start pipelines. First element is always a table name or let reference.
        tok = self.current
        if tok.type == TokenType.IDENTIFIER:
            self.consume()
            # Could be a table name or a let reference
            return TableRef(tok.value)
        if tok.type == TokenType.KEYWORD:
            # Keywords are not valid table sources
            self._error(f"unexpected keyword '{tok.value}' — expected a table name or let variable")
        self._error(f"expected table name, got {tok.value!r}")

    def _parse_operator(self) -> Node | None:
        """Dispatch to the correct operator parser."""
        if not self._is_operator_keyword() and self.current.type != TokenType.KEYWORD:
            # Could be a search operator: search "term" or a bare expression
            # Actually "search" IS a keyword. Let's handle gracefully.
            if self.current.type == TokenType.STRING:
                # Bare string after pipe? Probably malformed.
                self._error(f"unexpected string literal after pipe — did you mean 'search {self.current.value}'?")
            self._error(f"expected a tabular operator, got {self.current.value!r}")

        op_name = self.current.value

        if op_name == "where":
            return self._parse_where()
        if op_name == "project":
            return self._parse_project()
        if op_name == "project-away":
            return self._parse_project_away()
        if op_name == "project-rename":
            return self._parse_project_rename()
        if op_name == "project-reorder":
            return self._parse_project_reorder()
        if op_name == "extend":
            return self._parse_extend()
        if op_name == "summarize":
            return self._parse_summarize()
        if op_name == "count":
            return self._parse_count()
        if op_name == "distinct":
            return self._parse_distinct()
        if op_name == "take":
            return self._parse_take()
        if op_name == "limit":
            return self._parse_limit()
        if op_name == "top":
            return self._parse_top()
        if op_name in ("sort", "order"):
            return self._parse_sort()
        if op_name == "join":
            return self._parse_join()
        if op_name == "union":
            return self._parse_union()
        if op_name == "mv-expand":
            return self._parse_mv_expand()
        if op_name == "render":
            return self._parse_render()
        if op_name == "search":
            return self._parse_search()
        if op_name == "parse":
            return self._parse_parse_op()
        self._error(f"unknown operator: {op_name}")

    def _parse_where(self) -> Where:
        self.consume()  # 'where'
        return Where(self._parse_expr())

    def _parse_project(self) -> Project:
        self.consume()  # 'project'
        cols = self._parse_column_list()
        return Project(cols)

    def _parse_project_away(self) -> ProjectAway:
        self.consume()
        cols = []
        while True:
            t = self.current
            if t.type == TokenType.IDENTIFIER:
                cols.append(t.value)
                self.consume()
            elif t.type == TokenType.STAR:
                cols.append("*")
                self.consume()
            else:
                break
            if not self.match(TokenType.COMMA):
                break
        return ProjectAway(cols)

    def _parse_project_rename(self) -> ProjectRename:
        # KQL syntax: project-rename NewName = OldName, ...
        self.consume()
        renames = []
        while True:
            new_name = self.expect(TokenType.IDENTIFIER).value
            self.expect(TokenType.EQ)
            old_name = self.expect(TokenType.IDENTIFIER).value
            renames.append((old_name, new_name))
            if not self.match(TokenType.COMMA):
                break
        return ProjectRename(renames)

    def _parse_project_reorder(self) -> ProjectReorder:
        """project-reorder: no-op (Sentinel compatibility)."""
        self.consume()
        cols = []
        while self.current.type == TokenType.IDENTIFIER:
            cols.append(self.current.value)
            self.consume()
            if not self.match(TokenType.COMMA):
                break
        return ProjectReorder(cols)

    def _parse_extend(self) -> Extend:
        self.consume()  # 'extend'
        return Extend(self._parse_assignment_list())

    def _parse_summarize(self) -> Summarize:
        self.consume()  # 'summarize'
        aggregations = self._parse_agg_list()

        by_columns: list[Expr] = []
        bin_expr = None

        if self._is_keyword("by"):
            self.consume()
            # Parse group-by list, checking for bin()
            while True:
                # Check for bin() as a group expression
                if self._is_keyword("bin"):
                    bin_expr = self._parse_bin_expr()
                    # bin() can be standalone or followed by comma
                    if not self.match(TokenType.COMMA):
                        break
                    continue
                by_columns.append(self._parse_expr())
                if not self.match(TokenType.COMMA):
                    break

        return Summarize(aggregations=aggregations, by_columns=by_columns, bin_expr=bin_expr)

    def _parse_bin_expr(self) -> Expr:
        """bin(column, timespan) — parsed as a function call."""
        self.expect(TokenType.KEYWORD, "bin")
        self.expect(TokenType.LPAREN)
        col = self._parse_expr()
        self.expect(TokenType.COMMA)
        span = self._parse_expr()
        self.expect(TokenType.RPAREN)
        return FuncCall("bin", [col, span])

    def _parse_agg_list(self) -> list[tuple[str | None, Expr]]:
        """Parse aggregation list in summarize: count(), dcount(Col), Col=sum(Val),
        or arbitrary aggregate expressions like max(Sev) - 2."""
        aggs: list[tuple[str | None, Expr]] = []
        while True:
            if self.current.type in (TokenType.PIPE, TokenType.EOF,
                                     TokenType.SEMI, TokenType.RPAREN):
                break
            if self._is_keyword("by"):
                break
            # "Alias = expr" — identifier directly followed by =
            if (self.current.type == TokenType.IDENTIFIER
                    and self.lookahead(1).type == TokenType.EQ):
                alias = self.current.value
                self.consume()  # name
                self.consume()  # =
                aggs.append((alias, self._parse_expr()))
            else:
                aggs.append((None, self._parse_expr()))
            if not self.match(TokenType.COMMA):
                break
        return aggs

    def _parse_count(self) -> Count:
        self.consume()
        return Count()

    def _parse_distinct(self) -> Distinct:
        self.consume()
        cols = []
        while True:
            cols.append(self._parse_expr())
            if not self.match(TokenType.COMMA):
                break
        return Distinct(cols)

    def _parse_take(self) -> Take:
        self.consume()
        return Take(self._parse_integer())

    def _parse_limit(self) -> Limit:
        self.consume()
        return Limit(self._parse_integer())

    def _parse_top(self) -> Top:
        self.consume()
        count = self._parse_integer()
        self.expect(TokenType.KEYWORD, "by")
        by_expr = self._parse_expr()
        ascending = False
        if self._is_keyword("asc"):
            self.consume()
            ascending = True
        elif self._is_keyword("desc"):
            self.consume()
            ascending = False
        return Top(count, by_expr, ascending)

    def _parse_sort(self) -> Sort:
        self.consume()  # 'sort' or 'order'
        self.expect(TokenType.KEYWORD, "by")
        cols = []
        while True:
            expr = self._parse_expr()
            ascending = True
            if self._is_keyword("asc"):
                self.consume()
            elif self._is_keyword("desc"):
                self.consume()
                ascending = False
            cols.append((expr, ascending))
            if not self.match(TokenType.COMMA):
                break
        return Sort(cols)

    def _parse_join(self) -> Join:
        self.consume()  # 'join'
        kind = "inner"
        # kind=inner or kind=leftouter
        if self._is_keyword("kind"):
            self.consume()
            self.expect(TokenType.EQ)
            if self._is_keyword("inner"):
                kind = "inner"
            elif self._is_keyword("leftouter"):
                kind = "leftouter"
            elif self._is_keyword("fullouter"):
                kind = "fullouter"
            elif self._is_keyword("rightouter"):
                kind = "rightouter"
            else:
                self._error("expected 'inner', 'leftouter', 'fullouter', or 'rightouter' after kind=")
            self.consume()
        # Table reference (or parenthesized subquery)
        if self.current.type == TokenType.LPAREN:
            right = self._parse_subquery()
        else:
            right = self._parse_tabular_source()
        # keyword "on"
        self.expect(TokenType.KEYWORD, "on")
        # Handle comma-separated bare keys: on A, B => $left.A == $right.A and $left.B == $right.B
        keys: list[str] = []
        if self.current.type == TokenType.IDENTIFIER:
            # Try to parse as comma-separated bare column names first
            save = self.pos
            keys.append(self.current.value)
            self.consume()
            while self.match(TokenType.COMMA):
                if self.current.type == TokenType.IDENTIFIER:
                    keys.append(self.current.value)
                    self.consume()
                else:
                    break
            # If we successfully parsed one or more keys and the next token is | or EOF,
            # treat this as bare-key join syntax
            if len(keys) == 1 and self.current.type not in (TokenType.EOF, TokenType.PIPE, TokenType.SEMI):
                # Single key but more tokens follow — it might be `on A == B` or `on A | ...`
                # Rewind and parse as a full expression
                self.pos = save
                condition = self._parse_expr()
            elif len(keys) >= 2:
                # Multiple bare keys: build and-chain
                condition = None
                for k in keys:
                    eq = BinaryOp(DollarRef("left", k), "==", DollarRef("right", k))
                    if condition is None:
                        condition = eq
                    else:
                        condition = BinaryOp(condition, "and", eq)
            else:
                self.pos = save
                condition = self._parse_expr()
        else:
            condition = self._parse_expr()
        return Join(right=right, kind=kind, condition=condition)

    def _parse_union(self) -> Union:
        self.consume()
        # Handle parenthesised subquery or comma-separated table names
        if self.current.type == TokenType.LPAREN:
            right = self._parse_subquery()
            return Union(right=right)
        right = self._parse_tabular_source()
        return Union(right=right)

    def _parse_subquery(self) -> TableRef | LetRef:
        """Parse a parenthesized subquery like (U | where x=='y') into a nested AST.

        The subquery will be compiled as a separate CTE and referenced by name.
        We store it as a synthetic LetStatement to reuse the tabular let machinery.
        """
        self.expect(TokenType.LPAREN)
        inner = self._parse_pipeline()
        self.expect(TokenType.RPAREN)
        # Store the sub-pipeline for later compilation; return a synthetic name
        name = f"_sq{self._sq_counter}"
        self._sq_counter += 1
        self._subqueries.append((name, inner))
        return LetRef(name)

    def _parse_mv_expand(self) -> MvExpand:
        self.consume()
        col = self.expect(TokenType.IDENTIFIER).value
        to_type = None
        if self._is_keyword("to"):
            self.consume()
            self.expect(TokenType.KEYWORD, "typeof")
            to_type = self.expect(TokenType.IDENTIFIER).value
        return MvExpand(col, to_type)

    def _parse_render(self) -> Render:
        self.consume()
        args = []
        while self.current.type not in (TokenType.EOF, TokenType.PIPE, TokenType.SEMI):
            args.append(str(self.current.value))
            self.consume()
        return Render(args)

    def _parse_search(self) -> Search:
        self.consume()
        term = self.expect(TokenType.STRING).value
        return Search(term)

    def _parse_parse_op(self) -> Parse:
        self.consume()  # 'parse'
        column = ""
        pattern = ""
        args = []
        # parse kind=regex [flags=...] Column with pattern
        # We just slurp tokens until end-of-pipe
        while self.current.type not in (TokenType.EOF, TokenType.PIPE, TokenType.SEMI):
            if column == "" and self.current.type == TokenType.IDENTIFIER:
                column = str(self.current.value)
            elif self.current.type == TokenType.STRING:
                pattern = str(self.current.value)
            else:
                args.append(str(self.current.value))
            self.consume()
        return Parse(column, pattern, args)
