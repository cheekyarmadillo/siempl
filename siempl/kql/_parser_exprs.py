"""KqlParser mixin: expression parsing (precedence ladder, comparisons, function calls, dynamic literals, column lists)."""
from __future__ import annotations

from typing import Any

from ._nodes import (
    BetweenExpr,
    BinaryOp,
    ColumnRef,
    DollarRef,
    Expr,
    FuncCall,
    IndexAccess,
    KqlParseError,
    LetRef,
    Literal,
    StarExpr,
    UnaryOp,
)
from ._tokenizer import AGG_FUNCTIONS, PIPE_OPERATORS, SCALAR_FUNCTIONS, TokenType


class _ExprParsers:
    """Expression parsing; called from the operator parsers via self."""

    # Precedence levels (lowest to highest):
    #   0: or
    #   1: and
    #   2: not
    #   3: == != < > <= >= =~ !~ contains !contains contains_cs
    #       has !has has_any has_all startswith endswith
    #       in !in in~ between matches
    #   4: + -
    #   5: * / %
    #   6: unary -, unary !

    def _parse_expr(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._is_keyword("or"):
            self.consume()
            right = self._parse_and()
            left = BinaryOp(left, "or", right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_not()
        while self._is_keyword("and"):
            self.consume()
            right = self._parse_not()
            left = BinaryOp(left, "and", right)
        return left

    def _parse_not(self) -> Expr:
        if self._is_keyword("not"):
            self.consume()
            return UnaryOp("not", self._parse_not())
        return self._parse_comparison()

    # String ops that can appear as binary operators in expressions
    _STRING_BINARY_OPS = {
        "contains", "!contains", "contains_cs", "!contains_cs",
        "has", "!has", "has_cs", "!has_cs", "has_any", "!has_any", "has_all",
        "startswith", "!startswith", "endswith", "!endswith",
        "startswith_cs", "!startswith_cs", "endswith_cs", "!endswith_cs",
    }

    _IN_OPS = {"in", "!in", "in~", "!in~"}

    def _parse_comparison(self) -> Expr:
        left = self._parse_term()
        tok = self.current

        # Check for binary comparison operators
        if tok.type in (TokenType.EQEQ, TokenType.NEQ, TokenType.LT, TokenType.GT,
                         TokenType.LTE, TokenType.GTE, TokenType.TILDE_EQ, TokenType.TILDE_NEQ):
            self.consume()
            return BinaryOp(left, tok.value, self._parse_term())

        # String/keyword binary operators
        if tok.type == TokenType.KEYWORD:
            op = tok.value
            # String binary operators: contains, !contains, has, etc.
            if op in self._STRING_BINARY_OPS:
                self.consume()
                if op in ("has_any", "has_all") or (op.startswith("!") and op[1:] in ("has_any", "has_all")):
                    right = self._parse_paren_list()
                else:
                    right = self._parse_term()
                return BinaryOp(left, op, right)

            # in / !in / in~
            if op in self._IN_OPS:
                self.consume()
                self.expect(TokenType.LPAREN)
                items = self._parse_expr_list()
                self.expect(TokenType.RPAREN)
                return BinaryOp(left, op, FuncCall("_list", items))

            # between
            if op == "between":
                self.consume()
                self.expect(TokenType.LPAREN)
                low = self._parse_term()
                self.expect(TokenType.RANGE)  # ..
                high = self._parse_term()
                self.expect(TokenType.RPAREN)
                return BetweenExpr(left, low, high)

            # matches
            if op == "matches":
                self.consume()
                self.expect(TokenType.KEYWORD, "regex")
                pattern = self._parse_term()
                return BinaryOp(left, "matches", pattern)

            # isempty, isnotempty, isnull, isnotnull
            if op in ("isempty", "isnotempty", "isnull", "isnotnull"):
                self.consume()
                return UnaryOp(op, left)

        return left

    def _parse_term(self) -> Expr:
        left = self._parse_factor()
        while self.current.type in (TokenType.PLUS, TokenType.MINUS):
            op = self.current.value
            self.consume()
            right = self._parse_factor()
            left = BinaryOp(left, op, right)
        return left

    def _parse_factor(self) -> Expr:
        left = self._parse_unary()
        while self.current.type in (TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op = self.current.value
            self.consume()
            right = self._parse_unary()
            left = BinaryOp(left, op, right)
        return left

    def _parse_unary(self) -> Expr:
        if self.current.type == TokenType.MINUS:
            self.consume()
            return UnaryOp("-", self._parse_unary())
        if self._is_keyword("not"):
            self.consume()
            return UnaryOp("not", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Expr:
        tok = self.current

        # String literal
        if tok.type == TokenType.STRING:
            self.consume()
            result: Expr = Literal(tok.value, "string")
            return self._parse_suffix(result)

        # Number literal
        if tok.type == TokenType.NUMBER:
            self.consume()
            result = Literal(tok.value, "number")
            return self._parse_suffix(result)

        # Timespan literal
        if tok.type == TokenType.TIMESPAN:
            self.consume()
            val, unit = tok.value  # (int, "m")
            result = Literal(tok.value, "timespan")
            return self._parse_suffix(result)

        # Boolean / null keyword
        if tok.type == TokenType.KEYWORD:
            if tok.value == "true":
                self.consume()
                result = Literal(True, "bool")
                return self._parse_suffix(result)
            if tok.value == "false":
                self.consume()
                result = Literal(False, "bool")
                return self._parse_suffix(result)
            if tok.value == "null":
                self.consume()
                result = Literal(None, "null")
                return self._parse_suffix(result)
            if tok.value == "dynamic":
                return self._parse_dynamic()

        # Parenthesized expression
        if tok.type == TokenType.LPAREN:
            self.consume()
            expr = self._parse_expr()
            self.expect(TokenType.RPAREN)
            return self._parse_suffix(expr)

        # Dollar references ($left.Column, $right.Column)
        if tok.type == TokenType.DOLLAR_LEFT:
            self.consume()
            if self.match(TokenType.DOT):
                col = self.expect(TokenType.IDENTIFIER).value
                result = DollarRef("left", col)
                return self._parse_suffix(result)
            result = DollarRef("left", "")
            return self._parse_suffix(result)
        if tok.type == TokenType.DOLLAR_RIGHT:
            self.consume()
            if self.match(TokenType.DOT):
                col = self.expect(TokenType.IDENTIFIER).value
                result = DollarRef("right", col)
                return self._parse_suffix(result)
            result = DollarRef("right", "")
            return self._parse_suffix(result)

        # Identifier or function call
        if tok.type == TokenType.IDENTIFIER:
            name = tok.value
            self.consume()
            # Function call or maybe just a column reference?
            if self.current.type == TokenType.LPAREN:
                self.consume()
                # Handle empty args and non-empty args
                if self.current.type == TokenType.RPAREN:
                    self.consume()
                    result = FuncCall(name, [])
                    return self._parse_suffix(result)
                args = self._parse_expr_list()
                self.expect(TokenType.RPAREN)
                result = FuncCall(name, args)
                return self._parse_suffix(result)
            result = ColumnRef(name)
            return self._parse_suffix(result)

        # Keyword that could be a function (ago, now, datetime, count, etc.)
        if tok.type == TokenType.KEYWORD:
            name = tok.value
            if name in SCALAR_FUNCTIONS or name in AGG_FUNCTIONS or name in ("iff", "iif", "case", "coalesce", "toscalar", "range", "isempty", "isnotempty", "isnull", "isnotnull"):
                # Some names (e.g. count) are also pipe operators; treat as a
                # function only when directly followed by '('.
                if self.lookahead(1).type == TokenType.LPAREN:
                    self.consume()
                    if name == "toscalar":
                        return self._parse_toscalar()
                    return self._parse_suffix(self._parse_func_call_with_name(name))
                if tok.value not in PIPE_OPERATORS:
                    self._error(f"expected '(' after function name '{name}'")
            # Keywords that aren't functions in this position - error
            self._error(f"unexpected keyword '{tok.value}' in expression")

        # Star
        if tok.type == TokenType.STAR:
            self.consume()
            return StarExpr()

        self._error(f"unexpected token {tok.value!r}")

    def _parse_toscalar(self) -> FuncCall:
        """toscalar(<tabular query>) — evaluate a sub-pipeline to a single scalar.

        The inner pipeline is registered as a synthetic subquery (compiled as a
        CTE); the FuncCall carries a LetRef to it for the compiler.
        """
        self.expect(TokenType.LPAREN)
        inner = self._parse_pipeline()
        self.expect(TokenType.RPAREN)
        name = f"_sq{self._sq_counter}"
        self._sq_counter += 1
        self._subqueries.append((name, inner))
        return FuncCall("toscalar", [LetRef(name)])

    def _parse_func_call(self) -> FuncCall:
        """Parse a function call: name(args)"""
        tok = self.current
        if tok.type in (TokenType.IDENTIFIER, TokenType.KEYWORD):
            name = tok.value
            self.consume()
            self.expect(TokenType.LPAREN)
            if self.current.type == TokenType.RPAREN:
                self.consume()
                return FuncCall(name, [])
            args = self._parse_expr_list()
            self.expect(TokenType.RPAREN)
            return FuncCall(name, args)
        self._error(f"expected function name, got {tok.value!r}")

    def _parse_func_call_with_name(self, name: str) -> Expr:
        """Parse a function call when the name was already consumed."""
        self.expect(TokenType.LPAREN)
        if self.current.type == TokenType.RPAREN:
            self.consume()
            if name in ("case", "iff", "iif", "coalesce"):
                return FuncCall(name, [])
            return FuncCall(name, [])
        args = self._parse_expr_list()
        self.expect(TokenType.RPAREN)
        return FuncCall(name, args)

    def _parse_expr_list(self) -> list[Expr]:
        """Parse comma-separated expressions (for function args and in-parens lists)."""
        exprs = [self._parse_expr()]
        while self.match(TokenType.COMMA):
            exprs.append(self._parse_expr())
        return exprs

    def _parse_paren_list(self) -> Expr:
        """Parse (expr1, expr2, ...) as a list for has_any/has_all."""
        self.expect(TokenType.LPAREN)
        items = self._parse_expr_list()
        self.expect(TokenType.RPAREN)
        return FuncCall("_list", items)

    def _parse_dynamic(self) -> Expr:
        """Parse dynamic([...]) or dynamic({...}) literal."""
        self.expect(TokenType.KEYWORD, "dynamic")
        self.expect(TokenType.LPAREN)
        val = self._parse_dynamic_value()
        self.expect(TokenType.RPAREN)
        return Literal(val, "dynamic")

    def _parse_dynamic_value(self) -> Any:
        tok = self.current
        if tok.type == TokenType.LBRACKET:
            return self._parse_dynamic_array()
        if tok.type == TokenType.LBRACE:
            return self._parse_dynamic_object()
        if tok.type == TokenType.STRING:
            self.consume()
            return tok.value
        if tok.type == TokenType.NUMBER:
            self.consume()
            return tok.value
        if tok.type == TokenType.KEYWORD:
            if tok.value == "true":
                self.consume()
                return True
            if tok.value == "false":
                self.consume()
                return False
            if tok.value == "null":
                self.consume()
                return None
        return self._parse_expr()  # fallback

    def _parse_dynamic_array(self) -> list:
        self.expect(TokenType.LBRACKET)
        items = []
        if self.current.type != TokenType.RBRACKET:
            items.append(self._parse_dynamic_value())
            while self.match(TokenType.COMMA):
                items.append(self._parse_dynamic_value())
        self.expect(TokenType.RBRACKET)
        return items

    def _parse_dynamic_object(self) -> dict:
        self.expect(TokenType.LBRACE)
        obj = {}
        if self.current.type != TokenType.RBRACE:
            key = self.current.value
            # Keys are usually identifiers or strings
            if self.current.type == TokenType.IDENTIFIER:
                key = self.current.value
                self.consume()
            elif self.current.type == TokenType.STRING:
                key = self.current.value
                self.consume()
            else:
                self._error("expected object key")
            self.expect(TokenType.COLON)
            val = self._parse_dynamic_value()
            obj[key] = val
            while self.match(TokenType.COMMA):
                key = self.current.value
                if self.current.type == TokenType.IDENTIFIER:
                    self.consume()
                elif self.current.type == TokenType.STRING:
                    self.consume()
                else:
                    break
                self.expect(TokenType.COLON)
                obj[key] = self._parse_dynamic_value()
        self.expect(TokenType.RBRACE)
        return obj

    def _parse_column_list(self) -> list[Expr]:
        """Parse a comma-separated column list for project, distinct, etc.
        Handles: col1, col2, col3 = expr, *, col1.key, col1['key'], tostring(x), etc."""
        cols = []
        while True:
            if self.current.type == TokenType.STAR:
                self.consume()
                cols.append(StarExpr())
            elif self.current.type == TokenType.IDENTIFIER:
                name = self.current.value
                save = self.pos
                self.consume()
                # Check for rename: col = expr
                if self.match(TokenType.EQ):
                    expr = self._parse_expr()
                    cols.append(BinaryOp(ColumnRef(name), "=", expr))
                else:
                    # Parse as expression with suffix support (p.key, Extra['key'])
                    # Rewind to include the identifier and parse full expression
                    self.pos = save
                    expr = self._parse_expr()
                    cols.append(expr)
            elif self.current.type == TokenType.KEYWORD:
                # May be a function call like tostring(Extra.detail) or keyword like 'by'
                save = self.pos
                try:
                    expr = self._parse_expr()
                    cols.append(expr)
                except KqlParseError:
                    # Keywords that can't be expressions stop parsing
                    break
            else:
                break
            if not self.match(TokenType.COMMA):
                break
        return cols

    def _parse_assignment_list(self) -> list[tuple[str, Expr]]:
        """Parse name = expr, name = expr, ... for extend operator."""
        assignments = []
        while True:
            name = self.expect(TokenType.IDENTIFIER).value
            self.expect(TokenType.EQ)
            expr = self._parse_expr()
            assignments.append((name, expr))
            if not self.match(TokenType.COMMA):
                break
        return assignments

    def _parse_suffix(self, expr: Expr) -> Expr:
        """Parse dotted access (expr.key) and bracket access (expr['key'] or expr[0])."""
        while True:
            if self.current.type == TokenType.DOT:
                self.consume()
                # After dot: identifier for property access
                if self.current.type == TokenType.IDENTIFIER:
                    key = self.current.value
                    self.consume()
                    expr = IndexAccess(expr, key)
                elif self.current.type == TokenType.KEYWORD:
                    # Allow keywords as property names (e.g. Extra.type)
                    key = self.current.value
                    self.consume()
                    expr = IndexAccess(expr, key)
                else:
                    self._error(f"expected property name after '.', got {self.current.value!r}")
            elif self.current.type == TokenType.LBRACKET:
                self.consume()
                if self.current.type == TokenType.STRING:
                    key = self.current.value
                    self.consume()
                elif self.current.type == TokenType.NUMBER:
                    key = int(self.current.value) if isinstance(self.current.value, int) else self.current.value
                    self.consume()
                else:
                    key_expr = self._parse_expr()
                    self.expect(TokenType.RBRACKET)
                    expr = IndexAccess(expr, str(key_expr) if hasattr(key_expr, 'name') else '_expr')
                    continue
                self.expect(TokenType.RBRACKET)
                expr = IndexAccess(expr, key)
            else:
                break
        return expr

    def _parse_integer(self) -> int:
        tok = self.current
        if tok.type == TokenType.NUMBER:
            self.consume()
            if isinstance(tok.value, int):
                return tok.value
            return int(tok.value)
        self._error(f"expected integer, got {tok.value!r}")
