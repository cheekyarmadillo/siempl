"""Token cursor primitives for KqlParser: current/lookahead/consume/match/expect and the error helper."""
from __future__ import annotations

from ._nodes import KqlParseError, Pipeline
from ._tokenizer import PIPE_OPERATORS, Token, TokenType


class _ParserBase:
    """Token cursor shared by the statement and expression parsers."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0
        self._sq_counter = 0
        self._subqueries: list[tuple[str, Pipeline]] = []

    @property
    def current(self) -> Token:
        return self.tokens[self.pos]

    def _pos(self) -> int:
        return self.current.pos if self.pos < len(self.tokens) else 0

    def _error(self, msg: str, pos: int | None = None) -> None:
        raise KqlParseError(
            f"KQL parse error at position {pos or self._pos()}: {msg}"
        )

    def lookahead(self, n: int = 0) -> Token:
        idx = self.pos + n
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]  # EOF

    def consume(self) -> Token:
        t = self.tokens[self.pos]
        if t.type != TokenType.EOF:
            self.pos += 1
        return t

    def match(self, ttype: TokenType, value: str | None = None) -> bool:
        if self.current.type == ttype and (value is None or self.current.value == value):
            self.pos += 1
            return True
        return False

    def expect(self, ttype: TokenType, value: str | None = None) -> Token:
        t = self.current
        if t.type != ttype or (value is not None and t.value != value):
            expected = value or ttype.name
            got = t.value if t.value is not None else t.type.name
            self._error(f"expected {expected}, got {got}")
        return self.consume()

    def _is_keyword(self, *words: str) -> bool:
        return self.current.type == TokenType.KEYWORD and self.current.value in words

    def _is_operator_keyword(self) -> bool:
        return self.current.type == TokenType.KEYWORD and self.current.value in PIPE_OPERATORS

    def _is_pipe(self) -> bool:
        return self.current.type == TokenType.PIPE

    def _is_semi(self) -> bool:
        return self.current.type == TokenType.SEMI
