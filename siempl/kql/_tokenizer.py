"""KQL lexer/tokenizer.

Tokenizes KQL query text into a stream of tokens. Handles:
  - Identifiers (table names, column names, function names)
  - String literals (single-quoted, double-quoted, verbatim @""/'' form)
  - Numeric literals (integer, float)
  - Timespan literals (1h, 30m, 5d, etc.)
  - dynamic(...) prefixed-expressions (parsed as special tokens)
  - Keywords (case-insensitive matching)
  - Comments (// line, /* block */)
  - Operators and punctuation
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class TokenType(Enum):
    # Punctuation
    PIPE = auto()       # |
    SEMI = auto()       # ;
    COMMA = auto()      # ,
    DOT = auto()        # .
    LPAREN = auto()     # (
    RPAREN = auto()     # )
    LBRACKET = auto()   # [
    RBRACKET = auto()   # ]
    LBRACE = auto()     # {
    RBRACE = auto()     # }
    COLON = auto()      # :
    RANGE = auto()      # .. (between range)

    # Arithmetic
    PLUS = auto()       # +
    MINUS = auto()      # -
    STAR = auto()       # *
    SLASH = auto()      # /
    PERCENT = auto()    # %

    # Comparison
    EQEQ = auto()       # ==
    NEQ = auto()        # !=
    LT = auto()         # <
    GT = auto()         # >
    LTE = auto()        # <=
    GTE = auto()        # >=
    EQ = auto()         # = (for join kind=, let =)
    TILDE_EQ = auto()   # =~
    TILDE_NEQ = auto()  # !~

    # Literals
    STRING = auto()
    NUMBER = auto()
    TIMESPAN = auto()
    BOOLEAN = auto()    # true/false
    NULL = auto()       # null

    # Words
    IDENTIFIER = auto()
    KEYWORD = auto()    # generic keyword

    # Special
    DOLLAR_LEFT = auto()   # $left.
    DOLLAR_RIGHT = auto()  # $right.

    EOF = auto()


KEYWORDS = {
    "and", "or", "not",
    "where", "project", "extend", "summarize", "by", "bin",
    "count", "distinct", "take", "limit", "top", "sort", "order",
    "asc", "desc", "join", "inner", "leftouter", "kind", "on",
    "union", "let", "mv-expand", "mv-apply", "render", "search",
    "true", "false", "null",
    "contains", "!contains", "contains_cs", "!contains_cs",
    "has", "!has", "has_cs", "!has_cs",
    "has_any", "!has_any", "has_all",
    "cidr_contains", "ipv4_is_in_range", "ipv4_is_private",
    "startswith", "!startswith", "endswith", "!endswith",
    "startswith_cs", "!startswith_cs", "endswith_cs", "!endswith_cs",
    "in", "!in", "in~", "!in~", "between", "matches", "regex",
    "isempty", "isnotempty", "isnull", "isnotnull",
    "iff", "iif", "case", "coalesce",
    "dynamic", "typeof", "to",
    "ago", "now", "datetime",
    "floor", "startofday", "format_datetime",
    "tostring", "toint", "tolong", "todouble",
    "strcat", "strlen", "substring", "tolower", "toupper",
    "replace_string", "split", "extract",
    "parse_json", "todynamic", "array_length",
    "dcount", "countif", "sum", "avg", "min", "max",
    "make_set", "make_list", "arg_max", "arg_min", "any", "percentile",
    "range", "toscalar",
    "project-away", "project-rename", "project-reorder",
}

# String operators that appear as binary operators in expressions
STRING_BINARY_OPS = {
    "contains", "!contains", "contains_cs", "!contains_cs",
    "has", "!has", "has_cs", "!has_cs", "has_any", "!has_any", "has_all",
    "startswith", "!startswith", "endswith", "!endswith",
    "startswith_cs", "!startswith_cs", "endswith_cs", "!endswith_cs",
    "in", "!in", "in~", "!in~",
    "matches",
}

# Keywords that can appear as the first token of a tabular operator
PIPE_OPERATORS = {
    "where", "project", "project-away", "project-rename", "project-reorder",
    "extend", "summarize", "count", "distinct", "take", "limit",
    "top", "sort", "order", "join", "union", "mv-expand", "mv-apply",
    "render", "search", "parse",
}

# Aggregation functions (allowed in summarize)
AGG_FUNCTIONS = {
    "count", "countif", "dcount", "dcountif",
    "sum", "avg", "min", "max",
    "make_set", "make_list", "make_set_if", "make_list_if",
    "arg_max", "arg_min", "any", "anyif",
    "percentile", "percentilew", "percentiles",
    "stdev", "variance",
    "bin",
}

# Scalar functions
SCALAR_FUNCTIONS = {
    "cidr_contains", "ipv4_is_in_range", "ipv4_is_private",
    "ago", "now", "datetime",
    "floor", "startofday", "format_datetime",
    "tostring", "toint", "tolong", "todouble",
    "strcat", "strlen", "substring", "tolower", "toupper",
    "replace_string", "split", "extract",
    "parse_json", "todynamic", "array_length",
    "iff", "iif", "case", "coalesce",
    "range", "toscalar",
    "strcmp", "trim", "trim_start", "trim_end",
    "pack", "pack_all", "bag_pack",
}


@dataclass
class Token:
    type: TokenType
    value: Any  # str for keywords/identifiers, int/float for numbers, etc.
    pos: int    # character position in source (for error messages)

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r})"


class KqlTokenizer:
    """Lexer for KQL query strings."""

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.length = len(source)

    def _peek(self, offset: int = 0) -> str:
        p = self.pos + offset
        if p < self.length:
            return self.source[p]
        return ""

    def _advance(self, n: int = 1) -> None:
        self.pos += n

    def _skip_whitespace(self) -> None:
        while self.pos < self.length and self.source[self.pos] in " \t\r\n":
            self.pos += 1

    def _skip_line_comment(self) -> None:
        self.pos += 2  # skip //
        while self.pos < self.length and self.source[self.pos] != "\n":
            self.pos += 1

    def _skip_block_comment(self) -> None:
        self.pos += 2  # skip /*
        while self.pos < self.length:
            if self.source[self.pos] == "*" and self._peek(1) == "/":
                self.pos += 2
                return
            self.pos += 1
        # Unterminated block comment: accept anyway at EOF.

    def _read_string(self, quote: str) -> str:
        """Read a string literal delimited by `quote` (single or double)."""
        start = self.pos
        self.pos += 1  # skip opening quote
        result = []
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch == "\\" and quote != "'":  # KQL doesn't do backslash escapes in single quotes
                self.pos += 1
                if self.pos < self.length:
                    nxt = self.source[self.pos]
                    escapes = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", quote: quote}
                    result.append(escapes.get(nxt, nxt))
            elif ch == quote:
                self.pos += 1
                return "".join(result)
            else:
                result.append(ch)
            self.pos += 1
        raise self._error(start, "unterminated string literal")

    def _read_verbatim_string(self) -> str:
        """Read a verbatim string: @'...'  or @"..." """
        self.pos += 1  # skip @
        if self.pos >= self.length or self.source[self.pos] not in ('"', "'"):
            raise self._error(self.pos - 1, "expected quote after @")
        quote = self.source[self.pos]
        self.pos += 1
        result = []
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch == quote:
                # Check for doubled quote as escape
                if self._peek(1) == quote:
                    result.append(quote)
                    self.pos += 2
                    continue
                self.pos += 1
                return "".join(result)
            result.append(ch)
            self.pos += 1
        raise self._error(self.pos - 1, "unterminated verbatim string literal")

    def _read_number(self) -> Token:
        start = self.pos
        result = []
        while self.pos < self.length and self.source[self.pos].isdigit():
            result.append(self.source[self.pos])
            self.pos += 1
        # Decimal part
        if self.pos < self.length and self.source[self.pos] == "." and self._peek(1).isdigit():
            result.append(".")
            self.pos += 1
            while self.pos < self.length and self.source[self.pos].isdigit():
                result.append(self.source[self.pos])
                self.pos += 1
            return Token(TokenType.NUMBER, float("".join(result)), start)
        # Check for timespan suffix
        if self.pos < self.length and self.source[self.pos] in "smhd":
            # Could be a timespan literal
            # Check for 'ms', 'microsecond', 'tick', or just 's'/'m'/'h'/'d'
            suffix_start = self.pos
            suffix = self.source[self.pos]
            self.pos += 1
            if suffix == "m" and self.pos < self.length and self.source[self.pos] == "s":
                suffix = "ms"
                self.pos += 1
            # Make sure the suffix isn't part of an identifier
            if self.pos >= self.length or not self.source[self.pos].isalpha():
                # It's a timespan
                val = int("".join(result))
                return Token(TokenType.TIMESPAN, (val, suffix), start)
            # It's an identifier starting with digits, push back
            self.pos = suffix_start
            return Token(TokenType.NUMBER, int("".join(result)), start)
        # Check for 'e' scientific notation
        if self.pos < self.length and self.source[self.pos] in "eE":
            next_chars = self.source[self.pos + 1:self.pos + 3]
            if next_chars and (next_chars[0] in "+-" or next_chars[0].isdigit()):
                result.append(self.source[self.pos])
                self.pos += 1
                if self.pos < self.length and self.source[self.pos] in "+-":
                    result.append(self.source[self.pos])
                    self.pos += 1
                while self.pos < self.length and self.source[self.pos].isdigit():
                    result.append(self.source[self.pos])
                    self.pos += 1
                return Token(TokenType.NUMBER, float("".join(result)), start)

        val = "".join(result)
        if "." in val:
            return Token(TokenType.NUMBER, float(val), start)
        return Token(TokenType.NUMBER, int(val), start)

    def _read_identifier(self) -> Token:
        start = self.pos
        result = []
        while self.pos < self.length and (
            self.source[self.pos].isalnum() or self.source[self.pos] in "_$-"
        ):
            result.append(self.source[self.pos])
            self.pos += 1
        name = "".join(result)
        lower = name.lower()

        # $left and $right are special
        if lower in ("$left", "$right"):
            if lower == "$left":
                return Token(TokenType.DOLLAR_LEFT, "$left", start)
            return Token(TokenType.DOLLAR_RIGHT, "$right", start)

        if lower in KEYWORDS:
            return Token(TokenType.KEYWORD, lower, start)
        # Timespan suffix after number (e.g., 5m)
        # Already handled in _read_number

        return Token(TokenType.IDENTIFIER, name, start)

    def _error(self, pos: int, msg: str) -> SyntaxError:
        # Show context around the error position
        line_start = self.source.rfind("\n", 0, pos) + 1
        line_end = self.source.find("\n", pos)
        if line_end == -1:
            line_end = self.length
        line = self.source[line_start:line_end]
        col = pos - line_start
        pointer = " " * col + "^"
        return SyntaxError(f"{msg} at position {pos}:\n  {line}\n  {pointer}")

    def _handle_token_char(self, tokens: list[Token]) -> bool:
        """Handle single-character and two-character tokens.

        Returns True if the current character was consumed.
        """
        ch = self.source[self.pos]
        mapping: dict[str, tuple[list[str], list[TokenType]]] = {
            "|": (["|"], [TokenType.PIPE]),
            ";": ([";"], [TokenType.SEMI]),
            ",": ([","], [TokenType.COMMA]),
            ":": ([":"], [TokenType.COLON]),
            "(": (["("], [TokenType.LPAREN]),
            ")": ([")"], [TokenType.RPAREN]),
            "[": (["["], [TokenType.LBRACKET]),
            "]": (["]"], [TokenType.RBRACKET]),
            "{": (["{"], [TokenType.LBRACE]),
            "}": (["}"], [TokenType.RBRACE]),
            "+": (["+"], [TokenType.PLUS]),
            "-": (["-"], [TokenType.MINUS]),
            "*": (["*"], [TokenType.STAR]),
            "/": (["/"], [TokenType.SLASH]),
            "%": (["%"], [TokenType.PERCENT]),
            "=": (["==", "=~", "="], [TokenType.EQEQ, TokenType.TILDE_EQ, TokenType.EQ]),
            "<": (["<=", "<"], [TokenType.LTE, TokenType.LT]),
            ">": ([">=", ">"], [TokenType.GTE, TokenType.GT]),
        }
        if ch not in mapping:
            return False
        candidates, token_types = mapping[ch]
        for cand, tt in zip(candidates, token_types):
            if self._match(cand):
                tokens.append(Token(tt, cand, self.pos))
                self.pos += len(cand)
                return True
        return False

    def _match(self, s: str) -> bool:
        """Return True if `s` matches source starting at current position."""
        end = self.pos + len(s)
        return end <= self.length and self.source[self.pos:end] == s

    def _handle_alpha_identifier(self, tokens: list[Token]) -> bool:
        ch = self.source[self.pos]
        if not (ch.isalpha() or ch in "_$"):
            return False
        start = self.pos
        result = []
        # '!' and '~' are legal inside keyword operators (in~, !in~, !contains ...): keep them, as the
        # pre-refactor tokenizer did. Dropping '~' here made 'in~' fail to tokenize.
        while self.pos < self.length and (
            self.source[self.pos].isalnum() or self.source[self.pos] in "_$-!~"
        ):
            result.append(self.source[self.pos])
            self.pos += 1
        name = "".join(result)
        lower = name.lower()
        if lower.startswith("$left"):
            tokens.append(Token(TokenType.DOLLAR_LEFT, "$left", start))
            self.pos = start + 5
            return True
        if lower.startswith("$right"):
            tokens.append(Token(TokenType.DOLLAR_RIGHT, "$right", start))
            self.pos = start + 6
            return True
        if lower in KEYWORDS:
            tokens.append(Token(TokenType.KEYWORD, lower, start))
        else:
            tokens.append(Token(TokenType.IDENTIFIER, name, start))
        return True

    # Dispatch helpers used by tokenize to avoid long if/elif chains
    def _handle_number(self, tokens: list[Token]) -> bool:
        """Returns True if a numeric/timespan token was consumed."""
        if not self.source[self.pos].isdigit():
            return False
        tokens.append(self._read_number())
        return True

    def _handle_dot(self, tokens: list[Token]) -> bool:
        if self.source[self.pos] != ".":
            return False
        if self._peek(1) == ".":
            tokens.append(Token(TokenType.RANGE, "..", self.pos))
            self.pos += 2
            return True
        if self._peek(1).isdigit():
            tokens.append(self._read_number())
            return True
        tokens.append(Token(TokenType.DOT, ".", self.pos))
        self.pos += 1
        return True

    def _handle_exclamation(self, tokens: list[Token]) -> bool:
        ch = self.source[self.pos]
        if ch != "!":
            return False
        if self._peek(1) == "=":
            tokens.append(Token(TokenType.NEQ, "!=", self.pos))
            self.pos += 2
            return True
        if self._peek(1) == "~":
            tokens.append(Token(TokenType.TILDE_NEQ, "!~", self.pos))
            self.pos += 2
            return True
        if self._peek(1).isalpha():
            start = self.pos
            result = ["!"]
            self.pos += 1
            while self.pos < self.length and (
                self.source[self.pos].isalnum() or self.source[self.pos] in "_$-~"
            ):
                result.append(self.source[self.pos])
                self.pos += 1
            name = "".join(result).lower()
            tokens.append(Token(
                TokenType.KEYWORD if name in KEYWORDS else TokenType.IDENTIFIER,
                name, start,
            ))
            return True
        tokens.append(Token(TokenType.KEYWORD, "not", self.pos))
        self.pos += 1
        return True

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while True:
            self._skip_whitespace()
            if self.pos >= self.length:
                tokens.append(Token(TokenType.EOF, None, self.pos))
                return tokens

            ch = self.source[self.pos]

            if ch == "/" and self._peek(1) == "/":
                self._skip_line_comment(); continue
            if ch == "/" and self._peek(1) == "*":
                self._skip_block_comment(); continue
            if ch == "@" and self._peek(1) in ('"', "'"):
                s = self._read_verbatim_string(); tokens.append(Token(TokenType.STRING, s, self.pos)); continue
            if ch in ('"', "'"):
                s = self._read_string(ch); tokens.append(Token(TokenType.STRING, s, self.pos - 1)); continue
            if self._handle_number(tokens): continue
            if self._handle_dot(tokens): continue
            if self._handle_token_char(tokens): continue
            if self._handle_exclamation(tokens): continue
            if self._handle_alpha_identifier(tokens): continue
            raise self._error(self.pos, f"unexpected character {ch!r}")


def tokenize(source: str) -> list[Token]:
    return KqlTokenizer(source).tokenize()
