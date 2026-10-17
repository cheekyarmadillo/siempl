"""Function-call compilation for the KQL compiler (mixin).

Maps KQL function calls to DuckDB SQL: the FUNCTION_MAP table, functions with
their own argument handling, and a dispatch table for those special cases.
"""
from __future__ import annotations

from typing import Any

from ._compiler_sql import KqlCompilerError, SqlBuilder
from ._parser import Expr, FuncCall, LetRef

# Function name -> DuckDB SQL expression (with {0}, {1} placeholders)
FUNCTION_MAP: dict[str, str] = {
    # Time functions
    "now": "timezone('UTC', NOW())",
    "datetime": "CAST({0} AS TIMESTAMP)",
    # bin and ago handled specially (timespan args)
    "floor": "TIME_BUCKET(CAST({1} AS INTERVAL), {0})",  # for timestamps
    "startofday": "DATE_TRUNC('day', {0})",
    "format_datetime": "STRFTIME({0}, {1})",
    # Type conversion
    "tostring": "CAST({0} AS VARCHAR)",
    "toint": "CAST({0} AS INTEGER)",
    "tolong": "CAST({0} AS BIGINT)",
    "todouble": "CAST({0} AS DOUBLE)",
    "tobool": "CAST({0} AS BOOLEAN)",
    # String
    "strcat": None,  # handled specially — variable args
    "strlen": "LENGTH({0})",
    "substring": "SUBSTRING({0}, {1}, {2})",  # KQL 1-indexed, DuckDB 1-indexed
    "tolower": "LOWER({0})",
    "toupper": "UPPER({0})",
    "replace_string": "REPLACE({0}, {1}, {2})",
    "split": "STRING_SPLIT({0}, {1})",
    "extract": "REGEXP_EXTRACT({2}, {1}, {0})",  # extract(pattern, capture_group, text)
    "strcmp": "CASE WHEN {0} = {1} THEN 0 WHEN {0} < {1} THEN -1 ELSE 1 END",
    "trim": "TRIM({0})",
    "trim_start": "LTRIM({0})",
    "trim_end": "RTRIM({0})",
    # JSON/dynamic
    "parse_json": "CAST({0} AS JSON)",
    "ipv4_is_private": "CASE WHEN CAST({0} AS VARCHAR) LIKE '10.%' OR CAST({0} AS VARCHAR) LIKE '172.1[6-9].%' OR CAST({0} AS VARCHAR) LIKE '172.2[0-9].%' OR CAST({0} AS VARCHAR) LIKE '172.3[0-1].%' OR CAST({0} AS VARCHAR) LIKE '192.168.%' THEN TRUE ELSE FALSE END",
    "cidr_contains": "(COALESCE(CAST({0} AS VARCHAR), '') != '' AND COALESCE(CAST({1} AS VARCHAR), '') != '' AND CAST(CAST({0} AS VARCHAR) AS INET) <<= CAST(CAST({1} AS VARCHAR) AS INET))",
    "ipv4_is_in_range": "(COALESCE(CAST({0} AS VARCHAR), '') != '' AND COALESCE(CAST({1} AS VARCHAR), '') != '' AND CAST(CAST({0} AS VARCHAR) AS INET) <<= CAST(CAST({1} AS VARCHAR) AS INET))",
    "todynamic": "CAST({0} AS JSON)",
    "array_length": "ARRAY_LENGTH({0})",
    # Aggregation
    "dcount": "APPROX_COUNT_DISTINCT({0})",
    "count": "COUNT({0})",
    "countif": "SUM(CASE WHEN {0} THEN 1 ELSE 0 END)",
    "sum": "SUM({0})",
    "avg": "AVG({0})",
    "min": "MIN({0})",
    "max": "MAX({0})",
    "make_set": "ARRAY_AGG(DISTINCT {0})",
    "make_set_if": "ARRAY_AGG(DISTINCT CASE WHEN {1} THEN {0} END)",
    "make_list": "ARRAY_AGG({0})",
    "make_list_if": "ARRAY_AGG(CASE WHEN {1} THEN {0} END)",
    "arg_max": "ARG_MAX({0}, {1})",   # arg_max(col_to_max, col_to_return)
    "arg_min": "ARG_MIN({0}, {1})",
    "any": "ANY_VALUE({0})",
    "anyif": "ANY_VALUE(CASE WHEN {1} THEN {0} END)",
    "percentile": "QUANTILE_CONT({0}, {1}/100.0)",
    "percentilew": "QUANTILE_CONT({0}, {1}/100.0)",  # weighted approx
    "percentiles": "QUANTILE_CONT({0}, {1}/100.0)",
    "stdev": "STDDEV({0})",
    "variance": "VARIANCE({0})",
    # Conditional
    "iff": "CASE WHEN {0} THEN {1} ELSE {2} END",
    "iif": "CASE WHEN {0} THEN {1} ELSE {2} END",
    "coalesce": None,  # handled specially — variable args
    # range(), used in let statements
    "range": "GENERATE_SERIES({0}, {1}, {2})",
    "pack": None,   # handled specially
    "pack_all": "CAST(ROW(*) AS JSON)",  # rough
    "bag_pack": "MAP_FROM_ENTRIES(ARRAY[{0}], ARRAY[{1}])",  # bag_pack("key", val)
}

# Functions that have variable argument counts
VARARG_FUNCTIONS = {"coalesce", "strcat", "case"}

# Functions that take a timespan argument (bin, floor, ago)
TIMESPAN_ARG2 = {"floor"}


class _FuncsMixin:
    """Function-call compilation. Mixed into KqlCompiler; uses its _compile_expr."""

    def _compile_func_call(self, b: SqlBuilder, func: FuncCall) -> None:
        name = func.name.lower()
        dispatch = self._FUNC_DISPATCH.get(name)
        if dispatch is not None:
            dispatch(self, b, func)
            return
        # Look up in function map
        mapping = FUNCTION_MAP.get(name)
        if mapping is None:
            self._compile_passthrough_call(b, name, func.args)
            return
        # Handle special argument patterns
        if name in TIMESPAN_ARG2 and len(func.args) >= 2:
            self._compile_timespan_func(b, name, func.args)
            return
        if name == "extract":
            self._compile_extract(b, func.args)
            return
        self._compile_mapped_call(b, mapping, func.args)

    def _compile_passthrough_call(self, b: SqlBuilder, name: str, args) -> None:
        """Unknown function: pass the call through as a DuckDB function."""
        b.add(f"{name.upper()}(")
        for i, arg in enumerate(args):
            if i > 0:
                b.add(", ")
            self._compile_expr(b, arg)
        b.add(")")

    def _compile_mapped_call(self, b: SqlBuilder, mapping: str, args) -> None:
        """Fill a FUNCTION_MAP template with the compiled arguments."""
        if "{" in mapping:
            self._compile_mapped_interpolation(b, mapping, args)
        elif args:
            b.add(f"{mapping}(")
            for i, arg in enumerate(args):
                if i > 0:
                    b.add(", ")
                self._compile_expr(b, arg)
            b.add(")")
        else:
            b.add(mapping)

    def _compile_toscalar(self, b: SqlBuilder, func: FuncCall) -> None:
        arg = func.args[0] if func.args else None
        if isinstance(arg, LetRef):
            b.add(f'(SELECT * FROM "{arg.name}" LIMIT 1)')
        elif arg is not None:
            b.add("(")
            self._compile_expr(b, arg)
            b.add(" LIMIT 1)")
        else:
            raise KqlCompilerError("toscalar() requires a query argument")

    def _compile_ago(self, b: SqlBuilder, func: FuncCall) -> None:
        b.add("timezone('UTC', now()) - ")
        self._compile_expr(b, func.args[0])

    def _compile_bin(self, b: SqlBuilder, func: FuncCall) -> None:
        b.add("TIME_BUCKET(")
        self._compile_expr(b, func.args[1])
        b.add(", ")
        self._compile_expr(b, func.args[0])
        b.add(")")

    def _compile_strcat(self, b: SqlBuilder, func: FuncCall) -> None:
        b.add("CONCAT(")
        for i, arg in enumerate(func.args):
            if i > 0:
                b.add(", ")
            self._compile_expr(b, arg)
        b.add(")")

    def _compile_count(self, b: SqlBuilder, func: FuncCall) -> None:
        if not func.args:
            b.add("COUNT(*)")
        else:
            b.add("COUNT(")
            self._compile_expr(b, func.args[0])
            b.add(")")

    def _compile_isempty(self, b: SqlBuilder, func: FuncCall) -> None:
        self._compile_null_or_empty(b, func.args[0], empty=True)

    def _compile_isnotempty(self, b: SqlBuilder, func: FuncCall) -> None:
        self._compile_not_null_not_empty(b, func.args[0])

    def _compile_isnull(self, b: SqlBuilder, func: FuncCall) -> None:
        self._compile_expr(b, func.args[0])
        b.add(" IS NULL")

    def _compile_isnotnull(self, b: SqlBuilder, func: FuncCall) -> None:
        self._compile_expr(b, func.args[0])
        b.add(" IS NOT NULL")

    def _compile_range(self, b: SqlBuilder, func: FuncCall) -> None:
        if len(func.args) >= 2:
            b.add("GENERATE_SERIES(")
            self._compile_expr(b, func.args[0])
            b.add(", ")
            self._compile_expr(b, func.args[1])
            if len(func.args) >= 3:
                b.add(", ")
                self._compile_expr(b, func.args[2])
            b.add(")")
        else:
            b.add("GENERATE_SERIES(0, ")
            self._compile_expr(b, func.args[0])
            b.add(", 1)")

    def _compile_pack(self, b: SqlBuilder, func: FuncCall) -> None:
        pairs = []
        for i in range(0, len(func.args), 2):
            if i + 1 < len(func.args):
                key_b = SqlBuilder()
                self._compile_expr(key_b, func.args[i])
                val_b = SqlBuilder()
                self._compile_expr(val_b, func.args[i + 1])
                pairs.append(f"{key_b.build()}: {val_b.build()}")
                self._merge_params(key_b)
                self._merge_params(val_b)
        b.add("MAP {" + ", ".join(pairs) + "}")

    def _compile_null_or_empty(self, b: SqlBuilder, expr: Expr, *, empty: bool) -> None:
        b.add("(") ; self._compile_expr(b, expr)
        b.add(" IS NULL OR " ) ; self._compile_expr(b, expr)
        b.add(" = '')")

    def _compile_not_null_not_empty(self, b: SqlBuilder, expr: Expr) -> None:
        b.add("(") ; self._compile_expr(b, expr)
        b.add(" IS NOT NULL AND ") ; self._compile_expr(b, expr)
        b.add(" != '')")

    def _compile_timespan_func(self, b: SqlBuilder, name: str, args) -> None:
        if name == "ago":
            b.add("timezone('UTC', now()) - ")
            if len(args) == 1:
                self._compile_expr(b, args[0])
            else:
                b.add("INTERVAL ")
                self._compile_expr(b, args[0])
                b.add(" ")
                self._compile_expr(b, args[1])
        else:
            b.add("TIME_BUCKET(")
            if len(args) == 2:
                self._compile_expr(b, args[1])
                b.add(", ")
                self._compile_expr(b, args[0])
            else:
                b.add("INTERVAL ")
                self._compile_expr(b, args[1])
                b.add(" ")
                self._compile_expr(b, args[2])
                b.add(", ")
                self._compile_expr(b, args[0])
            b.add(")")

    def _compile_extract(self, b: SqlBuilder, args) -> None:
        b.add("REGEXP_EXTRACT(")
        self._compile_expr(b, args[2] if len(args) == 3 else args[1])
        b.add(", ")
        self._compile_expr(b, args[0])
        if len(args) == 3:
            b.add(", ")
            self._compile_expr(b, args[1])
        b.add(")")

    def _compile_mapped_interpolation(self, b: SqlBuilder, mapping: str, args) -> None:
        import re
        arg_texts = {}
        for idx, arg in enumerate(args):
            arg_b = SqlBuilder()
            self._compile_expr(arg_b, arg)
            text = arg_b.build()
            start_offset = len(b._params)
            b._params.extend(arg_b._params)
            def _renumber(m):
                return f"${start_offset + int(m.group(1))}"
            arg_texts[idx] = re.sub(r'\$(\d+)', _renumber, text)
        result = mapping
        for idx in range(len(args)):
            result = result.replace(f"{{{idx}}}", arg_texts[idx])
        b.add(result)

    def _compile_coalesce(self, b: SqlBuilder, func: FuncCall) -> None:
        b.add("COALESCE(")
        for i, arg in enumerate(func.args):
            if i > 0:
                b.add(", ")
            self._compile_expr(b, arg)
        b.add(")")

    def _compile_case_func(self, b: SqlBuilder, func: FuncCall) -> None:
        """case(pred1, val1, pred2, val2, ..., default)"""
        args = func.args
        if len(args) == 0:
            b.add("NULL")
            return
        if len(args) % 2 == 1:
            # Odd number: last is default
            conditions = args[:-1:2]
            values = args[1::2]
            default = args[-1]
        else:
            conditions = args[0::2]
            values = args[1::2]
            default = None

        b.add("CASE")
        for cond, val in zip(conditions, values):
            b.add(" WHEN ")
            self._compile_expr(b, cond)
            b.add(" THEN ")
            self._compile_expr(b, val)
        if default is not None:
            b.add(" ELSE ")
            self._compile_expr(b, default)
        b.add(" END")

    _FUNC_DISPATCH: dict[str, Any] = {
        "toscalar": _compile_toscalar,
        "ago": _compile_ago,
        "bin": _compile_bin,
        "strcat": _compile_strcat,
        "count": _compile_count,
        "isempty": _compile_isempty,
        "isnotempty": _compile_isnotempty,
        "isnull": _compile_isnull,
        "isnotnull": _compile_isnotnull,
        "case": lambda self, b, f: self._compile_case_func(b, f),
        "coalesce": lambda self, b, f: self._compile_coalesce(b, f),
        "range": _compile_range,
        "pack": _compile_pack,
    }
