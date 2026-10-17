"""Logs page client-side helpers (chart, pivot, error text, KQL builder), run under node.

The helpers live in the `<script id="logs-helpers">` block of siempl/web/templates/logs.html and touch no DOM,
so each test evaluates one expression against that block. Skipped when node is not installed.
Run: .venv/bin/python -m pytest -q tests/test_web_logs_js.py
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

TEMPLATE = Path(__file__).resolve().parents[1] / "siempl" / "web" / "templates" / "logs.html"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _helpers_source() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    m = re.search(r'<script id="logs-helpers">(.*?)</script>', text, re.S)
    assert m, "logs-helpers script block missing from logs.html"
    return m.group(1)


def js(expr: str):
    """Evaluate a JS expression against the helper block and return its JSON-decoded value."""
    program = _helpers_source() + f"\nconsole.log(JSON.stringify(({expr})));\n"
    proc = subprocess.run([NODE, "-e", program], capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# ---------------------------------------------------------------- chart defaults and aggregation

def test_default_chart_columns_label_first_text_value_first_number():
    cols = ["UserName", "Count", "Host"]
    rows = [["alice", 3, "h1"], ["bob", 5, "h2"]]
    assert js(f"defaultChartColumns({json.dumps(cols)}, {json.dumps(rows)})") == {"label": 0, "value": 1}


def test_default_chart_columns_all_numeric_falls_back_to_count():
    cols = ["a", "b"]
    rows = [[1, 2], [3, 4]]
    assert js(f"defaultChartColumns({json.dumps(cols)}, {json.dumps(rows)})") == {"label": 0, "value": 1}
    # only one column, numeric: label falls back to column 0 and there is no other numeric column
    assert js("defaultChartColumns(['n'], [[1],[2]])") == {"label": 0, "value": -1}


def test_default_chart_columns_text_only_counts_rows():
    assert js("defaultChartColumns(['u','h'], [['a','x'],['b','y']])") == {"label": 0, "value": -1}


def test_numeric_strings_and_blanks_are_handled():
    assert js("columnIsNumeric([['1.5'],[null],[''],['2']], 0)") is True
    assert js("columnIsNumeric([['x'],['2']], 0)") is False
    assert js("columnIsNumeric([[null],['']], 0)") is False  # nothing to plot


def test_chart_aggregate_counts_rows_per_label_including_null_label():
    rows = [["a", 1], ["a", 2], [None, 3]]
    out = js(f"chartAggregate({json.dumps(rows)}, 0, -1)")
    assert sorted(out["items"], key=lambda i: i["label"]) == [
        {"label": "(null)", "value": 1}, {"label": "a", "value": 2}]
    assert out["skipped"] == 0


def test_chart_aggregate_sums_and_skips_negative_and_text():
    rows = [["a", 10], ["a", -4], ["b", "7"], ["b", "oops"], ["c", None]]
    out = js(f"chartAggregate({json.dumps(rows)}, 0, 1)")
    items = {i["label"]: i["value"] for i in out["items"]}
    assert items == {"a": 10, "b": 7}  # label "c" has only a null value, so it does not appear
    assert out["skipped"] == 2  # -4 and "oops"; the null is not counted as skipped


def test_top_slices_keeps_twenty_and_folds_the_rest_into_other():
    items = [{"label": f"k{i:02d}", "value": 100 - i} for i in range(25)]
    slices = js(f"topSlices({json.dumps(items)}, 20)")
    assert len(slices) == 21
    assert slices[0]["label"] == "k00" and slices[19]["label"] == "k19"
    other = slices[-1]
    assert other["label"] == "Other" and other["other"] is True and other["groups"] == 5
    assert other["value"] == sum(100 - i for i in range(20, 25))


def test_top_slices_no_other_when_small():
    slices = js("topSlices([{label:'a',value:1},{label:'b',value:3}], 20)")
    assert [s["label"] for s in slices] == ["b", "a"]
    assert all(s["other"] is False for s in slices)


# ---------------------------------------------------------------- pivot

ROWS = [["alice", 10, "x"], ["bob", 5, "y"], ["alice", None, "z"], ["bob", "n/a", "w"], [None, 2, "v"]]
COLS = ["user", "bytes", "tag"]


def _pivot(group: int, value: int, agg: str):
    return js(f"computePivot({json.dumps(COLS)}, {json.dumps(ROWS)}, {group}, {value}, {json.dumps(agg)})")


def test_pivot_count_per_group_sorted_desc_nulls_last():
    out = _pivot(0, -1, "count")
    assert out["columns"] == ["user", "count"]
    assert out["rows"] == [["alice", 2], ["bob", 2], ["(null)", 1]]


def test_pivot_sum_ignores_blank_and_text_and_counts_skipped():
    out = _pivot(0, 1, "sum")
    assert out["columns"] == ["user", "sum(bytes)"]
    assert out["rows"] == [["alice", 10], ["bob", 5], ["(null)", 2]]  # blank alice value skipped, "n/a" skipped
    assert out["skipped"] == 1  # only "n/a" counts as skipped; the blank does not


def test_pivot_avg_min_max():
    assert {r[0]: r[1] for r in _pivot(0, 1, "avg")["rows"]} == {"alice": 10, "bob": 5, "(null)": 2}
    rows = [["g", 4], ["g", 9], ["h", 2]]
    out_min = js(f"computePivot(['g','v'], {json.dumps(rows)}, 0, 1, 'min')")
    out_max = js(f"computePivot(['g','v'], {json.dumps(rows)}, 0, 1, 'max')")
    assert {r[0]: r[1] for r in out_min["rows"]} == {"g": 4, "h": 2}
    assert {r[0]: r[1] for r in out_max["rows"]} == {"g": 9, "h": 2}


def test_pivot_avg_rounds_to_ten_significant_digits():
    rows = [["g", 1], ["g", 2]]
    out = js(f"computePivot(['g','v'], {json.dumps(rows)}, 0, 1, 'avg')")
    assert out["rows"] == [["g", 1.5]]


# ---------------------------------------------------------------- KQL builder

def test_build_pivot_kql_appends_summarize_to_user_query():
    out = js("buildPivotKql('NetworkEvents | take 500', 'SrcIp', 'sum', 'BytesOut')")
    assert out["kql"] == "NetworkEvents | take 500\n| summarize sum(BytesOut) by SrcIp"
    assert js("buildPivotKql('AuthEvents', 'UserName', 'count', '')") == {
        "kql": "AuthEvents\n| summarize count() by UserName"}


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["AuthEvents", "Bad Name", "count", ""], "not a plain KQL column name"),
        (["AuthEvents", "UserName", "sum", ""], "Choose a value column"),
        (["AuthEvents", "UserName", "sum", "x-y"], "not a plain KQL column name"),
        (["", "UserName", "count", ""], "Run a query first"),
        (["AuthEvents", "UserName", "median", "x"], "Unknown aggregate"),
    ],
)
def test_build_pivot_kql_rejects_unsafe_or_incomplete_input(args, fragment):
    out = js(f"buildPivotKql({', '.join(json.dumps(a) for a in args)})")
    assert "error" in out and fragment in out["error"]


# ---------------------------------------------------------------- error text and escaping

def test_response_error_message_shows_server_text_verbatim():
    out = js("responseErrorMessage(400, {error: \"unknown table 'X'\"}, '')")
    assert out == "unknown table 'X'"


def test_response_error_message_for_non_json_and_detail():
    assert js("responseErrorMessage(502, null, '<html>bad gateway</html>')") == "HTTP 502: <html>bad gateway</html>"
    assert js("responseErrorMessage(422, {detail: [{msg: 'x'}]}, '')") == 'HTTP 422: [{"msg":"x"}]'
    assert js("responseErrorMessage(500, null, '')") == "HTTP 500 (empty response)"


def test_escape_html_covers_quotes_and_angle_brackets():
    assert js("escapeHtml(`<a href=\"x\">'&'</a>`)") == "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"


def test_filename_from_disposition():
    assert js("filenameFromDisposition('attachment; filename=\"siempl-AuthEvents-20261014-010203.csv\"')") == \
        "siempl-AuthEvents-20261014-010203.csv"
    assert js("filenameFromDisposition(null)") == ""


def test_result_summary_mentions_truncation_limit_and_range():
    data = {"rows": [[1], [2]], "truncated": True, "limit_applied": 50, "time_range": "1h",
            "sql": "SELECT 1", "elapsed_ms": 3.2}
    text = js(f"resultSummary({json.dumps(data)})")
    assert text.startswith("Showing 2 rows (truncated) · display limit 50 applied · time range last 1h.")
    assert "(3ms)" in text


# ---------------------------------------------------------------- SVG output

def test_pie_svg_one_path_per_slice_with_escaped_tooltips():
    slices = [{"label": "<script>x</script>", "value": 3, "other": False},
              {"label": "b", "value": 1, "other": False}]
    svg = js(f"pieSvg({json.dumps(slices)})")
    assert svg.count("<path ") == 2
    assert "<script>" not in svg and "&lt;script&gt;x&lt;/script&gt;" in svg
    assert "75.0%" in svg


def test_pie_svg_single_slice_is_a_circle_and_zero_slices_are_skipped():
    svg = js("pieSvg([{label:'only', value: 4, other: false}, {label:'zero', value: 0, other: false}])")
    assert "<circle" in svg and "<path " not in svg


def test_pie_svg_nothing_to_plot_message():
    assert "Nothing to plot" in js("pieSvg([{label:'z', value: 0, other: false}])")


def test_bar_svg_one_rect_per_slice():
    slices = [{"label": f"l{i}", "value": 10 - i, "other": False} for i in range(4)]
    svg = js(f"barSvg({json.dumps(slices)})")
    assert svg.count("<rect ") == 4
    assert svg.startswith('<svg class="logs-chart-svg logs-chart-bar"')


def test_legend_lists_each_slice_with_share():
    slices = [{"label": "a", "value": 1, "other": False}, {"label": "b", "value": 3, "other": False}]
    html = js(f"legendHtml({json.dumps(slices)})")
    assert html.count("logs-legend-item") == 2
    assert "25.0%" in html and "75.0%" in html


def test_slice_colors_are_stable_and_other_is_grey():
    assert js("sliceColor({label:'a', other:false}, 0)") == "hsl(0 62% 50%)"
    assert js("sliceColor({label:'Other', other:true}, 3)") == "#8a8f98"
