"""Pure SVG chart builders for the alerts page: a pie of open alerts by severity and horizontal bars.

Input is plain tuples of (label, value, css_colour[, href]); output is an SVG string in which every
label and href is HTML-escaped. No database, no templates, no I/O.
Not for: deciding what to count (web/routes_alerts_page.py) or page layout (templates/alerts.html).
"""
from __future__ import annotations

import math
from html import escape

# Colours are CSS variables defined in siempl.css (so dark mode works). They are applied with style=,
# not fill=, because var() is not reliably honoured inside SVG presentation attributes.
SEVERITY_COLORS: dict[str, str] = {
    "critical": "var(--chart-critical)",
    "high": "var(--chart-high)",
    "medium": "var(--chart-medium)",
    "low": "var(--chart-low)",
    "informational": "var(--chart-informational)",
}
EMPTY_PIE_LABEL = "No open alerts"
EMPTY_BAR_LABEL = "No alerts"


def _clean(slices) -> list[tuple[str, int, str]]:
    """Drop zero or negative values; coerce types so the rest of the module can trust them."""
    rows = []
    for label, value, color in slices:
        count = int(value)
        if count > 0:
            rows.append((str(label), count, str(color)))
    return rows


def legend_items(slices) -> list[dict]:
    """Legend rows for a pie: label, value, colour and whole-number percent, zero slices omitted."""
    rows = _clean(slices)
    total = sum(value for _, value, _ in rows)
    return [{"label": label, "value": value, "color": color, "percent": round(100 * value / total)}
            for label, value, color in rows]


def _empty_svg(size: int, label: str, css_class: str) -> str:
    half = size / 2
    return (f'<svg class="chart {css_class} chart-empty" viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{escape(label)}">'
            f'<circle cx="{half}" cy="{half}" r="{half - 2}" fill="none" stroke="var(--color-border)" '
            f'stroke-width="2"/>'
            f'<text x="{half}" y="{half + 4}" text-anchor="middle" font-size="12" '
            f'fill="var(--color-muted)">{escape(label)}</text></svg>')


def _point(cx: float, cy: float, r: float, fraction: float) -> tuple[float, float]:
    """Point on the circle at *fraction* of a turn, clockwise from 12 o'clock."""
    angle = -math.pi / 2 + 2 * math.pi * fraction
    return cx + r * math.cos(angle), cy + r * math.sin(angle)


def _slice_element(label: str, value: int, color: str, geom: tuple[float, float, float, float, float]) -> str:
    """One pie slice as a <path>; a slice that is the whole pie is a <circle> (an arc cannot span 360 degrees)."""
    cx, cy, r, start, end = geom
    title = f"{escape(label)}: {value}"
    data = f'data-severity="{escape(label)}" data-value="{value}"'
    style = f'style="fill:{escape(color)}"'
    if end - start >= 1:
        return f'<circle class="pie-slice" {data} {style} cx="{cx}" cy="{cy}" r="{r}"><title>{title}</title></circle>'
    x1, y1 = _point(cx, cy, r, start)
    x2, y2 = _point(cx, cy, r, end)
    large = 1 if end - start > 0.5 else 0
    d = f"M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large} 1 {x2:.2f},{y2:.2f} Z"
    return f'<path class="pie-slice" {data} {style} d="{d}"><title>{title}</title></path>'


def pie_svg(slices, size: int = 180, empty_label: str = EMPTY_PIE_LABEL, hrefs: dict[str, str] | None = None) -> str:
    """Inline SVG pie of (label, value, colour) slices. Zero/empty input returns a placeholder SVG.

    Each slice carries data-severity and data-value so the page can read them back; the legend is built
    separately from legend_items() so both use the same filtered rows. A slice whose label is in *hrefs*
    is wrapped in a link (a click filters the list).
    """
    rows = _clean(slices)
    total = sum(value for _, value, _ in rows)
    if total == 0:
        return _empty_svg(size, empty_label, "chart-pie")
    cx = cy = size / 2
    r = size / 2 - 2
    parts: list[str] = []
    start = 0.0
    for label, value, color in rows:
        end = start + value / total
        element = _slice_element(label, value, color, (cx, cy, r, start, end))
        if hrefs and label in hrefs:
            element = f'<a href="{escape(hrefs[label], quote=True)}">{element}</a>'
        parts.append(element)
        start = end
    body = "".join(parts)
    return (f'<svg class="chart chart-pie" viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'role="img" aria-label="Open alerts by severity">{body}</svg>')


def _bar_row(index: int, bar: tuple, scale: int, layout: tuple[int, int, int, int]) -> str:
    """One labelled bar; wrapped in <a> when the bar has an href, so a click filters the list."""
    label, value, color = str(bar[0]), int(bar[1]), str(bar[2])
    href = bar[3] if len(bar) > 3 else None
    width, row_h, gap, label_w, bar_max = layout
    y = index * (row_h + gap)
    bar_len = round(bar_max * value / scale) if value else 0
    text_y = y + row_h - 6
    elements = [
        f'<text x="0" y="{text_y}" font-size="12" fill="currentColor">{escape(label)}</text>',
        f'<rect x="{label_w}" y="{y}" width="{bar_len}" height="{row_h}" rx="4" '
        f'style="fill:{escape(color)}"></rect>',
        f'<text x="{label_w + bar_len + 6}" y="{text_y}" font-size="12" font-weight="600" '
        f'fill="currentColor">{value}</text>',
    ]
    body = "".join(elements)
    if href:
        body = f'<a href="{escape(str(href), quote=True)}">{body}</a>'
    return f'<g class="bar-row" data-label="{escape(label)}" data-value="{value}">{body}</g>'


def bar_svg(bars, width: int = 320, row_h: int = 22, gap: int = 10, label_w: int = 150,
            empty_label: str = EMPTY_BAR_LABEL) -> str:
    """Inline SVG of horizontal bars from (label, value, colour[, href]) tuples.

    Zero values stay visible as a labelled empty bar (a status with no alerts is still information).
    When every value is zero the placeholder SVG is returned instead.
    """
    rows = [(str(b[0]), int(b[1]), str(b[2])) + tuple(b[3:4]) for b in bars]
    scale = max((value for _, value, _, *_ in rows), default=0)
    if scale <= 0:
        return _empty_svg(width, empty_label, "chart-bar")
    bar_max = max(width - label_w - 40, 20)
    layout = (width, row_h, gap, label_w, bar_max)
    height = len(rows) * (row_h + gap) - gap
    body = "".join(_bar_row(i, row, scale, layout) for i, row in enumerate(rows))
    return (f'<svg class="chart chart-bar" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="Alerts by status">{body}</svg>')


# ---- line/area chart (ingestion overview) -------------------------------------------------------
EMPTY_LINE_LABEL = "No events in this range"
_PAD_L, _PAD_R, _PAD_T, _PAD_B = 44, 12, 12, 24


def _nice_max(value: float) -> float:
    """Round *value* up to 1, 2, 2.5, 5 or 10 times a power of ten so the y-axis top is a clean number."""
    if value <= 0:
        return 0.0
    base = 10 ** math.floor(math.log10(value))
    for multiple in (1, 2, 2.5, 5, 10):
        if multiple * base >= value:
            return multiple * base
    return 10 * base


def _fmt_tick(value: float) -> str:
    """Whole numbers with thousands separators; fractions to one decimal."""
    if value == int(value):
        return f"{int(value):,}"
    return f"{value:.1f}"


def _empty_line_svg(width: int, height: int, label: str) -> str:
    """Placeholder frame for a line chart with no data: an axis baseline and a centred message."""
    base = height - _PAD_B
    return (f'<svg class="chart chart-line chart-empty" viewBox="0 0 {width} {height}" width="{width}" '
            f'height="{height}" role="img" aria-label="{escape(label)}">'
            f'<line class="axis-base" x1="{_PAD_L}" x2="{width - _PAD_R}" y1="{base}" y2="{base}"/>'
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" font-size="12" '
            f'fill="var(--color-muted)">{escape(label)}</text></svg>')


def _x_positions(count: int, left: float, plot_w: float) -> list[float]:
    """Evenly spaced x coordinates for *count* points; a single point sits in the middle."""
    if count == 1:
        return [left + plot_w / 2]
    step = plot_w / (count - 1)
    return [left + i * step for i in range(count)]


def _series_group(label: str, values: list[float], color: str, xs: list[float], top: float,
                  geom: tuple[float, float, float, float]) -> str:
    """One series: a translucent area under a polyline, grouped so the page can read data-series back."""
    _left, top_y, _plot_w, plot_h = geom
    pts = [(x, top_y + plot_h - plot_h * max(v, 0.0) / top) for x, v in zip(xs, values, strict=True)]
    stroke = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    base = top_y + plot_h
    area = f"M{stroke} L{pts[-1][0]:.1f},{base:.1f} L{pts[0][0]:.1f},{base:.1f} Z"
    return (f'<g class="line-series" data-series="{escape(label)}">'
            f'<path class="line-area" style="fill:{escape(color)}" d="{area}"/>'
            f'<polyline class="line-stroke" style="stroke:{escape(color)}" points="{stroke}"/></g>')


def _axes(top: float, x_labels: list[str], geom: tuple[float, float, float, float]) -> str:
    """Y gridlines with ticks at 0, half and the top; x labels at up to five evenly spaced points."""
    left, top_y, plot_w, plot_h = geom
    parts: list[str] = []
    for fraction in (0.0, 0.5, 1.0):
        y = top_y + plot_h - plot_h * fraction
        parts.append(f'<line class="axis-grid" x1="{left}" x2="{left + plot_w}" y1="{y:.1f}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis-tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">'
                     f'{_fmt_tick(top * fraction)}</text>')
    count = len(x_labels)
    if count:
        picks = sorted({round(i * (count - 1) / 4) for i in range(5)}) if count > 1 else [0]
        xs = _x_positions(count, left, plot_w)
        for i in picks:
            parts.append(f'<text class="axis-tick" x="{xs[i]:.1f}" y="{top_y + plot_h + 16}" '
                         f'text-anchor="middle">{escape(x_labels[i])}</text>')
    return "".join(parts)


def _normalise_series(series, x_labels) -> tuple[list[tuple[str, list[float], str]], int, list[str]]:
    """Coerce types and check shape: all series one length, x_labels (if any) the same length."""
    rows = [(str(label), [float(v) for v in values], str(color)) for label, values, color in series]
    lengths = {len(values) for _, values, _ in rows}
    if len(lengths) > 1:
        raise ValueError("line_svg: all series must have the same length")
    count = lengths.pop() if lengths else 0
    labels = [str(x) for x in x_labels]
    if labels and count and len(labels) != count:
        raise ValueError("line_svg: x_labels must match the series length")
    return rows, count, labels


def _peak(rows) -> float:
    """Largest non-negative value across all series (0.0 when there are none)."""
    return max((max(v, 0.0) for _, values, _ in rows for v in values), default=0.0)


def line_svg(series, x_labels=(), width: int = 640, height: int = 200,
             empty_label: str = EMPTY_LINE_LABEL, aria_label: str = "Trend") -> str:
    """Inline SVG line/area chart from (label, values, css_colour) series, all of one length.

    x_labels (optional) must match that length and are drawn as escaped ticks. Negative values are clamped
    to zero; the y-axis top is rounded up with _nice_max. No points, or only zeros, returns the placeholder
    SVG carrying *empty_label*. Series labels and aria_label are HTML-escaped. Raises ValueError on ragged input.
    """
    rows, count, labels = _normalise_series(series, x_labels)
    top = _nice_max(_peak(rows))
    if count == 0 or top <= 0:
        return _empty_line_svg(width, height, empty_label)
    geom = (_PAD_L, _PAD_T, width - _PAD_L - _PAD_R, height - _PAD_T - _PAD_B)
    xs = _x_positions(count, geom[0], geom[2])
    body = "".join(_series_group(label, values, color, xs, top, geom) for label, values, color in rows)
    axes = _axes(top, labels, geom)
    return (f'<svg class="chart chart-line" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{escape(aria_label)}">{axes}{body}</svg>')



# ---- stacked column chart (overview: alerts created over time, by severity) ----------------------
EMPTY_STACK_LABEL = "No alerts in this range"
_BAR_FILL = 0.7  # share of each column band taken by the bar itself


def _stack_totals(rows, count: int) -> list[float]:
    """Per-column sum over all series (negative values count as zero)."""
    return [sum(max(values[i], 0.0) for _, values, _ in rows) for i in range(count)]


def _empty_stack_svg(width: int, height: int, label: str) -> str:
    """Placeholder frame for a stacked chart with no data: an axis baseline and a centred message."""
    base = height - _PAD_B
    return (f'<svg class="chart chart-stack chart-empty" viewBox="0 0 {width} {height}" width="{width}" '
            f'height="{height}" role="img" aria-label="{escape(label)}">'
            f'<line class="axis-base" x1="{_PAD_L}" x2="{width - _PAD_R}" y1="{base}" y2="{base}"/>'
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" font-size="12" '
            f'fill="var(--color-muted)">{escape(label)}</text></svg>')


def _stack_column(index: int, rows, band_w: float, geom: tuple[float, float, float, float], scale: float) -> str:
    """One column: a rect per non-zero series, stacked bottom-up in series order, grouped with its index."""
    left, top_y, _plot_w, plot_h = geom
    bar_w = band_w * _BAR_FILL
    x = left + index * band_w + (band_w - bar_w) / 2
    base = top_y + plot_h
    parts: list[str] = []
    for label, values, color in rows:
        value = max(values[index], 0.0)
        if value <= 0:
            continue
        seg_h = plot_h * value / scale
        base -= seg_h
        shown = _fmt_tick(value)
        parts.append(f'<rect class="stack-seg" data-series="{escape(label)}" data-value="{shown}" '
                     f'style="fill:{escape(color)}" x="{x:.1f}" y="{base:.1f}" width="{bar_w:.1f}" '
                     f'height="{seg_h:.1f}"><title>{escape(label)}: {shown}</title></rect>')
    return f'<g class="stack-col" data-index="{index}">{"".join(parts)}</g>'


def _stack_x_labels(labels: list[str], geom: tuple[float, float, float, float], band_w: float) -> str:
    """Up to about six x labels, centred under their column band."""
    left, top_y, _plot_w, plot_h = geom
    step = max(1, math.ceil(len(labels) / 6))
    return "".join(
        f'<text class="axis-tick" x="{left + i * band_w + band_w / 2:.1f}" y="{top_y + plot_h + 16}" '
        f'text-anchor="middle">{escape(labels[i])}</text>'
        for i in range(0, len(labels), step))


def stacked_bar_svg(labels, series, width: int = 640, height: int = 200,
                    empty_label: str = EMPTY_STACK_LABEL, aria_label: str = "Stacked bars") -> str:
    """Inline SVG of stacked columns from (label, values, css_colour) series, all of one length.

    labels (optional) must match that length and are drawn as escaped x ticks. Each column is the sum of
    the series at that index; the y-axis top is rounded up with _nice_max. No data, or only zeros, returns
    the placeholder SVG carrying *empty_label*. Series labels and aria_label are HTML-escaped.
    Raises ValueError on ragged input.
    """
    rows, count, x_labels = _normalise_series(series, labels)
    top = _nice_max(max(_stack_totals(rows, count), default=0.0))
    if count == 0 or top <= 0:
        return _empty_stack_svg(width, height, empty_label)
    geom = (_PAD_L, _PAD_T, width - _PAD_L - _PAD_R, height - _PAD_T - _PAD_B)
    band_w = geom[2] / count
    cols = "".join(_stack_column(i, rows, band_w, geom, top) for i in range(count))
    axes = _axes(top, (), geom) + _stack_x_labels(x_labels, geom, band_w)
    return (f'<svg class="chart chart-stack" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{escape(aria_label)}">{axes}{cols}</svg>')
