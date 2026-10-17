"""Overview page (/): one-screen dashboard. Builds the SVG charts from the plain dicts in _overview_data.

Mounted before the legacy routes.py router, which no longer defines "/". Not for: the queries (_overview_data.py)
or the page layout (templates/overview.html).
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..db import Database
from ._overview_data import SEVERITIES, build_overview
from ._svg_charts import SEVERITY_COLORS, bar_svg, line_svg, pie_svg, stacked_bar_svg
from .routes import _ctx, templates  # type:ignore[attr-defined]

EVENT_COLOR = "var(--chart-low)"
RULE_COLOR = "var(--chart-high)"
EMPTY_EVENTS = "No events in this range"
EMPTY_ALERTS = "No alerts in this range"

def _error_ids(request: Request) -> frozenset:
    """Source ids the collector manager reports as failing (none when no collector manager is running)."""
    cm = getattr(request.app.state, "collector_manager", None)
    if cm is None:
        return frozenset()
    return frozenset(sid for sid, st in cm.status().items() if st.get("last_error"))


def _line(events: dict, bucket_label: str) -> str:
    """Total-events line over the range."""
    return line_svg([("All tables", events["values"], EVENT_COLOR)], events["labels"], width=720, height=240,
                    empty_label=EMPTY_EVENTS, aria_label=f"Events per {bucket_label}")


def _stacked(buckets: dict, bucket_label: str) -> str:
    """Alerts created per bucket, stacked by severity (critical at the bottom of each column)."""
    series = [(sev, buckets["series"][sev], SEVERITY_COLORS[sev]) for sev in SEVERITIES]
    return stacked_bar_svg(buckets["labels"], series, width=720, height=240, empty_label=EMPTY_ALERTS,
                           aria_label=f"Alerts created per {bucket_label}, by severity")


def _pie(open_by_severity: dict[str, int]) -> str:
    """Open alerts by severity."""
    slices = [(sev, n, SEVERITY_COLORS[sev]) for sev, n in open_by_severity.items()]
    return pie_svg(slices, size=200, empty_label="No open alerts")


def _table_bars(rows: list[dict]) -> str:
    """Events per data table, busiest first."""
    bars = [(r["table"], r["count"], EVENT_COLOR) for r in rows]
    return bar_svg(bars, width=300, row_h=22, gap=8, label_w=110, empty_label=EMPTY_EVENTS)


def _rule_bars(rows: list[dict]) -> str:
    """Alerts per rule in the range, most alerts first."""
    bars = [(_short(r["name"]), r["count"], RULE_COLOR) for r in rows]
    return bar_svg(bars, width=260, row_h=22, gap=8, label_w=118, empty_label=EMPTY_ALERTS)


def _short(text: str, limit: int = 18) -> str:
    """Cut a label to *limit* characters so it fits the bar chart's label column."""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _charts(data: dict) -> dict[str, str]:
    """All inline SVG charts for the page, keyed by the name the template uses."""
    bucket = data["bucket_label"]
    return {
        "events": _line(data["events"], bucket),
        "pie": _pie(data["open_by_severity"]),
        "stacked": _stacked(data["alert_buckets"], bucket),
        "tables": _table_bars(data["events_by_table"]),
        "rules": _rule_bars(data["top_rules"]),
    }


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        data = build_overview(db, request.query_params.get("range"), _error_ids(request))
        return templates.TemplateResponse(request, "overview.html", _ctx(
            request, "overview", "Overview", data=data, charts=_charts(data)),
            headers={"Cache-Control": "no-cache"})

    return r
