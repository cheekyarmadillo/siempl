"""Ingestion overview for the top of the Ingestion page: events per bucket (line), events per table (bars),
and status tiles (events, sources, errors/stale, filter drops, retention).

Reads the data tables through a TimeGenerated window (one COUNT per table, grouped by time bucket), plus
sources, ingest_filters and table_retention. Returns plain dicts with ready-made inline SVG strings.
Not for: source/filter/retention CRUD (routes_sources.py) or page layout (templates/ingestion.html).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ..db import Database
from ..schema import DATA_TABLES
from ._svg_charts import bar_svg, line_svg

DEFAULT_RANGE = "24h"
STALE_AFTER = timedelta(hours=1)  # an active source with no event newer than this is reported as stale
EPOCH = datetime(1970, 1, 1)
# range key -> window, bucket width, x-label format, bucket wording for the chart caption.
RANGES: dict[str, dict] = {
    "1h": {"window": timedelta(hours=1), "bucket": timedelta(minutes=5), "fmt": "%H:%M",
           "label": "last hour", "bucket_label": "5 minutes"},
    "24h": {"window": timedelta(hours=24), "bucket": timedelta(hours=1), "fmt": "%H:%M",
            "label": "last 24 hours", "bucket_label": "hour"},
    "7d": {"window": timedelta(days=7), "bucket": timedelta(hours=6), "fmt": "%m-%d %H:%M",
           "label": "last 7 days", "bucket_label": "6 hours"},
}


def parse_range(raw: str | None) -> str:
    """Return *raw* when it is a known range key, else DEFAULT_RANGE. A bad or missing ?range= never errors."""
    return raw if raw in RANGES else DEFAULT_RANGE


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _floor(ts: datetime, step: timedelta) -> datetime:
    """Align *ts* down to a multiple of *step* counted from the epoch (same grid as DuckDB time_bucket here)."""
    secs = int(step.total_seconds())
    offset = int((ts - EPOCH).total_seconds())
    return EPOCH + timedelta(seconds=offset - offset % secs)


def _bucket_starts(now: datetime, spec: dict) -> list[datetime]:
    """Start time of every bucket from the one containing (now - window) up to the one containing now."""
    step = spec["bucket"]
    first = _floor(now - spec["window"], step)
    last = _floor(now, step)
    count = int((last - first) / step) + 1
    return [first + i * step for i in range(count)]


def _existing_tables(db: Database) -> list[str]:
    """DATA_TABLES that exist in the database (a table missing from an old file is skipped, not an error)."""
    present = {r["table_name"] for r in db.query("SELECT table_name FROM information_schema.tables")}
    return [t for t in DATA_TABLES if t in present]


def _table_buckets(db: Database, table: str, spec: dict, cutoff: datetime, now: datetime) -> dict[datetime, int]:
    """Event count per bucket start for one table, only rows with TimeGenerated in [cutoff, now]."""
    secs = int(spec["bucket"].total_seconds())
    rows = db.query(
        f'SELECT time_bucket(INTERVAL {secs} SECOND, "TimeGenerated", TIMESTAMP \'1970-01-01\') AS b, '
        f'count(*) AS c FROM "{table}" WHERE "TimeGenerated" >= ? AND "TimeGenerated" <= ? GROUP BY b',
        [cutoff, now])
    return {r["b"]: int(r["c"]) for r in rows}


def _range_counts(db: Database, spec: dict, now: datetime) -> tuple[list[datetime], dict[str, dict[datetime, int]]]:
    """Bucket starts for the range, and per-table bucket counts (one grouped COUNT per existing table)."""
    cutoff = now - spec["window"]
    per_table = {t: _table_buckets(db, t, spec, cutoff, now) for t in _existing_tables(db)}
    return _bucket_starts(now, spec), per_table


def _totals_per_bucket(starts: list[datetime], per_table: dict[str, dict[datetime, int]]) -> list[int]:
    """Total events across all tables for each bucket start, in order."""
    return [sum(counts.get(s, 0) for counts in per_table.values()) for s in starts]


def _table_totals(per_table: dict[str, dict[datetime, int]]) -> dict[str, int]:
    """Events per table over the whole range."""
    return {table: sum(counts.values()) for table, counts in per_table.items()}


EVENT_COLOR = "var(--chart-low)"
TOP_TABLES = 12  # bars shown; the rest are summarised by the tiles, not drawn


def _line_chart(starts: list[datetime], per_table: dict, spec: dict) -> str:
    """Single total-events line over the range, x ticks formatted for the range."""
    values = [float(v) for v in _totals_per_bucket(starts, per_table)]
    labels = [s.strftime(spec["fmt"]) for s in starts]
    return line_svg([("All tables", values, EVENT_COLOR)], labels, width=640, height=200,
                    empty_label="No events in this range",
                    aria_label=f"Events per {spec['bucket_label']}, {spec['label']}")


def _table_bars(totals: dict[str, int]) -> str:
    """Horizontal bars of events per table, busiest first, tables with zero events left out."""
    ranked = sorted(((t, n) for t, n in totals.items() if n > 0), key=lambda item: (-item[1], item[0]))
    bars = [(table, n, EVENT_COLOR) for table, n in ranked[:TOP_TABLES]]
    return bar_svg(bars, width=520, label_w=140, empty_label="No events in this range")


def _source_health(db: Database, error_ids: frozenset, now: datetime) -> tuple[int, set, set]:
    """Active source count, sources in error (collector reports a last_error), stale active sources."""
    rows = db.query("SELECT source_id, status, last_event_at FROM sources")
    active = [r for r in rows if r["status"] == "active"]
    errors = {r["source_id"] for r in rows if r["source_id"] in error_ids}
    stale = {r["source_id"] for r in active
             if r["last_event_at"] is None or r["last_event_at"] < now - STALE_AFTER}
    return len(active), errors, stale - errors


def _filter_drops(db: Database) -> tuple[int, int]:
    """Events dropped by ingest_filters (cumulative counter kept on each filter) and the filter count."""
    row = db.query_one("SELECT COALESCE(SUM(dropped_total), 0) AS d, count(*) AS n FROM ingest_filters")
    return int(row["d"]), int(row["n"])


def _retention_summary(db: Database) -> str:
    """One-line summary of table_retention: how many tables have a limit and the shortest and longest."""
    days = [int(r["retention_days"]) for r in db.query("SELECT retention_days FROM table_retention")
            if r["retention_days"] is not None]
    if not days:
        return "none set"
    return f"{len(days)} tables, {min(days)}d to {max(days)}d"


def _tiles(total: int, active: int, errors: set, stale: set, drops: tuple[int, int], retention: str) -> list[dict]:
    """Status tiles shown above the charts: label, display value and a small detail line."""
    dropped, filters = drops
    return [
        {"label": "Events in range", "value": f"{total:,}", "detail": "all data tables"},
        {"label": "Active sources", "value": str(active), "detail": "status active"},
        {"label": "Error or stale", "value": str(len(errors) + len(stale)),
         "detail": f"{len(errors)} error, {len(stale)} stale (no event in 1h)"},
        {"label": "Dropped by filters", "value": f"{dropped:,}", "detail": f"{filters} filters, all time"},
        {"label": "Retention", "value": retention, "detail": "per table"},
    ]


def build_overview(db: Database, raw_range: str | None, error_ids=frozenset(), now: datetime | None = None) -> dict:
    """Everything the overview section needs for one range. *error_ids* are source ids the collectors report as failing."""
    key = parse_range(raw_range)
    spec = RANGES[key]
    now = now or _utc_now()
    starts, per_table = _range_counts(db, spec, now)
    totals = _table_totals(per_table)
    active, errors, stale = _source_health(db, frozenset(error_ids), now)
    return {
        "range": key,
        "ranges": list(RANGES),
        "label": spec["label"],
        "line_svg": _line_chart(starts, per_table, spec),
        "bar_svg": _table_bars(totals),
        "tiles": _tiles(sum(totals.values()), active, errors, stale, _filter_drops(db), _retention_summary(db)),
    }
