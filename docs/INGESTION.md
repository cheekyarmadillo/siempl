# Ingestion Pipeline — Design Document

## Purpose
Receives raw log records from collectors, normalizes them into typed event tables,
and writes them to DuckDB for querying and rule evaluation.

## Architecture / Data Flow

```
Collectors (syslog/HTTP/file/tail)
  └─► IngestPipeline.ingest(source_id, records)
        ├── resolve parser (arg > sources.parser > auto-detect)
        ├── normalize via parser.parse() → list[NormalizedEvent]
        ├── apply enabled ingest_filters (KQL subset matcher) → drop matches
        ├── extract_entities(events) → batch entity upsert
        ├── db.insert_events(table, rows)
        ├── bump table_usage.rows_ingested
        └── bump sources.events_total, set last_event_at
```

Key design choices:
- **Parser resolution** follows a priority chain: explicit argument > source configuration > auto-detect (per-record sniffing).
- **Auto-detection** checks CEF prefix, syslog PRI, Apache style, Windows EventID keys, JSON structure, then falls back to GenericEvents.
- **Entity extraction** is batched per ingest call to minimize writes.
- **Ingest filters** use a tiny safe KQL subset (`==` and `contains`); will delegate to `siempl.kql.compile_kql` once the full compiler is wired in.
- **Unknown source_ids** are auto-created with `status='pending'` so the onboarding agent can later configure them.

## Public API

```
NormalizedEvent(table, fields)              — event ready for DB insert
IngestResult(received, inserted, dropped,   — batch outcome
             failed, tables, errors)
IngestPipeline(db)
  .ingest(source_id, records, *, parser=None) → IngestResult
```

## Extension Points

1. **New parsers:** register via `siempl.ingest.parsers.register(name)(fn)` where `fn(raw, source_id) → list[NormalizedEvent]`.
2. **Declarative parsers:** `MappingParser(spec)` validates and parses records per a JSON spec (see docs/PARSERS.md).
3. **Filter expressions:** currently a tiny KQL subset; the full `compile_kql` will replace it when the full compiler is wired in.
4. **EntityStore integration:** currently uses a minimal internal fallback; will delegate to `siempl.entities.EntityStore` when that is wired in.

## Known Limitations

- No batching across collector boundaries (each collector flushes independently).
- Entity upsert uses INSERT ... ON CONFLICT; the EntityStore contract adds richer features (reputation, edges, link) not yet wired.
- Filter expressions are limited to `column==value` and `column contains "value"` until full KQL compiler is available.
- Syslog server ports are unprivileged (5514 by default); production would need port mapping or capabilities.

## How to Test / Run

```
# Unit tests (no services needed)
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_ingest.py -q

# Integration tests (servers, files; some need ports)
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_collectors.py -q
```

## TODOs

- [ ] Wire `siempl.entities.EntityStore` when available
- [ ] Use `siempl.kql.compile_kql` for filter evaluation
- [ ] Add `stop_collectors()` / graceful shutdown
- [ ] Add health-check endpoint in HTTP router
- [x] Performance: measure and optimize batch entity upsert — done 2026-10-12 (see below)
- [ ] Windows event XML format (Event Log XML) support

## 2026-10-12 — Throughput work

**Baseline:** ~103 events/s (5,000 synthetic events via `scripts/bench_ingest.py`).
**After:** ~5,980 events/s (20,000 events, 10 batches) — over the 5k/s target.

Profiling (cProfile) showed the cost was **not** the entity upsert as suspected:
DuckDB's Python parameter binding (~24 `?` params/row in `executemany`/multi-row
VALUES) triggered a **failing `import pandas` per bound parameter** — each miss
re-scans sys.path (~120k imports / 5k rows, ~90% of runtime). Even when blocked,
per-parameter binding stayed slow (~800 rows/s).

Fixes applied:
1. `db.insert_events` now spills each batch to a temp NDJSON file and runs
   `INSERT ... BY NAME SELECT * FROM read_json(path, format='newline_delimited')`
   (~80k rows/s in isolation), with a chunked parameterized-VALUES fallback.
2. `ingest/entities._is_meaningful`: noise-value/host sets are now precomputed
   module-level frozensets instead of a per-call `{h.lower() for h in NOISE_HOSTS}`.
3. `SyslogServer.stop()` no longer cancels the batch loop outright — messages
   already dequeued into its in-flight buffer were silently dropped, causing the
   three syslog collector tests to fail. The loop now flushes on exit and is only
   cancelled as a last resort (FLUSH_INTERVAL + 5s grace).

Verified: `tests/test_ingest.py` 59/59, `tests/test_collectors.py` 15/15 (incl.
all 3 syslog tests), plus triage/logalert/testdata suites — see the test files.
Benchmark: `SIEMPL_HOME=$(mktemp -d) .venv/bin/python scripts/bench_ingest.py --events 20000`.