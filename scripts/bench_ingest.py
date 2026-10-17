#!/usr/bin/env python3
"""Profile / benchmark the ingest pipeline on synthetic JSON events.

Usage:
  SIEMPL_HOME=$(mktemp -d) .venv/bin/python scripts/bench_ingest.py [--events N] [--profile]
"""
import argparse
import cProfile
import json
import pstats
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siempl.db import Database
from siempl.ingest import IngestPipeline


def synth_events(n: int) -> list:
    """Synthetic auth-like events with realistic entity fields."""
    evts = []
    for i in range(n):
        evts.append({
            "TimeGenerated": "2026-10-12T10:00:00",
            "Computer": f"host-{i % 200}.example.com",
            "Account": f"user{i % 500}",
            "IpAddress": f"203.0.113.{i % 250}",
            "EventID": 4625,
            "ProcessName": f"proc{i % 50}.exe",
            "Message": f"Failed logon attempt {i}",
        })
    return evts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--batches", type=int, default=5)
    ap.add_argument("--profile", action="store_true")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="siempl-bench-")
    db = Database(str(Path(tmp) / "bench.duckdb"))
    pipe = IngestPipeline(db)

    records = [json.dumps(e) for e in synth_events(args.events)]
    per_batch = max(1, len(records) // args.batches)
    batches = [records[i:i + per_batch] for i in range(0, len(records), per_batch)]

    # Warm-up batch (also creates the sources row)
    pipe.ingest("bench-src", batches[0][:50])

    t0 = time.monotonic()
    if args.profile:
        pr = cProfile.Profile()
        pr.enable()
    total = 0
    for b in batches:
        r = pipe.ingest("bench-src", b, parser="generic_json")
        total += r.inserted
    if args.profile:
        pr.disable()
    dt = time.monotonic() - t0
    print(f"ingested {total} events in {dt:.2f}s -> {total / dt:,.0f} events/s")

    if args.profile:
        stats = pstats.Stats(pr)
        stats.sort_stats("cumulative").print_stats(30)


if __name__ == "__main__":
    main()
