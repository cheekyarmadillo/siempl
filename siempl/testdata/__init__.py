"""Test data: downloaders for public datasets + synthetic attack scenario generator.

Paths: siempl/testdata/fetch.py, siempl/testdata/synth.py, siempl/testdata/load.py

Usage: python -m siempl.testdata load [--synth] [--fetch] [--seed SEED]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta, timezone

from ..db import Database, utcnow
from ..ingest import IngestPipeline


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def run_load(db: Database, *, synth: bool = False, fetch: bool = False,
             seed: int = 42) -> dict:
    """Run the test data loader. Returns summary dict."""
    result: dict = {"synth": None, "fetch": None}

    if synth:
        from .synth import generate_all
        result["synth"] = generate_all(db, seed=seed)

    if fetch:
        from .fetch import fetch_all
        result["fetch"] = fetch_all(db)

    return result


def main():
    """CLI entry point: python -m siempl.testdata load [--synth] [--fetch]"""
    import argparse
    parser = argparse.ArgumentParser(description="siempl test data loader")
    parser.add_argument("command", choices=["load"])
    parser.add_argument("--synth", action="store_true", help="Generate synthetic attack data")
    parser.add_argument("--fetch", action="store_true", help="Download public samples")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for synthetic data")
    args = parser.parse_args()

    db = Database()
    result = run_load(db, synth=args.synth, fetch=args.fetch, seed=args.seed)
    print(json.dumps(result, indent=2, default=str))
    db.close()


if __name__ == "__main__":
    main()

# Sample data for exercising the agents (siempl/testdata/sample.py)
from .sample import clear_samples, load_samples  # noqa: E402,F401
