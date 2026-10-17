"""Download SMALL public samples for testing. Uses real URLs verified via HEAD/GET.

Sources (capped at ~5MB each):
  1. splunk/attack_data: small Windows attack log datasets (Windows Event XML,
     one event per line; ingested as text into GenericEvents — there is no
     windows_xml parser yet)
     - T1110.001 RDP brute force (Sysmon)
     - T1059.001 encoded PowerShell (Sysmon)
     - T1021.002 Impacket smbexec (Windows Security 4688)

NOTE: attack_data stores .log files in Git LFS, so raw.githubusercontent.com
returns the 130-byte LFS pointer.  Real content is served by
media.githubusercontent.com (verified HTTP 200, 2026-10-12).

All downloads go to data/testdata/ (SIEMPL_HOME relative) and are NOT committed.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import home
from ..db import Database
from ..ingest import IngestPipeline

# Verified-available samples (checked with HEAD 2026-10): small, useful
DATASETS = [
    {
        "name": "T1110.001-rdp-brute",
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/rdp_brute_sysmon/sysmon.log",
        "parser": None,  # Windows Event XML lines -> auto-detect -> GenericEvents
        "format": "text",
        "max_bytes": 5_000_000,
    },
    {
        "name": "T1059.001-encoded-powershell",
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/windows-sysmon.log",
        "parser": None,
        "format": "text",
        "max_bytes": 5_000_000,
    },
    {
        "name": "T1021.002-impacket-smbexec",
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/impacket_smbexec/windows_security_xml.log",
        "parser": None,
        "format": "text",
        "max_bytes": 5_000_000,
    },
]


def _download(url: str, max_bytes: int, timeout: int = 30) -> bytes | None:
    """Download a URL synchronously, capped at max_bytes."""
    import urllib.request

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "siempl-testdata/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read(max_bytes + 1)
            if len(content) > max_bytes:
                content = content[:max_bytes]
            return content
    except Exception as e:
        print(f"  [WARN] Failed to download {url}: {e}")
        return None


def _ingest_text_file(db: Database, source_id: str, content: bytes, parser: str | None) -> int:
    """Ingest a text file, splitting by newlines."""
    lines = content.decode("utf-8", errors="replace").split("\n")
    # Skip empty lines and XML header lines
    records = [l.rstrip("\r") for l in lines if l.strip() and not l.strip().startswith("<?xml")]
    pipeline = IngestPipeline(db)
    result = pipeline.ingest(source_id, records, parser=parser)
    return result.inserted


def _ingest_json_file(db: Database, source_id: str, content: bytes, parser: str | None) -> int:
    """Ingest a JSON file that may be JSON array, NDJSON, or single object with embedded array."""
    text = content.decode("utf-8", errors="replace").strip()
    records = []

    # Try JSON array
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                records = arr
        except json.JSONDecodeError:
            pass

    # Try NDJSON
    if not records and text.startswith("{"):
        records = []
        for line in text.split("\n"):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    # Try XML wrapped (Splunk attack_data export format)
    if not records and "<Event" in text:
        # Extract JSON-like event data from XML (simplified: just store raw)
        pipeline = IngestPipeline(db)
        result = pipeline.ingest(source_id, [text], parser=parser)
        return result.inserted

    if not records:
        # Store as single object / raw
        pipeline = IngestPipeline(db)
        result = pipeline.ingest(source_id, [text], parser=parser)
        return result.inserted

    pipeline = IngestPipeline(db)
    result = pipeline.ingest(source_id, records, parser=parser)
    return result.inserted


def fetch_dataset(db: Database, dataset: dict, testdata_dir: Path) -> int:
    """Download and ingest one dataset. Returns number of events inserted."""
    name = dataset["name"]
    url = dataset["url"]
    fmt = dataset["format"]
    parser = dataset.get("parser")
    max_bytes = dataset.get("max_bytes", 5_000_000)

    print(f"  Fetching {name} ...", end=" ", flush=True)

    testdata_dir.mkdir(parents=True, exist_ok=True)

    # Check if already downloaded
    cache_path = testdata_dir / f"{name}.cache"
    if cache_path.exists():
        print("cached")
        content = cache_path.read_bytes()
    else:
        content = _download(url, max_bytes)
        if content is None:
            print("SKIP (download failed)")
            return 0
        # Save to cache
        cache_path.write_bytes(content)
        print(f"{len(content)} bytes")

    if not content:
        return 0

    source_id = f"testdata-fetch-{name}"
    if fmt == "text":
        return _ingest_text_file(db, source_id, content, parser)
    return _ingest_json_file(db, source_id, content, parser)


def fetch_all(db: Database) -> dict:
    """Download and ingest all datasets. Returns per-dataset counts."""
    testdata_dir = home() / "testdata"
    testdata_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    total = 0
    for ds in DATASETS:
        try:
            count = fetch_dataset(db, ds, testdata_dir)
            results[ds["name"]] = count
            total += count
        except Exception as e:
            results[ds["name"]] = f"error: {e}"

    results["total"] = total
    return results


if __name__ == "__main__":
    db = Database()
    fetch_all(db)
    db.close()
