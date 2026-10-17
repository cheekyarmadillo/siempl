"""Rule importers: fetch Sigma/Sentinel rules from GitHub, cache on disk,
and import into the DB.  HTTP client is injectable for testing.

Public API
----------
fetch_sigma(*, client, cache_dir, paths_or_query, max_files) -> list[dict]
fetch_sentinel(*, client, cache_dir, paths_or_query, max_files) -> list[dict]
import_rules(db, rules, enable=False) -> dict
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path

from ..db import Database
from .engine import RuleStore, UnsupportedRule, sentinel_to_rule, sigma_to_rule

logger = logging.getLogger(__name__)

# Default GitHub repos
SIGMA_REPO_API = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows"
SIGMA_RAW_PREFIX = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows"

SENTINEL_REPO_API = "https://api.github.com/repos/Azure/Azure-Sentinel/contents/Detections"
SENTINEL_RAW_PREFIX = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Detections"

DEFAULT_CACHE_DIR = "data/rules_cache"


def _cache_path(cache_dir: str | Path, url: str) -> Path:
    """Stable cache path for a URL."""
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    return Path(cache_dir) / h


def _read_cache(path: Path, max_age_sec: int = 86400) -> str | None:
    """Read cached content if fresh enough."""
    if not path.is_file():
        return None
    if time.time() - path.stat().st_mtime > max_age_sec:
        return None
    return path.read_text(encoding="utf-8")


def _write_cache(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _default_client() -> Callable[[str], dict]:
    """Factory for the real HTTP client (httpx).  Tests inject their own."""
    import httpx
    def _fetch(url: str) -> dict:
        r = httpx.get(url, headers={"User-Agent": "siempl/0.1"}, timeout=30,
                      follow_redirects=True)
        r.raise_for_status()
        return r.json() if url.startswith("https://api.github.com") else {"content": r.text}
    return _fetch


def fetch_sigma(
    *,
    client: Callable[[str], dict] | None = None,
    cache_dir: str | Path | None = None,
    paths_or_query: str | None = None,
    max_files: int = 20,
) -> list[dict]:
    """Fetch Sigma rules from GitHub.  Caches on disk.

    *paths_or_query*: a subdirectory under rules/windows (e.g. "process_creation")
                      or None for the top-level listing.  Can also be a direct
                      raw URL path.
    *max_files*: maximum rule files to download (rate-limit polite).
    """
    fetcher = client or _default_client()
    cache = Path(cache_dir or DEFAULT_CACHE_DIR)
    rules = []

    if paths_or_query and paths_or_query.startswith("http"):
        # Direct URL
        url = paths_or_query
        cp = _cache_path(cache, url)
        text = _read_cache(cp)
        if text is None:
            resp = fetcher(url)
            text = resp.get("content", "")
            _write_cache(cp, text)
        try:
            rule = sigma_to_rule(text, source_ref=url)
            rules.append(rule)
        except UnsupportedRule:
            pass
        return rules

    # List directory via GitHub API
    api_url = SIGMA_REPO_API
    if paths_or_query:
        api_url = f"{SIGMA_REPO_API}/{paths_or_query}"

    api_cache = _cache_path(cache, api_url + ".listing.json")
    listing_raw = _read_cache(api_cache)
    if listing_raw is None:
        resp = fetcher(api_url)
        resp_json = resp if isinstance(resp, (dict, list)) else json.loads(resp)
        listing_raw = json.dumps(resp_json)
        _write_cache(api_cache, listing_raw)

    listing = json.loads(listing_raw) if isinstance(listing_raw, str) else listing_raw
    if not isinstance(listing, list):
        return rules

    yml_files = [f for f in listing if f.get("name", "").endswith((".yml", ".yaml"))]
    yml_files = yml_files[:max_files]

    for item in yml_files:
        # Use raw URL for the file
        raw_url = item.get("download_url") or item.get("html_url", "")
        if not raw_url:
            continue
        cp = _cache_path(cache, raw_url)
        text = _read_cache(cp)
        if text is None:
            try:
                resp = fetcher(raw_url)
                text = resp.get("content", "") if isinstance(resp, dict) else str(resp)
                _write_cache(cp, text)
            except Exception:
                logger.warning("fetch_sigma: ignored error", exc_info=True)
                continue
        if not text.strip():
            continue
        try:
            rule = sigma_to_rule(text, source_ref=raw_url)
            rules.append(rule)
        except UnsupportedRule:
            continue
        # Rate-limit polite: brief sleep between fetches
        if len(yml_files) > 5:
            time.sleep(0.3)
    return rules


def fetch_sentinel(
    *,
    client: Callable[[str], dict] | None = None,
    cache_dir: str | Path | None = None,
    paths_or_query: str | None = None,
    max_files: int = 20,
) -> list[dict]:
    """Fetch Azure-Sentinel detection rules from GitHub.  Caches on disk."""
    fetcher = client or _default_client()
    cache = Path(cache_dir or DEFAULT_CACHE_DIR)
    rules = []

    if paths_or_query and paths_or_query.startswith("http"):
        url = paths_or_query
        cp = _cache_path(cache, url)
        text = _read_cache(cp)
        if text is None:
            resp = fetcher(url)
            text = resp.get("content", "")
            _write_cache(cp, text)
        try:
            rule = sentinel_to_rule(text, source_ref=url)
            rules.append(rule)
        except UnsupportedRule:
            pass
        return rules

    # List directory
    api_url = SENTINEL_REPO_API
    if paths_or_query:
        api_url = f"{SENTINEL_REPO_API}/{paths_or_query}"

    api_cache = _cache_path(cache, api_url + ".listing.json")
    listing_raw = _read_cache(api_cache)
    if listing_raw is None:
        resp = fetcher(api_url)
        resp_json = resp if isinstance(resp, (dict, list)) else json.loads(resp)
        listing_raw = json.dumps(resp_json)
        _write_cache(api_cache, listing_raw)

    listing = json.loads(listing_raw) if isinstance(listing_raw, str) else listing_raw
    if not isinstance(listing, list):
        return rules

    yml_files = [f for f in listing if f.get("name", "").endswith((".yml", ".yaml"))]
    yml_files = yml_files[:max_files]

    for item in yml_files:
        raw_url = item.get("download_url") or item.get("html_url", "")
        if not raw_url:
            continue
        cp = _cache_path(cache, raw_url)
        text = _read_cache(cp)
        if text is None:
            try:
                resp = fetcher(raw_url)
                text = resp.get("content", "") if isinstance(resp, dict) else str(resp)
                _write_cache(cp, text)
            except Exception:
                logger.warning("fetch_sentinel: ignored error", exc_info=True)
                continue
        if not text.strip():
            continue
        try:
            rule = sentinel_to_rule(text, source_ref=raw_url)
            rules.append(rule)
        except UnsupportedRule:
            continue
        if len(yml_files) > 5:
            time.sleep(0.3)
    return rules


def import_rules(db: Database, rules: list[dict], enable: bool = False) -> dict:
    """Import a list of rule dicts into the DB.  Rules are DISABLED by default.

    Returns summary dict with counts.
    """
    store = RuleStore(db)
    imported = 0
    skipped = 0
    errors: list[str] = []
    for rule in rules:
        try:
            rule["enabled"] = enable
            store.create(rule)
            imported += 1
        except Exception as e:
            skipped += 1
            errors.append(str(e)[:200])
    return {"imported": imported, "skipped": skipped, "errors": errors[:10]}
