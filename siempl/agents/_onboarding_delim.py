"""Detect delimiter-separated key=value records (e.g. 'TLX|v2|dev=GW-7|evt=ARM|ts=...') for onboarding."""
from __future__ import annotations

CANDIDATE_DELIMITERS = ("|", ";", "\t")
MIN_SHARE = 0.6


def _kv_parts(sample: str, delimiter: str | None) -> int:
    return sum("=" in part for part in sample.split(delimiter))


def detect_kv_delimiter(samples: list[str]) -> str | None:
    """Delimiter that splits most samples into 2+ key=value parts, but only if plain whitespace does not."""
    rows = [s.strip() for s in samples[:50] if s and s.strip()]
    if not rows:
        return None
    whitespace_hits = sum(_kv_parts(s, None) >= 2 for s in rows)
    hits, best = max((sum(_kv_parts(s, d) >= 2 for s in rows), d) for d in CANDIDATE_DELIMITERS)
    return best if hits / len(rows) >= MIN_SHARE and hits > whitespace_hits else None


def delimited_pairs(sample: str, delimiter: str) -> list[tuple[str, str]]:
    pairs = []
    for part in sample.split(delimiter):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            pairs.append((key.strip(), value.strip().strip('"').strip("'")))
    return pairs
