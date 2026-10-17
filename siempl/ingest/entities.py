"""Entity extraction from normalized events. Maps entity columns to (type, value) pairs.

Extracts from ENTITY_COLUMNS in schema.py. Filters noise values: empty strings, '-', 'unknown',
localhost-ish IPs (127.x, ::1), and well-known noise values like "SYSTEM", "LOCAL SERVICE".

Each call returns a list of (entity_type, value) tuples for upserting.
"""
from __future__ import annotations

import ipaddress

from ..schema import ENTITY_COLUMNS

# Values that are never meaningful entities
NOISE_VALUES: set[str] = {
    "", "-", "unknown", "Unknown", "<unknown>", "n/a", "N/A",
    "null", "None", "none", "nil",
}

# Well-known local/noise hostnames
NOISE_HOSTS: set[str] = {
    "localhost", "localhost.localdomain", "127.0.0.1", "::1",
}
NOISE_HOSTS_LOWER: frozenset[str] = frozenset(h.lower() for h in NOISE_HOSTS)
NOISE_VALUES_LOWER: frozenset[str] = frozenset(v.lower() for v in NOISE_VALUES)

# Well-known process names (not meaningful as entities)
NOISE_PROCESSES: set[str] = {
    "system", "idle", "system idle process",
}

# Well-known service accounts (not meaningful as entities)
NOISE_USERS: set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "LOCALSERVICE",
    "NETWORKSERVICE", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE", "root", "nobody",
}

# Private / loopback IP ranges to filter
PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
PRIVATE_RANGES_TUPLES = [(int(r.network_address), int(r.broadcast_address)) for r in PRIVATE_RANGES]
# flatten v4 and v6 for checking
for r in PRIVATE_RANGES:
    PRIVATE_RANGES_TUPLES.append((int(r.network_address), int(r.broadcast_address)))


def _is_localhost_ip(value: str) -> bool:
    """Check if an IP value falls in a private/loopback range."""
    try:
        addr = ipaddress.ip_address(value.strip())
        n = int(addr)
        for lo, hi in PRIVATE_RANGES_TUPLES:
            if lo <= n <= hi:
                return True
    except ValueError:
        return False
    return False


def _is_meaningful(type_: str, value: str) -> bool:
    """Return True if the value is a meaningful entity worth tracking."""
    if not value or not isinstance(value, str):
        return False
    v = value.strip()

    # Noise values
    if v in NOISE_VALUES:
        return False
    if v.lower() in NOISE_VALUES_LOWER:
        return False

    # Length check: too short isn't meaningful
    if len(v) < 1:
        return False

    # Host-specific noise
    if type_ == "host":
        if v.lower() in NOISE_HOSTS_LOWER:
            return False

    # User-specific noise
    if type_ == "user":
        if v.upper() in NOISE_USERS:
            return False

    # Process-specific noise
    if type_ == "process":
        if v.lower() in NOISE_PROCESSES:
            return False

    # IP-specific noise
    if type_ == "ip":
        if _is_localhost_ip(v):
            return False  # Private IPs still tracked but marked

    # Domain noise
    if type_ == "domain":
        if v.endswith(".local") or v.endswith(".localdomain") or v.endswith(".arpa"):
            return False

    # Max length sanity
    return not len(v) > 512


def _normalize(type_: str, value: str) -> str:
    """Normalize entity values for consistent dedup."""
    v = value.strip()

    if type_ in ("user", "host", "domain"):
        v = v.lower()
    # IPs: keep as-is (case doesn't matter for IPs)
    elif type_ == "process":
        v = v.lower()
    elif type_ == "file_hash":
        v = v.lower()

    return v


def extract_entities(table: str, fields: dict) -> list[tuple[str, str]]:
    """Extract (entity_type, normalized_value) pairs from event fields.

    Uses ENTITY_COLUMNS from schema.py: maps column names to entity types.
    Filters noise values and normalizes case.

    Args:
        table: target data table name (for context, not currently used in extraction).
        fields: normalized event fields dict.

    Returns:
        List of (entity_type, value) tuples ready for upserting.
    """
    pairs: list[tuple[str, str]] = []
    for col, etype in ENTITY_COLUMNS.items():
        val = fields.get(col)
        if not val or not isinstance(val, (str, int)):
            continue
        sval = str(val)
        if not _is_meaningful(etype, sval):
            continue
        normalized = _normalize(etype, sval)
        pairs.append((etype, normalized))
    return pairs
