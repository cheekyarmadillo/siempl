"""OpenRouter API key management for the Settings page: key file I/O, masked status, Test-key check.

Contract: the key lives ONLY in the key file (settings['openrouter_key_file'], mode 0600) or in env
OPENROUTER_API_KEY. It is never written to the DB, the audit log, or logs, and no function here returns
it to a caller except `resolve_key`, which the Test-key route uses server-side and never serializes.
Not for LLM calls (siempl/ai/llm.py) and not for HTTP routing (routes_settings.py).
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from ..db import Database

logger = logging.getLogger(__name__)

ENV_VAR = "OPENROUTER_API_KEY"
KEY_CHECK_URL = "https://openrouter.ai/api/v1/auth/key"
# printable ASCII only: no spaces, tabs, or newlines; length bounds are generous for sk-or-v1-... keys
_KEY_SHAPE = re.compile(r"[\x21-\x7e]{20,512}")

# (url, headers) -> (http status, parsed JSON body). Injected in tests; default performs the real GET.
Getter = Callable[[str, dict], tuple[int, Any]]


class InvalidKeyError(ValueError):
    """The submitted key failed the shape check. Message never contains the key."""


def validate_key(raw: object) -> str:
    """Return the stripped key or raise InvalidKeyError (shape only, no network)."""
    if not isinstance(raw, str):
        raise InvalidKeyError("key must be a string")
    key = raw.strip()
    if not key:
        raise InvalidKeyError("key is empty")
    if not _KEY_SHAPE.fullmatch(key):
        raise InvalidKeyError("key must be 20-512 characters with no spaces or line breaks")
    return key


def key_file_path(db: Database) -> Path | None:
    """Resolved key file path from settings, or None when the setting is blank."""
    raw = str(db.get_setting("openrouter_key_file", "") or "").strip()
    return Path(os.path.expanduser(raw)) if raw else None


def read_key_file(path: Path | None) -> str | None:
    """Key text from the file, or None if missing/unreadable/blank. Never logs the contents."""
    if path is None or not path.is_file():
        return None
    try:
        text = path.read_text().strip()
    except OSError:
        logger.warning("openrouter key file exists but cannot be read: %s", path)
        return None
    return text or None


def mask_key(key: str) -> str:
    """Display form like 'sk-or-…a1b2'. Short or odd-shaped keys show no characters at all."""
    if len(key) < 20:
        return "configured (unrecognized format)"
    prefix = "sk-or-…" if key.startswith("sk-or-") else "…"
    return f"configured ({prefix}{key[-4:]})"


def resolve_key(db: Database) -> tuple[str | None, str]:
    """Effective key and its source: env first (same precedence as llm.py), then the key file.

    Returns (key, 'env' | 'file') or (None, 'none'). The caller must not render the key.
    """
    env_key = os.environ.get(ENV_VAR)
    if env_key:
        return env_key, "env"
    file_key = read_key_file(key_file_path(db))
    if file_key:
        return file_key, "file"
    return None, "none"


def public_status(db: Database) -> dict:
    """Everything the Settings page may show about the key. Contains no key material."""
    path = key_file_path(db)
    file_key = read_key_file(path)
    env_set = bool(os.environ.get(ENV_VAR))
    source = "env" if env_set else ("file" if file_key else "none")
    return {
        "source": source,
        "env_set": env_set,
        "file_path": str(path) if path else "",
        "file_configured": file_key is not None,
        "label": mask_key(file_key) if file_key else "not set",
        "metric": {"env": "env var", "file": "key file", "none": "not set"}[source],
    }


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return


def write_key_file(path: Path, key: str) -> None:
    """Atomically replace the key file: 0700 parent (created if absent), 0600 file, fsync, rename."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        _unlink_quietly(tmp)
        raise


def save_key(db: Database, raw: object) -> Path:
    """Validate and store the key in the key file. Returns the path. Raises InvalidKeyError / OSError."""
    key = validate_key(raw)
    path = key_file_path(db)
    if path is None:
        raise InvalidKeyError("openrouter_key_file setting is blank")
    write_key_file(path, key)
    return path


def remove_key(db: Database) -> bool:
    """Delete the key file. Returns False if there was nothing to remove."""
    path = key_file_path(db)
    if path is None:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def _http_get(url: str, headers: dict) -> tuple[int, Any]:
    r = httpx.get(url, headers=headers, timeout=15)
    try:
        body: Any = r.json()
    except ValueError:
        body = {}
    return r.status_code, body


def _usage_message(data: dict) -> str:
    usage = data.get("usage")
    limit = data.get("limit")
    remaining = data.get("limit_remaining")
    parts = []
    if isinstance(usage, (int, float)):
        parts.append(f"usage ${usage:.4f}")
    if isinstance(limit, (int, float)):
        parts.append(f"limit ${limit:.2f}" + (f" (remaining ${remaining:.2f})" if isinstance(remaining, (int, float)) else ""))
    else:
        parts.append("no key limit set")
    return "; ".join(parts)


def _interpret(status: int, body: Any) -> dict:
    if status == 200:
        data = body.get("data") if isinstance(body, dict) and isinstance(body.get("data"), dict) else {}
        return {"result": "valid", "ok": True, "message": "Key is valid. " + _usage_message(data)}
    if status in (401, 403):
        return {"result": "invalid", "ok": False, "status_code": status,
                "message": f"Key rejected by OpenRouter (HTTP {status})."}
    return {"result": "unexpected", "ok": False, "status_code": status,
            "message": f"Unexpected response from OpenRouter (HTTP {status})."}


def check_key(key: str, getter: Getter | None = None) -> dict:
    """Call OpenRouter's key-info endpoint with `key`. Returns a result dict with no key material.

    result: valid | invalid | unexpected | network_error. Only the HTTP status and usage/limit numbers
    are reported; the key label and any other fields in the response are dropped.
    """
    get = getter or _http_get
    try:
        status, body = get(KEY_CHECK_URL, {"Authorization": f"Bearer {key}"})
    except (httpx.HTTPError, OSError) as e:
        logger.info("openrouter key check: network error (%s)", type(e).__name__)
        return {"result": "network_error", "ok": False,
                "message": f"Network error reaching OpenRouter ({type(e).__name__}); key not verified."}
    return _interpret(status, body)
