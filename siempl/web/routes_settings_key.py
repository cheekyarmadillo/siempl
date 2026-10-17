"""Settings: OpenRouter key entry endpoints (save / remove / test / status). The key never leaves the server."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..audit import record as audit_record
from ..db import Database
from . import _settings_key as sk

# Replaced in tests to avoid the network: (url, headers) -> (status, json body)
_getter = None


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    async def _body(request: Request) -> dict:
        try:
            b = await request.json()
        except ValueError:
            return {}
        return b if isinstance(b, dict) else {}

    @r.get("/api/settings/key/status")
    async def key_status():
        return sk.public_status(db)

    @r.post("/api/settings/key")
    async def key_save(request: Request):
        raw = (await _body(request)).get("key")
        try:
            path = sk.save_key(db, raw)
        except sk.InvalidKeyError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        except OSError as exc:
            return JSONResponse({"ok": False, "error": f"could not write key file ({type(exc).__name__})"}, status_code=500)
        audit_record(db, "user:web", "settings.key_save", "setting", "openrouter_key_file", details={"path": str(path)})
        return {"ok": True, **sk.public_status(db)}

    @r.delete("/api/settings/key")
    async def key_remove():
        removed = sk.remove_key(db)
        audit_record(db, "user:web", "settings.key_remove", "setting", "openrouter_key_file", details={"removed": removed})
        return {"ok": True, "removed": removed, **sk.public_status(db)}

    @r.post("/api/settings/key/test")
    async def key_test():
        key, source = sk.resolve_key(db)
        if not key:
            return JSONResponse({"ok": False, "result": "no_key", "message": "No key configured."}, status_code=400)
        res = sk.check_key(key, _getter)
        res["source"] = source
        return res

    return r
