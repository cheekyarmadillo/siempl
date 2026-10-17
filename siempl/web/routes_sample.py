"""Sample data routes: /samples page and /api/testdata/samples endpoints."""
from __future__ import annotations

import logging

import duckdb
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..audit import record as audit_record
from ..db import Database

try:
    from ..testdata.sample import clear_samples, load_samples
except ImportError:
    load_samples = clear_samples = None  # type: ignore[misc,assignment]
try:
    from ..testdata.scenarios import load_scenarios, reset_scenarios
except ImportError:
    load_scenarios = reset_scenarios = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

TEMPLATES_DIR = __import__("pathlib", fromlist=["Path"]).Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _ctx(request: Request, page: str, title: str, **extra):
    from .routes import SEVERITY_CLASS, _mod_state
    return {
        "request": request,
        "page": page,
        "title": title,
        "modules": _mod_state(),
        "severity_class": SEVERITY_CLASS,
        **extra,
    }


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/samples", response_class=HTMLResponse)
    async def samples_page(request: Request):
        has_samples = load_samples is not None
        return templates.TemplateResponse(
            request,
            "samples.html",
            _ctx(request, "samples", "Sample Data", has_samples=has_samples),
            headers={"Cache-Control": "no-cache"},
        )

    @r.post("/api/testdata/samples")
    async def api_load_samples(request: Request):
        if load_samples is None:
            return JSONResponse({"error": "testdata module not available"}, status_code=503)
        try:
            body = await request.json()
            seed = body.get("seed", 42)
        except Exception:
            seed = 42
        try:
            summary = load_samples(db, seed=seed)
            audit_record(db, "user:web", "samples.load", target_type="setting", target_id="samples",
                         outcome="ok", details=summary)
            return {"ok": True, "summary": summary}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @r.post("/api/testdata/samples/clear")
    async def api_clear_samples():
        if clear_samples is None:
            return JSONResponse({"error": "testdata module not available"}, status_code=503)
        try:
            summary = clear_samples(db)
            audit_record(db, "user:web", "samples.clear", target_type="setting", target_id="samples",
                         outcome="ok", details=summary)
            return {"ok": True, "summary": summary}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @r.post("/api/samples/scenarios")
    async def api_load_scenarios():
        """Load attack, noise and injection scenarios (idempotent). See testdata/scenarios.py."""
        if load_scenarios is None:
            return JSONResponse({"error": "scenario module not available"}, status_code=503)
        try:
            return {"ok": True, "summary": load_scenarios(db)}
        except (duckdb.Error, RuntimeError, ValueError) as exc:
            logger.exception("scenario load failed")
            return JSONResponse({"error": str(exc)}, status_code=500)

    @r.delete("/api/samples/scenarios")
    async def api_reset_scenarios():
        """Remove only scenario-tagged rows (SourceId scn-*, rule ids scn_*)."""
        if reset_scenarios is None:
            return JSONResponse({"error": "scenario module not available"}, status_code=503)
        try:
            return {"ok": True, "summary": reset_scenarios(db)}
        except (duckdb.Error, RuntimeError, ValueError) as exc:
            logger.exception("scenario reset failed")
            return JSONResponse({"error": str(exc)}, status_code=500)

    return r
