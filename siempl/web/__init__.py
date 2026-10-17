"""siempl web application.

FastAPI + Jinja2 + HTMX, Apple HIG styling. create_app(db) returns a fully wired
application. All pages feature-detect optional modules (kql, detect, entities,
ingest, collectors, agents) and degrade gracefully if absent.

Public API:
    create_app(db) -> FastAPI
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ..db import Database
from .routes import build_router

_WEB_DIR = Path(__file__).resolve().parent


def create_app(db: Database, collector_manager=None) -> FastAPI:
    """Build the FastAPI app wired to *db*.

    Mounts /static/ for CSS/JS, registers page routes and /api/* endpoints,
    and conditionally mounts siempl.collectors.make_ingest_router(db) at
    /api/ingest when the module is available.
    """
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        # Shutdown: stop collectors
        cm = getattr(app.state, "collector_manager", None)
        if cm is not None:
            cm.stop_all()

    app = FastAPI(title="siempl", docs_url=None, redoc_url=None, lifespan=lifespan)

    # Collector manager (runtime start/stop)
    if collector_manager is not None:
        app.state.collector_manager = collector_manager

    # Static files (CSS + HTMX)
    static_dir = _WEB_DIR / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Feature routers: any siempl/web/routes_<name>.py exposing build_router(db) is mounted
    # BEFORE the legacy routes.py router, so it can override a legacy path (first match wins).
    import importlib
    import pkgutil

    from . import __path__ as _pkg_path  # type: ignore[attr-defined]
    for mod in sorted(pkgutil.iter_modules(_pkg_path), key=lambda m: m.name):
        if mod.name.startswith("routes_"):
            m = importlib.import_module(f"{__name__}.{mod.name}")
            app.include_router(m.build_router(db))

    router = build_router(db)
    app.include_router(router)

    # Conditionally mount the ingest-collector sub-router
    try:
        from siempl.collectors import make_ingest_router  # type:ignore[import-untyped]
        ingest_router = make_ingest_router(db)
        app.include_router(ingest_router)
    except (ImportError, AttributeError):
        pass

    return app
