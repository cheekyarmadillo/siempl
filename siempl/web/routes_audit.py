"""Audit log page: filterable SiemplAudit rows."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..db import Database

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _ctx(request: Request, page: str, title: str, **extra):
    return {"request": request, "page": page, "title": title, **extra}


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request, actor_type: str = "", action: str = "",
                         target_type: str = "", q: str = ""):
        filters = ["1=1"]
        params: list = []
        if actor_type:
            filters.append("ActorType = ?")
            params.append(actor_type)
        if action:
            filters.append("Action ILIKE ?")
            params.append(f"%{action}%")
        if target_type:
            filters.append("TargetType = ?")
            params.append(target_type)
        if q:
            filters.append("(Actor ILIKE ? OR Message ILIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        where = " AND ".join(filters)
        rows = db.query(
            f"SELECT * FROM SiemplAudit WHERE {where} ORDER BY TimeGenerated DESC LIMIT 1000",
            params)
        actor_types = [r["ActorType"] for r in db.query(
            "SELECT DISTINCT ActorType FROM SiemplAudit ORDER BY ActorType")]
        actions = [r["Action"] for r in db.query(
            "SELECT DISTINCT Action FROM SiemplAudit ORDER BY Action")]
        target_types = [r["TargetType"] for r in db.query(
            "SELECT DISTINCT TargetType FROM SiemplAudit ORDER BY TargetType")]
        return templates.TemplateResponse(
            request, "audit.html",
            _ctx(request, "audit", "Audit Trail",
                 rows=rows, actor_type_filter=actor_type, action_filter=action,
                 target_type_filter=target_type, q_filter=q,
                 actor_types=actor_types, actions=actions, target_types=target_types))

    @r.get("/api/audit/export-kql")
    async def api_audit_export_kql(actor_type: str = "", action: str = "",
                                    target_type: str = "", q: str = ""):
        """Return a KQL query string that reproduces the current filters in the Logs page."""
        parts = ["SiemplAudit"]
        if actor_type:
            parts.append(f'ActorType == "{actor_type}"')
        if action:
            parts.append(f'Action contains "{action}"')
        if target_type:
            parts.append(f'TargetType == "{target_type}"')
        if q:
            parts.append(f'(Actor contains "{q}" or Message contains "{q}")')
        base = " | ".join(parts)
        return {"kql": f"{base} | take 1000"}

    return r
