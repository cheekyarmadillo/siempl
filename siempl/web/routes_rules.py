"""Rules page: full CRUD, test query, Sigma import, version history, run-now."""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..audit import record as audit_record
from ..db import Database
from ._rules_alerts import rule_alerts_panel, rules_with_alert_counts

logger = logging.getLogger(__name__)

# Feature detection
_KQL = _DETECT = None
try:
    import siempl.kql as _KQL  # type:ignore[import-untyped]
except ImportError:
    pass
try:
    import siempl.detect as _DETECT  # type:ignore[import-untyped]
except ImportError:
    pass

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_CLASS: dict[str, str] = {
    "informational": "sev-info", "low": "sev-low",
    "medium": "sev-medium", "high": "sev-high", "critical": "sev-critical",
}


def _ctx(request: Request, page: str, title: str, **extra):
    return {"request": request, "page": page, "title": title,
            "severity_class": SEVERITY_CLASS, **extra}


def _has(module) -> bool:
    return module is not None


# ---------------------------------------------------------------------------
# Import: formats, URL allow-list, capped fetch
# ---------------------------------------------------------------------------

IMPORT_FORMATS = ("sigma", "sentinel", "kql")
IMPORT_MAX_BYTES = 1024 * 1024          # 1 MB cap for pasted text and fetched URLs
IMPORT_FETCH_TIMEOUT = 10.0             # seconds
IMPORT_ALLOWED_HOSTS = ("github.com", "raw.githubusercontent.com")


class ImportInputError(Exception):
    """Bad input or fetch problem; message is shown to the user as-is."""


def normalize_import_url(url: str) -> str:
    """Validate an import URL and return the raw-file URL to fetch.

    https only, host allow-list, single .yml/.yaml file. github.com `/blob/` file
    views are rewritten to raw.githubusercontent.com. Raises ImportInputError.
    """
    p = urlparse((url or "").strip())
    if p.scheme != "https":
        raise ImportInputError("URL must use https://")
    host = (p.hostname or "").lower()
    if host not in IMPORT_ALLOWED_HOSTS:
        raise ImportInputError(
            f"Host '{host or '?'}' is not allowed. Use github.com or raw.githubusercontent.com.")
    if p.username or p.password or p.port not in (None, 443):
        raise ImportInputError("URL must not contain credentials or a custom port")
    path = p.path
    if host == "github.com":
        parts = path.strip("/").split("/")
        if len(parts) < 5 or parts[2] != "blob":
            raise ImportInputError(
                "github.com URLs must point to a file view (/owner/repo/blob/ref/path.yml)")
        path = "/" + "/".join([parts[0], parts[1]] + parts[3:])
        host = "raw.githubusercontent.com"
    if not path.lower().endswith((".yml", ".yaml")):
        raise ImportInputError("URL must point to a single .yml or .yaml rule file")
    return urlunparse(("https", host, path, "", "", ""))


def _http_get_capped(url: str, max_bytes: int = IMPORT_MAX_BYTES,
                     timeout: float = IMPORT_FETCH_TIMEOUT) -> str:
    """GET a URL with a timeout and a hard byte cap. No redirects (host check stays valid)."""
    import httpx
    too_large = f"File is larger than {max_bytes // 1024} KB; refusing to import."
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=False,
                          headers={"User-Agent": "siempl/0.1"}) as r:
            if r.status_code != 200:
                raise ImportInputError(f"Fetch failed: HTTP {r.status_code} (redirects are not followed)")
            cl = r.headers.get("content-length", "")
            if cl.isdigit() and int(cl) > max_bytes:
                raise ImportInputError(too_large)
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise ImportInputError(too_large)
    except httpx.HTTPError as e:
        raise ImportInputError(f"Fetch failed: {type(e).__name__}: {e}") from e
    return buf.decode("utf-8", errors="replace")


# Module attribute, looked up at call time so tests can monkeypatch it (no network in tests).
fetch_url_text = _http_get_capped


def _kql_rule(text: str, name: str, kql) -> dict:
    """Plain KQL paste -> rule dict. Raises UnsupportedRule-like via caller."""
    from siempl.detect.engine import UnsupportedRule
    q = text.strip()
    try:
        compiled = kql.compile_kql(q)
    except kql.KqlError as e:
        raise UnsupportedRule(f"KQL does not compile: {e}") from e
    tables = list(getattr(compiled, "tables", None) or [])
    digest = hashlib.sha256(q.encode()).hexdigest()
    return {
        "name": name or f"KQL import {digest[:8]}",
        "description": "", "triage_steps": "", "severity": "medium",
        "query": q, "tables": tables,
        "mitre_tactics": [], "mitre_techniques": [], "entity_mappings": [],
        "origin": "manual", "source_content": text, "query_lang": "kql",
    }


def _format_label(rule: dict) -> str:
    """Badge text for the rules list and detail page."""
    origin = (rule.get("origin") or "manual")
    if origin == "sigma":
        return "Sigma-imported"
    if origin == "sentinel":
        return "Sentinel"
    if origin.startswith("ai"):
        return "AI"
    if origin == "builtin":
        return "Built-in"
    return "KQL manual"


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    # ------------------------------------------------------------------ helpers
    def _rules_list(where_clause="1=1", params=None, limit=500):
        params = params or []
        return db.query(
            f"SELECT * FROM rules WHERE {where_clause} ORDER BY name LIMIT ?",
            params + [limit]
        )

    # ------------------------------------------------------------------ pages
    @r.get("/rules", response_class=HTMLResponse)
    async def rules_page(request: Request, q: str = "", severity: str = "",
                         origin: str = "", enabled: str = "", imported: str = ""):
        filters = ["1=1"]
        params: list = []
        if q:
            filters.append("(name ILIKE ? OR description ILIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if severity:
            filters.append("severity = ?")
            params.append(severity)
        if origin:
            filters.append("origin = ?")
            params.append(origin)
        if enabled in ("true", "false"):
            filters.append("enabled = ?")
            params.append(enabled == "true")
        if imported == "disabled":
            filters.append("origin IN ('sigma', 'sentinel') AND enabled = FALSE")
        where = " AND ".join(filters)
        rules = rules_with_alert_counts(db, where, params)
        origins = [row["origin"] or "" for row in db.query("SELECT DISTINCT origin FROM rules ORDER BY origin")]
        return templates.TemplateResponse(
            request, "rules.html",
            _ctx(request, "rules", "Rules",
                 rules=rules, q=q, severity_filter=severity, origin_filter=origin,
                 enabled_filter=enabled, imported_filter=imported, origins=origins))

    @r.get("/rules/{rule_id}", response_class=HTMLResponse)
    async def rule_detail(request: Request, rule_id: str):
        rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
        if not rule:
            return HTMLResponse("<div class='empty-state'>Rule not found.</div>", status_code=404)
        rule = dict(rule)
        # Parse tuning_history for display
        tuning_history = []
        try:
            th = json.loads(rule.get("tuning_history", "[]")) if isinstance(rule.get("tuning_history"), str) else rule.get("tuning_history", [])
            if isinstance(th, list):
                tuning_history = th[-10:]  # last 10
        except Exception:
            logger.debug("rule_detail: ignored error", exc_info=True)
        alerts_panel = rule_alerts_panel(db, rule_id)
        return templates.TemplateResponse(
            request, "rule_detail.html",
            _ctx(request, "rules", f"Rule: {rule.get('name', '')}",
                 rule=rule, tuning_history=tuning_history, alerts_panel=alerts_panel,
                 fmt_label=_format_label(rule),
                 query_lang=(rule.get("query_lang") or "kql"),
                 kql_keywords=_KQL.keywords() if _has(_KQL) else None))

    @r.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
    async def rule_edit_form(request: Request, rule_id: str = ""):
        rule = None
        if rule_id and rule_id != "new":
            rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
            if rule:
                rule = dict(rule)
        return templates.TemplateResponse(
            request, "rule_form.html",
            _ctx(request, "rules", "Edit Rule" if rule else "New Rule",
                 rule=rule, rule_id=rule_id if rule else "",
                 kql_keywords=_KQL.keywords() if _has(_KQL) else None,
                 severity_opts=["informational","low","medium","high","critical"]))

    # ------------------------------------------------------------------ API
    @r.post("/api/rules")
    async def api_rule_create(request: Request):
        if not _has(_DETECT):
            return JSONResponse({"error": "detect module not available"}, status_code=503)
        try:
            body = await request.json()
            rule = {
                "name": body.get("name", "Unnamed").strip(),
                "description": body.get("description", "").strip(),
                "triage_steps": body.get("triage_steps", "").strip(),
                "severity": body.get("severity", "medium").strip(),
                "query": body.get("query", "").strip(),
                "frequency_minutes": int(body.get("frequency_minutes", 5)),
                "lookback_minutes": int(body.get("lookback_minutes", 5)),
                "threshold": int(body.get("threshold", 1)),
                "mitre_tactics": body.get("mitre_tactics", []),
                "mitre_techniques": body.get("mitre_techniques", []),
                "entity_mappings": body.get("entity_mappings", []),
                "enabled": bool(body.get("enabled", True)),
                "expires_at": body.get("expires_at") or None,
                "origin": body.get("origin", "manual"),
            }
            rid = _DETECT.RuleStore(db).create(rule)
            # Try compile
            if _has(_KQL):
                try:
                    _KQL.compile_kql(rule["query"])
                except Exception:
                    logger.debug("api_rule_create: ignored error", exc_info=True)  # still created, user will see compile error on test
            audit_record(db, "user:web", "rule.create", "rule", rid,
                         details={"name": rule["name"]})
            return {"ok": True, "rule_id": rid}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.get("/api/rules/{rule_id}")
    async def api_rule_get(rule_id: str):
        rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
        if not rule:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return dict(rule)

    @r.put("/api/rules/{rule_id}")
    async def api_rule_update(rule_id: str, request: Request):
        if not _has(_DETECT):
            return JSONResponse({"error": "detect module not available"}, status_code=503)
        try:
            body = await request.json()
            allowed = {"name", "description", "triage_steps", "severity", "query",
                       "frequency_minutes", "lookback_minutes", "threshold",
                       "mitre_tactics", "mitre_techniques", "entity_mappings",
                       "enabled", "expires_at"}
            fields = {k: v for k, v in body.items() if k in allowed}
            if not fields:
                return JSONResponse({"error": "No updatable fields"}, status_code=400)
            audit_record(db, "user:web", "rule.update", "rule", rule_id,
                         details={"fields": list(fields.keys())})
            ok = _DETECT.RuleStore(db).update(rule_id, **fields)
            if not ok:
                return JSONResponse({"error": "Not found"}, status_code=404)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/rules/{rule_id}/clone")
    async def api_rule_clone(rule_id: str):
        if not _has(_DETECT):
            return JSONResponse({"error": "detect module not available"}, status_code=503)
        try:
            rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
            if not rule:
                return JSONResponse({"error": "Not found"}, status_code=404)
            rule_dict = dict(rule)
            for k in ("rule_id", "created_at", "updated_at", "last_run_at",
                      "last_error", "last_row_count", "version", "tuning_history"):
                rule_dict.pop(k, None)
            rule_dict["name"] = f"{rule_dict['name']} (clone)"
            rule_dict["origin"] = "manual"
            rid = _DETECT.RuleStore(db).create(rule_dict)
            audit_record(db, "user:web", "rule.clone", "rule", rid,
                         details={"from": rule_id, "name": rule_dict["name"]})
            return {"ok": True, "rule_id": rid}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/rules/{rule_id}/run-now")
    async def api_rule_run_now(rule_id: str):
        if not _has(_DETECT):
            return JSONResponse({"error": "detect module not available"}, status_code=503)
        try:
            runner = _DETECT.RuleRunner(db)
            alert_ids = runner.run_rule(rule_id)
            audit_record(db, "user:web", "rule.run", "rule", rule_id,
                         details={"alerts_generated": len(alert_ids)})
            return {"ok": True, "alert_ids": alert_ids, "count": len(alert_ids)}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/rules/{rule_id}/delete")
    async def api_rule_disable(rule_id: str):
        """Disable (soft-delete) a rule."""
        try:
            db.execute("UPDATE rules SET enabled = FALSE, updated_at = now() WHERE rule_id=?", [rule_id])
            audit_record(db, "user:web", "rule.disable", "rule", rule_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/rules/{rule_id}/enable")
    async def api_rule_enable(rule_id: str):
        try:
            db.execute("UPDATE rules SET enabled = TRUE, updated_at = now() WHERE rule_id=?", [rule_id])
            audit_record(db, "user:web", "rule.enable", "rule", rule_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/rules/test-query")
    async def api_rule_test_query(request: Request):
        """Test a KQL query against current data without creating alerts."""
        if not _has(_KQL):
            return JSONResponse({"error": "KQL module not available"}, status_code=503)
        try:
            body = await request.json()
            query = body.get("query", "").strip()
            if not query:
                return JSONResponse({"error": "Empty query"}, status_code=400)
            # Compile check
            compiled = _KQL.compile_kql(query)
            tables = list(compiled.tables) if hasattr(compiled, "tables") else []
            # Run
            result = _KQL.run_kql(db, query, origin="user", log=False)
            audit_record(db, "user:web", "rule.test_query", target_type="rule",
                         target_id=None,
                         details={"tables": tables, "row_count": len(result.rows)})
            return {
                "ok": True,
                "columns": result.columns,
                "rows": result.rows[:50],  # cap preview
                "row_count": len(result.rows),
                "tables": tables,
                "truncated": result.truncated,
                "elapsed_ms": result.elapsed_ms,
            }
        except _KQL.KqlError as e:
            return JSONResponse({"error": str(e), "ok": False}, status_code=400)
        except Exception as e:
            return JSONResponse({"error": str(e), "ok": False}, status_code=500)

    # -------------------------------------------------------------- import
    def _convert(fmt: str, text: str, source_ref: str, name: str) -> dict:
        """Convert one rule. Returns {rule, reason, warnings}; never raises."""
        from siempl.detect.engine import UnsupportedRule
        if fmt in ("sigma", "sentinel") and not _has(_DETECT):
            return {"rule": None, "reason": "detect module not available", "warnings": []}
        if fmt == "kql" and not _has(_KQL):
            return {"rule": None, "reason": "KQL module not available", "warnings": []}
        try:
            if fmt == "sigma":
                rule = _DETECT.sigma_to_rule(text, source_ref=source_ref)
            elif fmt == "sentinel":
                rule = _DETECT.sentinel_to_rule(text, source_ref=source_ref)
            else:
                rule = _kql_rule(text, name, _KQL)
        except UnsupportedRule as e:
            return {"rule": None, "reason": e.reason, "warnings": []}
        except Exception as e:  # noqa: BLE001 - show, never 500 the preview
            return {"rule": None, "reason": f"Could not convert: {e}", "warnings": []}
        warnings = []
        if not (rule.get("description") or "").strip():
            warnings.append("No description: the triage agent will have little context. Add one before enabling.")
        if not (rule.get("triage_steps") or "").strip():
            warnings.append("No triage steps: add first investigation steps before enabling.")
        if fmt == "sentinel":
            warnings.append("Sentinel tables/columns are mapped by name to siempl tables. Verify the results before enabling.")
        if not rule.get("tables"):
            warnings.append("No table could be resolved for this query.")
        return {"rule": rule, "reason": None, "warnings": warnings}

    def _preview_view(rule: dict) -> dict:
        keys = ("name", "description", "severity", "tables", "query", "query_lang",
                "query_sql", "triage_steps", "mitre_tactics", "mitre_techniques",
                "entity_mappings", "origin", "source_ref")
        return {k: rule.get(k) for k in keys}

    def _dedupe_hit(name: str, source_ref: str | None) -> dict | None:
        row = db.query_one(
            "SELECT rule_id, name FROM rules WHERE source_ref = ? OR name = ? LIMIT 1",
            [source_ref, name])
        return dict(row) if row else None

    def _audit_import(result: str, fmt: str, name: str | None, rule_id: str | None,
                      source_ref: str | None) -> None:
        audit_record(db, "user:web", "rule.import", "rule", rule_id,
                     outcome="ok" if result == "created" else "rejected",
                     details={"format": fmt, "result": result, "name": name,
                              "source_ref": source_ref})

    def _import_core(fmt: str, text: str = "", url: str = "", name: str = "",
                     commit: bool = False) -> tuple[int, dict]:
        """Shared by every import route. Returns (http_status, payload). Never raises.

        preview (commit=False): converts and reports, creates nothing.
        commit: creates the rule DISABLED, deduped by source_ref/name, audited.
        """
        fmt = (fmt or "").strip().lower()
        if fmt not in IMPORT_FORMATS:
            return 400, {"ok": False, "error": f"Unknown format '{fmt or '(none)'}'. Use sigma, sentinel or kql."}
        if url and url.strip():
            try:
                source_ref = normalize_import_url(url)
            except ImportInputError as e:
                if commit:
                    _audit_import("invalid_url", fmt, None, None, url)
                return 400, {"ok": False, "error": str(e)}
            try:
                text = fetch_url_text(source_ref)
            except ImportInputError as e:
                if commit:
                    _audit_import("fetch_failed", fmt, None, None, source_ref)
                return 400, {"ok": False, "error": str(e)}
        else:
            text = text or ""
            if not text.strip():
                return 400, {"ok": False, "error": "Empty input: paste a rule or give a URL."}
            if len(text.encode("utf-8")) > IMPORT_MAX_BYTES:
                return 413, {"ok": False, "error": "Pasted text is larger than 1 MB."}
            source_ref = "paste:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

        conv = _convert(fmt, text, source_ref, name.strip())
        rule = conv["rule"]
        if rule is not None:
            rule["source_ref"] = source_ref
        dup = _dedupe_hit(rule["name"], source_ref) if rule is not None else None

        if not commit:
            return 200, {
                "ok": True, "format": fmt, "convertible": rule is not None,
                "reason": conv["reason"], "warnings": conv["warnings"],
                "rule": _preview_view(rule) if rule is not None else None,
                "duplicate": dup, "source_ref": source_ref,
            }
        if rule is None:
            _audit_import("unsupported", fmt, name or None, None, source_ref)
            return 422, {"ok": False, "error": conv["reason"], "reason": conv["reason"]}
        if dup is not None:
            _audit_import("duplicate", fmt, rule["name"], dup["rule_id"], source_ref)
            return 409, {"ok": False, "error": f"Already imported as '{dup['name']}' ({dup['rule_id']}).",
                         "duplicate_of": dup}
        rule["enabled"] = False  # all imports land disabled; enabling is a separate, deliberate step
        rid = _DETECT.RuleStore(db).create(rule)
        _audit_import("created", fmt, rule["name"], rid, source_ref)
        return 200, {"ok": True, "rule_id": rid, "enabled": False, "format": fmt,
                     "warnings": conv["warnings"]}

    @r.post("/api/rules/import-preview")
    async def api_import_preview(request: Request):
        """Generic import. body: {format: sigma|sentinel|kql, yaml|url, name?, preview: bool=true}.
        preview=true converts and reports only. preview=false creates the rule DISABLED."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "Body must be JSON"}, status_code=400)
        status, payload = _import_core(
            body.get("format", ""), text=body.get("yaml", "") or "", url=body.get("url", "") or "",
            name=body.get("name", "") or "", commit=not bool(body.get("preview", True)))
        return JSONResponse(payload, status_code=status)

    @r.post("/api/rules/import-sentinel")
    async def api_import_sentinel(request: Request):
        """Microsoft Sentinel YAML. body: {yaml|url, preview: bool=true}."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "Body must be JSON"}, status_code=400)
        status, payload = _import_core(
            "sentinel", text=body.get("yaml", "") or "", url=body.get("url", "") or "",
            commit=not bool(body.get("preview", True)))
        return JSONResponse(payload, status_code=status)

    @r.post("/api/rules/import-sigma")
    async def api_import_sigma(request: Request):
        """Sigma YAML (backwards compatible). body: {yaml, mode: preview|import}.
        mode=preview returns {ok, preview: <rule dict>}; mode=import creates the rule DISABLED.
        Unlike before, a duplicate import is rejected with 409 and `enabled` is ignored."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Body must be JSON", "ok": False}, status_code=400)
        import_mode = body.get("mode", "preview")
        if import_mode != "preview":
            status, payload = _import_core("sigma", text=body.get("yaml", "") or "",
                                           url=body.get("url", "") or "", commit=True)
            if "error" in payload:
                payload.setdefault("ok", False)
            if status == 422:  # legacy route answered unsupported rules with 400
                status = 400
            return JSONResponse(payload, status_code=status)
        if not (body.get("url") or (body.get("yaml") or "").strip()):
            return JSONResponse({"error": "Empty YAML", "ok": False}, status_code=400)
        status, payload = _import_core("sigma", text=body.get("yaml", "") or "",
                                       url=body.get("url", "") or "", commit=False)
        if status != 200:
            return JSONResponse(payload, status_code=status)
        if not payload["convertible"]:
            return JSONResponse({"error": payload["reason"], "ok": False}, status_code=400)
        # Legacy shape: the full converted rule dict (incl. source_content).
        text = body.get("yaml", "") or ""
        rule = _DETECT.sigma_to_rule(text, source_ref=payload["source_ref"]) if not body.get("url") else None
        return {"ok": True, "preview": rule or payload["rule"], "warnings": payload["warnings"]}

    return r
