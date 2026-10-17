# siempl UI

Engineering design doc for the siempl web interface.

## Purpose

A FastAPI + Jinja2 + HTMX web application providing a professional Apple HIG-inspired
interface to the siempl agentic SIEM. Server-rendered pages with progressive enhancement
via HTMX for interactive features (KQL editor, alerts triage, settings toggles).

## Architecture & Data Flow

```
Browser                          FastAPI (uvicorn)
  │                                    │
  ├─ GET / ──────────────────────────►│  siempl/web/routes.py
  │  ◄── HTML (Jinja2 template) ──────│    └─ queries db, renders overview.html
  │                                    │
  ├─ POST /api/query ────────────────►│
  │  ◄── JSON {columns, rows} ────────│    └─ calls siempl.kql.run_kql(db, ...)
  │                                    │
  ├─ POST /api/alerts/{id}/verdict ──►│
  │  ◄── JSON {ok: true} ─────────────│    └─ db.execute(UPDATE...) + EntityStore.apply_verdict
  │                                    │
  └─ /static/siempl.css ◄─────────────│  StaticFiles mount
     /static/htmx.min.js ◄────────────│
```

All pages are rendered server-side; HTMX handles form submissions, AJAX calls,
and partial updates without a SPA framework.

## Module Structure

```
siempl/web/
  __init__.py       create_app(db) -> FastAPI; mounts /static, /api/ingest collector
  routes.py         build_router(db) -> APIRouter: pages + /api/* JSON endpoints
  routes_*.py       feature routers, auto-mounted BEFORE routes.py (alerts page/detail/api, overview,
                    rules, sources, logs, settings key, agent panel); underscore modules hold helpers
                    (_svg_charts, _overview_data, _ingestion_overview, _logs_query/_logs_export, ...)
  templates/        Jinja2 templates extending base.html
  static/
    siempl.css       black & white theme + traffic-light status colors (hand-written CSS)
    htmx.min.js      HTMX 2.0.4 (vendored locally; no CDN at runtime)
    alerts*.js       alerts list, inline edits, preview drawer, detail page
    agent_panel.js   shared agent panel (mounted on alerts drawer/detail, rule, ingestion, logs)
    attention.js     red nav dots (poll /api/agent-attention every 30s) and the Agents-page queue
```

## Public API (as implemented)

### Pages (HTML)
| Path | Template | Description |
|------|----------|-------------|
| `/` | overview.html | One-screen dashboard (1440x900, no page scroll). `?range=1h\|24h\|7d`. KPI strip (events, open alerts, alerts opened, agent runs + failures, pending approvals, AI spend vs cap), events over time, open alerts by severity (pie), alerts over time stacked by severity, events by table, recent agent runs, top rules, top entities, source health. Data: `_overview_data.py`, route: `routes_overview.py` |
| `/logs` | logs.html | KQL editor, schema browser, results table, query history. Real server errors shown in the page; time range inserted after the leading table; server-side CSV/JSON export (full result, 100k row cap); bar/pie chart and pivot/group-by tool on the results ("Run as KQL" for the full data); collapsible log-alert agent panel |
| `/alerts` | alerts.html | Alerts and incidents are ONE object now. Open-alerts-by-severity pie, status bars, list with #alert_number, inline status/severity selectors, bulk actions, filters (severity, status, title, rule), pagination, click-row side preview with the triage agent panel. Statuses: new, active, closed_tp, closed_fp (open = new + active). `?rule=<id>`, `?preview=<id>` |
| `/alerts/{id}` | alert_detail.html | Full page: #number, severity/status selectors, owner, evidence, entities, MITRE, rule link, comments, audit history, triage agent panel |
| `/incidents`, `/incidents/{id}` | (redirect) | 307 to `/alerts`; the incidents table is kept as legacy data only |
| `/rules` | rules.html | Rule list (no Format/Origin columns) with Alerts and Open counts linking to `/alerts?rule=` |
| `/rules/{id}` | rule_detail.html | Rule detail/edit with KQL editor, test run, alerts-from-this-rule panel, tuning/discovery agent panel |
| `/entities` | entities.html | Filterable entity list with reputation bars |
| `/entities/{id}` | entity_detail.html | Entity detail with alerts, related graph (SVG), notes |
| `/ingestion` | ingestion.html | Overview graphs on top (events per bucket line chart, events by table, tiles; `?range=1h\|24h\|7d`), sources, filters, retention, recommendations, onboarding/optimizer agent panel |
| `/agents` | agents.html | "Needs your attention" queue (pending agent approvals across portals), run history, run buttons, recommendations |
| `/settings` | settings.html | AI master switch, cost caps, dry-run toggle, policy matrix |

### JSON API
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/query` | Run KQL query, returns columns/rows/elapsed_ms (errors return the exact message) |
| POST | `/api/export` | Re-run the query server-side and download the FULL result as CSV/JSON (100k row cap, `time_range` field) |
| GET | `/api/agent-panel/{scope}/{id}` | Agent panel state: scope alert\|rule\|source\|logs (policy, last run, running, pending recommendations with allowed/blocked_reason, injection findings) |
| POST | `/api/agent-panel/{scope}/{id}/run` | Run the agent for that target (400 disabled/off, 404 unknown, 409 already running) |
| POST | `/api/agent-panel/recommendations/{id}/approve\|reject` | Policy-matrix gated (403 with blocked_reason) |
| GET | `/api/agent-attention` | Pending agent tasks per portal (feeds the red nav dots; never counts new alerts) |
| POST/DELETE | `/api/settings/key`, `/api/settings/key/test` | OpenRouter key: save/remove/test. Key lives only in the 0600 key file, never in the DB or HTML |
| POST | `/api/rules/{id}/test-run` | Test-run a rule query |
| PUT | `/api/rules/{id}` | Update rule fields |
| PUT | `/api/rules/{id}/toggle` | Toggle rule enabled |
| POST | `/api/alerts/{id}/status` | Set status: new, active, closed_tp, closed_fp (audited; closing applies entity reputation once) |
| POST | `/api/alerts/{id}/severity` | Set severity (critical..informational, audited) |
| POST | `/api/alerts/{id}/owner` | Set owner (audited) |
| GET | `/api/alerts/{id}/preview` | JSON for the side preview (fields, rule, entities, 5 evidence rows, comments, MITRE) |
| GET | `/api/alerts/summary` | open_by_severity, by_status, open_total |
| POST | `/api/alerts/{id}/verdict` | Compat shim: true_positive -> closed_tp, false_positive/benign -> closed_fp, escalate -> active |
| POST | `/api/alerts/{id}/comment` | Add comment to alert |
| PUT | `/api/entities/{id}/watch` | Toggle entity watch |
| POST | `/api/entities/{id}/notes` | Update entity notes |
| POST | `/api/recommendations/{id}/approve` | Approve recommendation (applies filter/retention) |
| POST | `/api/recommendations/{id}/dismiss` | Dismiss recommendation |
| POST | `/api/settings` | Update settings (ai_enabled, caps, toggles) |
| POST | `/api/settings/policy` | Upsert agent policy row |
| POST | `/api/agents/{name}/run` | Trigger agent run |
| POST | `/api/ingestion/retention` | Update table retention |
| GET | `/health` | Health check with module availability |

### Feature Detection

All optional modules are detected at import time via try/except:
`siempl.kql`, `siempl.detect`, `siempl.entities`, `siempl.ingest`,
`siempl.collectors`, `siempl.agents.*`.

When a module is absent, pages render a "not available yet" empty state
instead of 500 errors. The KQL editor and query API return 503 when
the KQL module is not present.

### Conditional Collector Mount

When `siempl.collectors.make_ingest_router(db)` is available, it is mounted
at `/api/ingest/{source_id}` automatically in `create_app()`.

## Design System

### Typography
- System font stack: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", system-ui`
- Monospace: `"SF Mono", "JetBrains Mono", "Fira Code", monospace`
- SF-like type scale: 11/13/15/17/20/24/30px

### Colors
Black & white chrome; the only color is traffic-light status color.
- **Dark (default, white on black):** #000 bg, #0A0A0A cards, #FFF text, #FFF accent (buttons are white with black text)
- **Light:** #FFF bg, #000 text, #000 accent
- **Status colors (both modes):** pure red #FF0000, yellow #FFFF00, green #00FF00. Used for severity badges, charts, status pills, switches and attention dots (`--sev-*`, `--color-sev-*`, `--chart-*`).
  low = green, medium = yellow, high = red, critical = dark maroon #590016 (rgb 89,0,22, user-specified; used for the badge and chart fill; inline severity text stays red because maroon is unreadable on black). Critical is a solid maroon badge with bold white text; high is an outlined red badge, and in charts high is red mixed 40% toward the background, so the two stay distinguishable.
- `--color-green` / `--color-yellow` are *text* tokens: pure in dark, darkened (#008A00 / #8F7A00) in light so they stay readable on white.
- Theme: `data-theme=dark|light` on the html element, set by the toggle and stored in localStorage key siempl-theme. Default is always dark; the OS prefers-color-scheme is deliberately ignored. color-scheme is set per theme so native scrollbars and form controls follow.
- No theme flash: a tiny inline script in the head sets data-theme from localStorage before the stylesheet loads, and an inline html background rule (black; white under data-theme=light) covers the moments before siempl.css arrives. Keep that script above the stylesheet link.

### Components
- **Sidebar**: 220px, translucent with backdrop-filter blur, sticky
- **Panels**: White card, 14px radius, subtle border/shadow
- **Tables**: Clean, sortable columns, hover highlight
- **Badges**: Pill-shaped severity indicators
- **Switches**: iOS-style toggle (44×26px, green when on)
- **Segmented controls**: CSS-only button groups
- **Sheets**: Modal overlay for AI enable confirmation
- **Reputation bars**: Inline horizontal bar with label overlay

### Icons
Hand-drawn SVG icons (16 icons), consistent 24×24 viewBox, 1.5px strokes.

Brand logo: `static/logo.svg` (traced from the supplied icon, `fill=currentColor`), rendered in the sidebar as a CSS mask on `.sidebar-logo` so it follows the theme color. The viewBox is the path bounding box plus an equal 150-unit pad on every side (measured: 55px margin on all four sides at 1000px wide). Tab icon: `static/favicon.svg` (square, centered, flips black/white with the browser color scheme) and `static/favicon-180.png` (white on black; PNG fallback and apple-touch-icon), linked from `base.html`.

## Extension Points

- New pages: add route in `build_router()`, create template in `templates/`
- New API: add route in `build_router()`, returns JSONResponse
- New feature module: add try/except block at top of routes.py, gate pages/templates
- Custom CSS: add to `siempl/web/static/siempl.css` (single file, no build step)

## Known Limitations

1. Charts use server-rendered inline SVG; no interactive zoom/pan
2. No pagination on list pages (hard limit of 200 rows)
3. Agent runs are synchronous in the request thread (background async planned)
4. Rule import-from-web panel is a placeholder
5. No real-time updates (polling needed for live dashboards; WebSocket support TBD)
6. Theme toggle is manual-only; the default is dark and the OS color-scheme preference is ignored

## How to Test

```bash
# Run the test suite
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_web.py -q

# Start the dev server with demo data
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m siempl --no-collectors --no-scheduler
# Open http://127.0.0.1:8765
```

## Rules import (single dialog)

The Rules page has one **Import rule** dialog (`/rules?import=1` opens it directly; the rule form links there).

- Format: Sigma YAML, Microsoft Sentinel YAML, or KQL / plain query.
- Source: paste, or a URL (github.com file view or raw.githubusercontent.com, .yml/.yaml, https, 1 MB cap).
- Preview shows name, severity, tables, the generated query (read-only), convertibility with the clear reason
  when not, warnings (no description, no triage steps, Sentinel mapping), and duplicates.
- "Import (disabled)" is enabled only for a convertible, non-duplicate preview. Imports are created disabled.

API (all JSON; see routes_rules.py): `POST /api/rules/import-preview {format, yaml|url, name?, preview}`
(preview=false creates), `POST /api/rules/import-sentinel {yaml|url, preview}`, and the legacy
`POST /api/rules/import-sigma {yaml, mode}`.

Rules list: a Format badge (Sigma-imported / Sentinel / KQL manual / AI / Built-in) and an "Imported, disabled"
filter (`?imported=disabled`). Rule detail: executable query, generated SQL if present, and the original
source in a collapsible block.

## TODOs

- [ ] Add WebSocket endpoint for live alert/ingestion updates
- [ ] Add pagination to list APIs
- [ ] Async agent execution via background tasks
- [ ] Full rule import-from-web integration with RuleDiscoveryAgent
- [ ] Interactive chart zoom/pan with minimal JS
- [ ] Responsive mobile layout improvements
- [ ] Accessibility audit (ARIA labels, focus management)