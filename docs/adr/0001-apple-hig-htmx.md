# ADR 0001: Apple HIG Design System with Server-Rendered Templates

**Status:** accepted

**Date:** 2026-10-12

## Context

siempl needs a web interface that is:
1. Professional and trustworthy (security tools need to inspire confidence)
2. Easy for a future agent to modify and maintain (no JS build chain)
3. Fast to render and low-maintenance
4. Works without external CDN dependencies at runtime

We considered:
- **React/Vue SPA** — powerful but requires a build chain, npm dependencies, and
  a separate API layer. Hard for an AI agent to modify atomically.
- **Streamlit/Gradio** — quick to prototype but look unpolished and offer limited
  layout control.
- **Server-rendered HTML with HTMX** — no build step, one codebase to modify,
  all state lives on the server, HTMX provides AJAX interactivity without writing
  JavaScript.

## Decision

**Server-rendered Jinja2 templates with HTMX 2.0.4, styled with hand-written CSS
following Apple's Human Interface Guidelines.**

### Specific choices:

1. **Single CSS file** (`siempl/web/static/siempl.css`, ~23KB): No CSS framework
   (Tailwind, Bootstrap). Apple HIG design tokens implemented directly:
   - System font stack: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", system-ui`
   - SF-like type scale: 11/13/15/17/20/24/30px
   - 8pt spacing grid
   - Light + dark mode via `prefers-color-scheme` and manual toggle (`data-theme` attribute)
   - Translucent blurred sidebar (`backdrop-filter: saturate(180%) blur(24px)`)
   - Grouped inset list panels (10-14px radius, subtle borders/shadows)
   - iOS-style switches (44×26px, green when on)
   - Pill badges for severity
   - Segmented controls (CSS-only)
   - Confirmation sheets (modal overlays)
   - Server-rendered SVG charts (no JS chart library)

2. **HTMX vendored locally**: `htmx.min.js` (51KB) downloaded once from unpkg
   and committed to `siempl/web/static/`. No CDN at runtime — the app works
   entirely offline after install.

3. **Jinja2 templates** with a single base layout (`base.html`) and 13 content
   pages that extend it.

4. **No custom JS framework**: The only JavaScript is inline event handlers
   (theme toggle, KQL editor shortcuts, API calls via `fetch`). Total JS is
   under 100 lines spread across templates, plus HTMX itself.

### Consequences

**Positive:**
- Zero build step; modify CSS/HTML and reload
- An AI agent can make atomic edits to any template
- Works offline (no CDN)
- Fast initial render (server-side, no client hydration)
- Professional Apple-like appearance

**Negative:**
- No interactive charts (static SVG only)
- No real-time updates without page refresh (WebSocket planned)
- Dark mode toggle resets on page navigation (localStorage synced but flash
  possible)
- Apple HIG CSS is ~23KB of hand-maintained code

## Alternatives Considered

| Approach | Rejected Because |
|----------|-----------------|
| Tailwind CSS | Requires build step; class bloat makes templates hard to read for agents |
| Bootstrap | Visual style doesn't match security tool aesthetic; heavy JS dependency |
| React + Vite | Build chain, JSX transformation, agent-unfriendly multi-file editing |
| Streamlit | Python-native but limited layout control; not suitable for a professional security tool |
| htmx from CDN | Offline breakage; violates "no CDN at runtime" requirement |