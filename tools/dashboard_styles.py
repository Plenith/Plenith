"""Plenith SOC dashboard — consolidated stylesheet.

Single source of truth for the design tokens + component styles, used by
both the main dashboard and every popped-out panel.  Lifted from the
prototypes at `docs/design/dashboard-prototype*.html` (Phase 1 of
docs/design/UI_WIRING.md) and deduplicated.

Why a separate file:
  - `tools/dashboard.py` would otherwise be 2000+ lines.  Splitting CSS
    into a Python string constant keeps each file single-purpose and
    independently reviewable.
  - Keeps the "no build step, no extra deps, single docker compose
    runs everything" pitch — the only cost is one extra Python import.
  - Tests can patch one file without touching the others.

Theme model:
  - Dark is default.  Light is opt-in via `body.light` (CSS variable
    overrides).
  - Auto-detection uses `prefers-color-scheme`; manual override
    persists in `localStorage`.
  - All severity / accent colors are CSS variables, so themes flip in
    one place.
"""
from __future__ import annotations

CSS = r"""
/* ==========================================================================
   Design tokens
   --------------------------------------------------------------------------
   Dark mode is the default; .light overrides at the end.  Severity colors
   are tuned per theme so contrast stays right on each surface family.
   ========================================================================== */

:root {
  /* Neutrals + brand unified with the Plenith website (dark/terminal
     identity). Severity ramp below is deliberately left high-contrast
     and semantic — the brand recolors the chrome, not the alarms. */
  --bg:         #14181a;   /* website --term-bg */
  --surface:    #1c2024;   /* website dark --surface */
  --surface-2:  #232a2d;
  --surface-3:  #2c343a;
  --border:     #2a2e32;   /* website dark --border */
  --border-2:   #21262a;

  --fg:         #e8e5dd;   /* website --ink */
  --fg-2:       #a7a39a;   /* website --ink-muted */
  --fg-3:       #8aa092;   /* website --term-muted */
  --fg-4:       #5a6a62;   /* website --term-dim */

  --brand:      #87b69d;   /* website dark --accent */
  --brand-dim:  #4d7d65;
  --brand-rgb:  135, 182, 157;

  --sev-critical: #ef4444;
  --sev-high:     #f97316;
  --sev-medium:   #eab308;
  --sev-low:      #3b82f6;
  --sev-info:     #71717a;
  --sev-ok:       #10b981;

  --conf-low:   #3b82f6;
  --conf-mid:   #eab308;
  --conf-high:  #ef4444;

  --tint-crit: rgba(239, 68, 68, 0.18);
  --tint-high: rgba(249, 115, 22, 0.18);
  --tint-med:  rgba(234, 179, 8, 0.18);
  --tint-info: rgba(113, 113, 122, 0.18);
  --tint-cmd-alert: rgba(239, 68, 68, 0.06);

  --shadow-card: 0 1px 3px rgba(0, 0, 0, 0.4);

  --pad: 14px;
  --gap: 14px;
  --radius: 6px;

  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --mono: "JetBrains Mono", "Berkeley Mono", "SF Mono", ui-monospace,
          "Cascadia Mono", Consolas, monospace;
}

body.light {
  /* Light theme mapped to the website's cream/green identity. */
  --bg:         #f5f2ec;   /* website light --bg */
  --surface:    #ffffff;
  --surface-2:  #efebe2;
  --surface-3:  #e3ddd1;
  --border:     #d6d0c4;   /* website light --border */
  --border-2:   #e3ddd1;

  --fg:         #1c1b1a;   /* website --ink */
  --fg-2:       #5c5957;
  --fg-3:       #8a857d;
  --fg-4:       #a59f95;

  --brand:      #2c4d3f;   /* website light --accent */
  --brand-dim:  #3d6753;
  --brand-rgb:  44, 77, 63;

  --sev-critical: #dc2626;
  --sev-high:     #ea580c;
  --sev-medium:   #ca8a04;
  --sev-low:      #2563eb;
  --sev-ok:       #059669;

  --conf-low:   #2563eb;
  --conf-mid:   #ca8a04;
  --conf-high:  #dc2626;

  --tint-crit: rgba(220, 38, 38, 0.10);
  --tint-high: rgba(234, 88, 12, 0.10);
  --tint-med:  rgba(202, 138, 4, 0.10);
  --tint-info: rgba(113, 113, 122, 0.10);
  --tint-cmd-alert: rgba(220, 38, 38, 0.05);

  --shadow-card: 0 1px 2px rgba(0, 0, 0, 0.04),
                 0 2px 8px rgba(0, 0, 0, 0.04);
}

/* ==========================================================================
   Base
   ========================================================================== */

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--fg);
  font-family: var(--sans);
  font-size: 13px;
  line-height: 1.4;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  transition: background 0.15s ease, color 0.15s ease;
}
.mono { font-family: var(--mono); }
.dim  { color: var(--fg-3); }
.dim2 { color: var(--fg-4); }
.num  { font-family: var(--mono); font-variant-numeric: tabular-nums; }

/* TV mode (wall display) */
body.tv .top, body.tv .ref-bar, body.tv .footer, body.tv .chrome { display: none; }
body.tv { font-size: 16px; }
body.tv .kpi-value, body.tv .gauge-val { font-size: 1.4em; }

/* ==========================================================================
   Top strip (main dashboard)
   ========================================================================== */

.top {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 18px;
  background: linear-gradient(180deg, var(--surface) 0%, var(--bg) 100%);
  border-bottom: 1px solid var(--border);
}
.brand {
  display: flex; align-items: center; gap: 12px;
  font-family: var(--mono);
}
.brand-mark {
  width: 22px; height: 22px;
  color: var(--brand);
}
.brand-name {
  font-weight: 600; letter-spacing: 0.1em; font-size: 13px;
}
.brand-sep { color: var(--fg-4); margin: 0 6px; }
.brand-meta { color: var(--fg-2); font-size: 12px; }
.brand-meta b { color: var(--fg); font-weight: 500; }

.top-actions {
  display: flex; gap: 6px;
  margin-left: 18px;
}
.top-action {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 4px 10px;
  border-radius: 4px;
  background: var(--surface);
  border: 1px solid var(--border-2);
  color: var(--fg-2);
  font-family: var(--mono);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.1s ease;
  user-select: none;
  /* Strip <button> default chrome — these are visually chips. */
  text-align: center;
  line-height: inherit;
  -webkit-appearance: none; appearance: none;
}
.top-action:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
.top-action:hover {
  background: var(--surface-2);
  color: var(--fg);
  border-color: var(--border);
}
.top-action.active {
  background: rgba(var(--brand-rgb), 0.10);
  border-color: var(--brand-dim);
  color: var(--brand);
}
body.light .top-action.active {
  background: rgba(var(--brand-rgb), 0.08);
}
.top-action .ico { font-size: 13px; line-height: 1; }
.top-action .badge {
  background: var(--sev-critical);
  color: white;
  font-size: 9px; font-weight: 600;
  padding: 0 4px; border-radius: 2px;
  margin-left: 2px;
}

.top-right {
  display: flex; align-items: center; gap: 18px;
  font-family: var(--mono); font-size: 12px;
}
.pulse-dot {
  display: inline-block; width: 6px; height: 6px; border-radius: 50%;
  background: var(--sev-ok);
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.6);
  animation: pulse 2s infinite;
  margin-right: 6px;
}
@keyframes pulse {
  0%   { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.6); }
  70%  { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
  100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* ==========================================================================
   KPI strip
   ========================================================================== */

.kpis {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: var(--gap);
  padding: var(--gap) 18px;
}
.kpi {
  background: var(--surface);
  border: 1px solid var(--border-2);
  border-radius: var(--radius);
  padding: 12px 14px;
  display: flex; flex-direction: column; gap: 4px;
  position: relative;
  box-shadow: var(--shadow-card);
}
.kpi-label {
  font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--fg-3);
  font-weight: 500;
}
.kpi-value {
  font-family: var(--mono); font-size: 22px; font-weight: 500;
  color: var(--fg);
  line-height: 1.1;
  display: flex; align-items: baseline; gap: 6px;
}
.kpi-delta {
  font-size: 11px; font-family: var(--mono);
  color: var(--fg-3);
}
.kpi-delta.up    { color: var(--sev-ok); }
.kpi-delta.down  { color: var(--sev-high); }
.kpi-delta.warn  { color: var(--sev-medium); }
.kpi-spark {
  height: 22px; position: absolute;
  right: 14px; bottom: 10px;
  width: 80px;
  opacity: 0.85;
}

/* ==========================================================================
   Main grid (engagement list + detail)
   ========================================================================== */

.main {
  display: grid;
  grid-template-columns: 1fr 480px;
  gap: var(--gap);
  padding: 0 18px var(--gap);
}
.panel {
  background: var(--surface);
  border: 1px solid var(--border-2);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow-card);
}
.panel-header {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-2);
  display: flex; align-items: center; justify-content: space-between;
  font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--fg-3);
  font-weight: 500;
}
.panel-header .count {
  font-family: var(--mono); color: var(--fg);
  background: var(--surface-2);
  padding: 2px 7px; border-radius: 3px;
  font-size: 11px; letter-spacing: 0;
}
.panel-header .actions {
  display: flex; gap: 12px; align-items: center;
}
.panel-header .filter {
  color: var(--fg-2); cursor: pointer; font-size: 11px;
  /* When rendered as <button data-filter-chip>, strip default chrome
     so the chip looks identical to the legacy <span> rendering used by
     anchor links in the export strip. */
  background: transparent;
  border: none;
  padding: 0;
  font-family: inherit;
  line-height: inherit;
  -webkit-appearance: none; appearance: none;
}
.panel-header .filter.active { color: var(--brand); }
.panel-header .filter:hover  { color: var(--fg); }
.panel-header .filter:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
  border-radius: 2px;
}

/* ---- Adjustable panels: column resize + collapse --------------------
   Client-injected, persisted in localStorage, re-applied after every
   SSE swap (see the resize/collapse module in dashboard_scripts.py). */
.panel { position: relative; }

/* Resize gripper — sits on a panel's right edge; drags the row's
   grid-template-columns.  Only injected on non-last panels in a row. */
.panel-resize {
  position: absolute; top: 0; right: -5px; width: 10px; height: 100%;
  z-index: 6; cursor: col-resize; touch-action: none;
  display: flex; align-items: center; justify-content: center;
}
.panel-resize::before {
  content: ""; width: 2px; height: 28px; border-radius: 2px;
  background: var(--border); transition: background 0.12s ease, height 0.12s ease;
}
.panel-resize:hover::before,
.panel-resize:focus-visible::before { background: var(--brand); height: 44px; }
.panel-resize:focus-visible { outline: none; }
.panel.resizing { user-select: none; }
.panel.resizing .panel-resize::before { background: var(--brand); height: 100%; }

/* Collapse toggle — injected into each .panel-header's actions. */
.panel-collapse {
  background: transparent; border: 1px solid var(--border-2);
  color: var(--fg-3); cursor: pointer; font-size: 11px; line-height: 1;
  padding: 2px 6px; border-radius: 3px;
  display: inline-flex; align-items: center; justify-content: center;
  transition: color 0.12s ease, border-color 0.12s ease;
}
.panel-collapse:hover { color: var(--fg); border-color: var(--border); }
.panel-collapse:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
.panel.panel-collapsed > *:not(.panel-header) { display: none !important; }
/* Same width as before collapse, but height shrinks to just the header
   instead of stretching to the grid row's height — so a collapsed
   panel reads as a slim title bar, not a tall empty box. */
.panel.panel-collapsed { box-shadow: none; align-self: start; }
.panel.panel-collapsed .panel-resize { display: none; }
/* Collapse = hide the body only.  The panel keeps its full grid-track
   width (the width it had at the time of collapse); the header — incl.
   its toolbar/filters/exports — stays intact, the panel just becomes
   header-height. */
.panel-collapse { margin-left: 8px; flex: 0 0 auto; }

/* Touch / narrow screens: dragging a 2px edge is impractical and the
   rows reflow anyway — hide the grippers (collapse stays usable). */
@media (max-width: 760px) {
  .panel-resize { display: none; }
}
@media (prefers-reduced-motion: reduce) {
  .panel-resize::before, .panel-collapse { transition: none; }
}

/* Alert-rate toolbar buttons need real click targets — the default
   .filter is a zero-padding text link, fine for the export strip but
   way too small for a tab strip the operator picks ranges from.
   The DNS + Activity toolbars use the same affordance. */
[data-alert-rate-toolbar] .filter,
[data-dns-toolbar]        .filter,
[data-activity-toolbar]   .filter {
  padding: 3px 8px;
  border: 1px solid transparent;
  border-radius: 3px;
  min-width: 28px;
  text-align: center;
}
[data-alert-rate-toolbar] .filter:hover,
[data-dns-toolbar]        .filter:hover,
[data-activity-toolbar]   .filter:hover {
  background: var(--surface-2);
  border-color: var(--border-2);
}
[data-alert-rate-toolbar] .filter.active,
[data-dns-toolbar]        .filter.active,
[data-activity-toolbar]   .filter.active {
  background: color-mix(in srgb, var(--brand) 14%, transparent);
  border-color: var(--brand-dim);
}
[data-alert-rate-toolbar] .filter.active:hover,
[data-dns-toolbar]        .filter.active:hover,
[data-activity-toolbar]   .filter.active:hover {
  background: color-mix(in srgb, var(--brand) 20%, transparent);
}

/* =========================================================================
   /panel/activity popout — summary tiles + heatmap + cell-drill modal.
   ========================================================================= */
.activity-popout-wrap { padding: 12px 16px 16px; }
.activity-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 10px;
}
.activity-stat {
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 8px 12px;
}
.activity-stat-v {
  font-size: 18px; font-weight: 500;
  color: var(--fg); line-height: 1;
}
.activity-stat-v.mono { font-family: var(--mono); font-size: 14px; }
.activity-stat-l {
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--fg-3);
  margin-top: 6px;
}
.activity-hint {
  font-size: 10px;
  margin: 4px 0 8px;
  letter-spacing: 0.04em;
}
[data-heatmap-cell] { cursor: pointer; }
[data-heatmap-cell]:hover {
  outline: 1px solid var(--brand);
  outline-offset: -1px;
}
.activity-cell-body { padding: 8px 0; }
.activity-cell-list {
  list-style: none; margin: 0; padding: 0;
}
.activity-cell-row {
  display: grid;
  grid-template-columns: 80px minmax(0, 1fr) 160px;
  gap: 12px;
  align-items: center;
  padding: 6px 14px;
  font-size: 11px;
  border-bottom: 1px solid var(--border-2);
}
.activity-cell-row:last-child { border-bottom: none; }
.activity-cell-row:hover { background: var(--surface-2); }
.activity-cell-eid { color: var(--fg-2); }
.activity-cell-who {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--fg);
}
.activity-cell-counts { text-align: right; }
@media (max-width: 700px) {
  .activity-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

/* =========================================================================
   /panel/dns-feed popout — KPI tiles, top blocked / top NXDOMAIN side
   lists, and the live feed below.
   ========================================================================= */
.dns-popout-wrap { padding: 12px 16px 16px; }
.dns-kpis {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}
.dns-kpi {
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 8px 12px;
}
.dns-kpi-v {
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 500;
  color: var(--fg);
  line-height: 1;
}
.dns-kpi-l {
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--fg-3);
  margin-top: 6px;
}
.dns-kpi.resolved .dns-kpi-v { color: var(--sev-info); }
.dns-kpi.blocked  .dns-kpi-v { color: var(--sev-critical); }
.dns-kpi.nxdomain .dns-kpi-v { color: var(--sev-medium); }
.dns-popout-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(220px, 320px);
  gap: 14px;
  align-items: start;
}
.dns-popout-feed { min-width: 0; }
.dns-popout-side {
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 6px 0 8px;
}
.dns-popout-side-head {
  padding: 6px 12px;
  font-size: 11px; font-weight: 600;
  border-bottom: 1px solid var(--border-2);
  margin-bottom: 4px;
}
.dns-top-list { list-style: none; margin: 0; padding: 0; }
.dns-top-row {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr) 32px;
  gap: 8px;
  align-items: center;
  padding: 4px 12px;
  font-size: 11px;
}
.dns-top-row:hover { background: var(--surface-2); }
.dns-top-host {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--fg);
  font-size: 11px;
}
.dns-top-count {
  text-align: right; color: var(--fg-2); font-size: 11px;
}
@media (max-width: 900px) {
  .dns-popout-grid { grid-template-columns: 1fr; }
  .dns-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

.icon-btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 22px; height: 22px;
  border-radius: 3px;
  color: var(--fg-3);
  cursor: pointer;
  transition: background 0.1s ease, color 0.1s ease;
  font-size: 14px;
  user-select: none;
}
.icon-btn:hover {
  background: var(--surface-2);
  color: var(--fg);
}
.icon-btn svg { width: 12px; height: 12px; }

/* ==========================================================================
   Engagement list (rows)
   ========================================================================== */

.engagements {
  display: flex;
  flex-direction: column;
  /* Container query root — .eng rows adapt to THIS width (the panel),
     not the viewport, so the row reshapes whenever the operator drags
     the Engagements panel into a narrower slot. */
  container-type: inline-size;
  container-name: engagements-list;
}
.eng {
  display: grid;
  grid-template-columns: 22px 6px 70px 1fr 110px 100px 96px 140px 90px;
  gap: 12px;
  padding: 10px 12px 10px 8px;
  border-bottom: 1px solid var(--border-2);
  align-items: center;
  cursor: pointer;
  transition: background 0.1s ease;
}
/* When the panel is in a narrower slot (e.g. dropped into the 3-column
   bottom row), drop low-priority columns progressively.  Dwell / commands
   / last-seen still surface in the detail panel and in the engagement
   popout, so hiding them in the row list is safe. */
@container engagements-list (max-width: 720px) {
  .eng {
    grid-template-columns: 22px 6px 70px minmax(120px, 1fr) 86px minmax(0, 1.4fr) 90px;
    gap: 10px;
  }
  .eng .eng-dwell, .eng .eng-cmds { display: none; }
}
@container engagements-list (max-width: 540px) {
  .eng {
    grid-template-columns: 22px 6px minmax(120px, 1fr) 70px minmax(0, 1.4fr);
    gap: 8px;
    padding: 8px 10px;
  }
  .eng .eng-id, .eng .eng-last { display: none; }
}
@container engagements-list (max-width: 380px) {
  .eng {
    grid-template-columns: 6px 1fr;
    gap: 8px;
  }
  .eng .eng-conf, .eng .pills, .eng .eng-check { display: none; }
}

/* Row-pulse animation — when an engagement gets a new command or alert
   between SSE swaps, briefly flash the row brand-color so the operator
   can see at a glance that this row "is alive right now" even though
   the row itself didn't move in the list. */
@keyframes eng-pulse-cmd {
  0%   { background: color-mix(in srgb, var(--brand) 18%, transparent); }
  100% { background: transparent; }
}
@keyframes eng-pulse-alert {
  0%, 20% {
    background: color-mix(in srgb, var(--sev-critical) 22%, transparent);
    box-shadow: inset 3px 0 0 var(--sev-critical);
  }
  100% { background: transparent; box-shadow: none; }
}
.eng.eng-pulse-cmd   { animation: eng-pulse-cmd   0.9s ease-out; }
.eng.eng-pulse-alert { animation: eng-pulse-alert 1.4s ease-out; }

/* Live event ticker — narrow strip above the engagement rows showing
   the last few alerts as they arrive.  Lets the operator see at a
   glance that real-time activity is flowing in even when the engagement
   list itself doesn't change row-count. */
.event-ticker {
  border-bottom: 1px solid var(--border-2);
  background: var(--surface-2);
  padding: 6px 12px 8px;
  font-size: 11px;
}
.event-ticker-head {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 4px;
}
.event-ticker-title {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  color: var(--fg-3);
}
.event-ticker-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--sev-critical);
  animation: ticker-pulse 1.4s ease-in-out infinite;
}
@keyframes ticker-pulse {
  0%, 100% { opacity: 0.35; transform: scale(1); }
  50%      { opacity: 1.00; transform: scale(1.25); }
}
.event-ticker-list {
  display: flex; flex-direction: column; gap: 1px;
  max-height: 110px;
  overflow: hidden;
}
.event-ticker-row {
  display: grid;
  grid-template-columns: 64px 38px minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  padding: 2px 0;
  font-family: var(--mono);
  font-size: 10.5px;
  line-height: 1.4;
  border-radius: 2px;
  transition: background 600ms ease-out;
}
.event-ticker-row.event-ticker-fresh {
  background: color-mix(in srgb, var(--brand) 18%, transparent);
}
.event-ticker-ts { color: var(--fg-4); }
.event-ticker-who {
  color: var(--fg-2);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.event-ticker-action {
  color: var(--fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  text-align: right;
}
.event-ticker-empty {
  font-size: 10px; padding: 4px 0;
}

/* Multi-select checkbox at the start of each engagement row.  Click to
   toggle; JS persists selected ids in sessionStorage and shows a batch
   action bar above the list when ≥1 row is checked. */
.eng-check {
  width: 16px; height: 16px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: transparent;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-family: var(--mono); font-size: 11px; line-height: 1;
  color: transparent;
  transition: background 80ms ease, color 80ms ease, border-color 80ms ease;
  user-select: none;
}
.eng:hover .eng-check { border-color: var(--brand-dim); }
.eng-check.on {
  background: var(--brand);
  border-color: var(--brand);
  color: #1a1106;
  font-weight: 700;
}
body.light .eng-check.on { color: white; }

/* Batch action bar — appears between the search bar and the row list
   whenever the multi-select set is non-empty. */
.batch-bar {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--border-2);
  background: var(--surface-2);
  font-size: 12px;
}
.batch-bar .batch-count {
  font-family: var(--mono); font-weight: 600; color: var(--brand);
}
.batch-bar button {
  background: transparent;
  color: var(--fg-2);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 3px 9px;
  font-family: var(--mono); font-size: 11px;
  cursor: pointer;
  transition: background 80ms ease, color 80ms ease, border-color 80ms ease;
}
.batch-bar button:hover {
  background: var(--surface-2);
  color: var(--fg);
  border-color: var(--brand-dim);
}
.batch-bar button:disabled { opacity: 0.45; cursor: wait; }
.batch-bar .batch-spacer { flex: 1; }
.batch-bar .batch-clear {
  color: var(--fg-3);
  border-color: transparent;
}
.eng:hover { background: var(--surface-2); }
.eng.selected { background: var(--surface-3); }
.eng-sev-bar {
  width: 3px; height: 36px; border-radius: 2px;
  background: var(--sev-info);
}
.eng.critical .eng-sev-bar { background: var(--sev-critical); }
.eng.high     .eng-sev-bar { background: var(--sev-high); }
.eng.medium   .eng-sev-bar { background: var(--sev-medium); }
.eng.low      .eng-sev-bar { background: var(--sev-low); }
.eng.proven   .eng-sev-bar { background: var(--sev-critical); box-shadow: 0 0 8px var(--sev-critical); }
.eng-id   { font-family: var(--mono); font-size: 12px; color: var(--fg-2); }
.eng-who  { display: flex; flex-direction: column; overflow: hidden; }
.eng-who .who {
  font-family: var(--mono); font-size: 13px;
  color: var(--fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.eng-who .host {
  font-family: var(--mono); font-size: 11px;
  color: var(--fg-4);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.eng-dwell, .eng-cmds, .eng-conf, .eng-alerts, .eng-last {
  font-family: var(--mono); font-size: 12px;
  color: var(--fg-2);
}
.eng-dwell .big, .eng-cmds .big { color: var(--fg); font-size: 13px; }
.eng-conf-bar {
  width: 100%; height: 6px;
  background: var(--surface-2);
  border-radius: 3px;
  position: relative;
  margin-top: 2px;
}
.eng-conf-bar .fill {
  position: absolute; left: 0; top: 0; bottom: 0;
  border-radius: 3px;
}
.eng-conf-value { font-size: 11px; color: var(--fg-3); display: block; }

/* Pills */
.pills {
  display: flex;
  flex-wrap: wrap;
  gap: 3px;
  /* Cell may be narrower than a single pill once the panel is dragged
     to a compact slot — clip the row instead of letting pills bleed
     into the next cell, and let each pill ellipsis its own text. */
  overflow: hidden;
  min-width: 0;
}
.pill {
  display: inline-block;
  max-width: 100%;
  padding: 1px 5px;
  border-radius: 2px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 500;
  line-height: 14px;
  letter-spacing: 0.02em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  box-sizing: border-box;
}
.pill.crit { background: var(--tint-crit); color: #fca5a5; }
.pill.high { background: var(--tint-high); color: #fdba74; }
.pill.med  { background: var(--tint-med);  color: #fcd34d; }
.pill.info { background: var(--tint-info); color: #d4d4d8; }
.pill.proven {
  background: var(--sev-critical); color: white;
  box-shadow: 0 0 6px rgba(239, 68, 68, 0.5);
}
body.light .pill.crit { color: var(--sev-critical); }
body.light .pill.high { color: var(--sev-high); }
body.light .pill.med  { color: var(--sev-medium); }
body.light .pill.info { color: var(--fg-2); }

.eng-last .ago { color: var(--fg-2); }
.eng-last .ts  { color: var(--fg-4); font-size: 11px; display: block; }

/* ==========================================================================
   Engagement detail (in-page right panel + popout)
   ========================================================================== */

.detail-header { padding: 14px; border-bottom: 1px solid var(--border-2); }
.detail-id {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 6px;
}
.detail-id .badge-sev {
  padding: 2px 6px; border-radius: 3px;
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  letter-spacing: 0.05em;
}
.detail-id .badge-sev.crit { background: var(--sev-critical); color: white; }
.detail-id .badge-sev.high { background: var(--sev-high); color: white; }
.detail-id .badge-sev.med  { background: var(--sev-medium); color: white; }
.detail-id .eid {
  font-family: var(--mono); font-size: 14px;
  color: var(--fg);
}
.detail-meta {
  display: grid; grid-template-columns: auto 1fr; gap: 4px 14px;
  font-size: 12px;
  margin-top: 6px;
}
.detail-meta .k {
  color: var(--fg-3);
  font-size: 11px; letter-spacing: 0.04em; text-transform: uppercase;
}
.detail-meta .v {
  color: var(--fg); font-family: var(--mono);
}

/* Counter-AI gauge */
.gauge-wrap {
  display: grid; grid-template-columns: 110px 1fr;
  gap: 14px;
  padding: 14px;
  border-bottom: 1px solid var(--border-2);
}
.gauge { position: relative; width: 110px; height: 110px; }
.gauge svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.gauge-center {
  position: absolute; inset: 0;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  font-family: var(--mono);
}
.gauge-val {
  font-size: 24px; font-weight: 500; color: var(--fg);
  line-height: 1;
}
.gauge-label {
  font-size: 9px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--fg-3); margin-top: 4px;
}
.gauge-trend {
  font-size: 9px;
  letter-spacing: 0.04em;
  color: var(--fg-3);
  margin-top: 4px;
  font-family: var(--mono);
  white-space: nowrap;
  min-height: 11px;
}
.gauge-trend .up   { color: var(--sev-critical); font-weight: 600; }
.gauge-trend .down { color: var(--sev-info);     font-weight: 600; }
.gauge-trend-server {
  display: flex; flex-direction: column; align-items: center; gap: 2px;
}

/* Proof-by-trap banner — surfaces above the counter-AI gauge when the
   attacker has echoed our planted trap marker back at us.  That's
   irrefutable evidence the attacker is consuming planted content. */
.proof-banner {
  margin: 10px 14px 6px;
  padding: 10px 14px;
  background: color-mix(in srgb, var(--sev-critical) 14%, transparent);
  border: 1px solid var(--sev-critical);
  border-left: 4px solid var(--sev-critical);
  border-radius: 4px;
  animation: proof-banner-pulse 2.4s ease-in-out 0s 2;
}
@keyframes proof-banner-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.0); }
  50%      { box-shadow: 0 0 0 6px rgba(239, 68, 68, 0.18); }
}
.proof-head {
  display: flex; align-items: center; gap: 10px;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  color: var(--sev-critical);
  letter-spacing: 0.04em;
}
.proof-icon { font-size: 18px; }
.proof-title { flex: 1; }
.proof-ts { font-weight: 400; font-size: 10px; }
.proof-body { margin-top: 8px; }
.proof-cmd {
  margin: 6px 0 0;
  padding: 8px 10px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--fg);
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

/* "Files modified" section — list of attacker-tampered VFS paths with
   per-row size delta vs the planted baseline.  Click → file-diff modal. */
.file-mod-list { list-style: none; margin: 0; padding: 0; }
.file-mod-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 110px 100px 70px;
  gap: 10px;
  align-items: center;
  padding: 6px 14px;
  font-family: var(--mono);
  font-size: 11px;
  border-bottom: 1px solid var(--border-2);
  cursor: pointer;
  transition: background 80ms ease;
}
.file-mod-row:last-child { border-bottom: none; }
.file-mod-row:hover { background: var(--surface-2); }
.file-mod-row.deleted .file-mod-path {
  text-decoration: line-through;
  color: var(--fg-3);
}
.file-mod-path {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--fg);
}
.file-mod-base { font-size: 10.5px; }
.file-mod-cur  { color: var(--fg-2); }
.file-mod-delta { text-align: right; font-weight: 600; }
.file-mod-delta.delta-up   { color: var(--sev-critical); }
.file-mod-delta.delta-down { color: var(--sev-info); }
.file-mod-delta.delta-zero { color: var(--fg-3); }

/* File-diff modal — two side-by-side pre blocks (baseline vs current).
   Reuses .export-modal-* chrome from the export-preview modal. */
.file-diff-card { max-width: 1200px; }
.file-diff-body {
  flex: 1 1 auto; min-height: 0;
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 0;
}
.file-diff-pane {
  display: flex; flex-direction: column;
  min-width: 0; min-height: 0;
  border-right: 1px solid var(--border-2);
}
.file-diff-pane:last-child { border-right: none; }
.file-diff-pane-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 8px 14px;
  border-bottom: 1px solid var(--border-2);
  background: var(--surface-2);
  font-size: 11px;
}
.file-diff-pane-label { font-weight: 600; color: var(--fg); }
.file-diff-pre {
  flex: 1 1 auto; min-height: 0;
  margin: 0; padding: 12px 14px;
  font-family: var(--mono); font-size: 11.5px; line-height: 1.45;
  color: var(--fg-2);
  background: var(--bg);
  overflow: auto;
  white-space: pre-wrap; word-break: break-word;
  outline: none;
}
@media (max-width: 800px) {
  .file-diff-body { grid-template-columns: 1fr; }
  .file-diff-pane { border-right: none; border-bottom: 1px solid var(--border-2); }
}

/* Signal bars */
.signals { display: flex; flex-direction: column; gap: 7px; justify-content: center; }
.signal { display: grid; grid-template-columns: 60px 1fr 36px; gap: 8px; align-items: center; }
.signal-name {
  font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--fg-3); font-weight: 500;
}
.signal-bar { height: 6px; background: var(--surface-2); border-radius: 3px; position: relative; overflow: hidden; }
.signal-fill { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 3px; }
.signal-fill.timing { background: linear-gradient(90deg, #6366f1, #818cf8); }
.signal-fill.lex    { background: linear-gradient(90deg, #8b5cf6, #a78bfa); }
.signal-fill.inj    { background: linear-gradient(90deg, #ec4899, #f472b6); }
.signal-val { font-family: var(--mono); font-size: 11px; color: var(--fg-2); text-align: right; }
.gate-pills { margin-top: 6px; display: flex; gap: 6px; }
.gate-pill {
  flex: 1;
  text-align: center;
  padding: 4px 6px;
  border-radius: 3px;
  background: var(--surface-2);
  font-family: var(--mono); font-size: 9px;
  letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--fg-3);
  border: 1px solid var(--border-2);
}
.gate-pill.fired {
  background: var(--tint-crit);
  color: var(--sev-critical);
  border-color: rgba(239, 68, 68, 0.3);
}

/* Alerts list */
.alerts-list { padding: 8px 14px 14px; border-bottom: 1px solid var(--border-2); }
.alert {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 8px; padding: 6px 0;
  border-bottom: 1px dashed var(--border-2);
  align-items: center;
  cursor: pointer;
  transition: background 80ms ease;
}
.alert:hover { background: color-mix(in srgb, var(--brand) 6%, transparent); }
.alert:last-child { border-bottom: none; }
.alert-sev {
  padding: 1px 5px; border-radius: 2px;
  font-family: var(--mono); font-size: 9px; font-weight: 600;
  letter-spacing: 0.05em; min-width: 38px; text-align: center;
}
.alert-sev.crit { background: var(--sev-critical); color: white; }
.alert-sev.high { background: var(--sev-high); color: white; }
.alert-sev.med  { background: var(--sev-medium); color: white; }
.alert-name { font-family: var(--mono); font-size: 12px; color: var(--fg); }
.alert-trigger {
  font-family: var(--mono); font-size: 10px;
  color: var(--fg-3);
  grid-column: 2 / 4;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.alert-ts { font-family: var(--mono); font-size: 10px; color: var(--fg-4); }

/* Phase 3: quick-actions row */
.quick-actions {
  display: flex; gap: 8px; flex-wrap: wrap;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border-2);
}
.action-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 12px;
  font-family: var(--mono); font-size: 11.5px;
  background: var(--surface);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  color: var(--fg);
  cursor: pointer;
  transition: all 0.1s ease;
  user-select: none;
  position: relative;
  overflow: hidden;
}
.action-btn:hover { background: var(--surface-2); border-color: var(--border); }
.action-btn:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
.action-btn:disabled { opacity: 0.5; cursor: wait; }
.action-btn.primary { color: var(--brand); border-color: var(--brand-dim); }
.action-btn.primary:hover:not(:disabled) {
  background: color-mix(in srgb, var(--brand) 14%, transparent);
  border-color: var(--brand);
}
.action-btn.danger { color: var(--sev-critical); border-color: rgba(239, 68, 68, 0.3); }
.action-btn.danger:hover {
  background: var(--tint-crit);
  border-color: var(--sev-critical);
  color: white;
}
.action-btn.danger[data-kill-state="pending"] {
  color: var(--sev-medium);
  border-color: var(--sev-medium);
}
.action-btn.danger[data-kill-state="killed"] {
  color: var(--fg-3);
  border-color: var(--border-2);
  cursor: not-allowed;
}
.action-btn .hold-fill {
  position: absolute; inset: 0;
  background: var(--sev-critical);
  transform-origin: left;
  transform: scaleX(0);
  transition: transform 1s linear;
  opacity: 0.85;
  pointer-events: none;
}
.action-btn.holding .hold-fill { transform: scaleX(1); }
.action-btn > * { position: relative; z-index: 1; }

/* Phase 3: notes list + composer */
.notes-list { padding: 6px 14px; border-bottom: 1px solid var(--border-2); }
.note-item {
  padding: 8px 0;
  border-bottom: 1px dashed var(--border-2);
}
.note-item:last-child { border-bottom: none; }
.note-header {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--mono); font-size: 10px;
  color: var(--fg-3);
  margin-bottom: 4px;
}
.note-author { color: var(--fg); font-weight: 500; }
.note-ts { color: var(--fg-4); flex: 1; }
.note-delete {
  background: none;
  border: 1px solid var(--border-2);
  border-radius: 3px;
  color: var(--fg-4);
  width: 20px; height: 20px;
  line-height: 1;
  cursor: pointer;
  padding: 0;
  font-size: 13px;
}
.note-delete:hover { color: var(--sev-critical); border-color: var(--sev-critical); }
.note-body {
  font-size: 12px;
  color: var(--fg);
  line-height: 1.5;
}
.note-body code {
  font-family: var(--mono);
  background: var(--surface-2);
  padding: 1px 5px;
  border-radius: 2px;
  font-size: 11px;
}
.note-body strong { color: var(--fg); font-weight: 600; }
.note-composer { padding: 10px 14px 12px; border-bottom: 1px solid var(--border-2); }
.note-toolbar {
  display: flex; gap: 4px;
  margin-bottom: 6px;
}
.note-tb-btn {
  background: transparent;
  color: var(--fg-3);
  border: 1px solid var(--border-2);
  border-radius: 3px;
  padding: 2px 8px;
  font-size: 11px;
  line-height: 14px;
  cursor: pointer;
  min-width: 24px;
  text-align: center;
  transition: background 80ms ease, color 80ms ease, border-color 80ms ease;
}
.note-tb-btn:hover {
  background: var(--surface-2);
  color: var(--fg);
  border-color: var(--brand-dim);
}
.note-tb-btn:active {
  background: var(--surface-3);
}
.note-tb-btn .mono { font-family: var(--mono); color: var(--fg-4); }
.note-input {
  width: 100%;
  min-height: 60px;
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 8px 10px;
  color: var(--fg);
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.5;
  resize: vertical;
  outline: none;
}
.note-input:focus { border-color: var(--brand-dim); }
.note-input::placeholder { color: var(--fg-4); }
.note-composer-foot {
  display: flex; align-items: center; justify-content: space-between;
  margin-top: 6px;
}
.note-save {
  padding: 5px 12px;
  background: var(--brand);
  color: #1a1106;
  border: none;
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
}
body.light .note-save { color: white; }
.note-save:hover { filter: brightness(1.08); }
.note-save:disabled { opacity: 0.5; cursor: wait; }

/* Acknowledged alert row — dimmed, strikethrough name, ack-meta visible */
.alert.acked .alert-name { color: var(--fg-3); text-decoration: line-through; }
.alert.acked .alert-trigger { color: var(--fg-4); }
.alert.acked .alert-sev { opacity: 0.6; }

/* The Acknowledge / Un-ack button — sits in the alert-ts column */
.ack-btn {
  font-family: var(--mono);
  font-size: 10px;
  padding: 2px 8px;
  background: var(--surface-2);
  color: var(--fg-2);
  border: 1px solid var(--border-2);
  border-radius: 3px;
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
  transition: all 0.1s ease;
}
.ack-btn:hover {
  background: var(--surface-3);
  color: var(--fg);
  border-color: var(--border);
}
.ack-btn[data-ack-state="acked"] {
  color: var(--sev-ok);
  border-color: rgba(16, 185, 129, 0.3);
}
.ack-btn[data-ack-state="acked"]:hover {
  background: rgba(16, 185, 129, 0.08);
}
.ack-btn[disabled] { opacity: 0.5; cursor: wait; }

/* Confirmation toast that the user sees after acking — with undo */
.ack-toast {
  position: fixed;
  bottom: 20px; left: 50%;
  transform: translateX(-50%);
  background: var(--surface);
  border: 1px solid var(--sev-ok);
  border-radius: var(--radius);
  padding: 10px 16px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--fg);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
  z-index: 300;
  display: flex; align-items: center; gap: 12px;
  animation: ack-toast-in 0.2s ease;
}
body.light .ack-toast {
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.10);
}
@keyframes ack-toast-in {
  from { transform: translate(-50%, 10px); opacity: 0; }
  to   { transform: translate(-50%, 0);    opacity: 1; }
}
.ack-toast .label { color: var(--fg-2); }
.ack-toast .check { color: var(--sev-ok); font-weight: 700; }
.ack-toast .undo {
  color: var(--brand);
  cursor: pointer;
  border: none;
  background: none;
  font-family: inherit;
  font-size: inherit;
  text-decoration: underline;
}
.ack-toast .undo:hover { color: var(--fg); }
.ack-toast .countdown { color: var(--fg-4); font-size: 10px; }

/* Command timeline */
.timeline { padding: 8px 14px 14px; }
.cmd {
  display: grid; grid-template-columns: 62px 80px 1fr;
  gap: 10px;
  padding: 3px 0;
  font-family: var(--mono); font-size: 11.5px;
  line-height: 1.5;
  cursor: pointer;
  transition: background 80ms ease;
  border-radius: 2px;
}
.cmd:hover { background: var(--surface-2); }
/* "scroll-to-command" flash when an alert row routes here */
@keyframes cmd-flash {
  0%   { background: var(--brand-dim); }
  100% { background: transparent; }
}
.cmd.cmd-flash {
  animation: cmd-flash 1.8s ease-out;
}
.cmd-ts { color: var(--fg-4); }
.cmd-src {
  color: var(--fg-3);
  font-size: 10px;
  padding: 0 4px; border-radius: 2px;
  background: var(--surface-2);
  text-align: center;
}
.cmd-src.cache   { color: #93c5fd; background: rgba(59, 130, 246, 0.10); }
.cmd-src.vfs     { color: #6ee7b7; background: rgba(16, 185, 129, 0.10); }
.cmd-src.sim-bot { color: #c4b5fd; background: rgba(139, 92, 246, 0.10); }
.cmd-src.llm     { color: #f0abfc; background: rgba(217, 70, 239, 0.10); }
.cmd-src.find    { color: #fdba74; background: rgba(249, 115, 22, 0.10); }
.cmd-src.error   { color: #f87171; background: rgba(239, 68, 68, 0.10); }
.cmd-src.alert   {
  color: var(--sev-critical);
  background: var(--tint-crit);
  font-weight: 600;
}
body.light .cmd-src.cache   { color: #2563eb; }
body.light .cmd-src.vfs     { color: #059669; }
body.light .cmd-src.sim-bot { color: #7c3aed; }
body.light .cmd-src.llm     { color: #c026d3; }
body.light .cmd-src.find    { color: #ea580c; }
.cmd-text {
  color: var(--fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.cmd.alerted {
  background: var(--tint-cmd-alert);
  margin: 0 -14px; padding-left: 14px; padding-right: 14px;
  border-left: 2px solid var(--sev-critical);
}

/* ==========================================================================
   Toast stack
   ========================================================================== */

.toast-stack {
  position: fixed;
  top: 14px; right: 14px;
  display: flex; flex-direction: column; gap: 8px;
  z-index: 200;
  width: 380px;
  pointer-events: none;
}
.toast {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--sev-info);
  border-radius: var(--radius);
  padding: 10px 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5),
              0 2px 4px rgba(0, 0, 0, 0.3);
  pointer-events: auto;
  animation: toast-in 0.25s ease;
  position: relative;
}
body.light .toast {
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.10),
              0 2px 4px rgba(0, 0, 0, 0.06);
}
.toast.critical { border-left-color: var(--sev-critical); }
.toast.high     { border-left-color: var(--sev-high); }
.toast.medium   { border-left-color: var(--sev-medium); }
.toast.info     { border-left-color: var(--sev-info); }
@keyframes toast-in {
  from { transform: translateX(20px); opacity: 0; }
  to   { transform: translateX(0); opacity: 1; }
}
.toast-head {
  display: flex; align-items: center; gap: 6px;
  font-family: var(--mono);
  font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--fg-3);
  margin-bottom: 4px;
}
.toast-head .sev-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--sev-info);
}
.toast.critical .sev-dot { background: var(--sev-critical);
                            box-shadow: 0 0 8px var(--sev-critical); }
.toast.high     .sev-dot { background: var(--sev-high); }
.toast.medium   .sev-dot { background: var(--sev-medium); }
.toast-head .ts { color: var(--fg-4); margin-left: auto; }
.toast-title { font-family: var(--mono); font-size: 13px; color: var(--fg); line-height: 1.3; }
.toast-body {
  font-family: var(--mono); font-size: 11px;
  color: var(--fg-3);
  margin-top: 4px;
  overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap;
}
.toast-actions { display: flex; gap: 10px; margin-top: 8px; font-size: 11px; }
.toast-actions a {
  color: var(--fg-2);
  text-decoration: none;
  cursor: pointer;
}
.toast-actions a:hover { color: var(--brand); }
.toast-actions a.primary { color: var(--brand); }
.toast-close {
  position: absolute; top: 8px; right: 8px;
  color: var(--fg-4); cursor: pointer;
  font-size: 14px; line-height: 1;
  width: 16px; height: 16px;
  display: flex; align-items: center; justify-content: center;
}
.toast-close:hover { color: var(--fg); }

/* ==========================================================================
   Search / filter bar
   ========================================================================== */

.search-bar {
  padding: 8px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border-2);
  display: flex; gap: 8px; align-items: center;
}

/* Time-bucket chip strip — sits below the search bar, lets the
   operator scope the list to active / 1h / today / week / older
   without losing the severity chips above. */
.time-bucket-strip {
  display: flex; align-items: center; flex-wrap: wrap;
  gap: 6px;
  padding: 6px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border-2);
}
.time-bucket-strip .filter {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border: 1px solid transparent;
  border-radius: 3px;
  background: transparent;
  color: var(--fg-2);
  cursor: pointer;
  -webkit-appearance: none; appearance: none;
  line-height: 1;
}
.time-bucket-strip .filter:hover {
  background: var(--surface-2);
  border-color: var(--border-2);
  color: var(--fg);
}
.time-bucket-strip .filter.active {
  background: color-mix(in srgb, var(--brand) 14%, transparent);
  border-color: var(--brand-dim);
  color: var(--brand);
}
.time-bucket-strip .filter:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}

/* Engagement-list sort + page-size chip strip — appears in the
   /panel/engagements popout below the time-bucket strip.  Shares the
   same .filter affordance as the other chip strips. */
.eng-sort-strip {
  display: flex; align-items: center; flex-wrap: wrap;
  gap: 6px;
  padding: 6px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border-2);
}
.eng-sort-strip .filter {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border: 1px solid transparent;
  border-radius: 3px;
  background: transparent;
  color: var(--fg-2);
  cursor: pointer;
  -webkit-appearance: none; appearance: none;
  line-height: 1;
}
.eng-sort-strip .filter:hover {
  background: var(--surface-2);
  border-color: var(--border-2);
  color: var(--fg);
}
.eng-sort-strip .filter.active {
  background: color-mix(in srgb, var(--brand) 14%, transparent);
  border-color: var(--brand-dim);
  color: var(--brand);
}
.eng-sort-strip .filter:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
.eng-sort-dir-wrap { display: inline-flex; }
.eng-sort-strip [data-eng-sort-dir-toggle] {
  font-size: 13px;
  padding: 2px 6px;
  border-color: var(--border-2);
  min-width: 22px;
  text-align: center;
}

/* Pagination chrome at the bottom of the engagement list popout. */
.eng-pagination {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-top: 1px solid var(--border-2);
  background: var(--surface);
}
.eng-pagination-controls {
  display: flex; align-items: center; gap: 8px;
}
.eng-pagination .filter {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 10px;
  border: 1px solid var(--border-2);
  border-radius: 3px;
  background: transparent;
  color: var(--fg-2);
  cursor: pointer;
  -webkit-appearance: none; appearance: none;
}
.eng-pagination .filter:hover:not([disabled]) {
  background: var(--surface-2);
  color: var(--fg);
  border-color: var(--border);
}
.eng-pagination .filter[disabled] {
  opacity: 0.35;
  cursor: not-allowed;
}

/* Dormant engagement rows — last seen more than 24h ago.  Dimmed
   so today's activity pops without losing the historical context. */
.eng.dormant {
  opacity: 0.5;
  transition: opacity 0.1s ease;
}
.eng.dormant:hover { opacity: 1; }
.eng.dormant.selected { opacity: 1; }
.search-input {
  flex: 1;
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 6px 10px;
  color: var(--fg);
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
}
.search-input:focus { border-color: var(--brand-dim); }
.search-input::placeholder { color: var(--fg-4); }
.search-chip {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 4px 8px;
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--fg-2);
  cursor: pointer;
  user-select: none;
}
.search-chip:hover { color: var(--fg); border-color: var(--border); }
.search-chip.active {
  color: var(--brand);
  border-color: var(--brand-dim);
  background: rgba(var(--brand-rgb), 0.06);
}
body.light .search-chip.active {
  background: rgba(var(--brand-rgb), 0.08);
}
.search-chip .x { color: var(--fg-4); font-size: 14px; line-height: 1; }
.kbd {
  display: inline-block;
  padding: 1px 5px;
  background: var(--surface-3);
  border: 1px solid var(--border);
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--fg-3);
}

/* ==========================================================================
   Window chrome (popouts only)
   ========================================================================== */

.chrome {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 18px;
  background: var(--surface);
  border-bottom: 1px solid var(--border-2);
}
.chrome-left {
  display: flex; align-items: center; gap: 14px;
  font-family: var(--mono); font-size: 12px;
  color: var(--fg-2);
}
.chrome-left .back {
  color: var(--fg-2); text-decoration: none;
  display: inline-flex; align-items: center; gap: 5px;
  padding: 4px 9px;
  border-radius: 4px;
  transition: background 0.1s ease, color 0.1s ease;
}
.chrome-left .back:hover { background: var(--surface-2); color: var(--fg); }
.chrome-left .crumb-sep { color: var(--fg-4); }
.chrome-left .eid-short { color: var(--fg); font-family: var(--mono); font-weight: 500; }
.chrome-right { display: flex; align-items: center; gap: 6px; }
.chrome-btn {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 10px;
  border-radius: 4px;
  background: var(--surface);
  border: 1px solid var(--border-2);
  color: var(--fg-2);
  font-family: var(--mono);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.1s ease;
  user-select: none;
}
.chrome-btn:hover {
  background: var(--surface-2);
  color: var(--fg);
  border-color: var(--border);
}
.chrome-btn.active {
  background: rgba(var(--brand-rgb), 0.10);
  color: var(--brand);
  border-color: var(--brand-dim);
}
body.light .chrome-btn.active { background: rgba(var(--brand-rgb), 0.08); }
.chrome-btn .ico { font-size: 12px; line-height: 1; }

/* ==========================================================================
   Bottom row (alert rate / DNS / heatmap)
   ========================================================================== */

.bottom {
  display: grid;
  grid-template-columns: 1.4fr 1fr 1fr;
  gap: var(--gap);
  padding: 0 18px var(--gap);
}
.chart-wrap { padding: 14px; }
.chart-stats {
  display: flex; gap: 18px;
  font-family: var(--mono); font-size: 11px;
  color: var(--fg-3);
  margin-bottom: 10px;
}
.chart-stat .v { color: var(--fg); font-size: 14px; }
.chart-stat .l { font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; }
/* Alert-rate chart: SVG geometry that may stretch to fill width, with
   the axis ticks + legend as a crisp HTML overlay (text never lives in
   the stretched SVG, so it can't be distorted at any panel width). */
.ar-chart { position: relative; width: 100%; height: 80px; display: block; }
.ar-chart .ar-svg { position: absolute; inset: 0; width: 100%; height: 100%; display: block; }
.ar-ax {
  position: absolute; inset: 0; pointer-events: none;
  font-family: var(--mono); font-size: 10px; color: var(--fg-4);
}
.ar-ax .ar-t { position: absolute; bottom: 1px; white-space: nowrap; }
.ar-ax .ar-left { left: 4px; }
.ar-ax .ar-now  { right: 4px; }
.ar-ax .ar-mid  { left: 50%; transform: translateX(-50%); }
.ar-ax .ar-lg {
  position: absolute; top: 1px; left: 6px;
  color: var(--fg-3); opacity: 0.85;
}

/* DNS feed */
.dns-feed {
  padding: 6px 14px 14px;
  max-height: 320px; overflow: hidden;
  font-family: var(--mono); font-size: 11px;
}
.dns-row {
  display: grid; grid-template-columns: 50px 1fr auto auto;
  gap: 10px;
  padding: 4px 0;
  border-bottom: 1px dashed var(--border-2);
  align-items: center;
}
.dns-row:last-child { border-bottom: none; }
.dns-ts { color: var(--fg-4); font-size: 10px; }
.dns-host { color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dns-type { color: var(--fg-3); font-size: 10px; }
.dns-result {
  padding: 1px 5px; border-radius: 2px; font-size: 10px;
  background: rgba(16, 185, 129, 0.10);
  color: var(--sev-ok);
}
.dns-result.blocked  { background: var(--tint-crit); color: var(--sev-critical); }
.dns-result.nxdomain { background: rgba(234, 179, 8, 0.10); color: var(--sev-medium); }

/* Heatmap */
.heatmap {
  padding: 14px;
  display: grid; grid-template-columns: 1fr;
  gap: 8px;
}
.heatmap-row {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 10px;
  align-items: center;
}
.heatmap-label {
  font-family: var(--mono); font-size: 10px;
  color: var(--fg-3);
  letter-spacing: 0.02em;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.heatmap-cells {
  display: grid; grid-template-columns: repeat(24, 1fr); gap: 2px;
}
.hcell {
  aspect-ratio: 1;
  border-radius: 1.5px;
  background: var(--surface-2);
}
.hcell.h1 { background: rgba(var(--brand-rgb), 0.15); }
.hcell.h2 { background: rgba(var(--brand-rgb), 0.30); }
.hcell.h3 { background: rgba(var(--brand-rgb), 0.55); }
.hcell.h4 { background: rgba(var(--brand-rgb), 0.80); }
.hcell.h5 { background: var(--brand); }
.hcell.c4 { background: rgba(239, 68, 68, 0.70); }
.hcell.c5 { background: var(--sev-critical); }

/* ==========================================================================
   Footer
   ========================================================================== */

.footer {
  display: flex; align-items: center; justify-content: space-between;
  padding: 8px 18px;
  border-top: 1px solid var(--border);
  font-family: var(--mono); font-size: 11px;
  color: var(--fg-4);
}
.footer a { color: var(--fg-3); text-decoration: none; }
.footer a:hover { color: var(--fg); }
.row { display: flex; align-items: center; gap: 8px; }
.sep { color: var(--fg-4); margin: 0 4px; }

/* ==========================================================================
   Layout dropdown (named layouts)
   ========================================================================== */
.layout-menu {
  position: absolute;
  top: 100%; left: 0;
  margin-top: 4px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 6px;
  min-width: 220px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.4);
  z-index: 150;
  display: none;
}
body.light .layout-menu {
  box-shadow: 0 10px 30px rgba(0,0,0,0.10);
}
.layout-menu.open { display: block; }
.layout-menu .head {
  font-family: var(--mono); font-size: 10px;
  letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--fg-4);
  padding: 4px 8px 6px;
}
.layout-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 5px 8px;
  border-radius: 3px;
  font-family: var(--mono); font-size: 12px;
  color: var(--fg-2);
  cursor: pointer;
}
.layout-item:hover { background: var(--surface-2); color: var(--fg); }
.layout-item .del {
  color: var(--fg-4);
  font-size: 13px; padding: 0 4px;
  cursor: pointer;
}
.layout-item .del:hover { color: var(--sev-critical); }
.layout-save-row {
  display: flex; gap: 4px; padding: 4px;
  border-top: 1px solid var(--border-2);
  margin-top: 4px;
}
.layout-save-row input {
  flex: 1;
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 3px;
  padding: 4px 8px;
  color: var(--fg);
  font-family: var(--mono);
  font-size: 11px;
  outline: none;
}
.layout-save-row input:focus { border-color: var(--brand-dim); }
.layout-save-row button {
  background: var(--brand);
  color: #1a1106;
  border: none;
  border-radius: 3px;
  padding: 4px 10px;
  font-family: var(--mono); font-size: 11px;
  cursor: pointer;
}
body.light .layout-save-row button { color: white; }

/* =========================================================================
   /panel/alert-rate popout — time-range tabs, severity chips, mode toggle,
   chart + top-alerts side panel.  All controls share .filter styling from
   the panel header; the layout below adds the side-by-side chart+list.
   ========================================================================= */
.alert-rate-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(220px, 340px);
  gap: 18px;
  margin-top: 10px;
  align-items: start;
}
.alert-rate-chart-host { min-width: 0; }
.alert-rate-side {
  background: var(--surface-2);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 6px 0 8px;
}
.alert-rate-side-head {
  padding: 6px 12px;
  font-size: 11px; font-weight: 600;
  border-bottom: 1px solid var(--border-2);
  margin-bottom: 4px;
}
.alert-top-list {
  list-style: none; margin: 0; padding: 0;
}
.alert-top-row {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr) 80px 28px;
  gap: 8px;
  align-items: center;
  padding: 4px 12px;
  font-size: 11px;
}
.alert-top-row:hover { background: var(--surface-2); }
.alert-top-name {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--fg);
  font-size: 11px;
}
.alert-top-count { text-align: right; color: var(--fg-2); font-size: 11px; }
.alert-top-spark { display: block; }

.alert-rate-sev-chips {
  display: flex; gap: 6px; flex-wrap: wrap;
  padding: 6px 0 0;
}
.alert-rate-sev-chips .filter {
  padding: 2px 8px;
  border: 1px solid var(--border-2);
  border-radius: 3px;
  background: transparent;
  font-family: var(--mono); font-size: 10.5px;
  cursor: pointer;
  -webkit-appearance: none; appearance: none;
}
.alert-rate-sev-chips .filter:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
.alert-rate-sev-chips .filter.sev-crit  { color: var(--sev-critical); }
.alert-rate-sev-chips .filter.sev-high  { color: var(--sev-high); }
.alert-rate-sev-chips .filter.sev-med   { color: var(--sev-medium); }
.alert-rate-sev-chips .filter.sev-info  { color: var(--fg-2); }
.alert-rate-sev-chips .filter:not(.active) {
  color: var(--fg-4);
  border-color: var(--border-2);
  text-decoration: line-through;
}
.alert-rate-sev-chips .filter.active {
  border-color: currentColor;
  background: color-mix(in srgb, currentColor 10%, transparent);
}
/* Stack the side panel under the chart on narrow popout sizes */
@media (max-width: 900px) {
  .alert-rate-grid { grid-template-columns: 1fr; }
}

/* =========================================================================
   View Transitions API — smooths the SSE swap of #panels every 3 seconds.
   The default browser crossfade is 250ms and applies to the whole document
   root; we shorten it so the dashboard's update cadence still feels live
   without the instant-replace jitter we had before.
   ========================================================================= */
::view-transition-old(root),
::view-transition-new(root) {
  animation-duration: 140ms;
  animation-timing-function: ease-out;
}

/* =========================================================================
   Drag handle on each main-grid panel header.  Click and hold the ⋮⋮ to
   reorder panels.  Same-row swap and cross-row (main ↔ bottom) swap both
   supported.  Active arrangement is auto-saved; named arrangements are
   managed via the Layout dropdown.
   ========================================================================= */
.drag-handle {
  display: inline-block;
  padding: 0 8px 0 0;
  margin-right: 4px;
  font-family: var(--mono);
  font-size: 13px;
  letter-spacing: -1px;
  color: var(--fg-4);
  cursor: grab;
  user-select: none;
  transition: color 120ms ease;
}
.drag-handle:hover { color: var(--brand); }
.drag-handle:active { cursor: grabbing; }
.drag-handle:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
  border-radius: 2px;
  color: var(--brand);
}

/* Keyboard "Move panel to..." picker that opens when Enter/Space is
   pressed on a focused drag handle.  Pure-keyboard alternative to the
   mouse drag flow.  Uses --surface-3 + a brand-tinted border so the
   popover reads clearly against the dark panel headers underneath. */
.move-picker {
  position: fixed;
  z-index: 9100;
  min-width: 220px;
  background: var(--surface-3);
  border: 1px solid var(--brand-dim);
  border-radius: 5px;
  box-shadow: 0 14px 40px rgba(0, 0, 0, 0.55),
              0 0 0 4px rgba(var(--brand-rgb), 0.06);
  padding: 6px 0;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--fg);
}
.move-picker-head {
  padding: 8px 14px 8px;
  color: var(--fg);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--brand) 8%, transparent);
}
.move-picker-item {
  display: block; width: 100%;
  background: transparent;
  border: none;
  text-align: left;
  padding: 8px 14px;
  color: var(--fg);
  font-family: var(--mono);
  font-size: 12px;
  cursor: pointer;
  transition: background 80ms ease, color 80ms ease;
}
.move-picker-item:hover {
  background: var(--surface-2);
  color: var(--brand);
}
.move-picker-item:focus-visible {
  background: var(--brand);
  color: #1a1106;
  outline: none;
  font-weight: 600;
}
.move-picker-hint {
  padding: 6px 14px 4px;
  border-top: 1px solid var(--border);
  color: var(--fg-3);
  font-size: 10px;
  background: var(--surface-2);
}
body.light .move-picker {
  background: var(--surface);
  border-color: var(--brand);
  box-shadow: 0 14px 40px rgba(0, 0, 0, 0.18),
              0 0 0 4px rgba(var(--brand-rgb), 0.10);
}
body.light .move-picker-item:focus-visible { color: white; }
body.light .move-picker-hint { background: var(--surface-2); }
.panel.dragging {
  opacity: 0.45;
  outline: 2px dashed var(--brand);
  outline-offset: -2px;
}
.panel.drop-target {
  outline: 2px solid var(--brand);
  outline-offset: -2px;
  background: color-mix(in srgb, var(--brand) 8%, transparent);
}
body.light .drag-handle { color: #888; }
body.light .panel.drop-target {
  background: color-mix(in srgb, var(--brand) 14%, transparent);
}

/* =========================================================================
   Export preview modal — opened by the audit / IoC / Sigma / STIX / narrate
   links in the engagement detail panel header.  Plain click → modal;
   Cmd/Ctrl/Shift/middle-click → browser default (new tab / DL).
   ========================================================================= */
.export-modal[hidden] { display: none !important; }
.export-modal {
  position: fixed; inset: 0; z-index: 9000;
  display: flex; align-items: center; justify-content: center;
  padding: 32px;
}
.export-modal-backdrop {
  position: absolute; inset: 0;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(2px);
}
.export-modal-card {
  position: relative; z-index: 1;
  width: min(1100px, 100%); max-height: 100%;
  display: flex; flex-direction: column;
  background: var(--surface-3);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
  overflow: hidden;
}
.export-modal-head {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-2);
  background: var(--surface-2);
}
.export-modal-title {
  font-weight: 600; font-size: 13px;
}
.export-modal-meta {
  font-size: 11px;
  flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.export-modal-actions {
  display: flex; gap: 6px; align-items: center;
}
.export-modal-actions .filter[data-modal-close] { cursor: pointer; }
.export-modal-body {
  flex: 1 1 auto; min-height: 0; overflow: hidden;
  display: flex;
}
.export-modal-pre {
  flex: 1 1 auto; min-height: 0;
  margin: 0; padding: 14px 16px;
  font-family: var(--mono); font-size: 12px; line-height: 1.45;
  color: var(--fg-1);
  background: var(--bg-0);
  overflow: auto;
  white-space: pre-wrap; word-break: break-word;
  outline: none;
}
body.light .export-modal-backdrop { background: rgba(0, 0, 0, 0.4); }
"""
