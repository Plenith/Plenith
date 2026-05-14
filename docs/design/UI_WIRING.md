# Dashboard UI ↔ Backend Wiring Spec

This document inventories every interactive element across the three
prototype files and maps each to the backend mechanism that fulfills it.
The goal is the principle that *nothing ships in the UI without a real
handler behind it* — no disabled-button-for-the-screenshot patterns,
no "coming soon" placeholders surviving into v1.0.1.

Source prototypes:

- `docs/design/dashboard-prototype.html` — main dashboard
- `docs/design/dashboard-prototype-popout.html` — engagement detail popout
- `docs/design/dashboard-prototype-popouts.html` — engagements / alert-rate / DNS / heatmap popouts

Status legend:

- ✓ **wired** — backend exists; UI just needs to call it
- ⚠ **partial** — backend mechanism exists but needs a thin endpoint wrapper or a small new field
- ✗ **to build** — material backend work required
- ✂ **cut for v1.0.1** — hide from UI; revisit in v1.1

---

## A. Main dashboard (`/`)

### A.1 Top-strip controls

| Element | Action | Backend mechanism | Status | Effort |
|---|---|---|---|---|
| LLM endpoint status + pulse | display only | `GET /policy` reports the configured endpoint; pulse is a client-side ping | ✓ | XS |
| Uptime / sig / rotated tags | display only | from `/content/manifest` | ✓ | XS |
| `TV mode` toggle | hides chrome, scales fonts, **auto-rotates focus every 30s** | client-side: `body.tv` class + `setInterval` rotator (~30 LOC); rotator pauses on `visibilitychange` | ✓ | S |
| `Notify` button + badge | request browser-notification permission; show unread count | client-side: `Notification.requestPermission()`; badge counts unacked critical alerts from `/alerts` | ⚠ | S |
| `Layout` button | save/load *named* multi-monitor window arrangements (`wall-room`, `triage`, `incident-response`) | client-side: `localStorage["plenith-layouts"] = {name: [{panel, x, y, w, h}, ...]}`; restore calls `window.open` per panel | ✓ | S |

### A.2 KPI strip (6 tiles)

| Tile | Data source | Status | Effort |
|---|---|---|---|
| Active engagements | `GET /engagements?status=open` count | ✓ | XS |
| Alerts (24h) + delta | `GET /alerts?since=86400` count + comparison to prior 24h | ⚠ | S |
| Counter-AI detections | engagements where `attacker_likely_llm=true` | ✓ | XS |
| Proof-by-trap | engagements where `attacker_llm_proven_via_trap=true` | ✓ | XS |
| Dwell p50 | computed from `last_seen_at - first_seen_at` across open engagements | ✗ | S |
| Decoys swallowed | sum of `decoys_swallowed` / `decoys_planted` across all engagements | ⚠ | S |

Sparklines on each tile: each is a per-hour or per-minute bucketed series. Needs a small bucketing helper in `audit.py` (~30 LOC).

### A.3 Notification toast stack

| Element | Action | Backend | Status | Effort |
|---|---|---|---|---|
| Toast arrival | server pushes via SSE on alert fire | extend existing `/api/stream` to emit `event: alert` frames | ⚠ | S |
| `View engagement` button | open detail panel | route to `/panel/engagement/<id>` | ✓ | XS |
| `Acknowledge` button | mark alert as acked by current operator | **NEW** `POST /alerts/{eng_id}/{action}/ack` | ✗ | S |
| `Isolate session` button | block source IP, route subsequent connections to dead-end | existing `POST /mfa/decisions/{ip}` with `decision=fail` | ✓ | XS |
| Toast `×` close | client-side dismissal | no backend | ✓ | XS |
| Browser notification (when unfocused) | same payload as toast, via Notifications API | client-side; permission flow in `Notify` button | ⚠ | S |

### A.4 Pop-out icons (↗) on all 5 panels

| Panel | URL route | Backend | Status | Effort |
|---|---|---|---|---|
| Engagements | `/panel/engagements` | new route renders the engagement-list partial | ✗ | S |
| Engagement detail | `/panel/engagement/<id>` | new route renders detail partial | ✗ | S |
| Alert rate | `/panel/alert-rate` | new route + bucketed aggregation endpoint | ✗ | M |
| DNS feed | `/panel/dns-feed` | new route + new DNS query streaming endpoint | ✗ | M |
| Activity heatmap | `/panel/activity` | new route + per-host-hour aggregation endpoint | ✗ | M |

Each popped window subscribes to a filtered SSE stream so updates flow independently. SSE filtering: `/api/stream?panel=<name>&engagement=<id>`.

### A.5 Engagement filter chips + search

| Element | Backend | Status | Effort |
|---|---|---|---|
| `all` / `critical` / `llm-detected` / `last 1h` | `GET /engagements?severity=&attacker_likely_llm=&since=` | ⚠ | S |
| Search input | `GET /engagements?q=<text>` substring match on `claimed_user`, `source_ip`, alerts, commands | ✗ | M |
| Chip facets (`user:`, `sev:`, `conf:`) | parsed client-side into query params | ✗ (parser) | S |

### A.6 Engagement row click

Action: drill into detail. Stays in-page (right panel updates) by default; pop-out icon opens the dedicated window.

| Mechanism | Status | Effort |
|---|---|---|
| In-page swap via JS + `GET /engagements/<id>` | ✓ (endpoint exists) | XS |

### A.7 Detail panel action links

| Link | Mechanism | Status | Effort |
|---|---|---|---|
| `→ audit.py` | new `GET /engagements/<id>/audit` returns plaintext rendering | ✗ | S |
| `→ narrate` | existing `GET /engagements/<id>/narrative` | ✓ | XS |
| `→ IoC export` | new `GET /engagements/<id>/ioc.{json,csv,stix,sigma}` — wraps `audit.export_ioc()` | ✗ | S |

### A.8 Alert rate severity filter chips

| Element | Backend | Status | Effort |
|---|---|---|---|
| all/critical/high/medium toggles | `GET /alerts/rate?severity=&since=` — **NEW** bucketed endpoint | ✗ | M |

### A.9 DNS feed panel

| Element | Backend | Status | Effort |
|---|---|---|---|
| Live DNS query rows | **NEW** SSE endpoint `/api/dns/stream` reading from CoreDNS query log | ✗ | M |
| Per-hour count | **NEW** `/api/dns/stats?since=` | ✗ | S |

### A.10 Heatmap panel

| Element | Backend | Status | Effort |
|---|---|---|---|
| 4 host × 24h grid | **NEW** `/api/activity/heatmap?since=&host=` | ✗ | M |

---

## B. Engagement detail popout (`/panel/engagement/<id>`)

### B.1 Chrome controls

| Element | Action | Backend | Status | Effort |
|---|---|---|---|---|
| `← Dashboard` back link | navigation | `<a href="/">` | ✓ | XS |
| Theme toggle (☾/☀) | dark↔light | client-side: `localStorage` + `prefers-color-scheme` | ✓ | XS |
| TV mode toggle | hide chrome + scale fonts + **auto-rotate focused section every 30s** | client-side: `body.tv` class + `setInterval` rotator (~30 LOC); rotator pauses when the tab is unfocused so it doesn't burn CPU off-screen | ✓ | S |
| `Notify` per-engagement | subscribe browser notifications scoped to this engagement | client-side filter on the SSE stream | ⚠ | S |
| `×` close | close window | `window.close()` | ✓ | XS |

### B.2 Quick actions (the most critical row to wire correctly)

| Button | Backend | Status | Effort | Confirmation pattern |
|---|---|---|---|---|
| `✓ Acknowledge` | **NEW** `POST /engagements/<id>/ack` | ✗ | S | single-click + success toast with 10s undo |
| `📋 Snapshot` | **NEW** `POST /engagements/<id>/snapshot` writes `state-docker/snapshots/<id>-<ts>.tar.gz` containing the persistence file, all session logs, VFS dump, observed dict | ✗ | M | single-click + toast |
| `⌫ Isolate` | existing `POST /mfa/decisions/<ip>` with `decision=fail` | ✓ | XS | single-click + 10s undo |
| `↗ Escalate L2` | **NEW** `POST /engagements/<id>/escalate` — invokes configured chatops connector (Slack/Teams/PagerDuty) with engagement summary | ⚠ (connectors exist; need wrapper) | S | single-click + confirmation toast |
| `⏹ Kill session` (hold-to-confirm) | **NEW** `POST /engagements/<id>/kill` — terminates active SSH connection(s) via `asyncssh.SSHServerProcess.close()` | ✗ | M | hold-to-confirm 1s; the hold is the confirmation |

### B.3 Counter-AI gauge + signal bars

| Element | Data source | Status | Effort |
|---|---|---|---|
| Composite confidence value | `observed.attacker_llm_confidence` | ✓ | XS |
| Timing / lexical / injection bars | `observed.attacker_llm_signals` | ✓ | XS |
| **Trend label** ("▲ 0.34 → 0.88 last 4 min") | **NEW** rolling-confidence history stored on `_counter_ai.confidence_history: list[(ts, value)]` | ⚠ | S |
| Gate-pill status (FIRED/HELD) | computed from confidence vs. `_THRESHOLD_LLM`, `_THRESHOLD_TRAP_ARM` | ✓ | XS |
| Trap echo "YES" marker | `_counter_ai.trap_leaked` | ✓ | XS |

### B.4 Alert rows

| Element | Action | Status | Effort |
|---|---|---|---|
| Click row | scroll to corresponding command in timeline OR expand inline detail | ✗ | S |
| Acknowledge state badge | reads from `actions_taken[].acknowledged_at` | ✗ | XS (needs B.2 ack endpoint first) |

### B.5 Command timeline

| Element | Action | Status | Effort |
|---|---|---|---|
| Row hover ⌕ zoom | click → modal with full command + response body | ⚠ (response body is in session log; modal is client-side) | S |
| Alerted rows highlighted | based on whether command timestamp matches an alert | ✓ | XS |

### B.6 File diff rows

| Element | Action | Status | Effort |
|---|---|---|---|
| Click path | show modal with current vs baseline file content (diff view) | ⚠ (VFS has content; diff is client-side) | S |

### B.7 Operator notes editor

| Element | Action | Status | Effort |
|---|---|---|---|
| Existing notes display | render markdown → HTML | ✗ | S |
| Note storage | **NEW** `Session.notes: list[{author, ts, body}]` field; **NEW** `POST /engagements/<id>/notes` and `GET /engagements/<id>/notes` | ✗ | M |
| `Write` / `Preview` tabs | client-side textarea↔rendered swap | ✓ | XS |
| Toolbar B / I / S / code / list / quote | JS wraps selection with markdown syntax | ✗ (JS module) | S |
| `@` mention autocomplete | **NEW** `GET /operators?prefix=` | ✗ | M |
| `#` engagement-ref autocomplete | **NEW** `GET /engagements?prefix=` | ✗ | S |
| `⊕` insert IoC | client-side: pull current engagement's IoC block from `/engagements/<id>/ioc.json` and format as markdown table | ⚠ | S |
| `Save note` button | `POST /engagements/<id>/notes` | ✗ | S (depends on storage) |

### B.8 Footer links

| Link | Mechanism | Status | Effort |
|---|---|---|---|
| `→ raw JSON` | `GET /engagements/<id>` (already returns JSON) | ✓ | XS |
| `→ audit.py` | rendered plaintext from A.7 | ✗ | XS (alias) |
| `→ narrate` | `GET /engagements/<id>/narrative` | ✓ | XS |
| `→ IoC export` | `GET /engagements/<id>/ioc.csv` | ✗ | XS (alias) |
| `→ Sigma rule` | new endpoint `GET /engagements/<id>/sigma.yaml` wraps `audit._sigma_*` | ✗ | XS |

### B.9 Proof-by-trap banner

| Element | Mechanism | Status | Effort |
|---|---|---|---|
| Visibility gate | render only when `observed.attacker_llm_proven_via_trap=true` | ✓ | XS |
| Marker text | `_counter_ai.trap_marker` | ✓ | XS |
| "lag plant → echo" calculation | computed from timestamps in `actions_taken[].ts_offset_s` | ⚠ | S |

---

## C. Engagement list popout (`/panel/engagements`)

### C.1 Toolbar

| Element | Backend | Status | Effort |
|---|---|---|---|
| Search input | `GET /engagements?q=` | ✗ | M |
| Filter chips | `?severity=&conf=&since=` | ⚠ | S |
| `+ add` filter builder | client-side dropdown | ✗ | S |
| Group-by chip | `GROUP BY` in query layer | ✗ | M |

### C.2 Table

| Element | Backend | Status | Effort |
|---|---|---|---|
| Sortable column headers | `?sort_by=&order=` | ✗ | S |
| Multi-select checkboxes | client-side state | ✓ | XS |
| Row click | route to `/panel/engagement/<id>` | ✓ | XS |
| Per-row menu (⋯) | dropdown with same actions as detail | ⚠ | S |

### C.3 Batch action bar

| Button | Backend | Status | Effort |
|---|---|---|---|
| Acknowledge all | **NEW** `POST /engagements/batch/ack` (body: `{ids: [...]}`) | ✗ | S |
| Snapshot | **NEW** `POST /engagements/batch/snapshot` | ✗ | M |
| **Tag…** | **NEW** `POST /engagements/batch/tag` requires `Session.tags` field | ✗ | M ✂ |
| Export IoC bundle | `GET /engagements/export?ids=&format=csv` | ✗ | S |
| Escalate L2 | `POST /engagements/batch/escalate` | ✗ | S |
| Kill sessions | `POST /engagements/batch/kill` | ✗ | M |

### C.4 Pagination

| Element | Backend | Status | Effort |
|---|---|---|---|
| Page nav + count | `?page=&per_page=` | ✗ | S |

---

## D. Alert rate popout (`/panel/alert-rate`)

| Element | Backend | Status | Effort |
|---|---|---|---|
| Time-range tabs (15m/1h/6h/24h/7d/30d) | `GET /alerts/rate?since=&bucket=` (auto bucket size by range) | ✗ | M |
| Custom range | date-picker → same endpoint | ✗ | M ✂ |
| Severity filter chips | `&severity=` | ✗ (depends on rate endpoint) | XS |
| `stacked` toggle | client-side rendering option | ✓ | XS |
| `vs. prior period` overlay | `&compare_to=previous` — server computes same-shape series for prior `since` window; chart renders as dashed overlay | ✓ | S |
| **Deployment annotation marker** | `GET /deployments/events` — **NEW** events log | ✗ | M ✂ |
| Time scrubber | overview series `GET /alerts/rate?since=-30d&bucket=day` | ✗ | S |
| Top alerts list + sparklines | `GET /alerts/top?since=` (aggregation) | ✗ | M |

---

## E. DNS feed popout (`/panel/dns-feed`)

| Element | Backend | Status | Effort |
|---|---|---|---|
| KPI tiles (per-min, per-hour, blocked, NXDOMAIN, resolved) | **NEW** `GET /dns/stats?since=` reads CoreDNS query log | ✗ | M |
| Live ticker | **NEW** `GET /dns/stream` SSE following the CoreDNS log | ✗ | M |
| Top blocked / NXDOMAIN | `/dns/top?type=blocked&since=` | ✗ | S |
| Per-engagement DNS breakdown | join DNS log against engagement IPs | ✗ | M |

The CoreDNS container at `linux-fork/coredns/` already writes a structured query log. The new endpoints tail that file and bucket/aggregate.

---

## F. Activity heatmap popout (`/panel/activity`)

| Element | Backend | Status | Effort |
|---|---|---|---|
| Time-range tabs (24h/7d/30d/90d) | `?since=` | ✗ | S |
| Alert filter chips (all/critical/llm) | `&severity=` | ✗ | XS |
| 4 host × 24h grid | **NEW** `GET /activity/heatmap?since=&host=` bucketed by hour | ✗ | M |
| `vs. last week` overlay | `&compare_to=-7d` | ✗ | S ✂ |
| Summary stats (peak hour, busiest decoy, anomalies) | computed in heatmap endpoint | ⚠ | S |
| Heatmap cell click → drill in | route to filtered engagement list | ✗ | S |

---

## G. New state-store fields required

These need to live on `Session.observed` (or sibling top-level) and round-trip through `to_persistent_state` / `_deserialize_observed`. Each adds two test cases (round-trip + restore).

| Field | Type | Purpose | Default |
|---|---|---|---|
| `actions_taken[].acknowledged_at` | `float \| None` | when the alert was ack'd (UTC epoch) | `None` |
| `actions_taken[].acknowledged_by` | `str \| None` | operator id who ack'd | `None` |
| `actions_taken[].acknowledge_note` | `str \| None` | optional context | `None` |
| `notes` | `list[{author, ts, body}]` | operator markdown notes | `[]` |
| `tags` | `list[str]` | operator tags | `[]` ✂ |
| `snapshots` | `list[{ts, path, size}]` | snapshot artifacts written for this engagement | `[]` |
| `_counter_ai.confidence_history` | `list[(ts, value)]` | rolling history for the trend label | `[]` |

---

## H. New API endpoints required

Grouped by area, with the minimum signatures.

### H.1 Acknowledgement (B.2 + A.3 + C.3)

```
POST   /engagements/{id}/ack                  body: {action_name, note?, op_id}
DELETE /engagements/{id}/ack/{action_name}    undo (within 10s for the toast)
POST   /engagements/batch/ack                 body: {ids: [...], action_name?}
```

### H.2 Snapshot (B.2 + C.3)

```
POST   /engagements/{id}/snapshot             body: {note?}
                                              returns: {path, size, sha256}
POST   /engagements/batch/snapshot            body: {ids: [...]}
GET    /engagements/{id}/snapshots            returns: list of snapshots
```

Snapshot writes a `.tar.gz` containing: persistence file, all session logs for the engagement, VFS dump, observed dict, audit-chain segment. Path: `state-docker/snapshots/<id>-<ts>.tar.gz`.

### H.3 Kill session (B.2 + C.3)

```
POST   /engagements/{id}/kill                 body: {reason?}
                                              returns: {killed: int, connections_terminated}
POST   /engagements/batch/kill                body: {ids: [...]}
```

Requires the orchestrator to maintain a `Dict[engagement_id, List[SSHServerProcess]]` so we can call `proc.close()` on each.

### H.4 Escalate (B.2 + C.3)

```
POST   /engagements/{id}/escalate             body: {tier: "L2"|"L3", message?}
                                              returns: {connectors_fired: [name, ...]}
POST   /engagements/batch/escalate            body: {ids: [...]}
```

Wraps the existing Slack/Teams/PagerDuty connectors in `plenith/connectors/chatops.py`.

### H.5 Operator notes (B.7)

```
GET    /engagements/{id}/notes                returns: list[note]
POST   /engagements/{id}/notes                body: {body: markdown, op_id}
                                              returns: note
DELETE /engagements/{id}/notes/{note_id}      author-only
```

### H.6 IoC export (B.8 + C.3)

```
GET    /engagements/{id}/audit                returns: text/plain rendering
GET    /engagements/{id}/ioc.json             returns: JSON IoC bundle
GET    /engagements/{id}/ioc.csv              returns: CSV (uses _csv_safe)
GET    /engagements/{id}/ioc.stix             returns: STIX 2.1 JSON
GET    /engagements/{id}/sigma.yaml           returns: Sigma rule
GET    /engagements/export?ids=&format=       batch export
```

These mostly wrap existing `audit.py` functions; new work is the URL routes.

### H.7 Time-bucketed aggregations (A.2 + A.8 + D + F)

```
GET    /alerts/rate?since=&bucket=&severity=  returns: [{ts, count, by_severity}]
GET    /alerts/top?since=&limit=10            returns: [{name, severity, count, sparkline}]
GET    /activity/heatmap?since=&host=         returns: 4x24 grid
GET    /engagements/stats                     returns: {dwell_p50, decoys_total, decoys_swallowed, ...}
```

### H.8 DNS endpoints (E)

```
GET    /dns/stats?since=                      returns: per-min/hr counts
GET    /dns/stream                            SSE; live query feed
GET    /dns/top?type=blocked|nxdomain&since=  returns: [{host, count}]
```

### H.9 Search + autocomplete (B.7 + C.1)

```
GET    /engagements?q=                        full-text-ish over user/IP/alerts
GET    /engagements?prefix=                   autocomplete for # mentions
GET    /operators?prefix=                     autocomplete for @ mentions
```

### H.10 Panel routes (A.4)

```
GET    /panel/engagements
GET    /panel/engagement/<id>
GET    /panel/alert-rate
GET    /panel/dns-feed
GET    /panel/activity
```

Each renders the same template the main dashboard uses for that section, but standalone (own `<html>`, own SSE subscription).

---

## I. Scope: v1.0.1 vs v1.1

The wiring inventory makes it clear that *some* features in the mock would require significant new backend work. Below is what I recommend keeping vs. cutting for v1.0.1.

### Keep (ship in v1.0.1 with full wiring)

These are essential for the dashboard to feel real and have meaningful ROI:

- ✓ Acknowledge / un-acknowledge (B.2, A.3, C.3)
- ✓ Snapshot to `state-docker/snapshots/` (B.2)
- ✓ Isolate via existing MFA endpoint (B.2)
- ✓ Escalate L2 via existing chatops connectors (B.2)
- ✓ Kill session via new endpoint + orchestrator wiring (B.2)
- ✓ Operator notes with markdown storage + toolbar (B.7)
- ✓ All `→ audit.py` / `→ narrate` / `→ IoC export` / `→ Sigma` footer links (B.8)
- ✓ Pop-out URL routes for all 5 panels (A.4)
- ✓ Browser notifications + tab title badge + favicon (A.1, A.3)
- ✓ Theme auto-detect + manual override (already shipped)
- ✓ TV mode CSS + **auto-rotation** (rotates focused section every 30s)
- ✓ **Saved named layouts** (client-side localStorage with named slots, restore from dropdown)
- ✓ Search/filter on engagement list (A.5, C.1)
- ✓ Multi-select + batch ack (C.3 — ack subset only)
- ✓ Time-range presets on alert-rate (D — without scrubber, **with `vs. prior period` overlay**)
- ✓ Activity heatmap basic grid (F — without comparison overlay)
- ✓ DNS stats + top-blocked (E — without live SSE ticker)

### Cut (✂) — hide from v1.0.1 UI; revisit in v1.1

Each of these adds material backend work disproportionate to the user value at launch:

- ✂ **Tag** (B.2.tags, C.3.tag) — requires new `tags` field, autocomplete, faceting. Defer.
- ✂ **Custom time-range** picker (D) — ship presets only.
- ✂ **Deployment annotation markers** (D) — needs new events log. Hide the dashed amber line.
- ✂ **vs-last-week heatmap overlay** (F) — needs comparison aggregation across week boundaries; the alert-rate vs-prior-period overlay (kept) handles the same need on a different axis.
- ✂ **Multi-analyst presence** ("Phoebe is viewing this") — never made it into the mock; mention as v1.1 wish.
- ✂ **DNS live SSE ticker** (E) — ship periodic-refresh version first; SSE for DNS is a v1.1 enhancement.
- ✂ **`@` operator-mention autocomplete** (B.7) — needs an operators registry. Ship `@username` as plain text first.
- ✂ **`#` engagement-ref autocomplete** (B.7) — ship plain text refs; render as links if they match a known engagement-id pattern.

Hidden UI elements should be **removed from the rendered HTML**, not just `display: none`'d. No "coming soon" placeholders.

### Bought-back from the original cut list (option B)

After review, three features were judged cheap enough to keep and visible enough at launch to be worth the ~1.5 extra days of work:

- ✓ **TV-mode auto-rotation** — focused section cycles every 30s. ~30 LOC of vanilla JS using `setInterval`. Visible payoff: the war-room demo screenshot is real, not hand-waved.
- ✓ **Saved named layouts** — operators can define `wall-room`, `triage`, `incident-response` window arrangements and restore them one-click. Pure client-side: `localStorage.setItem("plenith-layouts", JSON.stringify({name: [{panel, x, y, w, h}, ...]}))`. Cost: small dropdown UI + a script that calls `window.open` per panel on restore.
- ✓ **vs-prior-period overlay (alert-rate)** — adds `&compare_to=previous` query param to `/alerts/rate`; backend computes the same-shape series for the prior window and the chart overlays it as a dashed line. Cost: ~20 LOC in the aggregation endpoint + the existing dashed-line SVG that's already in the prototype.

---

## J. Implementation order

Phased so each phase is independently shippable.

### Phase 1 — UI port (foundation)

- Extract the CSS from the three prototype files into one stylesheet
- Rewrite `tools/dashboard.py`'s render functions to emit the new HTML
- Wire URL routes (A.4 / panel routes / H.10)
- Theme auto-detect + manual override + `localStorage` persistence
- **TV mode CSS + auto-rotation** (`setInterval` rotator paused on `visibilitychange`)
- **Saved named layouts** (`localStorage["plenith-layouts"]` + dropdown UI + `window.open` per panel on restore)
- Search/filter on engagement list (client-side first; backend search lands in Phase 5)
- Multi-select state (client-side only — no batch actions yet)

Estimated: **2 days** (+1d for TV auto-rotation, saved named layouts, and the corresponding JS plumbing — also gives breathing room for the CSS extraction and design polish). Visible result: the new design is live; pop-out + layout-restore + TV-rotation all work; buttons that require backend remain visually present but inert until later phases.

### Phase 2 — state + acknowledgement

- New `Session.observed` fields (G)
- Acknowledgement endpoints (H.1)
- Wire toast Ack button + B.2 Ack button + C.3 batch ack
- Tests for round-trip persistence of new fields

Estimated: **1 day**. Visible result: clicking Acknowledge actually does something.

### Phase 3 — quick actions + notes

- Snapshot endpoint + tarball writer (H.2)
- Kill session endpoint + orchestrator wiring (H.3)
- Escalate endpoint wrapping chatops (H.4)
- Operator notes endpoints + markdown rendering (H.5)
- Notes toolbar JS module

Estimated: **2 days**. Visible result: every quick-action button works end-to-end.

### Phase 4 — exports + footer links

- IoC / Sigma / audit URL aliases over existing `audit.py` (H.6)
- Sigma export route

Estimated: **0.5 day**. Visible result: all footer links download real artifacts.

### Phase 5 — aggregations + charts

- `/alerts/rate` with **`&compare_to=previous` overlay support** (H.7)
- `/alerts/top` (H.7)
- `/activity/heatmap` (H.7)
- `/dns/stats`, `/dns/top` (H.8 — without SSE ticker)
- Wire charts in alert-rate and activity popouts
- Wire the dashed prior-period overlay on the alert-rate stacked-bar chart

Estimated: **2 days** (+0.5d for the `compare_to=previous` overlay computation + chart wiring). Visible result: the bottom-row panels show real data; the alert-rate chart can compare current vs. prior window side-by-side.

### Phase 6 — notifications

- SSE alert-push extension (A.3)
- Browser Notifications API (A.1, A.3)
- Tab title badge + favicon dot

Estimated: **0.5 day**. Visible result: toasts arrive on real alerts; tab title shows unread count.

### Total v1.0.1 scope

**~8 days of focused engineering** (option B — strict scope from option A would be 6.5d).

Breakdown:

| Phase | Days | Cumulative |
|---|---:|---:|
| 1 — UI port + TV auto-rotation + saved layouts | 2.0 | 2.0 |
| 2 — state + acknowledgement | 1.0 | 3.0 |
| 3 — quick actions + notes | 2.0 | 5.0 |
| 4 — exports + footer links | 0.5 | 5.5 |
| 5 — aggregations + charts (incl. vs-prior overlay) | 2.0 | 7.5 |
| 6 — notifications | 0.5 | 8.0 |

Each phase ends with the dashboard demonstrably *more capable* than before. No phase ships hollow UI. Each phase = one PR.

---

## K. Sign-off criteria

Before any of this lands in `main`, every interactive element in the
three prototype files must be one of:

1. ✓ Real and wired
2. ✂ Removed from the rendered HTML (not hidden, not stubbed)
3. ⚠ Listed in `docs/ROADMAP.md` as v1.1 with an explicit timeline

No third option. If you can click it, it does something real or it's
not in the page.

---

*Authored 2026-05-14. Companion to `dashboard-prototype.html`,
`dashboard-prototype-popout.html`, `dashboard-prototype-popouts.html`.*
