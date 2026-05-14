"""Plenith SOC dashboard — consolidated client-side scripts.

Vanilla JavaScript, no framework, no build step.  Bundled into the
served HTML by `tools/dashboard.py`.  Split into its own Python module
so `dashboard.py` stays a manageable size (see also dashboard_styles.py).

Behaviors covered (Phase 1 of docs/design/UI_WIRING.md):

  - Theme: auto-detect prefers-color-scheme, manual toggle persists in
    localStorage; live OS-theme-change listener (manual choice wins).
  - TV mode: body.tv class + auto-rotation of focused section every 30s.
    Pauses while the tab is unfocused (visibilitychange) so the wall
    display doesn't burn CPU off-screen.
  - Saved named layouts: localStorage["plenith-layouts"] = {name: [...]}.
    Restore opens one window per panel in the saved layout.  Dropdown
    UI for save / load / delete.
  - Engagement filter: client-side text/chip filter on the list.
  - Multi-select state: tracks checked engagement IDs; batch action
    bar appears when any are selected.  (Batch handlers themselves
    land in Phase 2 + 3; Phase 1 just makes the UI react.)
  - Pop-out clicks: every `.icon-btn[data-popout]` opens
    `/panel/<name>` in a sized window.
  - SSE: subscribe to `/api/stream?panel=<current>` and swap the
    relevant DOM subtree.  Reconnect is handled by EventSource itself.

Public surface: a single `JS` string constant inlined into the
`<script>` tag of every rendered page.  Each behavior is an IIFE so
they share no globals.
"""
from __future__ import annotations


JS = r"""
// ===========================================================================
// THEME — auto-detect prefers-color-scheme, manual override persists.
// ===========================================================================
(function () {
  function applyTheme() {
    var explicit = localStorage.getItem("plenith-theme");
    var prefersLight = window.matchMedia &&
                        window.matchMedia("(prefers-color-scheme: light)").matches;
    var useLight = (explicit === "light") ||
                    (explicit === null && prefersLight);
    document.body.classList.toggle("light", useLight);
    document.querySelectorAll("[data-theme-icon]").forEach(function (e) {
      e.textContent = useLight ? "☀" : "☾";
    });
    document.querySelectorAll("[data-theme-name]").forEach(function (e) {
      e.textContent = useLight ? "Light" : "Dark";
    });
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.setAttribute("aria-pressed", useLight ? "true" : "false");
      b.setAttribute("aria-label",
        useLight ? "Switch to dark theme" : "Switch to light theme");
    });
  }
  applyTheme();
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var nowLight = !document.body.classList.contains("light");
      localStorage.setItem("plenith-theme", nowLight ? "light" : "dark");
      applyTheme();
    });
  });
  // Live-react to OS-level theme changes — only honored when the user
  // has not made an explicit choice.
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)")
          .addEventListener("change", applyTheme);
  }
})();

// ===========================================================================
// TV MODE — class toggle + auto-rotation of focus across sections every 30s.
// Pauses when the tab is unfocused so a wall display doesn't burn CPU.
// ===========================================================================
(function () {
  var rotateTimer = null;
  var ROTATE_MS = 30000;
  var currentIdx = 0;

  function rotatableSections() {
    return Array.from(document.querySelectorAll("[data-tv-section]"));
  }
  function focusSection(i) {
    var s = rotatableSections();
    if (s.length === 0) return;
    s.forEach(function (el, idx) { el.classList.toggle("tv-focus", idx === i); });
    s[i].scrollIntoView({ behavior: "smooth", block: "start" });
  }
  function startRotation() {
    stopRotation();
    if (rotatableSections().length === 0) return;
    focusSection(currentIdx);
    rotateTimer = setInterval(function () {
      currentIdx = (currentIdx + 1) % rotatableSections().length;
      focusSection(currentIdx);
    }, ROTATE_MS);
  }
  function stopRotation() {
    if (rotateTimer !== null) { clearInterval(rotateTimer); rotateTimer = null; }
  }

  document.querySelectorAll("[data-tv-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var on = document.body.classList.toggle("tv");
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      if (on) startRotation(); else { stopRotation(); document.querySelectorAll(".tv-focus").forEach(function (e) { e.classList.remove("tv-focus"); }); }
    });
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.body.classList.contains("tv")) return;
    if (document.hidden) stopRotation();
    else                  startRotation();
  });
})();

// ===========================================================================
// MAIN-GRID ARRANGEMENT — drag panels to reorder, save named arrangements.
// Each panel carries data-panel-id; rows are marked data-grid-row.  The
// active arrangement (auto-saved on every drag) and named arrangements
// both live in localStorage and are re-applied after every SSE swap so
// the panels don't snap back to default order every 3 seconds.
//
// Rows preserve their panel COUNT (main always has 2 panels, bottom
// always has 3) — cross-row drags swap one for one, keeping the grid
// proportions intact.
// ===========================================================================
(function () {
  var STORE_KEY     = "plenith-arrangements";        // named map
  var STORE_CURRENT = "plenith-arrangement-current"; // live active arrangement

  function loadStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function saveStore(s) {
    localStorage.setItem(STORE_KEY, JSON.stringify(s));
  }
  function loadCurrent() {
    try { return JSON.parse(localStorage.getItem(STORE_CURRENT) || "null"); }
    catch (e) { return null; }
  }
  function saveCurrent(arrangement) {
    if (arrangement) localStorage.setItem(STORE_CURRENT, JSON.stringify(arrangement));
    else localStorage.removeItem(STORE_CURRENT);
  }

  // Read the current panel-to-row mapping from the DOM.
  function captureArrangement() {
    var out = {};
    document.querySelectorAll("[data-grid-row]").forEach(function (row) {
      var name = row.getAttribute("data-grid-row");
      var ids = [];
      row.querySelectorAll(":scope > .panel[data-panel-id]").forEach(function (p) {
        ids.push(p.getAttribute("data-panel-id"));
      });
      out[name] = ids;
    });
    return out;
  }

  // Apply a saved arrangement to the live DOM (moves panel nodes between
  // rows / reorders within a row).  Panels not mentioned in the arrangement
  // are left where they are; unknown ids are skipped.
  function applyArrangement(arrangement) {
    if (!arrangement) return;
    Object.keys(arrangement).forEach(function (rowName) {
      var row = document.querySelector(
        "[data-grid-row=\"" + rowName + "\"]");
      if (!row) return;
      var desiredIds = arrangement[rowName];
      if (!Array.isArray(desiredIds)) return;
      desiredIds.forEach(function (id) {
        var panel = document.querySelector(
          ".panel[data-panel-id=\"" + id + "\"]");
        if (!panel) return;
        // Append moves the node (it's the same DOM element) — this both
        // pulls it from its current parent and places it in the desired
        // order within the new parent.
        row.appendChild(panel);
      });
    });
  }
  // Exposed so the SSE handler can re-run after each panel-swap render.
  window.plenithApplyArrangement = function () {
    applyArrangement(loadCurrent());
  };

  // ----- Drag and drop ----------------------------------------------------
  var draggingId = null;

  document.addEventListener("dragstart", function (ev) {
    var handle = ev.target.closest("[data-drag-handle]");
    if (!handle) return;
    var panel = handle.closest(".panel[data-panel-id]");
    if (!panel) return;
    draggingId = panel.getAttribute("data-panel-id");
    panel.classList.add("dragging");
    if (ev.dataTransfer) {
      ev.dataTransfer.effectAllowed = "move";
      ev.dataTransfer.setData("text/plain", draggingId);
    }
  });
  document.addEventListener("dragend", function (ev) {
    document.querySelectorAll(".panel.dragging").forEach(function (p) {
      p.classList.remove("dragging");
    });
    document.querySelectorAll(".panel.drop-target").forEach(function (p) {
      p.classList.remove("drop-target");
    });
    draggingId = null;
  });
  document.addEventListener("dragover", function (ev) {
    if (!draggingId) return;
    var target = ev.target.closest(".panel[data-panel-id]");
    if (!target) return;
    if (target.getAttribute("data-panel-id") === draggingId) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
    document.querySelectorAll(".panel.drop-target").forEach(function (p) {
      if (p !== target) p.classList.remove("drop-target");
    });
    target.classList.add("drop-target");
  });
  document.addEventListener("dragleave", function (ev) {
    var target = ev.target.closest(".panel.drop-target");
    if (!target) return;
    // Only drop the indicator if we've actually left this panel (not just
    // crossed into one of its children).
    if (!target.contains(ev.relatedTarget)) target.classList.remove("drop-target");
  });
  document.addEventListener("drop", function (ev) {
    if (!draggingId) return;
    var target = ev.target.closest(".panel[data-panel-id]");
    if (!target) return;
    var targetId = target.getAttribute("data-panel-id");
    if (targetId === draggingId) return;
    ev.preventDefault();
    var dragged = document.querySelector(
      ".panel[data-panel-id=\"" + draggingId + "\"]");
    if (!dragged) return;
    // Swap the two nodes — replace target with a placeholder, move
    // dragged into target's slot, then move target into dragged's
    // original slot.  Works for same-row reorder and cross-row swap.
    var draggedParent = dragged.parentNode;
    var draggedNext   = dragged.nextSibling;
    var targetParent  = target.parentNode;
    var targetNext    = target.nextSibling;
    targetParent.insertBefore(dragged,
      targetNext === dragged ? targetNext.nextSibling : targetNext);
    draggedParent.insertBefore(target,
      draggedNext === target ? draggedNext.nextSibling : draggedNext);
    target.classList.remove("drop-target");
    saveCurrent(captureArrangement());
  });

  // ----- Layout dropdown — save / restore / delete named arrangements ----
  function renderMenu(menu) {
    var store = loadStore();
    var names = Object.keys(store).sort();
    var html = '<div class="head">Saved arrangements</div>';
    if (names.length === 0) {
      html += '<div class="layout-item" style="color: var(--fg-4);">'
            + 'Drag panels to rearrange, then save</div>';
    } else {
      names.forEach(function (n) {
        html += '<div class="layout-item" data-restore="' + n + '">'
              + '<span>' + n + '</span>'
              + '<span class="del" data-del="' + n + '" '
              +       'title="Delete arrangement">×</span>'
              + '</div>';
      });
    }
    if (loadCurrent()) {
      html += '<div class="layout-item" data-reset '
            +       'style="color: var(--fg-3); font-style: italic;">'
            + '<span>↺ Reset to default</span></div>';
    }
    html += '<div class="layout-save-row">'
          + '<input type="text" id="layout-save-input" name="layout-save"'
          + ' autocomplete="off" placeholder="save current as…"'
          + ' data-layout-input>'
          + '<button data-layout-save>Save</button>'
          + '</div>';
    menu.innerHTML = html;

    menu.querySelectorAll("[data-restore]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        if (ev.target.matches("[data-del]")) return;
        var n = el.getAttribute("data-restore");
        var s = loadStore();
        if (!s[n]) return;
        applyArrangement(s[n]);
        saveCurrent(s[n]);
        menu.classList.remove("open");
      });
    });
    menu.querySelectorAll("[data-del]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var n = el.getAttribute("data-del");
        var s = loadStore();
        delete s[n];
        saveStore(s);
        renderMenu(menu);
      });
    });
    var resetEl = menu.querySelector("[data-reset]");
    if (resetEl) {
      resetEl.addEventListener("click", function () {
        saveCurrent(null);
        // Default arrangement = page-load DOM order.  Easiest way to
        // get back to it without round-tripping the server is a full
        // reload.
        window.location.reload();
      });
    }
    var saveBtn = menu.querySelector("[data-layout-save]");
    var input = menu.querySelector("[data-layout-input]");
    if (saveBtn && input) {
      saveBtn.addEventListener("click", function () {
        var name = (input.value || "").trim();
        if (!name) return;
        var s = loadStore();
        s[name] = captureArrangement();
        saveStore(s);
        input.value = "";
        renderMenu(menu);
      });
    }
  }

  document.querySelectorAll("[data-layout-toggle]").forEach(function (btn) {
    // Wrap btn in a relative position container if not already
    if (getComputedStyle(btn).position === "static") btn.style.position = "relative";
    var menu = document.createElement("div");
    menu.className = "layout-menu";
    btn.appendChild(menu);
    btn.addEventListener("click", function (ev) {
      // Clicks INSIDE the menu (e.g. on the rename input or Save button)
      // bubble up through here too — don't toggle the menu in that case.
      // Just stopPropagation so the outside-click handler doesn't close
      // the menu either, and let inner handlers run.
      if (menu.contains(ev.target) && ev.target !== menu) {
        ev.stopPropagation();
        return;
      }
      ev.stopPropagation();
      var open = menu.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        renderMenu(menu);
        // Auto-focus the rename input so the operator can type
        // immediately without a second click.
        var input = menu.querySelector("[data-layout-input]");
        if (input) setTimeout(function () { input.focus(); }, 0);
      }
    });
    // Submit-on-Enter convenience; Escape closes the menu.
    menu.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        ev.preventDefault();
        menu.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
        return;
      }
      if (ev.key !== "Enter") return;
      var input = ev.target.closest("[data-layout-input]");
      if (!input) return;
      ev.preventDefault();
      var saveBtn = menu.querySelector("[data-layout-save]");
      if (saveBtn) saveBtn.click();
    });
    document.addEventListener("click", function () {
      if (menu.classList.contains("open")) {
        menu.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
      }
    });
  });
})();

// ===========================================================================
// POP-OUT CLICKS — open the right /panel/<name> URL in a fresh window.
// Event-delegated so re-renders (SSE swaps #panels every tick) don't
// strip the handler off the new icon nodes.
// ===========================================================================
(function () {
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-popout]");
    if (!btn) return;
    ev.stopPropagation();
    var target = btn.getAttribute("data-popout");
    var features = "popup=yes,width=1280,height=820";
    window.open("/panel/" + target, "plenith-" + target, features);
  });
})();

// ===========================================================================
// ENGAGEMENT FILTER + MULTI-SELECT — both have to survive SSE re-renders.
// State lives in module-level closures + the input's *value* is reflected
// in a sessionStorage key so re-renders restore what the operator typed.
// `window.plenithReapplyClientState()` is called after every SSE update
// to put the value back, apply the filter, and restore checked rows.
// ===========================================================================
(function () {
  // Persistent state across SSE re-renders
  var STORE_QUERY    = "plenith-filter-query";
  var STORE_CHIP     = "plenith-filter-chip";     // "all" | "critical" | "llm" | "last-1h"
  var STORE_SELECTED = "plenith-multi-select";

  function loadSelected() {
    try {
      var s = JSON.parse(sessionStorage.getItem(STORE_SELECTED) || "[]");
      return new Set(Array.isArray(s) ? s : []);
    } catch (e) { return new Set(); }
  }
  function saveSelected(s) {
    sessionStorage.setItem(STORE_SELECTED, JSON.stringify(Array.from(s)));
  }

  function currentQuery() {
    return sessionStorage.getItem(STORE_QUERY) || "";
  }
  function setQuery(q) {
    sessionStorage.setItem(STORE_QUERY, q || "");
  }
  function currentChip() {
    return sessionStorage.getItem(STORE_CHIP) || "all";
  }
  function setChip(c) {
    sessionStorage.setItem(STORE_CHIP, c || "all");
  }

  function chipMatches(row, chip) {
    if (chip === "all") return true;
    if (chip === "critical") return row.getAttribute("data-eng-crit") === "1";
    if (chip === "llm")      return row.getAttribute("data-eng-llm")  === "1";
    if (chip === "last-1h") {
      var ts = parseInt(row.getAttribute("data-eng-last") || "0", 10);
      if (!ts) return false;
      return (Date.now() / 1000 - ts) <= 3600;
    }
    return true;
  }

  function applyFilter() {
    var q = currentQuery().toLowerCase().trim();
    var chip = currentChip();
    var total = 0, visible = 0;
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      total += 1;
      var hay = (row.getAttribute("data-eng-hay") || "").toLowerCase();
      var hitText = !q || hay.indexOf(q) !== -1;
      var hitChip = chipMatches(row, chip);
      var hit = hitText && hitChip;
      row.style.display = hit ? "" : "none";
      if (hit) visible += 1;
    });
    // Reflect the active chip in the chip strip — only one chip is
    // active at a time; SSE swaps re-render the chips so we have to
    // re-apply the class every render.
    document.querySelectorAll("[data-filter-chip]").forEach(function (c) {
      var isActive = c.getAttribute("data-filter-chip") === chip;
      c.classList.toggle("active", isActive);
      c.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    // Surface the match count on the panel header so it's obvious the
    // filter is working (otherwise with one matching row vs one total
    // you can't tell whether anything happened).
    var counter = document.querySelector("[data-filter-count]");
    if (counter) {
      var filtering = q || chip !== "all";
      counter.textContent = filtering
        ? "filter: " + visible + " of " + total
        : total + " total";
    }
    var search = document.querySelector("[data-eng-search]");
    if (search && search.value !== currentQuery() &&
        document.activeElement !== search) {
      // Only restore the value when the search isn't focused — otherwise
      // we'd overwrite mid-keystroke (this happens in the SSE re-apply
      // path; the live input event handler handles the typing case).
      search.value = currentQuery();
    }
  }

  function applyMultiselect() {
    var selected = loadSelected();
    document.querySelectorAll("[data-eng-check]").forEach(function (cb) {
      var id = cb.getAttribute("data-eng-check");
      if (selected.has(id)) {
        cb.classList.add("on");
        cb.textContent = "✓";
      } else {
        cb.classList.remove("on");
        cb.textContent = "";
      }
    });
    document.querySelectorAll("[data-batch-bar]").forEach(function (bar) {
      bar.style.display = selected.size > 0 ? "" : "none";
      bar.querySelectorAll("[data-batch-count]").forEach(function (el) {
        el.textContent = String(selected.size);
      });
    });
  }

  // Exposed so the SSE handler can re-run these after each swap
  window.plenithReapplyClientState = function () {
    // Order matters: arrangement (DOM re-order) BEFORE selection (which
    // refetches detail.html if needed) and filter (which iterates rows).
    if (window.plenithApplyArrangement)
      window.plenithApplyArrangement();
    applyFilter();
    applyMultiselect();
    if (window.plenithApplyEngagementSelection)
      window.plenithApplyEngagementSelection();
    if (window.plenithApplyConfidenceTrend)
      window.plenithApplyConfidenceTrend();
  };

  // Filter input — event-delegated since #panels is re-rendered.
  document.addEventListener("input", function (ev) {
    var search = ev.target.closest("[data-eng-search]");
    if (!search) return;
    setQuery(search.value || "");
    applyFilter();
  });

  // Filter chips — single-select; clicking the already-active chip
  // resets to "all" (cheap toggle-off without a separate clear button).
  document.addEventListener("click", function (ev) {
    var chip = ev.target.closest("[data-filter-chip]");
    if (!chip) return;
    ev.stopPropagation();
    var name = chip.getAttribute("data-filter-chip") || "all";
    if (currentChip() === name && name !== "all") name = "all";
    setChip(name);
    applyFilter();
  });

  // Multi-select checkbox clicks
  document.addEventListener("click", function (ev) {
    var cb = ev.target.closest("[data-eng-check]");
    if (!cb) return;
    ev.stopPropagation();
    var id = cb.getAttribute("data-eng-check");
    var selected = loadSelected();
    if (selected.has(id)) selected.delete(id); else selected.add(id);
    saveSelected(selected);
    applyMultiselect();
  });

  // `/` keyboard shortcut to focus the search box
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "/" && ev.target.tagName !== "INPUT" && ev.target.tagName !== "TEXTAREA") {
      var search = document.querySelector("[data-eng-search]");
      if (search) { ev.preventDefault(); search.focus(); }
    }
  });

  // First-page-load: apply any persisted state
  document.addEventListener("DOMContentLoaded", function () {
    window.plenithReapplyClientState();
  });
  // And immediately for synchronous-load case
  if (document.readyState !== "loading") {
    setTimeout(function () { window.plenithReapplyClientState(); }, 0);
  }

  // -----------------------------------------------------------------------
  // ENGAGEMENT ROW CLICK → swap the detail panel.  Selection is persisted
  // in sessionStorage and re-applied after every SSE swap (the server-side
  // renderer always picks engs[0] as selected, so without this the panel
  // would flick back to the first engagement every 3s).
  //
  // The detail.html response includes a <template data-export-strip> at
  // the top — we use it to also replace the audit/IoC/sigma/etc. anchors
  // in the panel header so they point at the newly-selected engagement
  // instead of staying on engs[0].
  // -----------------------------------------------------------------------

  var STORE_SELECTED_EID = "plenith-selected-eid";
  var pendingFetchSeq = 0;

  function getSelectedEid() {
    return sessionStorage.getItem(STORE_SELECTED_EID) || "";
  }
  function setSelectedEid(eid) {
    if (eid) sessionStorage.setItem(STORE_SELECTED_EID, eid);
    else sessionStorage.removeItem(STORE_SELECTED_EID);
  }

  function findDetailPanel() {
    var p = document.querySelector("[data-detail-panel]");
    if (p) return p;
    // Fallback for older renders / panels without the tag
    var found = null;
    document.querySelectorAll(".main .panel").forEach(function (pp) {
      if (pp.querySelector(".detail-header")) found = pp;
    });
    if (found) return found;
    var panels = document.querySelectorAll(".main > .panel");
    return panels.length >= 2 ? panels[1] : null;
  }

  async function loadDetail(detailPanel, eid) {
    if (!detailPanel || !eid) return;
    var seq = ++pendingFetchSeq;
    var url = "/api/engagements/" + encodeURIComponent(eid) + "/detail.html";
    var resp, htmlText;
    try {
      resp = await fetch(url, { headers: { "Accept": "text/html" } });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      htmlText = await resp.text();
    } catch (e) {
      console.warn("Failed to load engagement detail:", e);
      return;
    }
    // Discard stale responses (newer click already in flight)
    if (seq !== pendingFetchSeq) return;
    // The latest detail panel might be a different DOM node after an
    // intervening SSE swap — re-resolve.
    var panel = findDetailPanel();
    if (!panel) return;

    var wrapper = document.createElement("div");
    wrapper.innerHTML = htmlText;
    // Pluck out the export-strip template (if present) and use it to
    // replace the existing audit/IoC/sigma anchors in the panel header.
    var stripTpl = wrapper.querySelector("template[data-export-strip]");
    if (stripTpl) {
      var host = panel.querySelector("[data-export-host]");
      if (host) {
        // Remove only the export anchors; preserve the popout icon.
        host.querySelectorAll("a.filter").forEach(function (a) { a.remove(); });
        var popBtn = host.querySelector("[data-popout]");
        var frag = stripTpl.content.cloneNode(true);
        if (popBtn) host.insertBefore(frag, popBtn);
        else host.appendChild(frag);
      }
      stripTpl.remove();
    }
    // Swap body — keep the panel-header in place, replace everything
    // below it with the fresh content.
    var header = panel.querySelector(".panel-header");
    panel.innerHTML = "";
    if (header) panel.appendChild(header);
    while (wrapper.firstChild) panel.appendChild(wrapper.firstChild);
    panel.setAttribute("data-current-eid", eid);

    // Update the popout target so ↗ opens the right engagement.
    var popBtn2 = panel.querySelector(".panel-header [data-popout]");
    if (popBtn2) popBtn2.setAttribute("data-popout", "engagement/" + eid);
  }

  function applyEngagementSelection() {
    var eid = getSelectedEid();
    if (!eid) return;
    // Mark the matching row (if visible after filter/render)
    var matched = false;
    document.querySelectorAll("[data-eng-row]").forEach(function (r) {
      var rid = r.getAttribute("data-eng-id");
      var hit = rid === eid;
      r.classList.toggle("selected", hit);
      if (hit) matched = true;
    });
    if (!matched) return;
    var panel = findDetailPanel();
    if (!panel) return;
    if (panel.getAttribute("data-current-eid") === eid) return;
    loadDetail(panel, eid);
  }
  window.plenithApplyEngagementSelection = applyEngagementSelection;

  document.addEventListener("click", function (ev) {
    if (ev.target.closest("[data-eng-check], [data-popout], .filter, .ack-btn, button, a, input, textarea")) {
      return;
    }
    var row = ev.target.closest("[data-eng-row]");
    if (!row) return;
    var eid = row.getAttribute("data-eng-id");
    if (!eid) return;
    setSelectedEid(eid);
    document.querySelectorAll("[data-eng-row]").forEach(function (r) {
      r.classList.toggle("selected", r === row);
    });
    var panel = findDetailPanel();
    if (panel) loadDetail(panel, eid);
  });
})();

// ===========================================================================
// SSE — subscribe to /api/stream and swap the panel HTML on each push.
// Also consumes Phase 6 payload fields:
//   data.new_alerts        — alerts that arrived since the LAST tick.
//                            Each one creates a toast; critical ones
//                            also fire a desktop Notification when the
//                            tab is unfocused (permission permitting).
//   data.critical_unacked  — count of un-ack'd critical alerts; drives
//                            the tab-title badge and favicon dot.
// ===========================================================================
(function () {
  var holder = document.getElementById("panels");
  if (!holder) return;
  var url = "/api/stream";
  if (holder.getAttribute("data-panel-filter")) {
    url += "?panel=" + encodeURIComponent(holder.getAttribute("data-panel-filter"));
  }
  var es = new EventSource(url);
  var ts = document.getElementById("ts");
  var dropouts = 0;
  // Skip the panel swap while the operator is actively focused on ANY
  // interactive element inside #panels.  The swap replaces every child
  // node — including the element being typed into OR tabbed through —
  // which is the bug that made the search box / notes textarea
  // un-typeable, AND broke keyboard tab-chain navigation across the
  // action buttons (the focused button disappears between renders, so
  // the user can never reach Kill).  New alerts and the critical-count
  // badge still update from the same SSE payload; only the in-panel
  // HTML render is paused until focus leaves.
  function shouldSkipSwap() {
    var active = document.activeElement;
    if (!active || active === document.body) return false;
    if (!holder.contains(active)) return false;
    var tag = active.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    if (tag === "BUTTON" || tag === "A") return true;
    if (active.isContentEditable) return true;
    if (active.hasAttribute("tabindex") &&
        active.getAttribute("tabindex") !== "-1") return true;
    return false;
  }

  es.onmessage = function (e) {
    try {
      var data = JSON.parse(e.data);
      if (data.html && !shouldSkipSwap()) {
        holder.innerHTML = data.html;
        // Re-apply filter input value, filter visibility, and multi-
        // select highlight after every SSE swap — the swap replaces
        // every node inside #panels so any client-side state has to
        // be reflected back into the fresh DOM.
        if (window.plenithReapplyClientState)
          window.plenithReapplyClientState();
      }
      if (data.ts && ts) ts.textContent = data.ts;
      dropouts = 0;
      if (Array.isArray(data.new_alerts) && data.new_alerts.length > 0) {
        data.new_alerts.forEach(function (a) {
          if (window.plenithPushAlertToast)
            window.plenithPushAlertToast(a);
          if (window.plenithMaybeNotify)
            window.plenithMaybeNotify(a);
        });
      }
      if (typeof data.critical_unacked === "number") {
        document.dispatchEvent(new CustomEvent(
          "plenith:critical-count",
          { detail: { count: data.critical_unacked } }
        ));
      }
    } catch (err) { /* swallow */ }
  };
  es.onerror = function () {
    dropouts += 1;
    if (ts) ts.textContent = "reconnecting ... (" + dropouts + ")";
  };
})();

// ===========================================================================
// ACKNOWLEDGE BUTTONS — wire the per-alert Ack / Un-ack toggles to the
// dashboard's /api/engagements/<id>/ack endpoint, with a 10-second undo
// toast so an accidental click can be recovered.
// ===========================================================================
(function () {
  var toastEl = null;
  var toastTimer = null;
  var toastCountdown = null;

  function clearToast() {
    if (toastEl && toastEl.parentNode) toastEl.parentNode.removeChild(toastEl);
    toastEl = null;
    if (toastTimer)     { clearTimeout(toastTimer);     toastTimer = null; }
    if (toastCountdown) { clearInterval(toastCountdown); toastCountdown = null; }
  }

  function showUndoToast(message, undoFn) {
    clearToast();
    toastEl = document.createElement("div");
    toastEl.className = "ack-toast";
    var secondsLeft = 10;
    toastEl.innerHTML =
      '<span class="check">✓</span>' +
      '<span class="label"></span>' +
      '<button class="undo">Undo</button>' +
      '<span class="countdown"></span>';
    toastEl.querySelector(".label").textContent = message;
    toastEl.querySelector(".countdown").textContent = "(" + secondsLeft + "s)";
    toastEl.querySelector(".undo").addEventListener("click", function () {
      clearToast();
      try { undoFn(); } catch (e) { console.warn("undo failed:", e); }
    });
    document.body.appendChild(toastEl);
    toastCountdown = setInterval(function () {
      secondsLeft -= 1;
      if (toastEl) {
        var c = toastEl.querySelector(".countdown");
        if (c) c.textContent = "(" + secondsLeft + "s)";
      }
    }, 1000);
    toastTimer = setTimeout(clearToast, 10000);
  }

  async function ackAction(eng, action) {
    var resp = await fetch("/api/engagements/" + encodeURIComponent(eng) + "/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_name: action,
        op_id: localStorage.getItem("plenith-op-id") || "anonymous",
      }),
    });
    if (!resp.ok) throw new Error("ack failed: " + resp.status);
    return await resp.json();
  }

  async function unackAction(eng, action) {
    var resp = await fetch(
      "/api/engagements/" + encodeURIComponent(eng) +
      "/ack/" + encodeURIComponent(action),
      { method: "DELETE" }
    );
    if (!resp.ok && resp.status !== 404) {
      throw new Error("unack failed: " + resp.status);
    }
    return true;
  }

  // Optimistic DOM updates after an ack/un-ack — the SSE re-render is
  // paused while focus is on the just-clicked button (see shouldSkipSwap),
  // so without this the visible counts wouldn't decrement until the user
  // tabbed away.  Exposed on window so the batch Ack-all handler can
  // call it after each loop iteration too.
  function applyAckStateLocally(eng, action, acked) {
    // 1) Per-alert button state
    var btn = document.querySelector(
      '.ack-btn[data-ack-eng="' + eng + '"][data-ack-action="' + action + '"]');
    if (btn) {
      btn.setAttribute("data-ack-state", acked ? "acked" : "pending");
      btn.textContent = acked ? "Un-ack" : "Acknowledge";
      // Row dim — matches the .alert.acked rendering from the server
      var row = btn.closest(".alert");
      if (row) row.classList.toggle("acked", acked);
    }
    // 2) Acknowledge-all button — recompute pending list from visible
    //    per-alert buttons rather than mutating the cached attribute,
    //    so undo/redo cycles stay consistent.
    var ackAll = document.querySelector(
      '[data-quick-action="ack-all"][data-eng="' + eng + '"]');
    if (ackAll) {
      var pending = [];
      document.querySelectorAll(
        '.ack-btn[data-ack-eng="' + eng + '"][data-ack-state="pending"]'
      ).forEach(function (b) {
        var a = b.getAttribute("data-ack-action");
        if (a) pending.push(a);
      });
      ackAll.setAttribute("data-pending-actions", pending.join(" "));
      var badge = ackAll.querySelector(".dim2");
      var n = pending.length;
      if (badge) badge.textContent = n ? "(" + n + ")" : "";
      if (n === 0) {
        ackAll.setAttribute("disabled", "");
        ackAll.setAttribute("title", "No pending alerts to acknowledge");
      } else {
        ackAll.removeAttribute("disabled");
        ackAll.setAttribute(
          "title",
          "Ack " + n + " pending alert(s) in this engagement");
      }
    }
    // 3) "Alerts (N pending / M)" header counter — see the panel-header
    //    rendering; the pending span carries data-alerts-pending so we
    //    can update it without re-rendering the whole header.
    var pendingHeader = document.querySelector(
      '[data-alerts-pending][data-eng="' + eng + '"]');
    if (pendingHeader) {
      var p = document.querySelectorAll(
        '.ack-btn[data-ack-eng="' + eng + '"][data-ack-state="pending"]'
      ).length;
      pendingHeader.textContent = p;
    }
  }
  window.plenithApplyAckStateLocally = applyAckStateLocally;

  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest(".ack-btn");
    if (!btn) return;
    ev.preventDefault();
    ev.stopPropagation();
    var eng    = btn.getAttribute("data-ack-eng");
    var action = btn.getAttribute("data-ack-action");
    var state  = btn.getAttribute("data-ack-state");
    if (!eng || !action) return;
    btn.disabled = true;
    try {
      if (state === "acked") {
        await unackAction(eng, action);
        applyAckStateLocally(eng, action, false);
        showUndoToast(
          "Un-ack’d " + action + " on " + eng.substring(0, 8),
          function () { return ackAction(eng, action); }
        );
      } else {
        await ackAction(eng, action);
        applyAckStateLocally(eng, action, true);
        showUndoToast(
          "Ack’d " + action + " on " + eng.substring(0, 8),
          function () { return unackAction(eng, action); }
        );
      }
    } catch (e) {
      console.warn("ack-toggle failed:", e);
    } finally {
      btn.disabled = false;
    }
  });
})();

// ===========================================================================
// QUICK ACTIONS (Phase 3) — Snapshot, Escalate, Kill, Save Note, Delete Note.
// All hit the dashboard's own /api/engagements/* endpoints.  Toasts use the
// same .ack-toast component for visual consistency.
// ===========================================================================
(function () {
  function getOpId() {
    return localStorage.getItem("plenith-op-id") || "anonymous";
  }

  function showToast(message, ms) {
    var existing = document.querySelector(".ack-toast");
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
    var el = document.createElement("div");
    el.className = "ack-toast";
    el.innerHTML = '<span class="check">✓</span><span class="label"></span>';
    el.querySelector(".label").textContent = message;
    document.body.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, ms || 4000);
  }

  async function postJSON(url, body) {
    var resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    var data;
    try { data = await resp.json(); } catch (e) { data = {}; }
    if (!resp.ok) {
      throw new Error("HTTP " + resp.status + ": " +
        (data.error || data.detail || resp.statusText));
    }
    return data;
  }

  async function deleteAt(url) {
    var resp = await fetch(url, { method: "DELETE" });
    var data;
    try { data = await resp.json(); } catch (e) { data = {}; }
    if (!resp.ok && resp.status !== 404) {
      throw new Error("HTTP " + resp.status);
    }
    return data;
  }

  // --- Snapshot / Escalate / Kill (hold-to-confirm) ----------------------
  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-quick-action]");
    if (!btn) return;
    var action = btn.getAttribute("data-quick-action");
    var eng    = btn.getAttribute("data-eng");
    if (!eng) return;

    if (action === "snapshot") {
      ev.preventDefault();
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/snapshot",
          { op_id: getOpId() }
        );
        showToast("Snapshot saved · " + (r.name || "tar.gz") +
                  " (" + Math.round((r.size || 0) / 1024) + " KB)");
      } catch (e) {
        showToast("Snapshot failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === "escalate") {
      ev.preventDefault();
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/escalate",
          { tier: "L2", op_id: getOpId() }
        );
        var fired = (r.connectors_fired || []);
        showToast(fired.length
          ? "Escalated · fired: " + fired.join(", ")
          : "Escalate previewed — no chatops connectors configured.");
      } catch (e) {
        showToast("Escalate failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === "ack-all") {
      ev.preventDefault();
      var raw = btn.getAttribute("data-pending-actions") || "";
      var pending = raw.split(/\s+/).filter(function (s) { return s.length > 0; });
      if (!pending.length) {
        showToast("No pending alerts to acknowledge.");
        return;
      }
      btn.disabled = true;
      var ok = 0, fail = 0, firstErr = "";
      for (var i = 0; i < pending.length; i++) {
        try {
          await postJSON(
            "/api/engagements/" + encodeURIComponent(eng) + "/ack",
            { action_name: pending[i], op_id: getOpId() }
          );
          ok += 1;
          // Optimistic per-alert + counter update on each successful ack,
          // matching the per-button click handler so the visible state
          // doesn't wait for the next SSE re-render.
          if (window.plenithApplyAckStateLocally)
            window.plenithApplyAckStateLocally(eng, pending[i], true);
        } catch (e) {
          fail += 1;
          if (!firstErr) firstErr = pending[i] + ": " + e.message;
        }
      }
      if (fail === 0) {
        showToast("Acked " + ok + " alert(s)");
      } else {
        showToast("Acked " + ok + "/" + (ok + fail) + " — first failure: " + firstErr, 8000);
      }
      btn.disabled = false;
      return;
    }

    if (action === "isolate") {
      ev.preventDefault();
      var ip = btn.getAttribute("data-ip") || "";
      if (!ip) { showToast("Cannot isolate: source IP missing"); return; }
      // No hold-to-confirm but it IS a state mutation — bounce off the
      // browser's native confirm() so a stray click doesn't blackhole
      // the operator's own home IP during a demo.
      if (!confirm("Mark " + ip + " as failed MFA?\n" +
                   "This writes state-docker/mfa/" + ip + ".fail; " +
                   "the orchestrator's routing layer will treat this IP as " +
                   "untrusted on its next decision.")) return;
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/mfa/decisions/" + encodeURIComponent(ip),
          { decision: "fail", reason: "operator isolate from dashboard",
            op_id: getOpId() }
        );
        showToast("Isolated " + ip + " · wrote " +
                  ((r.path || "").split(/[\\/]/).pop() || "decision file"));
      } catch (e) {
        showToast("Isolate failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    // Kill: handled by the hold listener below — single clicks are ignored.
  });

  // Hold-to-confirm for Kill buttons.  Mouse / touch / stylus all work
  // via Pointer Events; keyboard support uses Space-and-hold (the SR
  // user can tab to the button, then hold Space for 1 second to fire).
  // Releasing early aborts.

  // Shared hold-trigger: starts the 1s timer, returns an `abort` fn the
  // caller invokes when the user releases or focus leaves.
  function _startKillHold(btn, reason) {
    btn.classList.add("holding");
    var fired = false;
    var holdTimer = setTimeout(async function () {
      fired = true;
      btn.disabled = true;
      var eng = btn.getAttribute("data-eng");
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/kill",
          { op_id: getOpId(), reason: reason }
        );
        btn.setAttribute("data-kill-state", "pending");
        showToast("Kill request queued — orchestrator will drop the connection on next poll.");
      } catch (e) {
        showToast("Kill failed: " + e.message);
      } finally {
        btn.classList.remove("holding");
        btn.disabled = false;
      }
    }, 1000);
    return function abort() {
      if (fired) return;
      clearTimeout(holdTimer);
      btn.classList.remove("holding");
    };
  }

  document.addEventListener("pointerdown", function (ev) {
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    if (ev.button !== undefined && ev.button !== 0) return;
    ev.preventDefault();
    var pid = ev.pointerId;
    try { btn.setPointerCapture(pid); } catch (e) {}
    var abort = _startKillHold(btn, "operator click-and-hold");
    function teardown(e) {
      if (e && e.pointerId !== pid) return;
      abort();
      try { btn.releasePointerCapture(pid); } catch (_) {}
      btn.removeEventListener("pointerup",     teardown);
      btn.removeEventListener("pointerleave",  teardown);
      btn.removeEventListener("pointercancel", teardown);
    }
    btn.addEventListener("pointerup",     teardown);
    btn.addEventListener("pointerleave",  teardown);
    btn.addEventListener("pointercancel", teardown);
  });

  // Keyboard equivalent: Space-and-hold for 1 second.  We preventDefault
  // on keydown to suppress the synthetic click that Space normally fires
  // on a <button> when released.  Holding fires the same kill flow as
  // mouse / touch.  Releasing Space or blurring the button aborts.
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== " " && ev.code !== "Space") return;
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    if (ev.repeat) { ev.preventDefault(); return; }
    if (btn._killHoldAbort) return;  // already holding from previous keydown
    ev.preventDefault();
    btn._killHoldAbort = _startKillHold(btn, "operator key-and-hold");
    function teardown() {
      if (btn._killHoldAbort) btn._killHoldAbort();
      btn._killHoldAbort = null;
      btn.removeEventListener("keyup", teardown);
      btn.removeEventListener("blur",  teardown);
    }
    btn.addEventListener("keyup", function (ke) {
      if (ke.key === " " || ke.code === "Space") teardown();
    });
    btn.addEventListener("blur", teardown);
  });

  // --- Notes markdown toolbar -------------------------------------------
  // Operates on the textarea's current selection and dispatches an
  // `input` event so any other listener (e.g. character counters) sees
  // the change.  All transforms are reversible by re-clicking the same
  // button on a previously-wrapped selection.
  function findNoteTextarea(toolbarEl) {
    var eng = toolbarEl.getAttribute("data-note-toolbar");
    if (!eng) return null;
    return document.querySelector('[data-note-input="' + eng + '"]');
  }
  function applyInlineWrap(ta, marker) {
    var s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
    var sel = v.slice(s, e);
    var inside = v.slice(s - marker.length, s) === marker &&
                 v.slice(e, e + marker.length) === marker;
    if (inside) {
      // Strip surrounding markers
      ta.value = v.slice(0, s - marker.length) + sel + v.slice(e + marker.length);
      ta.selectionStart = s - marker.length;
      ta.selectionEnd   = e - marker.length;
    } else if (sel) {
      ta.value = v.slice(0, s) + marker + sel + marker + v.slice(e);
      ta.selectionStart = s + marker.length;
      ta.selectionEnd   = e + marker.length;
    } else {
      // No selection: insert paired markers and place cursor between
      ta.value = v.slice(0, s) + marker + marker + v.slice(e);
      ta.selectionStart = ta.selectionEnd = s + marker.length;
    }
  }
  function applyLinePrefix(ta, prefix) {
    var s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
    // Expand selection to whole lines so the prefix toggle is per-line.
    var lineStart = v.lastIndexOf("\n", s - 1) + 1;
    var lineEnd = v.indexOf("\n", e);
    if (lineEnd === -1) lineEnd = v.length;
    var block = v.slice(lineStart, lineEnd);
    // Toggle: if every line already has the prefix, strip it. Else add.
    var lines = block.split("\n");
    var all = lines.every(function (l) { return l.indexOf(prefix) === 0; });
    var transformed = lines.map(function (l) {
      return all ? l.slice(prefix.length) : prefix + l;
    }).join("\n");
    ta.value = v.slice(0, lineStart) + transformed + v.slice(lineEnd);
    ta.selectionStart = lineStart;
    ta.selectionEnd   = lineStart + transformed.length;
  }
  function runMd(kind, ta) {
    if (kind === "bold")   applyInlineWrap(ta, "**");
    else if (kind === "italic") applyInlineWrap(ta, "*");
    else if (kind === "code")   applyInlineWrap(ta, "`");
    else if (kind === "list")   applyLinePrefix(ta, "- ");
    else if (kind === "quote")  applyLinePrefix(ta, "> ");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
    ta.focus();
  }
  document.addEventListener("click", function (ev) {
    var tb = ev.target.closest("[data-md]");
    if (!tb) return;
    var toolbar = tb.closest("[data-note-toolbar]");
    if (!toolbar) return;
    ev.preventDefault();
    var ta = findNoteTextarea(toolbar);
    if (!ta) return;
    runMd(tb.getAttribute("data-md"), ta);
  });
  // Keyboard shortcuts inside the textarea
  document.addEventListener("keydown", function (ev) {
    var ta = ev.target.closest("[data-note-input]");
    if (!ta) return;
    if (!(ev.ctrlKey || ev.metaKey)) return;
    var kind = null;
    if (ev.key === "b" || ev.key === "B") kind = "bold";
    else if (ev.key === "i" || ev.key === "I") kind = "italic";
    else if (ev.key === "e" || ev.key === "E") kind = "code";
    if (!kind) return;
    ev.preventDefault();
    runMd(kind, ta);
  });

  // --- Notes: save + delete ----------------------------------------------
  document.addEventListener("click", async function (ev) {
    var saveBtn = ev.target.closest("[data-note-save]");
    if (saveBtn) {
      ev.preventDefault();
      var eng = saveBtn.getAttribute("data-note-save");
      var textarea = document.querySelector('[data-note-input="' + eng + '"]');
      if (!textarea) return;
      var body = (textarea.value || "").trim();
      if (!body) return;
      saveBtn.disabled = true;
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/notes",
          { body: body, author: getOpId() }
        );
        textarea.value = "";
        showToast("Note saved.");
      } catch (e) {
        showToast("Note save failed: " + e.message);
      } finally {
        saveBtn.disabled = false;
      }
      return;
    }
    var delBtn = ev.target.closest("[data-note-delete]");
    if (delBtn) {
      ev.preventDefault();
      ev.stopPropagation();
      var noteId = delBtn.getAttribute("data-note-delete");
      var eng    = delBtn.getAttribute("data-eng");
      if (!eng || !noteId) return;
      delBtn.disabled = true;
      try {
        await deleteAt(
          "/api/engagements/" + encodeURIComponent(eng) +
          "/notes/" + encodeURIComponent(noteId)
        );
        showToast("Note deleted.");
      } catch (e) {
        showToast("Delete failed: " + e.message);
      } finally {
        delBtn.disabled = false;
      }
    }
  });

  // --- Batch action bar -------------------------------------------------
  // Snapshot / Escalate over the multi-select set.  We loop client-side
  // (one POST per engagement) because the server only batches /ack today;
  // adding /batch/snapshot etc. server-side would need orchestration
  // (rate-limit, concurrency cap) we don't want to litigate yet.
  function loadSelectedSet() {
    try {
      var s = JSON.parse(sessionStorage.getItem("plenith-multi-select") || "[]");
      return Array.isArray(s) ? s : [];
    } catch (e) { return []; }
  }
  function clearSelectedSet() {
    sessionStorage.setItem("plenith-multi-select", "[]");
    if (window.plenithReapplyClientState) window.plenithReapplyClientState();
  }
  async function batchPost(verb, body) {
    var ids = loadSelectedSet();
    if (!ids.length) return;
    var ok = 0, fail = 0;
    var failReasons = [];
    for (var i = 0; i < ids.length; i++) {
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(ids[i]) + "/" + verb,
          Object.assign({ op_id: getOpId() }, body || {})
        );
        ok += 1;
      } catch (e) {
        fail += 1;
        failReasons.push(ids[i].slice(0, 8) + ": " + e.message);
      }
    }
    if (fail === 0) {
      showToast(verb + " · " + ok + " of " + ids.length + " succeeded");
    } else {
      showToast(verb + " · " + ok + "/" + ids.length + " ok, " +
                fail + " failed (" + failReasons[0] + (fail > 1 ? ", …" : "") + ")",
                8000);
    }
  }

  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-batch-action]");
    if (!btn) return;
    ev.preventDefault();
    var action = btn.getAttribute("data-batch-action");
    if (action === "clear") { clearSelectedSet(); return; }
    var ids = loadSelectedSet();
    if (!ids.length) return;
    btn.disabled = true;
    try {
      if (action === "snapshot") {
        await batchPost("snapshot", {});
      } else if (action === "escalate") {
        await batchPost("escalate", { tier: "L2" });
      } else {
        showToast("Unknown batch action: " + action);
      }
    } finally {
      btn.disabled = false;
    }
  });
})();

// ===========================================================================
// TAB TITLE BADGE + FAVICON DOT — Phase 6.  Two reactions to the
// `plenith:critical-count` custom event:
//   - document.title prepends "(N CRIT) " so the count is visible on
//     the tab strip even when the tab is unfocused / minimized
//   - favicon swaps to an "alert" variant (same brand mark plus a red
//     dot) when count > 0; back to normal at 0
// ===========================================================================
(function () {
  var baseTitle = document.title;
  function ensureFavicon() {
    var link = document.querySelector('link[rel="icon"]');
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    return link;
  }
  // Brand-mark favicon (amber diamond on dark) — two variants encoded
  // as inline data URIs so we don't need a separate static asset.
  var FAV_NORMAL =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#0a0a0b"/>' +
    '<rect x="9" y="9" width="14" height="14" fill="none" ' +
          'stroke="#fbbf24" stroke-width="2" transform="rotate(45 16 16)"/>' +
    '<rect x="13" y="13" width="6" height="6" fill="#fbbf24" ' +
          'transform="rotate(45 16 16)"/>' +
    '</svg>');
  var FAV_ALERT =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#0a0a0b"/>' +
    '<rect x="9" y="9" width="14" height="14" fill="none" ' +
          'stroke="#fbbf24" stroke-width="2" transform="rotate(45 16 16)"/>' +
    '<rect x="13" y="13" width="6" height="6" fill="#fbbf24" ' +
          'transform="rotate(45 16 16)"/>' +
    '<circle cx="24" cy="8" r="7" fill="#ef4444" ' +
            'stroke="#0a0a0b" stroke-width="1.5"/>' +
    '</svg>');
  var link = ensureFavicon();
  link.href = FAV_NORMAL;

  document.addEventListener("plenith:critical-count", function (e) {
    var n = (e && e.detail && e.detail.count) || 0;
    document.title = (n > 0 ? "(" + n + " CRIT) " : "") + baseTitle;
    link.href = (n > 0) ? FAV_ALERT : FAV_NORMAL;
    // Topbar Notify badge — lives outside #panels so SSE swaps never
    // touch it.  Drive its text + visibility from the same event.
    document.querySelectorAll("[data-notify-badge]").forEach(function (b) {
      b.textContent = String(n);
      if (n > 0) b.removeAttribute("hidden");
      else b.setAttribute("hidden", "");
    });
  });
})();

// ===========================================================================
// LIVE ALERT TOAST INJECTOR — Phase 6.  Pushes a toast onto the
// existing #toast-stack (the markup is in dashboard_styles.py / .toast).
// Toasts auto-dismiss after 12s for non-critical, 30s for critical;
// click X to dismiss early.  Exposed as window.plenithPushAlertToast
// so the SSE handler above can call it.
// ===========================================================================
(function () {
  function ensureStack() {
    var stack = document.getElementById("toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.id = "toast-stack";
      stack.className = "toast-stack";
      // Default to polite for the stack; per-toast severity can override
      // by setting aria-live="assertive" on the individual toast element.
      stack.setAttribute("role", "log");
      stack.setAttribute("aria-live", "polite");
      stack.setAttribute("aria-atomic", "false");
      stack.setAttribute("aria-label", "Plenith alerts and notifications");
      document.body.appendChild(stack);
    }
    return stack;
  }
  function severityClass(sev) {
    return ({"critical": "critical", "high": "high",
              "medium": "medium", "info": "info"})[sev] || "info";
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  window.plenithPushAlertToast = function (alert) {
    var stack = ensureStack();
    var sev = severityClass(alert.severity);
    var el = document.createElement("div");
    el.className = "toast " + sev;
    // Per-toast politeness override: critical/high alerts interrupt
    // active screen-reader narration; medium/info are polite.
    if (sev === "critical" || sev === "high") {
      el.setAttribute("role", "alert");
      el.setAttribute("aria-live", "assertive");
    }
    el.innerHTML =
      '<div class="toast-close" aria-label="Dismiss notification">×</div>' +
      '<div class="toast-head">' +
        '<span class="sev-dot" aria-hidden="true"></span>' +
        '<span>' + sev.toUpperCase() + ' · ' + escapeHtml(alert.action) + '</span>' +
        '<span class="ts">now</span>' +
      '</div>' +
      '<div class="toast-title">' +
        escapeHtml(alert.engagement_short) + ' · ' +
        escapeHtml(alert.claimed_user) + '@' + escapeHtml(alert.source_ip) +
      '</div>' +
      '<div class="toast-body">' + escapeHtml(alert.triggered_by) + '</div>' +
      '<div class="toast-actions">' +
        '<a class="primary" data-toast-view="' + escapeHtml(alert.engagement_id) + '">View engagement</a>' +
        '<a data-toast-ack="' + escapeHtml(alert.engagement_id) + '|' + escapeHtml(alert.action) + '">Acknowledge</a>' +
      '</div>';
    stack.appendChild(el);
    el.querySelector(".toast-close").addEventListener("click", function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    var dismissMs = (sev === "critical") ? 30000 : 12000;
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, dismissMs);
  };

  // Toast action handlers (delegated)
  document.addEventListener("click", async function (ev) {
    var view = ev.target.closest("[data-toast-view]");
    if (view) {
      ev.preventDefault();
      var eid = view.getAttribute("data-toast-view");
      window.open("/panel/engagement/" + encodeURIComponent(eid),
                   "plenith-eng-" + eid.substring(0, 8),
                   "popup=yes,width=1100,height=820");
      return;
    }
    var ack = ev.target.closest("[data-toast-ack]");
    if (ack) {
      ev.preventDefault();
      var parts = ack.getAttribute("data-toast-ack").split("|");
      var eng = parts[0], action = parts[1];
      try {
        await fetch("/api/engagements/" + encodeURIComponent(eng) + "/ack", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action_name: action,
            op_id: localStorage.getItem("plenith-op-id") || "anonymous",
          }),
        });
        var toast = ack.closest(".toast");
        if (toast && toast.parentNode) toast.parentNode.removeChild(toast);
      } catch (e) { console.warn("toast ack failed:", e); }
    }
  });
})();

// ===========================================================================
// BROWSER NOTIFICATIONS — Phase 6.  Two pieces:
//   1. The "Notify" button in the top strip requests permission on click.
//      Persists the permission state so the user only sees the prompt once.
//   2. window.plenithMaybeNotify(alert) fires a desktop Notification for
//      critical alerts when the tab is unfocused (document.hidden).
//      No-op when permission is "denied" or "default" — operators who
//      didn't grant explicitly don't get pestered.
// ===========================================================================
(function () {
  function permission() {
    return ("Notification" in window) ? Notification.permission : "denied";
  }
  function refreshBtnLabel() {
    document.querySelectorAll("[data-notify-toggle]").forEach(function (b) {
      var perm = permission();
      var icon = b.querySelector(".ico");
      if (icon) icon.textContent = (perm === "granted") ? "🔔" : "◉";
      b.classList.toggle("active", perm === "granted");
      b.setAttribute("aria-pressed", perm === "granted" ? "true" : "false");
      b.setAttribute("aria-label",
        perm === "granted" ? "Disable desktop notifications" :
        perm === "denied"  ? "Notifications blocked by browser settings" :
                              "Enable desktop notifications for critical alerts");
    });
  }
  function escapeForToast(s) {
    return String(s).replace(/[<>&"]/g, function (c) {
      return ({"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;"})[c];
    });
  }
  function statusToast(message, kind) {
    var stack = document.getElementById("toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.id = "toast-stack";
      stack.className = "toast-stack";
      stack.setAttribute("role", "log");
      stack.setAttribute("aria-live", "polite");
      stack.setAttribute("aria-atomic", "false");
      stack.setAttribute("aria-label", "Plenith alerts and notifications");
      document.body.appendChild(stack);
    }
    var el = document.createElement("div");
    el.className = "toast " + (kind || "info");
    el.innerHTML =
      '<div class="toast-close">×</div>' +
      '<div class="toast-head"><span class="sev-dot"></span>' +
      '<span>' + escapeForToast(message) + '</span></div>';
    stack.appendChild(el);
    el.querySelector(".toast-close").addEventListener("click", function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 6000);
  }
  // Wire all [data-notify-toggle] buttons to request permission on click.
  // Always surfaces a toast so the operator gets visible feedback even
  // when the permission is already "granted" or already "denied" (the
  // browser silently skips re-prompts in those states).
  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-notify-toggle]");
    if (!btn) return;
    ev.preventDefault();
    if (!("Notification" in window)) {
      statusToast("Browser does not support desktop notifications.", "high");
      return;
    }
    var before = Notification.permission;
    if (before === "default") {
      try {
        var result = await Notification.requestPermission();
        if (result === "granted") {
          statusToast("Notifications enabled — critical alerts will pop when this tab is in the background.", "info");
        } else {
          statusToast("Notifications declined. Re-enable in browser settings if you change your mind.", "high");
        }
      } catch (e) {
        statusToast("Permission request failed: " + e.message, "high");
      }
    } else if (before === "granted") {
      statusToast("Notifications already enabled. Showing a test notification…", "info");
      try {
        new Notification("Plenith SOC", {
          body: "Notifications are working. Critical alerts will pop when this tab is unfocused.",
          tag:  "plenith-test",
        });
      } catch (e) { /* swallow */ }
    } else {
      statusToast("Notifications blocked by browser. To re-enable: open site settings → notifications → allow.", "high");
    }
    refreshBtnLabel();
  });
  refreshBtnLabel();

  window.plenithMaybeNotify = function (alert) {
    if (permission() !== "granted") return;
    if (!document.hidden) return;        // tab focused → toast is enough
    if (alert.severity !== "critical" && alert.severity !== "high") return;
    try {
      var n = new Notification(
        "[" + alert.severity.toUpperCase() + "] " + alert.action,
        {
          body: alert.engagement_short + " · " +
                alert.claimed_user + "@" + alert.source_ip + "\n" +
                (alert.triggered_by || ""),
          tag:  "plenith-" + alert.key,   // dedupe — re-firing same key replaces
          icon: document.querySelector('link[rel="icon"]') &&
                  document.querySelector('link[rel="icon"]').href,
        }
      );
      n.onclick = function () {
        window.focus();
        window.open(
          "/panel/engagement/" + encodeURIComponent(alert.engagement_id),
          "plenith-eng-" + alert.engagement_short,
          "popup=yes,width=1100,height=820",
        );
        n.close();
      };
    } catch (e) { console.warn("Notification failed:", e); }
  };
})();

// ===========================================================================
// COUNTER-AI GAUGE TREND
// The server renders the current composite confidence as
// `<div class="gauge-trend" data-trend-eid=… data-trend-conf=…/>`.
// We persist (ts, conf) per engagement in sessionStorage and fill the
// trend label with "▲ 0.34 → 0.88" when the value has moved.  The
// stored baseline only rotates every ~4 minutes so a noisy 3-second
// SSE refresh doesn't keep resetting the displayed delta.
// ===========================================================================
(function () {
  var STORE_KEY = "plenith-conf-baseline";
  var WINDOW_S  = 240;        // rotate baseline after ~4 minutes
  var EPS       = 0.02;       // ignore jitter below 2 points

  function loadAll() {
    try { return JSON.parse(sessionStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function saveAll(s) { sessionStorage.setItem(STORE_KEY, JSON.stringify(s)); }

  function fmt(v) { return (Math.round(v * 100) / 100).toFixed(2); }

  window.plenithApplyConfidenceTrend = function () {
    var all = loadAll();
    var nowS = Date.now() / 1000;
    document.querySelectorAll("[data-trend-eid]").forEach(function (el) {
      var eid  = el.getAttribute("data-trend-eid");
      var conf = parseFloat(el.getAttribute("data-trend-conf") || "0");
      if (!eid || isNaN(conf)) return;
      var entry = all[eid];
      var html  = "";
      if (entry && typeof entry.conf === "number") {
        var d = conf - entry.conf;
        if (Math.abs(d) >= EPS) {
          var cls   = d > 0 ? "up" : "down";
          var arrow = d > 0 ? "▲" : "▼";
          html = '<span class="' + cls + '">' + arrow + ' ' +
                 fmt(entry.conf) + ' → ' + fmt(conf) + '</span>';
        } else {
          html = '<span class="dim">steady</span>';
        }
        // Rotate the baseline only when the window expires; that way
        // the displayed delta is stable, not flickering on every tick.
        if (nowS - entry.ts >= WINDOW_S) {
          all[eid] = { conf: conf, ts: nowS };
          saveAll(all);
        }
      } else {
        // No baseline yet — seed it and mark as "new".
        html = '<span class="dim">new</span>';
        all[eid] = { conf: conf, ts: nowS };
        saveAll(all);
      }
      el.innerHTML = html;
    });
  };
})();

// ===========================================================================
// ALERT-ROW ↔ COMMAND TIMELINE LINKING + COMMAND INSPECT MODAL
// Clicking an alert row scrolls the matching command row into view and
// flashes it.  Clicking a command row opens a modal showing the full
// command + response_source + response_preview.  Both surface details
// the row markup deliberately truncates.
// ===========================================================================
(function () {
  function findCmdRowByTs(ts) {
    if (!ts) return null;
    // Search globally — a popped-out engagement window has its own
    // detail panel + timeline, and the main page swaps panels via SSE.
    return document.querySelector('[data-cmd-row][data-cmd-ts="' + ts + '"]');
  }
  function flash(el) {
    if (!el) return;
    el.classList.remove("cmd-flash");
    // force reflow so the animation restarts when the class is re-added
    void el.offsetWidth;
    el.classList.add("cmd-flash");
    setTimeout(function () { el.classList.remove("cmd-flash"); }, 1800);
  }
  document.addEventListener("click", function (ev) {
    // Don't capture clicks on the Acknowledge button inside the row.
    if (ev.target.closest("button, a")) return;
    var row = ev.target.closest("[data-alert-row]");
    if (!row) return;
    var ts = row.getAttribute("data-alert-ts");
    var cmd = findCmdRowByTs(ts);
    if (!cmd) {
      // Surface a hint instead of silently doing nothing — alerts can
      // fire on events with no matching command (auth events, etc.).
      if (window.plenithPushAlertToast || window.plenithStatusToast) {
        // soft toast — reuse the ack-toast helper if loaded
        var t = document.createElement("div");
        t.className = "ack-toast";
        t.innerHTML = '<span class="label">No matching command in the visible timeline window.</span>';
        document.body.appendChild(t);
        setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 3000);
      }
      return;
    }
    cmd.scrollIntoView({ behavior: "smooth", block: "center" });
    flash(cmd);
  });

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function ensureCmdModal() {
    var m = document.getElementById("command-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "command-modal";
    m.className = "export-modal";        // reuse styles
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">Command</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="export-modal-body"><pre class="export-modal-pre" tabindex="0"></pre></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) m.setAttribute("hidden", "");
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) m.setAttribute("hidden", "");
    });
    return m;
  }
  function openCommandModal(row) {
    var m = ensureCmdModal();
    var ts   = row.getAttribute("data-cmd-ts-display") || "—";
    var src  = row.getAttribute("data-cmd-src") || "?";
    var cmd  = row.getAttribute("data-cmd-text") || "";
    var resp = row.getAttribute("data-cmd-resp") || "";
    m.querySelector(".export-modal-title").textContent =
      "Command · " + (src.split("+")[0] || "?");
    m.querySelector(".export-modal-meta").textContent = ts + "  ·  source: " + src;
    var pre = m.querySelector(".export-modal-pre");
    pre.innerHTML =
      '<strong>$ ' + escapeHtml(cmd) + '</strong>\n\n' +
      (resp
        ? escapeHtml(resp) + (resp.length >= 200
            ? '\n\n<span class="dim">— response preview truncated at 200 chars; see ' +
              'session log for full output —</span>'
            : '')
        : '<span class="dim">(no response body captured)</span>');
    m.removeAttribute("hidden");
    setTimeout(function () {
      try { pre.focus({ preventScroll: true }); } catch (_) { pre.focus(); }
    }, 0);
  }
  document.addEventListener("click", function (ev) {
    if (ev.target.closest("button, a, [data-modal-close]")) return;
    var row = ev.target.closest("[data-cmd-row]");
    if (!row) return;
    openCommandModal(row);
  });
})();

// ===========================================================================
// EXPORT-LINK MODAL PREVIEW
// Plain click on an audit / IoC / Sigma / STIX / narrate link in the
// detail-panel header opens an in-page modal with the export's content.
// Cmd/Ctrl/Shift/middle-click bypass the handler so the browser still
// opens the link in a new tab (or downloads it) — that's the muscle-
// memory escape hatch.  Downloads (`.csv` / `.yaml`) get the preview
// too, with a "Download" button so the operator can still save the file.
// ===========================================================================
(function () {
  function isModifierClick(ev) {
    // Modifier keys + middle-click → respect browser default (new tab / DL)
    return ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey ||
           ev.button === 1 || ev.which === 2;
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function ensureModal() {
    var m = document.getElementById("export-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "export-modal";
    m.className = "export-modal";
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">Export preview</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<a class="filter" data-modal-newtab target="_blank">Open in new tab</a>' +
            '<a class="filter" data-modal-download>Download</a>' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="export-modal-body"><pre class="export-modal-pre" tabindex="0"></pre></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) closeModal();
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) closeModal();
    });
    return m;
  }
  function closeModal() {
    var m = document.getElementById("export-modal");
    if (m) m.setAttribute("hidden", "");
  }
  function prettyByContentType(text, contentType) {
    if (!contentType) return text;
    if (contentType.indexOf("json") !== -1) {
      try { return JSON.stringify(JSON.parse(text), null, 2); }
      catch (e) { return text; }
    }
    return text;
  }
  function inferTitle(href) {
    if (/\/audit$/.test(href))     return "Plaintext audit";
    if (/\/narrate$/.test(href))   return "Narrative summary";
    if (/\/ioc\.json$/.test(href)) return "IoC bundle (JSON)";
    if (/\/ioc\.csv$/.test(href))  return "IoC bundle (CSV)";
    if (/\/ioc\.stix$/.test(href)) return "STIX 2.1 bundle";
    if (/\/sigma\.yaml$/.test(href)) return "Sigma rule(s) (YAML)";
    return "Export preview";
  }
  function isDownloadable(href) {
    return /\.(csv|yaml)$/.test(href);
  }
  async function openInModal(href, anchorEl) {
    var m = ensureModal();
    var title = inferTitle(href);
    m.querySelector(".export-modal-title").textContent = title;
    var pre = m.querySelector(".export-modal-pre");
    var meta = m.querySelector(".export-modal-meta");
    pre.textContent = "Loading…";
    meta.textContent = href;
    var nt = m.querySelector("[data-modal-newtab]");
    nt.setAttribute("href", href);
    var dl = m.querySelector("[data-modal-download]");
    if (isDownloadable(href)) {
      dl.setAttribute("href", href);
      dl.setAttribute("download", "");
      dl.style.display = "";
    } else {
      dl.style.display = "none";
      dl.removeAttribute("href");
    }
    m.removeAttribute("hidden");
    // Focus the pre so Esc / arrows / ctrl-A target it
    setTimeout(function () {
      try { pre.focus({ preventScroll: true }); } catch (e) { pre.focus(); }
    }, 0);

    try {
      var resp = await fetch(href, { headers: { "Accept": "*/*" } });
      var ct = resp.headers.get("content-type") || "";
      var body = await resp.text();
      // Truncate very large bodies — 1.5 MB cap
      var MAX = 1500000;
      var truncated = body.length > MAX;
      if (truncated) body = body.slice(0, MAX);
      pre.textContent = prettyByContentType(body, ct);
      meta.textContent = href +
        "  ·  " + (ct.split(";")[0] || "?") +
        "  ·  " + body.length + " bytes" +
        (truncated ? "  ·  truncated, use Open in new tab for full content" : "");
    } catch (e) {
      pre.textContent = "Failed to load: " + e.message;
      meta.textContent = href + "  ·  error";
    }
  }

  // Event-delegated so this works after every SSE swap and inside popouts.
  document.addEventListener("click", function (ev) {
    var a = ev.target.closest("a.filter[href*=\"/api/engagements/\"]");
    if (!a) return;
    // Only intercept the export links that live in the panel header's
    // [data-export-host] container (or any element marked as export host)
    // so we don't change behavior of other .filter anchors elsewhere.
    if (!ev.target.closest("[data-export-host]")) return;
    if (isModifierClick(ev)) return;        // respect new-tab / DL modifier
    ev.preventDefault();
    var href = a.getAttribute("href");
    if (href) openInModal(href, a);
  });

  // Expose so other code (e.g. toast-action links) could reuse.
  window.plenithOpenExportModal = openInModal;
})();

// ===========================================================================
// ALERT-RATE POPOUT CONTROLS
// Time-range tabs, severity filter chips, and stacked/line mode toggle.
// State is held in sessionStorage so the operator's choices persist
// across SSE re-renders of the popout's #panels container.
//
// Every control change does ONE fetch each to:
//   /api/alerts/chart.html?since=…&until=…&bucket_seconds=…&mode=…&severities=…
//   /api/alerts/top.html?since=…&until=…&limit=8
// and swaps the returned HTML into [data-alert-chart] and [data-alert-top].
// The /api/alerts/rate JSON endpoint is left untouched for SOAR consumers.
// ===========================================================================
(function () {
  // Only wire when this popout's toolbar is on the page.  The same JS
  // bundle ships everywhere; the toolbar selector keeps us a no-op on
  // pages that don't have the alert-rate panel.
  function findToolbar() {
    return document.querySelector("[data-alert-rate-toolbar]");
  }
  if (!findToolbar()) return;

  var STORE_RANGE = "plenith-ar-range";
  var STORE_MODE  = "plenith-ar-mode";
  var STORE_SEV   = "plenith-ar-sev";   // comma-joined list

  // Map each range key to (seconds_back, bucket_seconds, label, top_window_seconds).
  // top_window_seconds is what we ask /alerts/top for — usually matches
  // the chart range, but we floor it at 1h so very-short ranges still
  // show something useful in the side list.
  var RANGES = {
    "15m": { width: 900,     bucket: 30,    topWidth: 3600    },
    "1h":  { width: 3600,    bucket: 120,   topWidth: 3600    },
    "6h":  { width: 21600,   bucket: 300,   topWidth: 21600   },
    "24h": { width: 86400,   bucket: 900,   topWidth: 86400   },
    "7d":  { width: 604800,  bucket: 7200,  topWidth: 604800  },
    "30d": { width: 2592000, bucket: 43200, topWidth: 2592000 },
  };
  var ALL_SEV = ["critical", "high", "medium", "info"];

  // localStorage (not sessionStorage) so the choice survives both
  // page reloads AND a separate popout window writing to the same
  // keys (sessionStorage is per-tab; localStorage is per-origin and
  // fires a `storage` event in OTHER tabs).
  function getRange() {
    var r = localStorage.getItem(STORE_RANGE);
    return RANGES[r] ? r : "6h";
  }
  function setRange(r) { localStorage.setItem(STORE_RANGE, r); }
  function getMode() {
    var m = localStorage.getItem(STORE_MODE);
    return (m === "line" || m === "stacked") ? m : "stacked";
  }
  function setMode(m) { localStorage.setItem(STORE_MODE, m); }
  function getSeverities() {
    var raw = localStorage.getItem(STORE_SEV);
    if (raw === null) return ALL_SEV.slice();
    var s = raw.split(",").filter(function (x) { return ALL_SEV.indexOf(x) >= 0; });
    return s.length ? s : ALL_SEV.slice();
  }
  function setSeverities(s) { localStorage.setItem(STORE_SEV, s.join(",")); }

  var inFlight = 0;

  async function refresh() {
    var range = getRange();
    var mode  = getMode();
    var sev   = getSeverities();
    var conf  = RANGES[range];
    var now   = Math.floor(Date.now() / 1000);
    var since = now - conf.width;

    // Reflect the active controls in the DOM (chip classes + aria-pressed).
    document.querySelectorAll("[data-ar-range]").forEach(function (b) {
      var on = b.getAttribute("data-ar-range") === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-mode]").forEach(function (b) {
      var on = b.getAttribute("data-ar-mode") === mode;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-sev]").forEach(function (b) {
      var on = sev.indexOf(b.getAttribute("data-ar-sev")) >= 0;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });

    var seq = ++inFlight;
    var chartQS = new URLSearchParams({
      since: String(since),
      until: String(now),
      bucket_seconds: String(conf.bucket),
      mode: mode,
      severities: sev.join(","),
      range: range,
    }).toString();
    var topSince = now - conf.topWidth;
    var topQS = new URLSearchParams({
      since: String(topSince),
      until: String(now),
      limit: "8",
    }).toString();

    try {
      var [chartResp, topResp] = await Promise.all([
        fetch("/api/alerts/chart.html?" + chartQS,
              { headers: { "Accept": "text/html" } }),
        fetch("/api/alerts/top.html?" + topQS,
              { headers: { "Accept": "text/html" } }),
      ]);
      if (seq !== inFlight) return;   // newer request superseded this one
      var chartHtml = await chartResp.text();
      var topHtml   = await topResp.text();

      // The chart fragment ships two siblings: a [data-ar-stats] block
      // and either an <svg> or a <div class="dim"> when empty.  Parse
      // once, extract each piece, replace in place.
      var tmp = document.createElement("div");
      tmp.innerHTML = chartHtml;
      var newStats = tmp.querySelector("[data-ar-stats]");
      var newChart = tmp.querySelector("svg.sparkline-large, .dim");

      var statsHost = document.querySelector("[data-ar-stats]");
      if (newStats && statsHost && statsHost.parentNode) {
        statsHost.parentNode.replaceChild(newStats, statsHost);
      }
      var chartHost = document.querySelector("[data-alert-chart]");
      if (chartHost && newChart) {
        chartHost.innerHTML = "";
        chartHost.appendChild(newChart);
      }
      var topEl = document.querySelector("[data-alert-top]");
      if (topEl) topEl.innerHTML = topHtml;
    } catch (e) {
      console.warn("alert-rate refresh failed:", e);
    }
  }

  // Range tabs — single-select
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-range]");
    if (!btn) return;
    ev.stopPropagation();
    setRange(btn.getAttribute("data-ar-range"));
    refresh();
  });
  // Mode toggle — single-select
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-mode]");
    if (!btn) return;
    ev.stopPropagation();
    setMode(btn.getAttribute("data-ar-mode"));
    refresh();
  });
  // Severity chips — multi-select; refuses to leave the set empty.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-sev]");
    if (!btn) return;
    ev.stopPropagation();
    var sev = getSeverities();
    var name = btn.getAttribute("data-ar-sev");
    var i = sev.indexOf(name);
    if (i >= 0) {
      if (sev.length === 1) return;       // keep at least one severity on
      sev.splice(i, 1);
    } else {
      sev.push(name);
    }
    setSeverities(sev);
    refresh();
  });

  // Cross-tab sync: localStorage writes from a SIBLING tab (e.g. the
  // popout when this window is the main dashboard, or vice versa) fire
  // a `storage` event here.  Refresh whenever one of our keys changes.
  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_RANGE || ev.key === STORE_MODE || ev.key === STORE_SEV) {
      refresh();
    }
  });

  // Initial sync — reflect persisted state on first load, then refresh
  // so the server-rendered defaults are replaced by what the operator
  // last picked.  Also re-run after each SSE swap of the panel.
  function init() {
    if (!findToolbar()) return;
    refresh();
  }
  init();
  // Hook into the shared post-SSE-swap callback that every other
  // client-state module uses — much more reliable than a per-IIFE
  // MutationObserver, which races with the first SSE tick.  The
  // selector check inside refresh() means this is a no-op on pages
  // that don't have the alert-rate toolbar.
  window.plenithApplyAlertRate = function () {
    if (findToolbar()) refresh();
  };
  var _orig = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _orig === "function") _orig();
    if (window.plenithApplyAlertRate) window.plenithApplyAlertRate();
  };
})();

// ===========================================================================
// DNS POPOUT / MAIN-PANEL CONTROLS
// Result-type filter chips (all / resolved / blocked / nxdomain).  The
// popout adds KPI tiles + top blocked / top NXDOMAIN side lists which
// also refresh on filter change.  State is cross-tab via localStorage
// (same pattern as alert-rate).
// ===========================================================================
(function () {
  function findToolbar() {
    return document.querySelector("[data-dns-toolbar]");
  }
  if (!findToolbar()) return;

  var STORE_FILTER = "plenith-dns-filter";
  var VALID = ["all", "resolved", "blocked", "nxdomain"];

  function getFilter() {
    var v = localStorage.getItem(STORE_FILTER);
    return VALID.indexOf(v) >= 0 ? v : "all";
  }
  function setFilter(v) { localStorage.setItem(STORE_FILTER, v); }

  var inFlight = 0;

  async function refresh() {
    var filter = getFilter();

    // Reflect chip state — every toolbar on the page (main + popout
    // could co-exist in different windows of the same origin).
    document.querySelectorAll("[data-dns-filter]").forEach(function (b) {
      var on = b.getAttribute("data-dns-filter") === filter;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });

    var seq = ++inFlight;
    var feedQS = new URLSearchParams({
      result: filter,
      limit: "80",
    }).toString();

    var fetches = [
      fetch("/api/dns/feed.html?" + feedQS,
            { headers: { "Accept": "text/html" } }).then(r => r.text()),
    ];
    // The popout has the side lists; the main panel does not.  Only
    // fetch them when their hosts exist on the page.
    var blockedHost  = document.querySelector("[data-dns-top-blocked]");
    var nxdomainHost = document.querySelector("[data-dns-top-nxdomain]");
    if (blockedHost) {
      fetches.push(
        fetch("/api/dns/top.html?type=blocked&limit=10",
              { headers: { "Accept": "text/html" } }).then(r => r.text())
      );
    } else { fetches.push(Promise.resolve(null)); }
    if (nxdomainHost) {
      fetches.push(
        fetch("/api/dns/top.html?type=nxdomain&limit=10",
              { headers: { "Accept": "text/html" } }).then(r => r.text())
      );
    } else { fetches.push(Promise.resolve(null)); }

    try {
      var [feedHtml, blockedHtml, nxdomainHtml] = await Promise.all(fetches);
      if (seq !== inFlight) return;   // newer request superseded

      // Parse and swap the feed fragment.  The fragment ships a hidden
      // <span data-dns-feed-count-fragment> with the new count.
      var tmp = document.createElement("div");
      tmp.innerHTML = feedHtml;
      var countSpan = tmp.querySelector("[data-dns-feed-count-fragment]");
      if (countSpan) {
        var n = parseInt(countSpan.textContent, 10);
        document.querySelectorAll("[data-dns-feed-count]").forEach(function (c) {
          c.textContent = isNaN(n) ? "0" : String(n);
        });
        countSpan.remove();
      }
      var feedHost = document.querySelector("[data-dns-feed-host]");
      if (feedHost) {
        feedHost.innerHTML = "";
        while (tmp.firstChild) feedHost.appendChild(tmp.firstChild);
      }
      if (blockedHost && blockedHtml != null) blockedHost.innerHTML = blockedHtml;
      if (nxdomainHost && nxdomainHtml != null) nxdomainHost.innerHTML = nxdomainHtml;
    } catch (e) {
      console.warn("dns refresh failed:", e);
    }
  }

  // Filter chips — single-select; clicking the active chip resets to "all".
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-dns-filter]");
    if (!btn) return;
    ev.stopPropagation();
    var name = btn.getAttribute("data-dns-filter") || "all";
    if (getFilter() === name && name !== "all") name = "all";
    setFilter(name);
    refresh();
  });

  // Cross-tab sync
  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_FILTER) refresh();
  });

  function init() {
    if (!findToolbar()) return;
    refresh();
  }
  init();
  window.plenithApplyDns = function () {
    if (findToolbar()) refresh();
  };
  var _dnsOrig = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _dnsOrig === "function") _dnsOrig();
    if (window.plenithApplyDns) window.plenithApplyDns();
  };
})();
"""
