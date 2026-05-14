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
      if (open) {
        renderMenu(menu);
        // Auto-focus the rename input so the operator can type
        // immediately without a second click.
        var input = menu.querySelector("[data-layout-input]");
        if (input) setTimeout(function () { input.focus(); }, 0);
      }
    });
    // Submit-on-Enter convenience
    menu.addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter") return;
      var input = ev.target.closest("[data-layout-input]");
      if (!input) return;
      ev.preventDefault();
      var saveBtn = menu.querySelector("[data-layout-save]");
      if (saveBtn) saveBtn.click();
    });
    document.addEventListener("click", function () {
      menu.classList.remove("open");
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
  var STORE_QUERY = "plenith-filter-query";
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

  function applyFilter() {
    var q = currentQuery().toLowerCase().trim();
    var total = 0, visible = 0;
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      total += 1;
      var hay = (row.getAttribute("data-eng-hay") || "").toLowerCase();
      var hit = !q || hay.indexOf(q) !== -1;
      row.style.display = hit ? "" : "none";
      if (hit) visible += 1;
    });
    // Surface the match count on the panel header so it's obvious the
    // filter is working (otherwise with one matching row vs one total
    // you can't tell whether anything happened).
    var counter = document.querySelector("[data-filter-count]");
    if (counter) {
      counter.textContent = q
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
  };

  // Filter input — event-delegated since #panels is re-rendered.
  document.addEventListener("input", function (ev) {
    var search = ev.target.closest("[data-eng-search]");
    if (!search) return;
    setQuery(search.value || "");
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
  // Skip the panel swap while the operator is actively typing or
  // interacting with an input/textarea/contenteditable inside #panels.
  // The swap replaces every child node — including the element being
  // typed into — which is the bug that made the search box, notes
  // textarea, and ack toasts feel un-typeable.  The next swap when
  // focus moves away will catch up.
  function shouldSkipSwap() {
    var active = document.activeElement;
    if (!active || !holder.contains(active)) return false;
    var tag = active.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    if (active.isContentEditable) return true;
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
        btn.setAttribute("data-ack-state", "pending");
        btn.textContent = "Acknowledge";
        showUndoToast(
          "Un-ack’d " + action + " on " + eng.substring(0, 8),
          function () { return ackAction(eng, action); }
        );
      } else {
        await ackAction(eng, action);
        btn.setAttribute("data-ack-state", "acked");
        btn.textContent = "Un-ack";
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

    // Kill: handled by the hold listener below — single clicks are ignored.
  });

  // Hold-to-confirm for Kill buttons.  Press-and-hold the .danger
  // button for 1s to confirm; releasing early aborts.
  document.addEventListener("mousedown", function (ev) {
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    btn.classList.add("holding");
    var holdTimer = setTimeout(async function () {
      btn.disabled = true;
      var eng = btn.getAttribute("data-eng");
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/kill",
          { op_id: getOpId(), reason: "operator click-and-hold" }
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
    function abort() {
      clearTimeout(holdTimer);
      btn.classList.remove("holding");
      btn.removeEventListener("mouseup",    abort);
      btn.removeEventListener("mouseleave", abort);
    }
    btn.addEventListener("mouseup",    abort);
    btn.addEventListener("mouseleave", abort);
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
    el.innerHTML =
      '<div class="toast-close">×</div>' +
      '<div class="toast-head">' +
        '<span class="sev-dot"></span>' +
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
"""
